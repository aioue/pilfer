# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""pilfer set: change top-level scalars in a closed whole-file vault.

Decrypts and encrypts in memory, so plaintext never touches disk. The
destination is replaced only after the new ciphertext is complete and decrypts
back to the edited text, via a same-directory temp file and os.replace.

`ansible-vault encrypt` on an existing path shreds that file before the new
ciphertext is written (ansible/ansible#87679, open as of 2026-11). This module
never encrypts in place, so a failed encrypt leaves the original ciphertext.

`pilfer open` writes a *.pilfer-open sidecar next to each target before the
plaintext, so a sidecar or a plaintext file means a session is open. set refuses
both rather than walking vaultedFileList.json.

A `$ANSIBLE_VAULT;1.2;AES256;<label>` header keeps its label: VaultLib.encrypt
writes 1.1 unless it is given the vault_id, and a dropped label changes which
--vault-id ansible-vault later matches.

Ansible runs Jinja over vaulted strings: a vaulted "ab{{ 7*6 }}cd" reaches a play
as ab42cd (checked on ansible-core 2.21). A value that contains a Jinja delimiter
is therefore written as `!unsafe "..."`, which Ansible leaves literal when the
text still loads as a string. `!unsafe` re-resolves the scalar, so `!unsafe "0123"`
becomes the integer 83. An existing !unsafe tag is kept only when Ansible would
still load the new text as that string. Otherwise the tag is dropped and the
value is a plain quoted scalar. A value that needs !unsafe and would not stay a
string is refused. Other values stay plain double-quoted scalars, the form line
readers such as homelab's ha_token.py parse.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

import yaml

from pilfer.cli import (
    OPEN_SIDECAR_SUFFIX,
    REKEY_TEMP_PREFIX,
    PilferError,
    _load_password,
    _make_vault,
)
from pilfer.inline import (
    VaultLabelError,
    _vault_id_from_ciphertext,
    is_whole_file_vault,
    normalize_whole_file_vault,
)
from pilfer.publish import copy_owner_group_and_acls, vault_file_lock

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
UNSAFE_TAG = "!unsafe"
# Jinja's default block, variable and comment openers, which Ansible uses.
JINJA_DELIMITERS = ("{{", "{%", "{#")
# Large enough for a certificate or key bundle; small enough that a mistaken
# `< /dev/zero` or a pasted log is refused instead of read into memory.
MAX_STDIN_VALUE_BYTES = 1024 * 1024


class _Unsafe(str):
    """A string read from an !unsafe scalar, so the round-trip check can see the tag."""


class _SetLoader(yaml.SafeLoader):
    """SafeLoader that also reads Ansible's !unsafe, so vaults that use it can be edited.

    Pure Python, not CSafeLoader: the edit slices the text at the composer's marks,
    and the check below must parse with the same rules that produced them.
    """


def _construct_unsafe(loader: yaml.SafeLoader, node: yaml.Node):
    if isinstance(node, yaml.ScalarNode):
        return _Unsafe(loader.construct_scalar(node))
    # Ansible also accepts !unsafe on a list or mapping. Its items are left as
    # they are by set, so building them plainly is enough for the comparison.
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


# add_constructor on the subclass copies the table; yaml.SafeLoader is untouched.
_SetLoader.add_constructor(UNSAFE_TAG, _construct_unsafe)


def set_keys(
    path: str | os.PathLike,
    values: Mapping[str, str],
    vault_password_file: str | None = None,
    *,
    check_only: bool = False,
) -> dict[str, str]:
    """Insert or replace top-level scalars in one encrypt. Returns key -> added/updated/unchanged.

    All keys land in one write, so a crash cannot leave some of them set. A new
    key is appended at the end. If nothing changes, the file bytes are left alone
    so git does not see a new vault blob. Error messages never contain a value or
    a decrypted line. Every refusal and failure is a PilferError.

    check_only runs every step except the final os.replace: the edit, the encrypt
    and round-trip, and writing the ciphertext to a temp file in the vault's
    directory, which is then removed. An edit that does not change the text still
    writes that temp, so a read-only directory or a full disk is reported before
    the real call. A caller can learn before an irreversible action (minting a
    token) whether the write will be refused. Pass a placeholder shaped like the
    real value. A concurrent change between the check and the real call is still
    refused then.
    """
    path = Path(path)
    if not values:
        raise PilferError("no keys to set")
    for key, value in values.items():
        _check_key(key)
        if not isinstance(value, str) or value == "":
            raise PilferError(f"refusing an empty value for {key}")
        if "\0" in value:
            raise PilferError(f"refusing a value for {key} that contains NUL")

    try:
        return _set_keys(path, values, vault_password_file, check_only)
    except VaultLabelError as exc:
        raise PilferError(str(exc)) from None
    except OSError as exc:
        # Callers in scripts catch PilferError; an unreadable password file or an
        # unwritable directory must not escape as a bare PermissionError. Name the
        # file and the OS reason only. A failed write on a descriptor has no filename.
        if not exc.strerror:
            detail = str(exc)
        elif exc.filename is None:
            detail = f"{exc.strerror} while writing {path}"
        else:
            detail = f"{exc.strerror}: {exc.filename}"
        raise PilferError(detail) from None


def _check_key(key: str) -> None:
    if not isinstance(key, str) or not KEY_RE.fullmatch(key):
        # The key slot is where a pasted secret shows up. Do not echo it.
        raise PilferError("refusing key; use a single YAML identifier")
    # YAML 1.1 reads yes/no/on/off/true/false/null keys as bools or None, so
    # `yes: x` would never be the key "yes" a playbook asks for.
    if yaml.safe_load(key) != key:
        raise PilferError("refusing key; YAML reads it as a bool or null, not a name")


def _set_keys(
    path: Path, values: Mapping[str, str], vault_password_file: str | None, check_only: bool
) -> dict[str, str]:
    with vault_file_lock(path):
        return _set_keys_locked(path, values, vault_password_file, check_only)


def _set_keys_locked(
    path: Path, values: Mapping[str, str], vault_password_file: str | None, check_only: bool
) -> dict[str, str]:
    original = _read_closed_vault(path)
    try:
        password, _ = _load_password(vault_password_file)
    except UnicodeDecodeError:
        # The exception text quotes a byte of the password.
        raise PilferError("vault password file is not valid text") from None
    normalized = normalize_whole_file_vault(original)
    vault_id = _vault_id_from_ciphertext(normalized)
    vault = _make_vault(password, [vault_id])
    try:
        # Decrypt the bytes just read, not the path, so the compare-before-replace
        # below is against exactly the ciphertext this edit is based on.
        text = vault.decrypt(normalized).decode("utf-8")
    except UnicodeDecodeError:
        raise PilferError(f"{path} did not decrypt to UTF-8") from None
    except Exception:
        raise PilferError(f"could not decrypt {path} with this vault password") from None

    actions = {}
    edited = text
    for key, value in values.items():
        edited, actions[key] = _edit_plaintext(edited, key, value)
    if edited == text:
        if check_only:
            # A no-op edit used to return before the temp write, so a placeholder
            # that already matched the stored value reported success on a
            # read-only directory.
            _replace_if_unchanged(path, original, original, publish=False)
        return actions

    plaintext = edited.encode("utf-8")
    try:
        ciphertext = vault.encrypt(plaintext, vault_id=vault_id)
    except Exception as exc:
        # Ansible's messages here do not quote plaintext, but name only the type:
        # the contract is that no PilferError carries vault content.
        raise PilferError(f"could not encrypt {path} ({type(exc).__name__}); unchanged") from None
    if is_whole_file_vault(ciphertext):
        try:
            round_trip = vault.decrypt(ciphertext)
        except Exception:
            raise PilferError(f"encryption did not round-trip; {path} unchanged") from None
    else:
        round_trip = None
    # Prove the bytes decrypt to what we meant before they replace anything.
    if round_trip != plaintext:
        raise PilferError(f"encryption did not round-trip; {path} unchanged")
    _replace_if_unchanged(path, ciphertext, original, publish=not check_only)
    return actions


def _read_closed_vault(path: Path) -> bytes:
    """Refuse symlinks, pilfer sessions, and plaintext on disk. Returns ciphertext bytes."""
    if path.is_symlink():
        # os.replace would turn the link into a regular file.
        raise PilferError(f"refusing to edit symlink {path}")
    if not path.is_file():
        raise PilferError(f"not a vault file: {path}")
    # Path.with_suffix(".pilfer-open") would replace .yml. The sidecar keeps the full name.
    if (path.parent / f"{path.name}{OPEN_SIDECAR_SUFFIX}").exists():
        raise PilferError(f"{path} is open in a pilfer session; run 'pilfer close' first")
    original = path.read_bytes()
    if not is_whole_file_vault(original):
        raise PilferError(
            f"{path} is not a whole-file vault; refusing to write plaintext. "
            "Run 'pilfer close', then set the key on the encrypted file"
        )
    return original


def _ansible_keeps_string(value: str) -> bool:
    """True when Ansible's !unsafe constructor still yields this exact string.

    The constructor resolves the scalar again, so quotes do not protect 0123,
    yes, null, or a date. A plain JSON-quoted scalar does not take that path.
    """
    from ansible.parsing.yaml.loader import AnsibleLoader

    rendered = json.dumps(value, ensure_ascii=False)
    try:
        loaded = AnsibleLoader(f"k: !unsafe {rendered}\n").get_single_data()
    except Exception:
        return False
    if not isinstance(loaded, dict):
        return False
    got = loaded.get("k")
    return isinstance(got, str) and got == value


def _load(text: str):
    # _SetLoader is a SafeLoader subclass; it adds only the !unsafe constructor.
    loader = _SetLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _tagged(mapping: dict) -> dict:
    # A plain str and an _Unsafe compare equal; the tag must match too.
    return {k: (isinstance(v, _Unsafe), v) for k, v in mapping.items()}


def _edit_plaintext(text: str, key: str, value: str) -> tuple[str, str]:
    # YAML errors quote the offending line, which is vault plaintext. Constructors
    # also raise plain ValueError (a "2023-02-30" date names its digits), so catch
    # every Exception here and in the round-trip load below, and drop the detail.
    try:
        old = _load(text)
        root = yaml.compose(text, Loader=_SetLoader)
    except Exception:
        raise PilferError("vault plaintext is not a single valid YAML document") from None
    if old is None:
        old = {}
    if not isinstance(old, dict) or not isinstance(root, yaml.MappingNode | None):
        raise PilferError("vault plaintext is not a YAML mapping")

    # The composer keeps duplicate keys that safe_load would silently collapse.
    nodes = [node for name, node in (root.value if root else []) if name.value == key]
    if len(nodes) > 1:
        raise PilferError(f"{key} appears {len(nodes)} times; refusing to guess")

    unsafe = any(delimiter in value for delimiter in JINJA_DELIMITERS)
    tagged = False
    if nodes:
        node = nodes[0]
        if not isinstance(node, yaml.ScalarNode) or node.style in ("|", ">"):
            raise PilferError(f"{key} is not a flow scalar; edit it in a pilfer open session")
        tagged = node.tag == UNSAFE_TAG
    # !unsafe re-resolves the scalar as a plain YAML value. Keep the tag only
    # when Ansible would still load this string. Call the loader only when the
    # tag would otherwise be written.
    if unsafe or tagged:
        stays = _ansible_keeps_string(value)
        if unsafe and not stays:
            raise PilferError(
                f"refusing to write {key}: !unsafe would change the value Ansible loads"
            )
        unsafe = unsafe or (tagged and stays)
    if nodes and old.get(key) == value and tagged == unsafe:
        return text, "unchanged"
    # json.dumps gives a double-quoted scalar, so YAML 1.1 does not coerce yes/no/numbers.
    rendered = json.dumps(value, ensure_ascii=False)
    if unsafe:
        rendered = f"{UNSAFE_TAG} {rendered}"
    if nodes:
        # Replace only the scalar's span, so an inline comment on the line survives.
        # The span starts at a tag or anchor when there is one, so a kept !unsafe is
        # written again above and an anchor is dropped (an alias to it then fails
        # the reload below).
        start, end = node.start_mark.index, node.end_mark.index
        if text[start - 1] not in " \t":
            # An empty value ("key:") marks the position right after the colon.
            rendered = f" {rendered}"
        new_text = text[:start] + rendered + text[end:]
        action = "updated"
    else:
        separator = "\n" if text and not text.endswith("\n") else ""
        new_text = f"{text}{separator}{key}: {rendered}\n"
        action = "added"

    # The quoted form cannot carry everything: U+0085 (NEL) is a YAML 1.1 line break and
    # folds to a space, and noncharacters such as U+FFFE fail the YAML reader. Refuse
    # rather than store a different secret.
    try:
        new = _load(new_text)
    except Exception:
        raise PilferError(f"refusing to write {key}: edit did not produce valid YAML") from None
    expected = {**old, key: _Unsafe(value) if unsafe else value}
    if not isinstance(new, dict) or _tagged(new) != _tagged(expected):
        raise PilferError(
            f"refusing to write {key}: YAML round-trip did not preserve the value or other keys"
        )
    return new_text, action


def _replace_if_unchanged(
    path: Path, data: bytes, expected: bytes, *, publish: bool = True
) -> None:
    """Publish ciphertext with the file's mode, unless another writer changed it meanwhile.

    With publish=False every step runs except os.replace, and the temp is removed:
    check_only uses it so a read-only directory or a full disk is reported before
    the real call. A mode or os.access check would miss ACLs, read-only mounts and
    sandbox denials. Not covered: a sticky directory where the vault belongs to
    another user, which only refuses the rename itself.

    The temp uses pilfer's rekey prefix, so open's scan skips a temp left by a
    killed process. It holds ciphertext only. open and close keep vault
    ciphertext temps; only a confirmed rekey deletes them.
    """
    mode = path.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=REKEY_TEMP_PREFIX, dir=path.parent)
    replaced = False
    try:
        # New inode. Copy uid, gid, mode, and ACLs, or a 0640 file would be
        # owned by the editor's primary group. Failure leaves the vault in place.
        copy_owner_group_and_acls(path, fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or path.read_bytes() != expected:
            raise PilferError(f"{path} changed during the edit; nothing written. Retry")
        # open writes the sidecar before plaintext. Recheck under the same lock
        # the open holds, so a session that appeared after the first read is refused.
        if (path.parent / f"{path.name}{OPEN_SIDECAR_SUFFIX}").exists():
            raise PilferError(f"{path} is open in a pilfer session; run 'pilfer close' first")
        if publish:
            os.replace(tmp, path)
            replaced = True
    finally:
        # BaseException too: KeyboardInterrupt must not leave the temp behind.
        if not replaced:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def read_value(key: str) -> str:
    """Read a value for `pilfer set` without putting it on the command line.

    A terminal gets a no-echo prompt. Piped or redirected input is read whole and
    one trailing line ending is dropped, so `echo "$TOKEN" | pilfer set ...` stores
    the token without a newline; a value that must end in a newline cannot come in
    this way. argv is visible in `ps` and lands in shell history; stdin is neither.
    """
    stdin = sys.stdin
    if stdin is None:
        raise PilferError(f"no value for {key}: pass it on stdin")
    if stdin.isatty():
        try:
            return getpass.getpass(f"Value for {key} (input hidden): ")
        except EOFError:
            raise PilferError(f"no value for {key}") from None
    data = stdin.buffer.read(MAX_STDIN_VALUE_BYTES + 1)
    if len(data) > MAX_STDIN_VALUE_BYTES:
        raise PilferError(f"value for {key} on stdin is over {MAX_STDIN_VALUE_BYTES} bytes")
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        # The exception text quotes the offending byte.
        raise PilferError(f"value for {key} on stdin is not UTF-8") from None
    return value.removesuffix("\n").removesuffix("\r") if value.endswith("\n") else value
