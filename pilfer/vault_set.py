# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
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
"""

from __future__ import annotations

import json
import os
import re
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
from pilfer.inline import is_whole_file_vault, normalize_whole_file_vault

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def set_keys(
    path: str | os.PathLike, values: Mapping[str, str], vault_password_file: str | None = None
) -> dict[str, str]:
    """Insert or replace top-level scalars in one encrypt. Returns key -> added/updated/unchanged.

    All keys land in one write, so a crash cannot leave some of them set. A new
    key is appended at the end. If nothing changes, the file bytes are left alone
    so git does not see a new vault blob. Error messages never contain a value or
    a decrypted line.
    """
    path = Path(path)
    if not values:
        raise PilferError("no keys to set")
    for key, value in values.items():
        if not KEY_RE.fullmatch(key):
            raise PilferError(f"refusing key {key!r}; use a single YAML identifier")
        if not isinstance(value, str) or value == "":
            raise PilferError(f"refusing an empty value for {key}")
        if "\0" in value:
            raise PilferError(f"refusing a value for {key} that contains NUL")

    original = _read_closed_vault(path)
    password, _ = _load_password(vault_password_file)
    vault = _make_vault(password)
    try:
        # Decrypt the bytes just read, not the path, so the compare-before-replace
        # below is against exactly the ciphertext this edit is based on.
        text = vault.decrypt(normalize_whole_file_vault(original)).decode("utf-8")
    except UnicodeDecodeError:
        raise PilferError(f"{path} did not decrypt to UTF-8") from None
    except Exception:
        raise PilferError(f"could not decrypt {path} with this vault password") from None

    actions = {}
    edited = text
    for key, value in values.items():
        edited, actions[key] = _edit_plaintext(edited, key, value)
    if edited == text:
        return actions

    plaintext = edited.encode("utf-8")
    ciphertext = vault.encrypt(plaintext)
    # Prove the bytes decrypt to what we meant before they replace anything.
    if not is_whole_file_vault(ciphertext) or vault.decrypt(ciphertext) != plaintext:
        raise PilferError(f"encryption did not round-trip; {path} unchanged")
    _replace_if_unchanged(path, ciphertext, original)
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


def _edit_plaintext(text: str, key: str, value: str) -> tuple[str, str]:
    # YAML errors quote the offending line, which is vault plaintext. Constructors
    # also raise plain ValueError (a "2023-02-30" date names its digits), so catch
    # every Exception here and in the round-trip load below, and drop the detail.
    try:
        old = yaml.safe_load(text)
        root = yaml.compose(text, Loader=yaml.SafeLoader)
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

    # json.dumps gives a double-quoted scalar, so YAML 1.1 does not coerce yes/no/numbers.
    rendered = json.dumps(value, ensure_ascii=False)
    if nodes:
        node = nodes[0]
        if not isinstance(node, yaml.ScalarNode) or node.style in ("|", ">"):
            raise PilferError(f"{key} is not a flow scalar; edit it in a pilfer open session")
        if old.get(key) == value:
            return text, "unchanged"
        # Replace only the scalar's span, so an inline comment on the line survives.
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
        new = yaml.safe_load(new_text)
    except Exception:
        raise PilferError(f"refusing to write {key}: edit did not produce valid YAML") from None
    if new != {**old, key: value}:
        raise PilferError(
            f"refusing to write {key}: YAML round-trip did not preserve the value or other keys"
        )
    return new_text, action


def _replace_if_unchanged(path: Path, data: bytes, expected: bytes) -> None:
    """Publish ciphertext with the file's mode, unless another writer changed it meanwhile.

    The temp uses pilfer's rekey prefix, so open's scan skips a temp left by a
    killed process. It holds ciphertext only. open and close keep vault
    ciphertext temps; only a confirmed rekey deletes them.
    """
    mode = path.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=REKEY_TEMP_PREFIX, dir=path.parent)
    replaced = False
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or path.read_bytes() != expected:
            raise PilferError(f"{path} changed during the edit; nothing written. Retry")
        os.replace(tmp, path)
        replaced = True
    finally:
        # BaseException too: KeyboardInterrupt must not leave the temp behind.
        if not replaced:
            try:
                os.unlink(tmp)
            except OSError:
                pass
