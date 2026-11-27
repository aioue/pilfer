# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""pilfer set: change scalar values, by key path, in a closed whole-file vault.

Decrypts and encrypts in memory, so plaintext never touches disk. The
destination is replaced only after the new ciphertext is complete and decrypts
back to the edited text, via a same-directory temp file and os.replace.

`ansible-vault encrypt` on an existing path shreds that file before the new
ciphertext is written (ansible/ansible#87679, open as of 2026-11). This module
never encrypts in place, so a failed encrypt leaves the original ciphertext.

`pilfer open` writes a *.pilfer-open sidecar next to each target before the
plaintext, so a sidecar or a plaintext file means a session is open. set refuses
both rather than walking vaultedFileList.json.

The new ciphertext is made with the secret that decrypts the old one, under
its `$ANSIBLE_VAULT;1.2;AES256;<label>` label, as ansible-vault edit does
(vault_secrets.encrypt_like). VaultLib.encrypt writes 1.1 unless it is given
the vault_id, and a dropped label changes which --vault-id ansible-vault later
matches.

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

import copy
import getpass
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

import yaml
from ansible.parsing.vault import VaultLib

from pilfer.cli import (
    MAX_READ_BYTES,
    PilferError,
    _open_sidecar_path,
    _read_no_follow,
    _too_large_message,
)
from pilfer.inline import (
    _compose,
    _compose_as_ansible,
    block_newline,
    find_inline_vault_spans,
    format_encrypted_block,
    is_whole_file_vault,
    normalize_whole_file_vault,
)
from pilfer.key_paths import IDENTIFIER_RE, parse_key_path, render_key_path, walk_keys
from pilfer.publish import locked_by_path, publish_vault
from pilfer.vault_secrets import (
    RoundTripError,
    VaultLabelError,
    encrypt_like,
    load_vault,
    vault_label,
)

UNSAFE_TAG = "!unsafe"
# The value a check-only run uses when the real one has not been read yet (or
# must not be): a dry run, or the refusal check before a prompt.
CHECK_PLACEHOLDER = "pilfer-set-check-placeholder"
# Printed by a dry run (set and update) that used CHECK_PLACEHOLDER, so the
# "would update" line is not read as a check of a value nobody supplied.
DRY_RUN_UNCHECKED = "The value was not checked: stdin was not read."
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
    vault_password_file=None,
    *,
    check_only: bool = False,
    create: bool = True,
) -> dict[str, str]:
    """Insert or replace scalars, by key path, in one encrypt. Returns key -> added/updated/unchanged.

    vault_password_file is a password file or script path, a
    pilfer.vault_secrets.VaultSources, or a VaultLib already loaded. None uses
    Ansible's config as of import, then pilfer's fallback paths.

    All keys land in one write, so a crash cannot leave some of them set. A new
    key is appended at the end. A key may be a Jinja path (`aws.prod.key`,
    `users[0].password`); missing mappings along it are created. create=False
    refuses a key that does not exist (pilfer update). If nothing changes, the
    file bytes are left alone so git does not see a new vault blob. Error
    messages never contain a value or a decrypted line. Every refusal and
    failure is a PilferError.

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
        # parse_key_path never quotes the key: the key slot is where a pasted secret shows up.
        parse_key_path(key)
        _check_value(key, value)

    try:
        return _set_keys(path, values, vault_password_file, check_only, create)
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


# A key can be any length, and a refusal quotes it. Clip what is shown.
_SHOWN_KEY_CHARS = 80


def _clip(text: str) -> str:
    return text if len(text) <= _SHOWN_KEY_CHARS else text[:_SHOWN_KEY_CHARS] + "…"


def _shown_path(path: list) -> str:
    return _clip(render_key_path(path))


def _check_new_top_name(top: str) -> None:
    """Refuse a top-level name that a playbook could not ask for by name.

    Applied only when the key is missing and would be created: an existing key
    (find-keys prints `['a.b'].c`) must stay updatable whatever its name.
    """
    if not IDENTIFIER_RE.fullmatch(top):
        raise PilferError("refusing key; a top-level name must be a YAML identifier")
    # YAML 1.1 reads yes/no/on/off/true/false/null keys as bools or None, so
    # `yes: x` would never be the key "yes" a playbook asks for.
    if yaml.safe_load(top) != top:
        raise PilferError("refusing key; YAML reads it as a bool or null, not a name")


@locked_by_path
def _set_keys(
    path: Path, values: Mapping[str, str], vault_password_file, check_only: bool, create: bool
) -> dict[str, str]:
    """The edit itself. No sidecar recheck before the write is needed: this holds
    vault_file_lock from its first read, and open writes its sidecar under it.
    """
    original = _read_closed_vault(path)
    normalized = normalize_whole_file_vault(original)
    # Before the password loads: a label that cannot be written back is refused as such.
    vault_label(normalized)
    if isinstance(vault_password_file, VaultLib):
        vault = vault_password_file
    else:
        vault = load_vault(vault_password_file)
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
        edited, actions[key] = _edit_plaintext(edited, key, value, create=create)
    if edited == text:
        if check_only:
            # A no-op edit used to return before the temp write, so a placeholder
            # that already matched the stored value reported success on a
            # read-only directory.
            publish_vault(path, original, expected=original, action="set", publish=False)
        return actions

    plaintext = edited.encode("utf-8")
    try:
        ciphertext = encrypt_like(vault, plaintext, normalized)
    except RoundTripError:
        raise PilferError(f"encryption did not round-trip; {path} unchanged") from None
    except Exception as exc:
        # Ansible's messages here do not quote plaintext, but name only the type:
        # the contract is that no PilferError carries vault content.
        raise PilferError(f"could not encrypt {path} ({type(exc).__name__}); unchanged") from None
    # encrypt_like already proved the ciphertext decrypts to plaintext with the
    # secret it was made with (RoundTripError above), so no second decrypt here.
    publish_vault(path, ciphertext, expected=original, action="set", publish=not check_only)
    return actions


def read_capped(path, what: str) -> bytes:
    """Read a file without following a link, refusing over MAX_READ_BYTES (the scan's own cap).

    No-follow: a repo can plant a symlink where pilfer expects a vault file, a
    backup or a sidecar, and a read must not go through it.
    """
    data = _read_no_follow(str(path), what, MAX_READ_BYTES + 1)
    if len(data) > MAX_READ_BYTES:
        raise PilferError(f"{what} {_too_large_message()}")
    return data


def _read_unopened(path: Path) -> bytes:
    """Refuse symlinks, non-files and files open in a pilfer session; return the bytes."""
    if path.is_symlink():
        # os.replace would turn the link into a regular file.
        raise PilferError(f"refusing to edit symlink {path}")
    if not path.is_file():
        raise PilferError(f"not a vault file: {path}")
    if os.path.exists(_open_sidecar_path(str(path))):
        raise PilferError(f"{path} is open in a pilfer session; run 'pilfer close' first")
    return read_capped(path, "vault file")


def _read_closed_vault(path: Path) -> bytes:
    """Like _read_unopened, and also refuse plaintext on disk. Returns ciphertext bytes."""
    original = _read_unopened(path)
    if not is_whole_file_vault(original):
        # A file pilfer opened has its sidecar, refused above. This one was
        # never encrypted, or was decrypted by something other than pilfer.
        message = f"{path} is not a whole-file vault; refusing to write plaintext."
        if find_inline_vault_spans(original):
            message += (
                " It holds inline !vault values: change those in a "
                "'pilfer open --include-encrypted-vars' session or, for an existing key, "
                "'pilfer update KEY --include-encrypted-vars'."
            )
        else:
            message += " pilfer set edits whole-file vaults only."
        raise PilferError(message)
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
    return yaml.load(text, Loader=_SetLoader)  # nosec B506 - a SafeLoader subclass


_MISSING = object()


def _value_at(obj, path: list):
    """The loaded value at path, or _MISSING."""
    for segment in path:
        try:
            obj = obj[segment]
        except (KeyError, IndexError, TypeError):
            return _MISSING
    return obj


def _assign(obj, path: list, value) -> None:
    """Set value at path in a loaded structure, creating mappings for missing names."""
    for segment in path[:-1]:
        obj = obj[segment] if isinstance(segment, int) else obj.setdefault(segment, {})
    obj[path[-1]] = value


def _locate(root, path: list):
    """Walk path through the composed document.

    Returns (depth, container, target, loaded_path). target is the node at the
    whole path, or None when a name is missing: depth is then the first missing
    segment and container the mapping that should hold it (None for an empty
    document). Refuses a parent that is not a mapping or list, a list index out of
    range, and duplicate keys, none of which can be edited safely.

    loaded_path is path with each name replaced by the key the loader makes from its
    node: YAML 1.1 reads a key such as yes, on, null or 1 as a bool, None or int, so
    the loaded mapping holds True where the path says "yes". Names that do not exist
    yet, and everything after them, stay as written.
    """
    loader = _SetLoader("")
    resolved: list = []
    try:
        node = root
        for depth, segment in enumerate(path):
            if node is None:
                return depth, None, None, resolved + path[depth:]
            where = _shown_path(path[:depth]) if depth else "the document"
            if isinstance(segment, int):
                if not isinstance(node, yaml.SequenceNode):
                    raise PilferError(f"{where} is not a list; refusing to index it")
                if segment >= len(node.value):
                    raise PilferError(
                        f"{where} has {len(node.value)} item(s); index {segment} is out of range"
                    )
                child = node.value[segment]
                resolved.append(segment)
            else:
                if not isinstance(node, yaml.MappingNode):
                    raise PilferError(f"{where} is not a mapping; refusing to replace it")
                # The composer keeps duplicate keys that safe_load would silently collapse.
                matches = [
                    (key, value)
                    for key, value in node.value
                    if isinstance(key, yaml.ScalarNode) and key.value == segment
                ]
                if len(matches) > 1:
                    raise PilferError(
                        f"{_shown_path(path[: depth + 1])} appears {len(matches)} times; "
                        "refusing to guess"
                    )
                if not matches:
                    return depth, node, None, resolved + path[depth:]
                resolved.append(loader.construct_object(matches[0][0]))
                child = matches[0][1]
            if depth == len(path) - 1:
                return depth, node, child, resolved
            node = child
        raise AssertionError("empty path")  # parse_key_path never returns one
    finally:
        loader.dispose()


# One message for every anchor, alias and << merge refusal.
_SHARED_MESSAGE = (
    "{shown} touches a YAML anchor, alias or << merge; edit it in a pilfer open session"
)


def _has_merge_key(node) -> bool:
    """True if a mapping node has a `<<` merge key: a key missing from its own pairs may come from it."""
    return isinstance(node, yaml.MappingNode) and any(
        isinstance(key, yaml.ScalarNode) and key.tag == "tag:yaml.org,2002:merge"
        for key, _ in node.value
    )


def _shared_on_path(root, path: list):
    """True if a node on the path to the edit is reached through an alias too.

    The composer returns the same node object for an anchor and each alias of
    it, so a node with more than one parent reference is shared. Neither path's
    round-trip check catches an edit through one: the copy it compares against keeps
    the sharing, so `prod: *d` edited at prod.token would silently change d too.
    """
    refs: dict[int, int] = {}
    seen: set[int] = set()
    stack = [root] if root is not None else []
    while stack:
        node = stack.pop()
        if isinstance(node, yaml.MappingNode):
            children = [part for pair in node.value for part in pair]
        elif isinstance(node, yaml.SequenceNode):
            children = list(node.value)
        else:
            children = []
        for child in children:
            refs[id(child)] = refs.get(id(child), 0) + 1
            if id(child) not in seen:
                seen.add(id(child))
                stack.append(child)
    node = root
    for segment in path:
        if node is None:
            return False
        if isinstance(segment, int) and isinstance(node, yaml.SequenceNode):
            child = node.value[segment] if segment < len(node.value) else None
        elif isinstance(node, yaml.MappingNode):
            child = next(
                (
                    value
                    for key, value in node.value
                    if isinstance(key, yaml.ScalarNode) and key.value == segment
                ),
                None,
            )
        else:
            return False
        if child is not None and refs.get(id(child), 0) > 1:
            return True
        node = child
    return False


def _after_last_line(text: str, node: yaml.Node) -> int:
    """Offset of the line after node's last value, where a new sibling key goes.

    Descends to the last scalar or flow collection, since a block collection's own
    end mark can sit past trailing comments. Inserting after that line keeps an
    inline comment on it. A last child that is an alias reports its anchor's marks,
    so the key can land in the wrong place; the round-trip check then refuses it.
    """
    while (
        isinstance(node, yaml.MappingNode | yaml.SequenceNode)
        and not node.flow_style
        and node.value
    ):
        node = node.value[-1][1] if isinstance(node, yaml.MappingNode) else node.value[-1]
    end = node.end_mark.index
    if end > 0 and text[end - 1] == "\n":
        return end
    newline = text.find("\n", end)
    return len(text) if newline < 0 else newline + 1


def _yaml_key(name: str) -> str:
    """A mapping key as YAML text: plain when YAML reads it back as the same string."""
    if IDENTIFIER_RE.fullmatch(name) and yaml.safe_load(name) == name:
        return name
    return json.dumps(name, ensure_ascii=False)


def _edit_plaintext(text: str, key: str, value: str, *, create: bool = True) -> tuple[str, str]:
    path = parse_key_path(key)
    shown = _shown_path(path)
    # YAML errors quote the offending line, which is vault plaintext. Constructors
    # also raise plain ValueError (a "2023-02-30" date names its digits), so catch
    # every Exception here and in the round-trip load below, and drop the detail.
    try:
        old = _load(text)
        root = yaml.compose(text, Loader=_SetLoader)
    except Exception as exc:
        # Editing needs exact marks, so a tab Ansible tolerates still refuses here.
        # Only a scan/parse failure gets this message: an unknown tag, a nested
        # !vault, a bad date or several documents fail for other reasons.
        if (
            isinstance(exc, yaml.scanner.ScannerError | yaml.parser.ParserError)
            and _compose_as_ansible(text) is not None
        ):
            raise PilferError(
                "pilfer's YAML parser rejects this vault plaintext, though Ansible reads it "
                "(often a tab where YAML wants a space); replace the tab with spaces "
                "(edit it with ansible-vault edit)"
            ) from None
        raise PilferError("vault plaintext is not a single valid YAML document") from None
    if old is None:
        old = {}
    if not isinstance(old, dict) or not isinstance(root, yaml.MappingNode | None):
        raise PilferError("vault plaintext is not a YAML mapping")

    depth, container, node, loaded_path = _locate(root, path)
    # A shared node (an anchor used by an alias or a << merge elsewhere) cannot be
    # edited in place, and a key a << merge supplies is not in the mapping's own pairs.
    if _shared_on_path(root, path[: depth + 1] if node is None else path) or (
        node is None and _has_merge_key(container)
    ):
        raise PilferError(_SHARED_MESSAGE.format(shown=shown))
    if node is None:
        if not create:
            raise PilferError(f"{shown} does not exist")
        if any(isinstance(segment, int) for segment in path[depth:]):
            raise PilferError(
                f"refusing to create {shown}: a list cannot be created here; "
                "edit it in a pilfer open session"
            )
        if not depth:
            _check_new_top_name(path[0])
        if depth and container.flow_style:
            raise PilferError(
                f"refusing to add to {_shown_path(path[:depth])}: it is a flow mapping; "
                "edit it in a pilfer open session"
            )

    # Ansible's own test (lazy import: ansible.template is slow to load), so
    # a "#jinja2:" header is tagged too, not only {{ {% {#.
    from ansible.template import Templar

    unsafe = Templar().is_possibly_template(value)
    tagged = False
    if node is not None:
        if not isinstance(node, yaml.ScalarNode) or node.style in ("|", ">"):
            what = (
                "a mapping, not a single value"
                if isinstance(node, yaml.MappingNode)
                else "a list, not a single value"
                if isinstance(node, yaml.SequenceNode)
                else "a block scalar"
            )
            raise PilferError(f"{shown} is {what}; edit it in a pilfer open session")
        tagged = node.tag == UNSAFE_TAG
    # !unsafe re-resolves the scalar as a plain YAML value. Keep the tag only
    # when Ansible would still load this string. Call the loader only when the
    # tag would otherwise be written.
    if unsafe or tagged:
        stays = _ansible_keeps_string(value)
        if unsafe and not stays:
            raise PilferError(
                f"refusing to write {shown}: !unsafe would change the value Ansible loads"
            )
        unsafe = unsafe or (tagged and stays)
    if node is not None and _value_at(old, loaded_path) == value and tagged == unsafe:
        return text, "unchanged"
    # json.dumps gives a double-quoted scalar, so YAML 1.1 does not coerce yes/no/numbers.
    rendered = json.dumps(value, ensure_ascii=False)
    if unsafe:
        rendered = f"{UNSAFE_TAG} {rendered}"
    if node is not None:
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
        # A missing name goes after the mapping's last line, indented like its keys;
        # missing parents above it are created as nested mappings. At the top level
        # that is the end of the file.
        if depth:
            indent = container.value[0][0].start_mark.column
            position = _after_last_line(text, container)
        else:
            indent = 0
            position = len(text)
        names = path[depth:]
        lines = [" " * (indent + 2 * i) + f"{_yaml_key(name)}:" for i, name in enumerate(names)]
        lines[-1] += f" {rendered}"
        # Match the file's line endings, so a CRLF vault does not end up mixed.
        newline = "\r\n" if "\r\n" in text else "\n"
        separator = newline if position and text[position - 1] != "\n" else ""
        new_text = (
            f"{text[:position]}{separator}" + newline.join(lines) + f"{newline}{text[position:]}"
        )
        action = "added"

    # The quoted form cannot carry everything: U+0085 (NEL) is a YAML 1.1 line break and
    # folds to a space, and noncharacters such as U+FFFE fail the YAML reader. Refuse
    # rather than store a different secret.
    try:
        new = _load(new_text)
    except Exception:
        raise PilferError(f"refusing to write {shown}: edit did not produce valid YAML") from None
    expected = copy.deepcopy(old)
    wanted = _Unsafe(value) if unsafe else value
    _assign(expected, loaded_path, wanted)
    # A plain str and an _Unsafe compare equal, so the edited value's tag is checked apart.
    try:
        kept = new == expected and type(_value_at(new, loaded_path)) is type(wanted)
    except RecursionError:  # a recursive anchor (&a [*a]) compares forever
        kept = False
    if not kept:
        raise PilferError(
            f"refusing to write {shown}: YAML round-trip did not preserve the value or other keys"
        )
    return new_text, action


def update_inline_value(
    path: str | os.PathLike,
    key: str,
    value: str,
    vault: VaultLib,
    *,
    check_only: bool = False,
) -> str:
    """Replace one inline `key: !vault |` value, re-encrypted under its existing label.

    Only that value's block is rewritten; every other byte of the file stays, so
    git sees one changed value. Same refusals and error contract as set_keys:
    messages never carry a value. check_only stops before the final os.replace.
    """
    path = Path(path)
    _check_value(key, value)
    keypath = parse_key_path(key)
    try:
        return _update_inline(path, keypath, value, vault, check_only)
    except OSError as exc:
        raise PilferError(f"{exc.strerror}: {exc.filename or path}") from None


def _check_value(key: str, value: str) -> None:
    if not isinstance(value, str):
        raise PilferError(f"the value for {_clip(key)} must be a string")
    if value == "":
        raise PilferError(f"refusing an empty value for {_clip(key)}")
    if "\0" in value:
        raise PilferError(f"refusing a value for {_clip(key)} that contains NUL")


@locked_by_path
def _update_inline(path: Path, keypath: list, value: str, vault: VaultLib, check_only: bool) -> str:
    shown = _shown_path(keypath)
    original = _read_unopened(path)
    try:
        text, documents = _compose(original)
    except ValueError as exc:
        raise PilferError(f"{path}: {exc}") from None
    hits = [
        found
        for document in documents
        for found in walk_keys(document)
        if found.path == keypath and found.value_node.tag == "!vault"
    ]
    if len(hits) != 1:
        raise PilferError(
            f"{shown} is not a single inline !vault value in {path}"
            if not hits
            else f"{shown} appears {len(hits)} times in {path}; refusing to guess"
        )
    # Same refusal as the whole-file path: a value under a shared anchor (&db
    # reused by *db or a << merge) cannot be rewritten in place.
    if any(_shared_on_path(document, keypath) for document in documents):
        raise PilferError(_SHARED_MESSAGE.format(shown=shown))
    offset = len(text[: hits[0].value_node.start_mark.index].encode("utf-8"))
    spans = [s for s in find_inline_vault_spans(original) if s.start <= offset < s.end]
    if len(spans) != 1:
        # `key: !vault "..."` and list items have no `!vault |` block to rewrite.
        raise PilferError(f"{shown} in {path} is not in the `!vault |` block form pilfer rewrites")
    span = spans[0]
    try:
        current = vault.decrypt(span.ciphertext)
    except Exception:
        raise PilferError(f"could not decrypt {shown} in {path} with this vault password") from None
    # Same value: leave the file alone, so git sees no new vault blob and the
    # mtime stays. Compared in memory only.
    if current == value.encode("utf-8"):
        return "unchanged"
    try:
        ciphertext = encrypt_like(vault, value.encode("utf-8"), span.ciphertext)
    except RoundTripError:
        raise PilferError(f"encryption did not round-trip; {path} unchanged") from None
    except VaultLabelError as exc:
        raise PilferError(str(exc)) from None
    except Exception as exc:
        raise PilferError(f"could not encrypt {path} ({type(exc).__name__}); unchanged") from None
    block = format_encrypted_block(
        ciphertext,
        span.line_prefix,
        span.body_indent,
        block_newline(span.encrypted),
    )
    edited = original[: span.start] + block + original[span.end :]
    publish_vault(path, edited, expected=original, action="update", publish=not check_only)
    return "updated"


def warn_value_on_argv(args) -> None:
    """Warn on stderr when VALUE came from the command line (set and update)."""
    if getattr(args, "value", None) is not None:
        print(
            "pilfer: warning: VALUE on the command line is visible in ps and shell "
            "history; omit it to read the value from stdin, which is safer",
            file=sys.stderr,
        )


def read_value(key: str) -> str:
    """Read a value for `pilfer set` and `pilfer update` without putting it on the command line.

    A terminal gets a no-echo prompt. Piped or redirected input is read whole and
    one trailing line ending is dropped, so `echo "$TOKEN" | pilfer set ...` stores
    the token without a newline; a value that must end in a newline cannot come in
    this way. argv is visible in `ps` and lands in shell history; stdin is neither.
    """
    stdin = sys.stdin
    if stdin is None:
        raise PilferError(f"no value for {_clip(key)}: pass it on stdin")
    if stdin.isatty():
        try:
            return getpass.getpass(f"Value for {_clip(key)} (input hidden): ")
        except EOFError:
            raise PilferError(f"no value for {_clip(key)}") from None
    data = stdin.buffer.read(MAX_STDIN_VALUE_BYTES + 1)
    if not data:
        # Nothing piped (</dev/null, cron, a closed pipe): say how to give one.
        raise PilferError(
            f"no value for {_clip(key)}: stdin is not a terminal and is empty. "
            "Pipe the value on stdin or pass it as VALUE"
        )
    if len(data) > MAX_STDIN_VALUE_BYTES:
        raise PilferError(f"value for {_clip(key)} on stdin is over {MAX_STDIN_VALUE_BYTES} bytes")
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        # The exception text quotes the offending byte.
        raise PilferError(f"value for {_clip(key)} on stdin is not UTF-8") from None
    return value.removesuffix("\n").removesuffix("\r") if value.endswith("\n") else value
