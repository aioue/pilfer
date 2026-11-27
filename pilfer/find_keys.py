# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""pilfer find-keys and pilfer update: find vault keys by name, change one by name.

find-keys reads key names, never values. Whole-file vaults are decrypted in
memory (a vault hides its key names too, so this reveals them) and the YAML is
composed, not constructed, so no value is ever turned into a Python object. The
only things printed are file names, key paths, a kind, an open flag and a vault
label. There is deliberately no value search: it would let anyone with the
password test guesses against secrets without ever reading one.

A file open in a pilfer session holds plaintext on disk, so it is read from
there and tagged (open); closed files are never written to disk in plaintext.
"""

import fnmatch
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass

from pilfer.cli import (
    PilferError,
    _classify_file_bytes,
    _encrypted_backup_path,
    _inline_meta_path,
    _load_session,
    _open_sidecar_path,
    _session_is_open,
    _sources,
    _warn_unused_sources,
    scan_project,
)
from pilfer.inline import (
    OpenedFileError,
    _compose,
    is_whole_file_vault,
    normalize_whole_file_vault,
    read_marked_values,
)
from pilfer.key_paths import parse_key_path, render_key_path, walk_keys
from pilfer.vault_secrets import load_vault, vault_label

PLACEHOLDER = "pilfer-update-check-placeholder"


@dataclass
class KeyHit:
    """A key name found in a vault. Never carries a value."""

    file: str  # absolute path
    path: list
    kind: str  # "file" for a whole-file vault key, "inline" for an inline !vault value
    open: bool
    vault_id: str | None


class _LazyVault:
    """Load the vault password once, and only if some file needs it."""

    def __init__(self, sources):
        self._sources = sources
        self._vault = None

    def get(self):
        if self._vault is None:
            self._vault = load_vault(self._sources)
        return self._vault

    @property
    def loaded(self):
        return self._vault


def _label_or_none(ciphertext: bytes) -> str | None:
    try:
        return vault_label(ciphertext)
    except Exception:
        return None


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _closed_hits(path: str, kind: str, vault: _LazyVault) -> list[KeyHit]:
    data = _read(path)
    if kind == "file":
        normalized = normalize_whole_file_vault(data)
        try:
            plaintext = vault.get().decrypt(normalized)
        except PilferError:
            raise
        except Exception:
            raise PilferError(f"could not decrypt {path} with this vault password") from None
        _, documents = _compose(plaintext)
        label = _label_or_none(normalized)
        return [
            KeyHit(path, found.path, "file", False, label)
            for document in documents
            for found in walk_keys(document)
        ]
    _, documents = _compose(data)
    return [
        KeyHit(path, found.path, "inline", False, _label_or_none(found.value_node.value.encode()))
        for document in documents
        for found in walk_keys(document)
        if found.value_node.tag == "!vault"
    ]


def _open_hits(path: str, kind: str, include_inline: bool) -> list[KeyHit] | None:
    """Keys of a file open in a session, read from its plaintext. None if it is not open."""
    if not os.path.exists(_open_sidecar_path(path)):
        return None
    data = _read(path)
    if is_whole_file_vault(data):
        return None  # recorded but not yet decrypted: the scan reports it as closed
    if kind == "file":
        _, documents = _compose(data)
        try:
            label = vault_label(_read(_encrypted_backup_path(path)))
        except Exception:
            label = None
        return [
            KeyHit(path, found.path, "file", True, label)
            for document in documents
            for found in walk_keys(document)
        ]
    if not include_inline:
        return []
    labels = {}
    try:
        with open(_inline_meta_path(path)) as handle:
            labels = {span["id"]: span.get("vault_id") for span in json.load(handle)["spans"]}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    by_key = {marked.key_index: marked.span_id for marked in read_marked_values(data)}
    _, documents = _compose(data)
    return [
        KeyHit(
            path, found.path, "inline", True, labels.get(by_key[found.key_node.start_mark.index])
        )
        for document in documents
        for found in walk_keys(document)
        if found.key_node.start_mark.index in by_key
    ]


def collect_keys(
    vault: _LazyVault, include_inline: bool, only_file: str | None = None
) -> tuple[list[KeyHit], int]:
    """Every key in the project's vault files. Returns (hits, number of files that failed).

    A file that cannot be read is reported on stderr and skipped, so one bad file
    does not hide the rest. Messages name the file, never its content.
    """
    hits: list[KeyHit] = []
    failures = 0
    wanted = os.path.abspath(only_file) if only_file else None
    seen: set[str] = set()

    def attempt(path, produce, *call_args):
        nonlocal failures
        try:
            return produce(*call_args)
        except (PilferError, OpenedFileError) as exc:
            print(f"pilfer: {path}: {exc}", file=sys.stderr)
        except OSError as exc:
            print(f"pilfer: {path}: {exc.strerror}", file=sys.stderr)
        except Exception as exc:
            # Never str(exc): a YAML or crypto error can quote the plaintext.
            print(f"pilfer: {path}: failed ({type(exc).__name__})", file=sys.stderr)
        failures += 1
        return None

    if _session_is_open():
        for entry in _load_session():
            path = os.path.abspath(entry["path"])
            if wanted and path != wanted:
                continue
            found = attempt(path, _open_hits, path, entry.get("kind", "file"), include_inline)
            if found is not None:
                seen.add(path)
                hits.extend(found)

    if wanted:
        # Outside the project tree is allowed when it is named.
        targets = []
        if os.path.isfile(wanted) and not os.path.islink(wanted):
            kind = _classify_file_bytes(
                wanted, _read(wanted), include_encrypted_vars=include_inline
            )
            if kind:
                targets.append({"kind": kind, "path": wanted})
    else:
        targets = scan_project(include_encrypted_vars=include_inline, announce_skips=False).targets
    for target in targets:
        path = os.path.abspath(target["path"])
        if path in seen:
            continue
        found = attempt(path, _closed_hits, path, target["kind"], vault)
        if found:
            hits.extend(found)
    return hits, failures


def _shown(path: str) -> str:
    return os.path.relpath(path)


def _matcher(args):
    """A function from (name, rendered path) to bool, from the patterns and flags."""
    patterns = args.patterns
    if not patterns:
        return lambda name, rendered: True
    flags = re.IGNORECASE if args.ignore_case else 0
    if args.regex:
        try:
            compiled = [re.compile(pattern, flags) for pattern in patterns]
        except re.error as exc:
            raise PilferError(f"invalid regular expression: {exc}") from None
        test = lambda text: any(rx.search(text) for rx in compiled)  # noqa: E731
    else:
        folded = [pattern.lower() for pattern in patterns] if args.ignore_case else patterns
        test = lambda text: any(  # noqa: E731
            fnmatch.fnmatchcase(text.lower() if args.ignore_case else text, pattern)
            for pattern in folded
        )
    return lambda name, rendered: test(rendered if args.path else name)


def run_find_keys(args) -> int:
    """Exit 0 when a key matched, 1 when none did, 2 on an error."""
    try:
        matches = _matcher(args)
        vault = _LazyVault(_sources(args))
        hits, failures = collect_keys(vault, args.include_encrypted_vars)
    except PilferError as exc:
        print(f"pilfer: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Never str(exc): the rule for this command is that no error carries content.
        print(f"pilfer: find-keys failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    hits = [hit for hit in hits if matches(str(hit.path[-1]), render_key_path(hit.path))]
    hits.sort(key=lambda hit: (_shown(hit.file), render_key_path(hit.path)))

    if args.files_with_matches:
        files = list(dict.fromkeys(_shown(hit.file) for hit in hits))
        for name in files:
            print(json.dumps({"file": name}) if args.json else name)
    else:
        for hit in hits:
            rendered = render_key_path(hit.path)
            if args.json:
                record = {
                    "file": _shown(hit.file),
                    "key": hit.path[-1],
                    "path": hit.path,
                    "kind": hit.kind,
                    "open": hit.open,
                    # A 1.1 header has no label: ansible-vault writes one when it
                    # encrypts under the id "default" (or none), so report that id.
                    "vault_id": hit.vault_id or "default",
                }
                print(json.dumps(record, ensure_ascii=False))
            else:
                tags = ("  (inline)" if hit.kind == "inline" else "") + (
                    "  (open)" if hit.open else ""
                )
                print(f"{_shown(hit.file)}: {rendered}{tags}")
    if failures:
        return 2
    if not hits:
        print("pilfer: no key matched", file=sys.stderr)
        return 1
    return 0


def run_update(args) -> int:
    """Replace the value of an existing key, found by name. Refuses missing or ambiguous keys."""
    from pilfer.vault_set import read_value, set_keys, update_inline_value

    keypath = parse_key_path(args.key)
    shown = render_key_path(keypath)
    vault = _LazyVault(_sources(args))
    hits, failures = collect_keys(vault, True, only_file=args.file)
    matching = [hit for hit in hits if hit.path == keypath]
    for hit in matching:
        if hit.open:
            raise PilferError(
                f"{shown} is in {_shown(hit.file)}, which is open in a pilfer session; "
                "run 'pilfer close' first"
            )
    targets = [hit for hit in matching if hit.kind == "file" or args.include_encrypted_vars]
    if not targets:
        if matching:
            raise PilferError(
                f"{shown} exists only as an inline !vault value in {_shown(matching[0].file)}; "
                "pass --include-encrypted-vars to update it"
            )
        hint = f"; to create it run: pilfer set FILE {shlex.quote(args.key)}"
        suffix = f" ({failures} file(s) could not be read)" if failures else ""
        raise PilferError(f"{shown} not found in any vault file{suffix}{hint}")
    if len(targets) > 1:
        listing = "\n".join(f"  {name}" for name in sorted(_shown(hit.file) for hit in targets))
        raise PilferError(
            f"{shown} is in {len(targets)} files; pass --file FILE to choose one:\n{listing}"
        )
    target = targets[0]
    secrets = vault.get()

    def write(value: str, check_only: bool) -> str:
        if target.kind == "file":
            return set_keys(
                target.file, {args.key: value}, secrets, check_only=check_only, create=False
            )[args.key]
        return update_inline_value(target.file, args.key, value, secrets, check_only=check_only)

    if args.dry_run:
        write(PLACEHOLDER, True)
        print(f"would update {shown} in {_shown(target.file)}")
        _warn_unused_sources(secrets, _shown(target.file))
        return 0
    value = args.value
    if value is None:
        # Refuse before asking for the secret, not after someone has pasted it.
        write(PLACEHOLDER, True)
        value = read_value(args.key)
    action = write(value, False)
    print(f"{action} {shown} in {_shown(target.file)}")
    _warn_unused_sources(secrets, _shown(target.file))
    return 0
