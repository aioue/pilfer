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
import sys
from dataclasses import dataclass

from ansible.parsing.vault import AnsibleVaultFormatError

from pilfer.cli import (
    MAX_FAILURE_LINES,
    PilferError,
    _capped,
    _classify_file_bytes,
    _describe_skipped_vault_values,
    _encrypted_backup_path,
    _inline_meta_path,
    _is_regular_file,
    _load_session,
    _open_sidecar_path,
    _refuse_planted_session_links,
    _session_is_open,
    _sources,
    _warn_unused_sources,
    safe_multiline,
    safe_text,
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
from pilfer.vault_secrets import (
    load_vault,
    require_terminal_if_prompting,
    vault_label,
)
from pilfer.vault_set import CHECK_PLACEHOLDER, DRY_RUN_UNCHECKED, _shown_path, read_capped


def _listing(names) -> str:
    """Sorted, escaped names, one per line, capped."""
    lines = [f"  {name}" for name in sorted(safe_text(name) for name in names)]
    return "\n".join(_capped(lines, "  ... and {n} more"))


@dataclass
class KeyHit:
    """A key name found in a vault. Never carries a value."""

    file: str  # absolute path
    path: list
    kind: str  # "file" for a whole-file vault key, "inline" for an inline !vault value
    open: bool
    vault_id: str | None


class VaultLoadError(PilferError):
    """The vault password could not be loaded. Fatal for the whole run, not one file."""


class _LazyVault:
    """Load the vault password once, and only if some file needs it.

    A failure is cached and raised as VaultLoadError: a missing source or a -p
    script that exits non-zero would otherwise be retried (the script run again)
    and reported once per vault file.
    """

    def __init__(self, sources):
        self._sources = sources
        self._vault = None
        self._error = None

    def get(self):
        if self._error is not None:
            raise self._error
        if self._vault is None:
            try:
                self._vault = load_vault(self._sources)
            except PilferError as exc:
                text = str(exc)
                if not text.startswith("vault password"):
                    text = f"vault password: {text}"
                self._error = VaultLoadError(text)
                raise self._error from None
        return self._vault


def _label_or_none(ciphertext: bytes) -> str | None:
    try:
        return vault_label(ciphertext)
    except Exception:
        return None


def _found_keys(documents) -> list:
    return [found for document in documents for found in walk_keys(document)]


def _closed_hits(path: str, kind: str, vault: _LazyVault) -> list[KeyHit]:
    data = read_capped(path, "file")
    if kind == "file":
        normalized = normalize_whole_file_vault(data)
        label = _label_or_none(normalized)
        try:
            plaintext = vault.get().decrypt(normalized)
        except PilferError:
            raise
        except AnsibleVaultFormatError:
            # A header that parses but a body that does not (non-hex, truncated).
            raise PilferError("vault format error (the file is damaged)") from None
        except Exception:
            # The caller prefixes the file name.
            if label:
                raise PilferError(
                    "could not decrypt with the loaded vault passwords "
                    f"(file uses vault id '{safe_text(label)}')"
                ) from None
            raise PilferError("could not decrypt with this vault password") from None
        _, documents = _compose(plaintext, ansible_fallback=True)
        return [KeyHit(path, found.path, "file", False, label) for found in _found_keys(documents)]
    _, documents = _compose(data, ansible_fallback=True)
    return [
        KeyHit(path, found.path, "inline", False, _label_or_none(found.value_node.value.encode()))
        for found in _found_keys(documents)
        if found.value_node.tag == "!vault"
    ]


def _open_hits(path: str, kind: str, include_inline: bool) -> list[KeyHit] | None:
    """Keys of a file open in a session, read from its plaintext. None if it is not open."""
    if not os.path.exists(_open_sidecar_path(path)):
        return None
    data = read_capped(path, "file")
    if is_whole_file_vault(data):
        return None  # recorded but not yet decrypted: the scan reports it as closed
    if kind == "file":
        _, documents = _compose(data, ansible_fallback=True)
        try:
            label = vault_label(read_capped(_encrypted_backup_path(path), "file"))
        except Exception:
            label = None
        return [KeyHit(path, found.path, "file", True, label) for found in _found_keys(documents)]
    if not include_inline:
        return []
    labels = {}
    try:
        meta = json.loads(read_capped(_inline_meta_path(path), "file"))
        labels = {span["id"]: span.get("vault_id") for span in meta["spans"]}
    except (PilferError, ValueError, KeyError, TypeError):
        pass
    by_key = {marked.key_index: marked.span_id for marked in read_marked_values(data)}
    _, documents = _compose(data)
    return [
        KeyHit(
            path, found.path, "inline", True, labels.get(by_key[found.key_node.start_mark.index])
        )
        for found in _found_keys(documents)
        if found.key_node.start_mark.index in by_key
    ]


def collect_keys(
    vault: _LazyVault, include_inline: bool, only_file: str | None = None
) -> tuple[list[KeyHit], list[str]]:
    """Every key in the project's vault files. Returns (hits, paths of files that failed).

    A file that cannot be read is reported on stderr and skipped, so one bad file
    does not hide the rest. Messages name the file, never its content.
    """
    hits: list[KeyHit] = []
    failures: list[str] = []
    wanted = os.path.abspath(only_file) if only_file else None
    seen: set[str] = set()
    # A wrong password that loads but does not decrypt fails every vault file:
    # print the first few and summarise, so the real error is not buried.
    reported = 0
    suppressed = 0

    def report(line: str) -> None:
        nonlocal reported, suppressed
        if reported < MAX_FAILURE_LINES:
            reported += 1
            print(line, file=sys.stderr)
        else:
            suppressed += 1

    def attempt(path, produce, *call_args):
        try:
            return produce(*call_args)
        except VaultLoadError:
            raise
        except (PilferError, OpenedFileError) as exc:
            report(f"pilfer: {safe_text(path)}: {safe_multiline(str(exc))}")
        except OSError as exc:
            report(f"pilfer: {safe_text(path)}: {exc.strerror}")
        except Exception as exc:
            # Never str(exc): a YAML or crypto error can quote the plaintext.
            report(f"pilfer: {safe_text(path)}: failed ({type(exc).__name__})")
        failures.append(path)
        return None

    if _session_is_open():
        _refuse_planted_session_links()
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
                wanted, read_capped(wanted, "file"), include_encrypted_vars=include_inline
            )
            if kind:
                targets.append({"kind": kind, "path": wanted})
    else:
        scan = scan_project(include_encrypted_vars=include_inline, announce_skips=False)
        targets = sorted(scan.targets, key=lambda target: target["path"])
        for path, reason in sorted(scan.unreadable):
            report(f"pilfer: {safe_text(path)}: {reason}")
            failures.append(path)
        # Cannot be a vault by extension: worth knowing, not a failed search.
        warnings = [
            f"pilfer: warning: {safe_text(path)}: {reason}"
            for path, reason in sorted(scan.unreadable_other)
        ]
        for line in _capped(warnings, "pilfer: ... and {n} more warning(s)"):
            print(line, file=sys.stderr)
        if scan.skipped_vault_values:
            # Their names are not searched: say so, or a file whose only !vault
            # values are in unsupported forms looks like it holds no keys.
            print(
                f"pilfer: warning: {_describe_skipped_vault_values(scan)}; their keys are not searched",
                file=sys.stderr,
            )
    for target in targets:
        path = os.path.abspath(target["path"])
        if path in seen:
            continue
        found = attempt(path, _closed_hits, path, target["kind"], vault)
        if found:
            hits.extend(found)
    if suppressed:
        print(f"pilfer: {suppressed} more file(s) could not be read", file=sys.stderr)
    return hits, failures


def _shown(path: str) -> str:
    return os.path.relpath(path)


def _matcher(args):
    """A function from (name, rendered path) to bool, from the patterns and flags."""
    if not args.patterns:
        return lambda name, rendered: True
    flags = re.IGNORECASE if args.ignore_case else 0
    # Only * and ? are wildcards: a [ in a key path such as users[0] is literal.
    # fnmatch.translate anchors the whole name, as -E's search does not.
    sources = (
        args.patterns
        if args.regex
        else [fnmatch.translate(pattern.replace("[", "[[]")) for pattern in args.patterns]
    )
    try:
        compiled = [re.compile(pattern, flags) for pattern in sources]
    except re.error as exc:
        raise PilferError(f"invalid regular expression: {exc}") from None

    # -E matches anywhere in the name; a glob must cover all of it.
    find = (
        (lambda rx, text: rx.search(text)) if args.regex else (lambda rx, text: rx.fullmatch(text))
    )

    def test(text: str) -> bool:
        return any(find(rx, text) for rx in compiled)

    return lambda name, rendered: test(rendered if args.path else name)


def run_find_keys(args) -> int:
    """Exit 0 when a key matched, 1 when none did, 2 on an error."""
    try:
        matches = _matcher(args)
        require_terminal_if_prompting(_sources(args))
        vault = _LazyVault(_sources(args))
        hits, failures = collect_keys(vault, args.include_encrypted_vars)
    except PilferError as exc:
        print(f"pilfer: {safe_multiline(str(exc))}", file=sys.stderr)
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
            print(safe_text(name))
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
                # Default ensure_ascii on purpose: bidi, zero-width and lone-surrogate
                # names arrive as \u escapes, not raw characters.
                print(json.dumps(record))
            else:
                tags = ("  (inline)" if hit.kind == "inline" else "") + (
                    "  (open)" if hit.open else ""
                )
                print(f"{safe_text(_shown(hit.file))}: {safe_text(rendered)}{tags}")
    if failures:
        return 2
    if not hits:
        print("pilfer: no key matched", file=sys.stderr)
        return 1
    return 0


def run_update(args) -> int:
    """Replace the value of an existing key, found by name. Refuses missing or ambiguous keys."""
    from pilfer.vault_set import read_value, set_keys, update_inline_value, warn_value_on_argv

    warn_value_on_argv(args)
    require_terminal_if_prompting(_sources(args))
    keypath = parse_key_path(args.key)
    shown = _shown_path(keypath)
    if args.file and not _is_regular_file(args.file):
        problem = "is not a regular file" if os.path.lexists(args.file) else "does not exist"
        raise PilferError(f"--file {args.file} {problem}")
    vault = _LazyVault(_sources(args))
    hits, failed = collect_keys(vault, True, only_file=args.file)
    matching = [hit for hit in hits if hit.path == keypath]
    for hit in matching:
        if hit.open:
            raise PilferError(
                f"{shown} is in {_shown(hit.file)}, which is open in a pilfer session; "
                "run 'pilfer close' first"
            )
    targets = [hit for hit in matching if hit.kind == "file" or args.include_encrypted_vars]
    if not targets and args.file and failed:
        # The failure was reported above; "not found" would be untrue.
        raise PilferError(f"{args.file} could not be read (see above); nothing was changed")
    if not targets:
        if matching:
            raise PilferError(
                f"{shown} exists only as an inline !vault value in "
                f"{_shown(matching[0].file)}; "
                "pass --include-encrypted-vars to update it"
            )
        if failed:
            note = f"; it may be in one of {len(failed)} file(s) that could not be read"
            if not args.file:
                note += "; pass --file FILE to update one you know holds it"
        elif any(isinstance(segment, int) for segment in keypath):
            note = ""  # set cannot create a list item, so there is nothing to suggest
        else:
            note = "; to create it run: pilfer set FILE KEY"
        raise PilferError(f"{shown} not found in any vault file{note}")
    # One entry per file: a key twice in one file is set_keys' duplicate refusal,
    # not "in 2 files".
    targets = list({hit.file: hit for hit in targets}.values())
    if len(targets) > 1:
        listing = _listing(_shown(hit.file) for hit in targets)
        raise PilferError(
            f"{shown} is in {len(targets)} files; pass --file FILE to choose one:\n{listing}"
        )
    if failed and not args.file:
        # The key may be in a file we could not read too; updating only the
        # readable copy would leave a stale one behind.
        listing = _listing(_shown(name) for name in failed)
        raise PilferError(
            f"{shown} may also be in {len(failed)} file(s) that could not be read; "
            f"fix them or pass --file FILE to choose one:\n{listing}"
        )
    target = targets[0]
    secrets = vault.get()

    def write(value: str, check_only: bool) -> str:
        if target.kind == "file":
            return set_keys(
                _shown(target.file),
                {args.key: value},
                secrets,
                check_only=check_only,
                create=False,
            )[args.key]
        return update_inline_value(
            _shown(target.file), args.key, value, secrets, check_only=check_only
        )

    value = args.value
    if args.dry_run:
        outcome = write(CHECK_PLACEHOLDER if value is None else value, True)
        # With no value there is nothing to compare, so it would update.
        action = "unchanged" if outcome == "unchanged" and value is not None else "would update"
    else:
        if value is None:
            # Refuse before asking for the secret, not after someone has pasted it.
            write(CHECK_PLACEHOLDER, True)
            value = read_value(args.key)
        action = write(value, False)
    print(f"{action} {safe_text(shown)} in {safe_text(_shown(target.file))}")
    if args.dry_run and value is None:
        print(DRY_RUN_UNCHECKED)
    _warn_unused_sources(secrets, safe_text(_shown(target.file)))
    return 0
