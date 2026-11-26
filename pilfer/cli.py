# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# heavily borrows from this excellent repo https://github.com/dellis23/ansible-toolkit

# pilfer - decrypt all ansible vault files recursively for search/editing
# pilfer [open|close|rekey|set]

import argparse
import functools
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

import ansible.constants as C
from ansible.parsing.vault import VaultLib, VaultSecret, is_encrypted
from ansible.utils.path import unfrackpath

from pilfer import __version__
from pilfer.errors import PilferError
from pilfer.inline import (
    INLINE_FORMAT,
    MARKER_PREFIX,
    MARKER_RE,
    VAULT_HEADER_PREFIX,
    InlineCloseRefusal,
    MarkerMissingSecretPresent,
    SecretLineDeleted,
    decrypt_inline_content,
    find_inline_vault_spans,
    format_encrypted_block,
    intentional_removal_candidate_names,
    is_whole_file_vault,
    normalize_whole_file_vault,
    recrypt_inline_content,
    splice,
    unsafe_missing_marker_names,
    var_name_from_prefix,
    vault_values_pilfer_skips,
)
from pilfer.publish import (
    LOCK_SUFFIX,
    TEMP_PREFIX,
    locked_by_path,
    project_session_lock,
    publish_vault,
    vault_mode_and_group,
    write_atomic,
)
from pilfer.vault_secrets import (
    SourceVault,
    VaultSources,
    decrypts,
    encrypt_like,
    encrypt_with,
    is_plain_password_file,
    load_new_secret,
    load_vault,
    password_file_secret,
    secret_for,
    single_secret_vault,
    vault_label,
)

temp_vault_file_list_path = "vaultedFileList.json"
temp_hidden_encrypted_copies_directory_path = ".vault"
# 3: no password fingerprint; close proves the password against a .vault backup.
SESSION_VERSION = 3
# Sibling lock written next to each opened target so orphan detection still works
# if vaultedFileList.json and .vault/ are deleted (whole-file opens have no markers).
OPEN_SIDECAR_SUFFIX = ".pilfer-open"

_SKIP_DIR_NAMES = {
    temp_hidden_encrypted_copies_directory_path,
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
}

# Skip binary / non-text artifacts during discovery (extension denylist).
# Unknown or text-like extensions are still scanned so inline !vault in
# unusual filenames is not missed when --include-encrypted-vars is set.
_SKIP_FILE_EXTENSIONS = frozenset(
    {
        ".db",
        ".sqlite",
        ".sqlite3",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".tif",
        ".tiff",
        ".gz",
        ".zip",
        ".tar",
        ".tgz",
        ".bz2",
        ".xz",
        ".zst",
        ".zstd",
        ".lz4",
        ".7z",
        ".whl",
        ".egg",
        ".so",
        ".dylib",
        ".dll",
        ".o",
        ".a",
        ".pyc",
        ".pyo",
        ".class",
        ".jar",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".webm",
        ".mkv",
        ".iso",
        ".img",
        ".dmg",
        ".bin",
        ".exe",
    }
)

# Enough bytes to see `$ANSIBLE_VAULT;` even after a UTF-8 BOM and light leading WS.
_VAULT_HEADER_READ_SIZE = 256


def _session_is_open() -> bool:
    return Path(temp_vault_file_list_path).is_file()


def _backup_dir_for(vaulted_file_path: str) -> str:
    parts = Path(vaulted_file_path).parts
    if parts and (parts[0] == os.sep or (len(parts[0]) == 2 and parts[0][1] == ":")):
        parts = parts[1:]
    return os.path.join(temp_hidden_encrypted_copies_directory_path, *parts)


def _encrypted_backup_path(vaulted_file_path: str) -> str:
    return os.path.join(_backup_dir_for(vaulted_file_path), "encrypted")


def _hash_backup_path(vaulted_file_path: str) -> str:
    return os.path.join(_backup_dir_for(vaulted_file_path), "hash")


def _inline_meta_path(vaulted_file_path: str) -> str:
    return os.path.join(_backup_dir_for(vaulted_file_path), "inline.json")


def _open_sidecar_path(vaulted_file_path: str) -> str:
    return f"{vaulted_file_path}{OPEN_SIDECAR_SUFFIX}"


def _write_open_sidecar(vaulted_file_path: str, kind: str) -> None:
    """Mark an opened target so orphan scans work without session/.vault."""
    # Atomic replace refuses a pre-planted sidecar symlink instead of truncating
    # whatever it points at.
    write_atomic(
        _open_sidecar_path(vaulted_file_path),
        json.dumps({"kind": kind, "path": vaulted_file_path}).encode("utf-8"),
    )


def _remove_file(path: str) -> None:
    """Delete a file pilfer wrote, if it is there.

    A failure is printed, not raised: the caller is cleaning up, and whatever
    is left is reported by the orphan check on the next open.
    """
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"Warning: could not remove {path}: {exc.strerror}", file=sys.stderr)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_target_path(vaulted_file_path: str, cwd: Path) -> Path:
    path = Path(vaulted_file_path)
    if path.is_symlink():
        raise PilferError(
            f"Refusing to operate on symlink (decrypt would write through it): {vaulted_file_path}"
        )
    if not path.exists():
        raise PilferError(f"Vault file does not exist: {vaulted_file_path}")

    resolved = path.resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError as exc:
        raise PilferError(f"Refusing path outside project directory: {vaulted_file_path}") from exc
    return resolved


def _refuse_if_symlink(path: str) -> None:
    """Refuse a symlink leaf.

    open() follows the link, so a dangling vaultedFileList.json, .vault, or
    *.pilfer-open planted in the tree truncates or creates the target.
    os.replace does not follow, but the open() writers below would.
    """
    if os.path.islink(path):
        raise PilferError(f"Refusing to operate on symlink (write would follow it): {path}")


def _refuse_planted_session_links() -> None:
    _refuse_if_symlink(temp_vault_file_list_path)
    _refuse_if_symlink(temp_hidden_encrypted_copies_directory_path)


def _ensure_private_dir(path: str) -> None:
    """Create a real directory. os.makedirs follows a symlink leaf, so a planted
    .vault link would store ciphertext backups outside the project.
    """
    normalized = os.path.normpath(path)
    existing = normalized
    missing = []
    while existing not in ("", ".", os.sep) and not os.path.lexists(existing):
        missing.append(existing)
        parent = os.path.dirname(existing)
        if parent == existing:
            break
        existing = parent
    # dirname("relpath") is "" — that parent is the cwd, which already exists.
    if existing not in ("", ".", os.sep):
        if os.path.islink(existing):
            raise PilferError(
                f"Refusing to use symlink as a directory (writes would follow it): {existing}"
            )
        if os.path.lexists(existing) and not os.path.isdir(existing):
            raise PilferError(f"Refusing to use non-directory path: {existing}")
    for directory in reversed(missing):
        if directory in ("", ".", os.sep):
            continue
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            if os.path.islink(directory) or not os.path.isdir(directory):
                raise PilferError(
                    f"Refusing to use symlink as a directory (writes would follow it): {directory}"
                ) from None
    try:
        os.chmod(normalized, 0o700)
    except OSError:
        pass


def _normalize_entries(data):
    """Return session entries from session JSON.

    Lists and {"files": [...]} came from pilfer releases too old to close
    safely here; refuse rather than guess how they opened inline values. A
    password_sha256 field written by pilfer < 2.31 is ignored: close proves
    the password against a .vault backup instead of storing a hash of it.
    """
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        return data["entries"]
    raise PilferError(
        f"{temp_vault_file_list_path} was written by an older pilfer or is damaged. "
        "Close the session with the pilfer release that opened it."
    )


def _load_session():
    with open(temp_vault_file_list_path) as vault_list_file:
        data = json.load(vault_list_file)
    return _normalize_entries(data)


def _emit_warning_block(title: str, detail: str) -> None:
    """Print a fail-closed warning with ⚠️ prefix and paragraph spacing."""
    print(f"⚠️  {title}", file=sys.stderr)
    print(file=sys.stderr)
    detail = detail.strip()
    if not detail:
        return
    parts = re.split(r"(?<=\.)\s+", detail)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        print(part, file=sys.stderr)
        print(file=sys.stderr)


def _emit_inline_close_refusal(file_path: str, exc: InlineCloseRefusal) -> None:
    """Print structured inline close errors (marker missing vs secret line deleted)."""
    if isinstance(exc, MarkerMissingSecretPresent):
        print(f"⚠️  {file_path} — cannot close (marker missing)", file=sys.stderr)
        print(f"  Variable:     {exc.var_name}", file=sys.stderr)
        print(
            f"  Problem:      # pilfer:vault:{exc.span_id} marker was removed but the "
            "secret is still in the file.",
            file=sys.stderr,
        )
        print(file=sys.stderr)
        print(
            "  Fix:          restore the marker comment on the value line, then pilfer close",
            file=sys.stderr,
        )
        return
    if isinstance(exc, SecretLineDeleted):
        print(f"⚠️  {file_path} — cannot close (secret line deleted)", file=sys.stderr)
        print(
            f"  Variable:     {exc.var_name}  (# pilfer:vault:{exc.span_id})",
            file=sys.stderr,
        )
        print("  Problem:      opened inline secret was removed from the file.", file=sys.stderr)
        print(file=sys.stderr)
        print("  Confirm delete:  pilfer close --confirm-delete", file=sys.stderr)
        print("  Undo:            restore the line, then pilfer close", file=sys.stderr)
        return
    raise TypeError(f"Unhandled inline close refusal: {exc!r}")


def _span_id_for(var_name: str, span_records: list[dict]) -> int | None:
    for record in span_records:
        if var_name_from_prefix(record["line_prefix"]) == var_name:
            return int(record["id"])
    return None


def _entry_has_open_artifacts(entry) -> bool:
    path = entry["path"]
    return (
        os.path.isfile(_encrypted_backup_path(path))
        or os.path.isfile(_open_sidecar_path(path))
        or os.path.isfile(_inline_meta_path(path))
    )


def _path_still_vault_ciphertext(entry, data: bytes) -> bool:
    """True if path bytes still look like vault ciphertext (open never decrypted)."""
    if entry.get("kind") == "inline":
        return bool(find_inline_vault_spans(data)) or is_whole_file_vault(data)
    return is_whole_file_vault(data)


def _session_is_incomplete(entries) -> bool:
    """True when session list exists but decrypt never produced backups/sidecars.

    Only treat as crash-before-decrypt when listed paths still look encrypted.
    If artifacts were deleted after a real open (plaintext remains), do NOT
    abandon - that would let open exit 0 over untracked secrets.
    """
    if not entries:
        return True
    if any(_entry_has_open_artifacts(e) for e in entries):
        return False
    saw_encrypted = False
    for entry in entries:
        path = entry["path"]
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if _path_still_vault_ciphertext(entry, data):
            saw_encrypted = True
        else:
            return False
    return saw_encrypted


class NothingOpened(PilferError):
    """decrypt_vault_files opened no file and wrote nothing."""


def _abandon_incomplete_session() -> bool:
    """If session looks like crash-before-decrypt, clear it and return True."""
    if not _session_is_open():
        return False
    try:
        entries = _load_session()
    except Exception:
        return False
    if not _session_is_incomplete(entries):
        return False
    _remove_file(temp_vault_file_list_path)
    print("ℹ️  Cleared incomplete session (no decrypt backups/sidecars found); retrying open.")
    return True


def _require_close_password(entries, vault: SourceVault) -> None:
    """Refuse close unless these secrets decrypt every .vault backup from the open.

    close re-encrypts each edited value with the secret that decrypts its
    backup (encrypt_like), so a backup no loaded secret decrypts cannot be
    closed, and a different password must not silently re-key anything. Every
    backup is checked before any file is written: with several vault ids, one
    backup proves only its own secret. pilfer < 2.31 also stored an unsalted
    SHA-256 of the password in vaultedFileList.json, which is far cheaper to
    guess offline than the vault's own key derivation.
    """
    checked = 0
    labels: set[str] = set()
    for entry in entries:
        backup = _encrypted_backup_path(entry["path"])
        if not os.path.isfile(backup):
            continue
        with open(backup, "rb") as handle:
            data = handle.read()
        if entry.get("kind") == "inline":
            ciphertexts = [span.ciphertext for span in find_inline_vault_spans(data)]
        else:
            ciphertexts = [normalize_whole_file_vault(data)]
        if not all(decrypts(vault, ciphertext) for ciphertext in ciphertexts):
            raise PilferError(
                "Vault password does not match the password used for 'pilfer open' "
                f"(it does not decrypt the backup of {entry['path']}). Refusing to close "
                "(would re-key modified files under a different password). Use the same "
                "-p / --vault-id / ansible.cfg password as open."
            )
        labels.update(label for label in map(vault_label, ciphertexts) if label)
        checked += 1
    if checked:
        # Another source (ansible.cfg's password, say) decrypted the backups.
        # A flag that decrypts none of them may be a new password meant as a
        # rotation; close never changes passwords, so refuse. Only a flag that
        # could be that: an unlabelled one, or one whose label a backup carries.
        # `--vault-id dev@X --vault-id prod@X` on a session that holds only dev
        # files opened fine, and its prod flag is merely unused.
        for source in vault.unused_explicit():
            if source.vault_id == C.DEFAULT_VAULT_IDENTITY or source.vault_id in labels:
                if source.secret is None:
                    raise PilferError(
                        f"Vault password from {source.flag} could not be loaded (Ansible "
                        "printed why above). Refusing to close; fix or drop the flag."
                    )
                raise PilferError(
                    f"Vault password from {source.flag} does not match the password used for "
                    "'pilfer open': it decrypts none of the session's backups, which another "
                    "source (ansible.cfg, vault_identity_list or another flag) does. Refusing "
                    "to close. close keeps each file's password; use 'pilfer rekey' to change "
                    "it, or drop the flag if it is not meant to decrypt anything in this session."
                )
        _warn_unused_sources(vault, "the session's files")
        return
    raise PilferError(
        "No .vault backup left to check the password against. Restore .vault "
        "backups and retry close, or remove vaultedFileList.json if the open never "
        "finished."
    )


def _write_session(entries) -> None:
    payload = {
        "version": SESSION_VERSION,
        "entries": entries,
    }
    # Temp-and-replace: a crash cannot leave truncated JSON, and a symlink
    # session path is refused instead of followed.
    write_atomic(
        temp_vault_file_list_path,
        json.dumps(payload, indent=2).encode("utf-8"),
    )


def _should_skip_by_extension(file_path: str) -> bool:
    """True for known binary / non-text extensions we never treat as vault YAML.

    Every suffix counts. splitext('backup.tar.zst') is only '.zst', so a last-
    suffix check read those archives in full (hundreds of MB on this homelab).
    """
    return any(suffix.lower() in _SKIP_FILE_EXTENSIONS for suffix in Path(file_path).suffixes)


def _is_nested_git_checkout(path: str) -> bool:
    """True if path is its own git checkout (.git directory or submodule gitfile)."""
    git_meta = os.path.join(path, ".git")
    return os.path.isdir(git_meta) or os.path.isfile(git_meta)


def _classify_file_bytes(file_path: str, data: bytes, include_encrypted_vars: bool = False):
    """Classify from already-read bytes (avoids a second open during scan)."""
    if file_path.endswith(OPEN_SIDECAR_SUFFIX):
        return None
    header = data[:_VAULT_HEADER_READ_SIZE]
    if not header:
        return None
    if is_whole_file_vault(header):
        return "file"
    if not include_encrypted_vars:
        return None
    if VAULT_HEADER_PREFIX in data and find_inline_vault_spans(data):
        return "inline"
    return None


@dataclass
class ProjectScan:
    """Result of a single project walk (targets + orphan signals)."""

    targets: list = field(default_factory=list)
    marker_files: list = field(default_factory=list)
    sidecar_files: list = field(default_factory=list)
    nested_skipped: list = field(default_factory=list)
    # (path, count) of !vault values Ansible reads that pilfer does not open.
    # Only collected with include_encrypted_vars.
    skipped_vault_values: list = field(default_factory=list)


def scan_project(include_encrypted_vars: bool = False, announce_skips: bool = True) -> ProjectScan:
    """Walk the tree once: vault targets, orphan markers/sidecars, nested skips."""
    marker = MARKER_PREFIX.encode("utf-8")
    result = ProjectScan()
    walk_dir = os.path.abspath(os.getcwd())

    for dirpath, dirnames, filenames in os.walk(walk_dir):
        kept = []
        for d in dirnames:
            if d in _SKIP_DIR_NAMES:
                continue
            child = os.path.join(dirpath, d)
            if _is_nested_git_checkout(child):
                result.nested_skipped.append(child)
                if announce_skips:
                    print(
                        f"⏭️  Skipping nested git repo: {child}"
                        f" (run 'pilfer open' from that directory instead)"
                    )
                continue
            kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            file_path = os.path.join(dirpath, name)
            if os.path.islink(file_path):
                continue
            # Sibling used by vault_file_lock (it can exist while another pilfer
            # runs, or after a killed one). Not a vault target.
            if name.endswith(LOCK_SUFFIX):
                continue
            # Sidecars / markers must be collected even if renamed behind the
            # rekey temp prefix or a denylisted extension - otherwise orphan
            # detection fail-opens.
            if file_path.endswith(OPEN_SIDECAR_SUFFIX):
                result.sidecar_files.append(file_path)
                continue
            denylisted = _should_skip_by_extension(file_path)
            try:
                with open(file_path, "rb") as open_file:
                    # Cap denylisted reads: markers are small ASCII; avoid
                    # slurping multi-GB binaries during orphan detection.
                    data = open_file.read(1_048_576) if denylisted else open_file.read()
            except OSError:
                continue
            if not data:
                continue
            if marker in data:
                # Markers in YAML and in extensionless Ansible files (group_vars/all)
                # are orphan evidence. Docs and scripts that quote the prefix are
                # not. Denylisted renames (.pyc, .db) must still block open.
                _, ext = os.path.splitext(name)
                ext_lc = ext.lower()
                if ext_lc in (".yml", ".yaml", "") or denylisted:
                    result.marker_files.append(file_path)
            if denylisted:
                continue
            # Staging leftovers are never vault targets, but may still carry
            # orphan markers above.
            if name.startswith(TEMP_PREFIX):
                continue
            kind = _classify_file_bytes(
                file_path, data, include_encrypted_vars=include_encrypted_vars
            )
            if kind:
                result.targets.append({"kind": kind, "path": file_path})
            if include_encrypted_vars and kind != "file":
                skipped = vault_values_pilfer_skips(data)
                if skipped:
                    result.skipped_vault_values.append((file_path, skipped))
    return result


def _describe_skipped_vault_values(scan: ProjectScan) -> str:
    total = sum(count for _path, count in scan.skipped_vault_values)
    shown = ", ".join(f"{path} ({count})" for path, count in scan.skipped_vault_values[:5])
    more = " ..." if len(scan.skipped_vault_values) > 5 else ""
    return (
        f"{total} !vault value(s) that Ansible reads are in a form pilfer does not "
        f"handle (it handles `key: !vault |` only): {shown}{more}"
    )


# A write_atomic temp: the prefix plus mkstemp's random letters, digits and
# underscores. A name with a dot after the prefix is not one of pilfer's.
_STALE_TEMP_RE = re.compile(re.escape(TEMP_PREFIX) + r"[A-Za-z0-9_]+")


def _remove_stale_temps(root: str | None = None) -> int:
    """Delete write_atomic temps a killed pilfer left behind. Returns how many.

    A temp exists only until its rename, so a leftover is never the only copy:
    the file it was meant to replace still holds its previous content. A
    leftover from a killed open holds plaintext, so open, close and rekey (dry
    runs included) remove them before anything else. A concurrent `pilfer set`
    can lose its live temp too; it then fails and leaves its vault as it was.
    .vault is walked as well, so a killed backup write does not look like
    orphaned open state. Nested git checkouts are skipped.
    """
    walk_dir = os.path.abspath(root or os.getcwd())
    skip = _SKIP_DIR_NAMES - {temp_hidden_encrypted_copies_directory_path}
    removed = 0
    for dirpath, dirnames, filenames in os.walk(walk_dir):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in skip and not _is_nested_git_checkout(os.path.join(dirpath, d))
        ]
        for name in filenames:
            if not _STALE_TEMP_RE.fullmatch(name):
                continue
            path = os.path.join(dirpath, name)
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    continue
                os.unlink(path)
                removed += 1
            except OSError:
                pass
    if removed:
        print(f"ℹ️  Removed {removed} leftover temp file(s) from an interrupted pilfer run.")
    return removed


def _prune_empty_dirs(root: str) -> None:
    """Remove empty directories under root, then root if it is empty. Never removes a file.

    Used instead of rmtree on .vault: anything still in there is a backup or
    session file pilfer did not expect, possibly the only ciphertext of a
    file, and the next open reports it as orphaned state.
    """
    if os.path.islink(root) or not os.path.isdir(root):
        return
    for dirpath, _dirnames, _filenames in os.walk(root, topdown=False):
        try:
            os.rmdir(dirpath)
        except OSError:
            pass  # not empty


def _vault_dir_has_artifacts() -> bool:
    """True if .vault holds any file. Empty directories hold no backup."""
    root = Path(temp_hidden_encrypted_copies_directory_path)
    if not root.is_dir():
        return False
    return any(not path.is_dir() or path.is_symlink() for path in root.rglob("*"))


def assert_no_orphaned_open_state(scan: ProjectScan | None = None):
    """Fail closed if a prior open left plaintext markers, sidecars, or .vault.

    Without this, deleting vaultedFileList.json after open leaves secrets in
    plaintext and a subsequent open exits 0 with 'No vault files found'.
    Whole-file opens leave no # pilfer:vault: markers, so *.pilfer-open
    sidecars are required for that case.
    """
    if _session_is_open():
        return

    if scan is None:
        scan = scan_project(include_encrypted_vars=False, announce_skips=False)
    marker_files = scan.marker_files
    sidecar_files = scan.sidecar_files
    has_vault = _vault_dir_has_artifacts()
    if not marker_files and not sidecar_files and not has_vault:
        return

    details = []
    if marker_files:
        shown = marker_files[:5]
        details.append(
            "leftover # pilfer:vault: markers in: "
            + ", ".join(shown)
            + (" ..." if len(marker_files) > 5 else "")
        )
    if sidecar_files:
        shown = sidecar_files[:5]
        details.append(
            f"leftover {OPEN_SIDECAR_SUFFIX} locks: "
            + ", ".join(shown)
            + (" ..." if len(sidecar_files) > 5 else "")
        )
    if has_vault:
        details.append(f"leftover {temp_hidden_encrypted_copies_directory_path}/ backups")
    raise PilferError(
        "Orphaned open state detected (no vaultedFileList.json session) but "
        + "; ".join(details)
        + ". Restore vaultedFileList.json from backup if you have it and run "
        "'pilfer close', or manually re-encrypt / restore secrets before opening."
    )


def _prepare_project() -> None:
    """First step of open, close and rekey.

    Refuse a planted session symlink, then delete temps a killed pilfer left
    behind; one from a killed open holds plaintext.
    """
    _refuse_planted_session_links()
    _remove_stale_temps()


def open_vault_files(
    vault_password_file_path=None,
    *,
    include_encrypted_vars: bool = False,
    announce_skips: bool = True,
) -> int:
    """pilfer open: find vault targets, record the session, decrypt them.

    Only whole-file vaults unless include_encrypted_vars, which also opens
    inline !vault / encrypt_string scalars. Close re-encrypts whatever the
    session recorded, so it needs no such flag. Returns how many files opened.
    """
    _prepare_project()
    if _session_is_open() and not _abandon_incomplete_session():
        raise PilferError(
            f"Session already open ({temp_vault_file_list_path} exists). "
            "Run 'pilfer close' first. Re-running open would destroy "
            "encrypted backups and can leave secrets in plaintext."
        )

    # Single walk: orphan detection + discovery (nested skips once).
    scan = scan_project(
        include_encrypted_vars=include_encrypted_vars, announce_skips=announce_skips
    )
    assert_no_orphaned_open_state(scan)
    found = scan.targets
    if not found:
        print("No vault files found in current directory tree.")
        return 0

    # Load the secrets now, once, so a missing password fails before anything
    # is written and a password script or prompt runs only one time.
    vault = load_vault(vault_password_file_path)
    _write_session(found)

    whole = sum(1 for e in found if e["kind"] == "file")
    print(
        f"ℹ️  Found {len(found)} vault target(s) "
        f"({whole} whole-file, {len(found) - whole} with inline encrypt_string)"
    )
    if not include_encrypted_vars:
        print("(inline !vault strings skipped - pass --include-encrypted-vars to open them)")
    elif scan.skipped_vault_values:
        print(
            f"⚠️  {_describe_skipped_vault_values(scan)}. They stay encrypted.",
            file=sys.stderr,
        )
    try:
        opened = decrypt_vault_files(vault=vault)
        _warn_unused_sources(vault, "the opened files")
        return opened
    except NothingOpened:
        # This open wrote the session list a moment ago, under the caller's
        # project lock, and every file cleaned up after itself.
        _remove_file(temp_vault_file_list_path)
        _prune_empty_dirs(temp_hidden_encrypted_copies_directory_path)
        raise


def _warn_unused_sources(vault: SourceVault, what: str) -> None:
    """Warn for each -p / --vault-id / -J whose password decrypted none of `what`."""
    for source in vault.unused_explicit():
        print(
            f"⚠️  Vault password from {source.flag} decrypted none of {what}; another source "
            "(ansible.cfg, vault_identity_list or another flag) did.",
            file=sys.stderr,
        )


def _holds_plaintext(path: str, plaintext: bytes) -> bool:
    """True if path now holds plaintext, so its replace landed. Never follows a symlink."""
    try:
        return _read_no_follow(path, path) == plaintext
    except PilferError:
        return False


def _publish_opened(
    vaulted_file_path: str, kind: str, plaintext: bytes, original: bytes, backups: dict
) -> None:
    """Write the .vault backups and the sidecar, then the plaintext. Undo all of it on failure.

    The sidecar goes before the plaintext, so a crash never leaves unmarked
    plaintext. The plaintext replace is atomic: until it lands the file still
    holds its ciphertext, so cleanup removes only what this call wrote and
    never rewrites the target. expected=original: if the file changed while it
    was decrypted (an editor, or a tool other than pilfer), publishing this
    plaintext would throw that change away.

    An interrupt can land after write_atomic's os.replace (in its directory
    fsync). The target then holds the plaintext, and the backups and sidecar
    are the only record of how to close it: they stay, and close restores it.
    """
    written = []
    try:
        _ensure_private_dir(_backup_dir_for(vaulted_file_path))
        # Recorded before each write: an interrupt in write_atomic's directory
        # fsync lands after the replace, and a file not recorded would be left
        # for close or open to trip over. Cleanup tolerates one never written.
        for path, data in backups.items():
            written.append(path)
            write_atomic(path, data)
        written.append(_open_sidecar_path(vaulted_file_path))
        _write_open_sidecar(vaulted_file_path, kind)
        write_atomic(vaulted_file_path, plaintext, expected=original, action="open")
    except BaseException:
        if not _holds_plaintext(vaulted_file_path, plaintext):
            for path in written:
                _remove_file(path)
        raise


@locked_by_path
def _decrypt_whole_file(vaulted_file_path: str, vault: VaultLib, cwd: Path) -> None:
    """Open one whole-file vault."""
    _validate_target_path(vaulted_file_path, cwd)

    with open(vaulted_file_path, "rb") as f:
        raw = f.read()

    # Tolerate BOM / leading whitespace on whole-file vaults (editors).
    encrypted_data = normalize_whole_file_vault(raw)

    if not is_whole_file_vault(encrypted_data):
        raise PilferError(
            "Input is not vault encrypted data (refusing to overwrite encrypted backup)"
        )

    decrypted_bytes = vault.decrypt(encrypted_data)

    _publish_opened(
        vaulted_file_path,
        "file",
        decrypted_bytes,
        raw,
        {
            # The raw bytes, BOM and leading whitespace included, so an
            # unchanged close puts back exactly what was there.
            _encrypted_backup_path(vaulted_file_path): raw,
            _hash_backup_path(vaulted_file_path): _sha256_hex(decrypted_bytes).encode("utf-8"),
        },
    )


@locked_by_path
def _decrypt_inline_file(vaulted_file_path: str, vault: VaultLib, cwd: Path) -> int:
    """Decrypt inline spans. Returns the span count."""
    _validate_target_path(vaulted_file_path, cwd)

    with open(vaulted_file_path, "rb") as f:
        original = f.read()

    new_content, records = decrypt_inline_content(original, vault)
    if not records:
        raise PilferError(f"No inline vault spans found in {vaulted_file_path}")

    _publish_opened(
        vaulted_file_path,
        "inline",
        new_content,
        original,
        {
            # Full original, for the unchanged-file shortcut on close.
            _encrypted_backup_path(vaulted_file_path): original,
            _hash_backup_path(vaulted_file_path): _sha256_hex(new_content).encode("utf-8"),
            _inline_meta_path(vaulted_file_path): json.dumps(
                {"format": INLINE_FORMAT, "spans": records}, indent=2
            ).encode("utf-8"),
        },
    )

    return len(records)


def decrypt_vault_files(vault_password_file_path=None, *, vault: VaultLib | None = None):
    """Decrypt all vault entries listed in the current session.

    vault_password_file_path is a path or VaultSources; a vault already loaded
    (by open) is used as it is.
    Returns the number of successfully decrypted entries.
    Raises PilferError if any entry fails (session list retained for recovery).
    """
    entries = _load_session()
    if vault is None:
        vault = load_vault(vault_password_file_path)
    cwd = Path.cwd().resolve()

    _ensure_private_dir(temp_hidden_encrypted_copies_directory_path)

    # Record each file's mode and group before any is opened, which makes it
    # 0600 with the opener's group. Close puts them back, and after an
    # interrupted open the session must already hold them.
    for entry in entries:
        try:
            entry.update(vault_mode_and_group(entry["path"]))
        except OSError:
            pass  # the decrypt below reports a file that is not there
    _write_session(entries)

    failed = []
    succeeded = []

    for entry in entries:
        path = entry["path"]
        kind = entry.get("kind", "file")
        try:
            if kind == "inline":
                _decrypt_inline_file(path, vault, cwd)
            else:
                _decrypt_whole_file(path, vault, cwd)
            succeeded.append(entry)
        except Exception as e:
            print(f"Failed to decrypt {path}: {e}")
            failed.append(path)

    if failed and not succeeded:
        # Each file undid what it wrote, and nothing else is touched here: the
        # session list and .vault may belong to an open that is still in use.
        # The CLI, which wrote this session list under the project lock, clears it.
        raise NothingOpened(
            f"Failed to decrypt all {len(entries)} file(s); nothing was opened. "
            "Fix the errors and retry 'pilfer open'."
        )

    _write_session(succeeded)

    if failed:
        raise PilferError(
            f"Failed to decrypt {len(failed)} of {len(entries)} file(s). "
            f"Session kept for {len(succeeded)} decrypted file(s); "
            "fix errors then run 'pilfer close' or retry carefully."
        )

    return len(succeeded)


def _require_round_trip(vault: VaultLib, ciphertext: bytes, plaintext: bytes, path: str) -> None:
    """Refuse to publish ciphertext unless it decrypts to exactly plaintext.

    Not merely that it decrypts: a wrong secret under the right password is
    still a lost secret. Ansible raises several types for a bad blob.
    """
    try:
        ok = vault.decrypt(normalize_whole_file_vault(ciphertext)) == plaintext
    except Exception:
        ok = False
    if not ok:
        raise PilferError(
            f"Refusing to replace {path}: new ciphertext does not decrypt to the edit"
        )


@locked_by_path
def _recrypt_whole_file(
    vaulted_file_path: str, vault: VaultLib, cwd: Path, restore: dict | None = None
) -> bool:
    """Re-encrypt a whole-file vault. Returns True if modified.

    Does not delete session backups - caller cleans up only after all entries succeed
    so a partial close remains retryable. Idempotent if the working file is already
    vault ciphertext from a prior interrupted close.
    """
    _validate_target_path(vaulted_file_path, cwd)

    encrypted_backup = _encrypted_backup_path(vaulted_file_path)
    hash_path = _hash_backup_path(vaulted_file_path)

    with open(encrypted_backup, "rb") as f:
        old_encrypted_data = f.read()

    with open(hash_path) as f:
        old_hash = f.read().strip()

    with open(vaulted_file_path, "rb") as f:
        new_data_bytes = f.read()

    if old_hash != _sha256_hex(new_data_bytes):
        if is_whole_file_vault(new_data_bytes):
            normalized = normalize_whole_file_vault(new_data_bytes)
            # Interrupted close already wrote ciphertext - treat as done.
            if normalized == normalize_whole_file_vault(old_encrypted_data):
                return False
            if not decrypts(vault, normalized):
                raise PilferError(
                    "File is already vault-encrypted but not with the session password; "
                    "refusing to continue"
                )
            print(f"ℹ️  Already re-encrypted (retrying close): {vaulted_file_path}")
            return True
        # The secret that decrypts the backup, under its vault-id label (a 1.2
        # header stays 1.2), as ansible-vault edit does.
        new_encrypted_data = encrypt_like(
            vault, new_data_bytes, normalize_whole_file_vault(old_encrypted_data)
        )
        print(f"ℹ️  Re-encrypting modified file: {vaulted_file_path}")
        modified = True
    else:
        new_encrypted_data = old_encrypted_data
        modified = False

    # Prove the bytes round-trip before replace. open('wb') would truncate the
    # live file first; a crash or short write then left garbage that a retry
    # re-encrypted, and the .vault backup was deleted on the way out. An
    # unchanged file gets its backup back, which decrypts to the same bytes:
    # the hashes matched.
    _require_round_trip(vault, new_encrypted_data, new_data_bytes, vaulted_file_path)
    publish_vault(
        vaulted_file_path,
        new_encrypted_data,
        expected=new_data_bytes,
        action="close",
        restore=restore or {},
    )

    return modified


@locked_by_path
def _recrypt_inline_file(
    vaulted_file_path: str,
    vault: VaultLib,
    cwd: Path,
    confirm_delete: bool = False,
    restore: dict | None = None,
) -> bool:
    """Re-encrypt inline spans. Returns True if any span was modified/removed.

    Idempotent if a prior close already restored/re-encrypted the file (no markers).
    """
    _validate_target_path(vaulted_file_path, cwd)

    with open(_hash_backup_path(vaulted_file_path)) as f:
        old_hash = f.read().strip()
    with open(_encrypted_backup_path(vaulted_file_path), "rb") as f:
        backup = f.read()
    with open(vaulted_file_path, "rb") as f:
        current = f.read()

    if old_hash == _sha256_hex(current):
        publish_vault(
            vaulted_file_path, backup, expected=current, action="close", restore=restore or {}
        )
        return False

    # Interrupted close: working copy already matches backup ciphertext.
    if current == backup:
        return False

    with open(_inline_meta_path(vaulted_file_path)) as f:
        meta = json.load(f)
    if meta.get("format") != INLINE_FORMAT:
        raise PilferError(
            f"{vaulted_file_path} was opened by an older pilfer, which showed some secrets "
            "in a form this release reads differently. Close it with the pilfer release "
            "that opened it, or restore the file from its .vault backup."
        )
    spans = meta.get("spans", [])

    # Interrupted close after successful recrypt: no markers left. Only treat as
    # done when none of the opened secrets still appear as plaintext and any
    # remaining keys hold decryptable !vault ciphertext (not garbage tags).
    if MARKER_RE.search(current) is None:
        if not spans:
            raise PilferError(
                "Inline session metadata has no spans; refusing to treat file as "
                "already re-encrypted (would clear session while plaintext may remain)."
            )
        unsafe = unsafe_missing_marker_names(current, spans, vault)
        if unsafe:
            raise MarkerMissingSecretPresent(unsafe[0], _span_id_for(unsafe[0], spans) or 0)
        removed_like = intentional_removal_candidate_names(current, spans)
        if removed_like and not confirm_delete:
            span_id = _span_id_for(removed_like[0], spans)
            if span_id is not None:
                raise SecretLineDeleted(removed_like[0], span_id)
        print(f"⏭️  Already re-encrypted inline file (retrying close): {vaulted_file_path}")
        return True

    # recrypt_inline_content refuses (ValueError) unless its output reads back
    # as the edited file with every opened value decrypting to its edit.
    result = recrypt_inline_content(current, spans, vault, confirm_delete=confirm_delete)
    publish_vault(
        vaulted_file_path, result.content, expected=current, action="close", restore=restore or {}
    )

    if result.removed_vars:
        print(f"🔍 Detected removal of {len(result.removed_vars)} encrypted vars:")
        for name in result.removed_vars:
            print(f"  - {name}")

    if result.modified_count > len(result.removed_vars):
        changed = result.modified_count - len(result.removed_vars)
        print(
            f"ℹ️  Re-encrypting modified inline vault string(s) in: {vaulted_file_path}"
            f" ({changed} changed)"
        )

    for name, yaml_type in result.typed_notes:
        # Never the value: it is a secret.
        print(
            f"ℹ️  {name}: stored as a string, though plain YAML would read it as {yaml_type}. "
            "An inline !vault value is always a string; convert it where it is used "
            "(for example | int or | bool)."
        )

    return result.modified_count > 0


def _cleanup_entry_backups(vaulted_file_path: str) -> None:
    for path in (
        _encrypted_backup_path(vaulted_file_path),
        _hash_backup_path(vaulted_file_path),
        _inline_meta_path(vaulted_file_path),
        _open_sidecar_path(vaulted_file_path),
    ):
        _remove_file(path)
    try:
        os.removedirs(_backup_dir_for(vaulted_file_path))
    except OSError:
        pass  # not empty: close reports what is left in .vault


def _drop_never_opened(entries):
    """Leave out entries an interrupted open never reached.

    open lists every target before decrypting any. After ctrl-c, the ones it
    had not reached have no backup, sidecar or metadata and are still
    ciphertext: there is nothing to close, and failing on them would leave the
    session open for no reason.
    """
    kept = []
    for entry in entries:
        path = entry["path"]
        if not _entry_has_open_artifacts(entry):
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError:
                data = None
            if data is not None and _path_still_vault_ciphertext(entry, data):
                print(f"ℹ️  Skipping {path}: it was never opened.")
                continue
        kept.append(entry)
    return kept


def recrypt_vault_files(vault_password_file_path=None, confirm_delete: bool = False):
    """Re-encrypt vault entries. Only clears the session if every file succeeds.

    Successfully closed entries are removed from the session immediately so a
    later failure leaves a retryable list of remaining plaintext files only.

    Returns the number of modified files (whole-file or inline with changes).
    Raises PilferError on any failure without deleting remaining session artifacts.
    """
    _prepare_project()
    if not _session_is_open():
        raise PilferError("No vault file list found. Run 'pilfer open' first.")

    entries = _drop_never_opened(_load_session())
    # An interrupted open can leave nothing to close: no password to load then.
    if entries:
        vault = load_vault(vault_password_file_path)
        _require_close_password(entries, vault)

    cwd = Path.cwd().resolve()

    modified_count = 0
    failed = []
    remaining = list(entries)

    for entry in entries:
        path = entry["path"]
        kind = entry.get("kind", "file")
        try:
            restore = {k: entry[k] for k in ("mode", "gid") if k in entry}
            if kind == "inline":
                if _recrypt_inline_file(
                    path, vault, cwd, confirm_delete=confirm_delete, restore=restore
                ):
                    modified_count += 1
            else:
                if _recrypt_whole_file(path, vault, cwd, restore):
                    modified_count += 1
            # Persist session removal before deleting backups so a crash mid-close
            # leaves a retryable list (already-closed files are not re-listed).
            remaining = [e for e in remaining if e["path"] != path]
            _write_session(remaining)
            _cleanup_entry_backups(path)
        except InlineCloseRefusal as exc:
            _emit_inline_close_refusal(path, exc)
            failed.append(path)
            _write_session(remaining)
        except Exception as e:
            _emit_warning_block(f"Failed to process {path}:", str(e))
            failed.append(path)
            _write_session(remaining)
            # Continue attempting other files; all failures reported at end.

    if failed:
        raise PilferError(
            f"Failed to re-encrypt {len(failed)} file(s); session NOT cleared. "
            "Plaintext may remain for failed paths - fix and re-run 'pilfer close'."
        )

    _prune_empty_dirs(temp_hidden_encrypted_copies_directory_path)
    if os.path.isdir(temp_hidden_encrypted_copies_directory_path):
        print(
            f"⚠️  Left {temp_hidden_encrypted_copies_directory_path}/ in place: it holds files "
            "this session did not create. Check them before deleting.",
            file=sys.stderr,
        )

    _remove_file(temp_vault_file_list_path)
    return modified_count


@dataclass(frozen=True)
class NewSecret:
    """What rekey encrypts with.

    label is the vault-id an explicit --new-vault-id names. None (a password
    file, or an id without a label) keeps each value's own label, where
    ansible-vault rekey would drop it: a dropped label changes which --vault-id
    Ansible matches the file to later.
    """

    secret: VaultSecret
    label: str | None

    def label_for(self, ciphertext: bytes) -> str | None:
        return self.label or vault_label(ciphertext)

    def decrypts(self, ciphertext: bytes) -> bool:
        return decrypts(single_secret_vault(self.secret, vault_label(ciphertext)), ciphertext)


def _rekey_probe_file(
    path: str, kind: str, old_vault: VaultLib, new: NewSecret
) -> tuple[str, int, set[bytes]]:
    """Classify a target for rekey resume.

    Returns (status, span_count, old secrets used) where status is
    'needs_rekey' or 'already_new'. The old secrets are the bytes of each
    secret that decrypts a value, so rekey can refuse a tree on several.
    Raises PilferError if neither password decrypts the file cleanly.
    """
    with open(path, "rb") as handle:
        data = handle.read()
    if kind == "inline":
        ciphertexts = [span.ciphertext for span in find_inline_vault_spans(data)]
        if not ciphertexts:
            raise PilferError(f"No inline vault spans found in {path}")
    else:
        ciphertexts = [normalize_whole_file_vault(data)]
    try:
        used = {secret_for(old_vault, c).bytes for c in ciphertexts}
    except Exception:
        used = None
    if used is not None:
        return "needs_rekey", len(ciphertexts), used
    if all(new.decrypts(c) for c in ciphertexts):
        return "already_new", len(ciphertexts), set()
    raise PilferError(
        f"Neither old nor new password can decrypt every vault value in {path} "
        "(mixed or foreign ciphertext)."
    )


@locked_by_path
def _rekey_whole_file(path: str, old_vault: VaultLib, new: NewSecret) -> None:
    with open(path, "rb") as handle:
        data = handle.read()
    normalized = normalize_whole_file_vault(data)
    plaintext = old_vault.decrypt(normalized)
    # encrypt_with reads the result back with the new secret alone.
    new_cipher = encrypt_with(new.secret, plaintext, new.label_for(normalized))
    publish_vault(path, new_cipher, expected=data, action="rekey")


@locked_by_path
def _rekey_inline_file(path: str, old_vault: VaultLib, new: NewSecret) -> int:
    with open(path, "rb") as handle:
        content = handle.read()
    spans = find_inline_vault_spans(content)
    if not spans:
        raise PilferError(f"No inline vault spans found in {path}")
    replacements = []
    plaintexts = []
    for span in spans:
        plaintext = old_vault.decrypt(span.ciphertext)
        plaintexts.append(plaintext)
        new_cipher = encrypt_with(new.secret, plaintext, new.label_for(span.ciphertext))
        replacements.append(
            (
                span.start,
                span.end,
                format_encrypted_block(new_cipher, span.line_prefix, span.body_indent),
            )
        )
    new_content = splice(content, replacements)
    # Verify before replace: the same spans, in order, each giving back its
    # secret under the new password alone.
    new_spans = find_inline_vault_spans(new_content)
    if len(new_spans) != len(plaintexts):
        raise PilferError(f"re-encrypted {path} has a different number of !vault values; unchanged")
    for span, plaintext in zip(new_spans, plaintexts, strict=True):
        _require_round_trip(
            single_secret_vault(new.secret, span.vault_id), span.ciphertext, plaintext, path
        )
    publish_vault(path, new_content, expected=content, action="rekey")
    return len(replacements)


def _stat_or_none(path: str | None) -> os.stat_result | None:
    if path is None:
        return None
    try:
        return os.stat(path)
    except OSError:
        return None


def _rotation_paths(old: VaultSources, new: VaultSources) -> tuple[str, str]:
    """The two password files --rotate-password-file swaps, or a refusal.

    Rotation writes the new password into the old file. That needs one plain
    file on each side: a script prints its password from somewhere else (a
    keyring, a password manager), and writing a password over it would replace
    the script with a non-executable file and leave that store unchanged.
    Both files are copied as they are, so both must be plain: a vault-encrypted
    one would be installed as a blob Ansible cannot use as a password.
    """
    old_path, new_path = old.single_password_file, new.single_password_file
    if old_path is None or new_path is None:
        raise PilferError(
            "--rotate-password-file needs exactly one --old-vault-password-file and "
            "one --new-vault-password-file, with no --vault-id or prompt."
        )
    for path, which in ((old_path, "old"), (new_path, "new")):
        if not is_plain_password_file(path):
            raise PilferError(
                f"--rotate-password-file refused: the {which} password file is a script "
                "that Ansible runs, not a file it reads. Change the password where the "
                "script gets it, and rekey without --rotate-password-file."
            )
    _check_rotation_targets(old_path, new_path)
    for path, which in ((old_path, "old"), (new_path, "new")):
        # Core strips the file before it looks for the header (a leading blank
        # line is still a vault), so the test strips it too.
        if is_encrypted(_read_no_follow(path, f"{which} password file").strip()):
            raise PilferError(
                f"--rotate-password-file refused: the {which} password file is vault-encrypted. "
                "Rotation copies password files, so both must be plain text."
            )
    return old_path, new_path


def _check_rotation_targets(old_path: str, new_path: str) -> None:
    """Refuse a rotation that cannot finish, before anything is written.

    Rotation is the last step of rekey, after every target is re-keyed, so a
    failure here would leave the tree on the new password and the live password
    file on the old one. A second rotation is the usual case: the first left
    <old>_old. Called before --dry-run returns; the write itself is guarded by
    O_EXCL | O_NOFOLLOW and _read_no_follow.
    """
    backup = f"{old_path}_old"
    for path in (old_path, new_path, backup):
        if os.path.islink(path):
            raise PilferError(f"refusing symlink password file: {path}")
    if os.path.lexists(backup):
        raise PilferError(f"Password backup already exists: {backup}. Move it aside first.")
    directory = os.path.dirname(old_path) or "."
    if not os.access(directory, os.W_OK | os.X_OK):
        raise PilferError(f"cannot write the password backup: {directory} is not writable")


def rekey_vault_files(
    old_password_file,
    new_password_file,
    *,
    include_encrypted_vars: bool = True,
    dry_run: bool = False,
    yes: bool = False,
    rotate_password_file: bool = False,
    announce_skips: bool = True,
) -> int:
    """Re-key whole-file and inline vault targets from old password to new.

    Each side is a path or VaultSources. The old side loads like open (with
    vault_identity_list and ansible.cfg's vault_password_file); the new side
    is exactly one source (load_new_secret).
    Does not use an open/close session. Refuses if a session or orphan state exists.
    Resumable: files already decryptable with the new password are skipped.
    Returns number of files rewritten (0 on dry-run / already complete).
    """
    old_sources = VaultSources.of(old_password_file)
    new_sources = VaultSources.of(new_password_file)
    # A leftover temp from a killed open can hold plaintext with markers, which
    # the orphan check below would report. It is never the only copy.
    _prepare_project()
    if _session_is_open():
        raise PilferError(
            f"Session already open ({temp_vault_file_list_path}). Run 'pilfer close' before rekey."
        )

    if rotate_password_file and not include_encrypted_vars:
        raise PilferError(
            "--rotate-password-file requires inline !vault spans to be included "
            "(omit --no-include-encrypted-vars). Otherwise rotating the live "
            "password file would leave inline ciphertext on the old password."
        )
    if rotate_password_file:
        old_path, new_path = _rotation_paths(old_sources, new_sources)

    # A SourceVault, so a flag that decrypts nothing is reported as open does.
    old_vault = load_vault(old_sources)
    old_secrets = old_vault.secrets
    new_label, new_secret = load_new_secret(new_sources, old_secrets)
    # Every loaded old secret, ansible.cfg's included: one equal to the new
    # password would make "already on the new password" true of old files.
    if any(secret.bytes == new_secret.bytes for _id, secret in old_secrets):
        raise PilferError(
            "The new vault password is the same as an old one (from the flags or ansible.cfg)."
        )
    new = NewSecret(new_secret, None if new_label == C.DEFAULT_VAULT_IDENTITY else new_label)

    # One walk: orphan signals and rekey targets. A second scan_project here
    # used to re-read every file in the tree.
    scan = scan_project(
        include_encrypted_vars=include_encrypted_vars, announce_skips=announce_skips
    )
    assert_no_orphaned_open_state(scan)
    if scan.skipped_vault_values:
        raise PilferError(
            f"Rekey refused: {_describe_skipped_vault_values(scan)}. They would stay on the "
            "old password. Rewrite them as `key: !vault |` blocks, or rekey them with "
            "ansible-vault, first."
        )
    targets = scan.targets
    if not targets:
        print("No vault files found in current directory tree.")
        return 0

    # A password file that is itself a target would be re-keyed under the
    # password it holds: the new password would then exist only encrypted with
    # itself. The files are the ones that loaded (so ansible.cfg's count), and
    # are compared by device and inode: "~", "$VAR" and a different-case
    # spelling on a case-insensitive disk all name the same file.
    target_stats = [st for st in (_stat_or_none(entry["path"]) for entry in targets) if st]
    for which, secrets in (("old", [sec for _id, sec in old_secrets]), ("new", [new_secret])):
        for secret in secrets:
            info = _stat_or_none(getattr(secret, "filename", None))
            if info and any(os.path.samestat(info, target) for target in target_stats):
                raise PilferError(
                    f"the {which} password file is a vault in this tree; move it out first."
                )

    cwd = Path.cwd().resolve()

    plan = []
    used_secrets: set[bytes] = set()
    for entry in targets:
        path = entry["path"]
        kind = entry.get("kind", "file")
        _validate_target_path(path, cwd)
        status, span_count, used = _rekey_probe_file(path, kind, old_vault, new)
        plan.append((path, kind, span_count, status))
        used_secrets |= used

    if used_secrets:
        # Another source (ansible.cfg's password, say) may have done the work.
        # Skipped when every target is already on the new password: then no old
        # flag decrypted anything, and that is not a mistake in the flags.
        _warn_unused_sources(old_vault, "the files to rekey")
    if len(used_secrets) > 1:
        raise PilferError(
            f"Rekey refused: the targets are encrypted with {len(used_secrets)} different "
            "vault passwords. pilfer rekey moves a tree from one password to a new one; "
            "rekey a tree on several vault ids with ansible-vault rekey per id."
        )
    # The file being rotated must hold the password the tree is on, not one
    # that ansible.cfg or vault_identity_list loaded alongside it.
    if (
        rotate_password_file
        and used_secrets
        and used_secrets != {password_file_secret(old_path).bytes}
    ):
        raise PilferError(
            "--rotate-password-file refused: the targets are not encrypted with the "
            "password in --old-vault-password-file."
        )

    to_write = [p for p in plan if p[3] == "needs_rekey"]
    already = [p for p in plan if p[3] == "already_new"]
    whole = sum(1 for _, k, _, _ in plan if k == "file")
    inline_files = sum(1 for _, k, _, _ in plan if k == "inline")
    spans = sum(n for _, k, n, _ in plan if k == "inline")
    print(
        f"ℹ️  Rekey plan: {len(plan)} file(s) "
        f"({whole} whole-file, {inline_files} inline file(s), {spans} inline span(s)); "
        f"{len(to_write)} to rewrite, {len(already)} already on new password"
    )
    if dry_run:
        for path, kind, n, status in plan:
            tag = "skip" if status == "already_new" else "rewrite"
            print(f"  - [{kind}/{tag}] {path}" + (f" ({n} spans)" if kind == "inline" else ""))
        print("Dry run only - no files written.")
        return 0

    if rotate_password_file and scan.nested_skipped:
        raise PilferError(
            "--rotate-password-file refused: nested git checkout(s) were skipped "
            f"({len(scan.nested_skipped)}). Rekey those trees first or omit "
            "--rotate-password-file so the live password file is not rotated "
            "while nested vault ciphertext remains on the old password."
        )

    if not to_write:
        print("ℹ️  All targets already decrypt with the new password; nothing to rewrite.")
        if rotate_password_file:
            _confirm_rekey(yes, action="rotate the vault password file")
            _rotate_password_file(old_path, new_path)
            _log_vault_password_file_rotated()
        return 0

    action = "re-encrypt remaining targets with the new password"
    if rotate_password_file:
        action += " and rotate the vault password file"
    _confirm_rekey(yes, action=action)

    succeeded = []
    failed = []
    for path, kind, _n, status in plan:
        if status == "already_new":
            print(f"⏭️  Already on new password (resume): {path}")
            continue
        try:
            if kind == "inline":
                _rekey_inline_file(path, old_vault, new)
            else:
                _rekey_whole_file(path, old_vault, new)
            succeeded.append(path)
            print(f"✅  Re-keyed {path}")
        except Exception as exc:
            print(f"Failed to rekey {path}: {exc}")
            failed.append(path)

    if failed:
        raise PilferError(
            f"Rekey incomplete: {len(succeeded)} rewritten this run, "
            f"{len(failed)} failed, {len(already)} already on new password. "
            "Keep the old password and re-run rekey to resume "
            "(mixed passwords possible until complete)."
        )

    if rotate_password_file:
        _rotate_password_file(old_path, new_path)
        _log_vault_password_file_rotated()

    return len(succeeded)


def _confirm_rekey(yes: bool, *, action: str) -> None:
    """Require interactive REKEY confirmation unless --yes."""
    if yes:
        return
    try:
        answer = input(f"Type REKEY to {action}: ")
    except EOFError as exc:
        raise PilferError("Confirmation required (non-interactive; pass --yes).") from exc
    if answer.strip() != "REKEY":
        raise PilferError("Rekey aborted (confirmation not matched).")


def _log_vault_password_file_rotated() -> None:
    """Log rotate success without paths (avoids CodeQL taint from password file paths)."""
    print("ℹ️  Vault passphrase file rotation complete.")


def _rotate_password_file(old_path: str, new_path: str) -> None:
    """Archive the old password file as old_path + '_old' and install the new one at old_path.

    Script and vault-encrypted password files were refused up front by
    _rotation_paths.
    """
    backup = f"{old_path}_old"
    new_contents = _read_no_follow(new_path, "new password file")
    old_contents = _read_no_follow(old_path, "old password file")
    # O_EXCL so a dangling symlink at the backup path is not created through.
    backup_fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(backup_fd, "wb") as handle:
            handle.write(old_contents)
            handle.flush()
            os.fsync(handle.fileno())
        # Replace, never rename the live file away first: that left Ansible
        # with no password file if the process was cancelled in between.
        write_atomic(old_path, new_contents)
    finally:
        if _still_holds(old_path, old_contents):
            # The live file still holds the old password; the backup is a spare
            # copy. Not _remove_file: its warning would print a password-file
            # path, which CodeQL reports as logging sensitive data.
            try:
                os.remove(backup)
            except OSError:
                pass


def _still_holds(path: str, contents: bytes) -> bool:
    """True only when path is readable and holds contents.

    Decided by content, not by whether write_atomic returned: ctrl-c in its
    directory fsync arrives after os.replace, with the new password already
    live and the backup the only copy of the old one. A read error keeps the
    backup too.
    """
    try:
        return _read_no_follow(path, "password file") == contents
    except PilferError:
        return False


def _read_no_follow(path: str, what: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PilferError(f"could not read {what}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


_HELP_FORMATTER = argparse.RawDescriptionHelpFormatter

_HELP_EPILOG = """
Vault passwords load as ansible-vault loads them: vault_identity_list, then
--vault-id, then -p files, then vault_password_file from Ansible's config
(ANSIBLE_CONFIG, ./ansible.cfg, ~/.ansible.cfg, ANSIBLE_VAULT_* variables),
then the -J prompt.
An executable password file named by a flag or config is run and its output
used; a *-client script is passed --vault-id. With no source at all, pilfer
tries ~/.ansible-vault/.vault-file, .vault_password, vault_password_file, and
finally ../../vault_password_file, reading each as a plain password file:
those are never run, even when executable.

Never commit while a session is open. Add vaultedFileList.json, .vault/,
*.pilfer-open sidecars and *.pilfer-lock files (left only when pilfer is
killed) to your project's .gitignore. Check the exit code of close.

Run 'pilfer COMMAND --help' for command-specific options and examples.
"""

_OPEN_EPILOG = """
Examples:
  pilfer open
  pilfer open --include-encrypted-vars
  pilfer open --include-encrypted-vars --quiet
  pilfer open -p ~/.ansible-vault/.vault-file

Whole-file vault YAML is opened by default. With --include-encrypted-vars, inline
!vault / encrypt_string scalars become quoted plaintext plus a # pilfer:vault:N
marker (leave the marker until close).
"""

_CLOSE_EPILOG = """
Examples:
  pilfer close
  pilfer close --confirm-delete
  pilfer close -p ~/.ansible-vault/.vault-file

Re-encrypts every entry recorded in the open session (whole-file and inline).
No --include-encrypted-vars flag is needed on close. Each edited value is
encrypted with the vault id and password that decrypt its backup, as
ansible-vault edit does, so close needs the same sources as open.
"""

_SET_EPILOG = """
Examples:
  pilfer set inventory/group_vars/all/secrets.yml db_password
      (prompts for the value without echoing it)
  printf '%s' "$TOKEN" | pilfer set secrets.yml api_token
  pilfer set secrets.yml api_token -- '-starts-with-a-dash'

Sets one top-level key in a closed whole-file vault without writing plaintext to
disk. A new key is appended; an existing scalar is replaced in place, keeping an
inline comment. The value is stored as a JSON-quoted string, so yes/no/0123 stay
strings. A value containing {{, {% or {# is stored as !unsafe so Ansible does
not template it. An existing !unsafe tag is kept only when Ansible would still
load the new text as that string; otherwise the tag is dropped. A value that
needs !unsafe and would not stay a string is refused. Refuses plaintext and
files open in a pilfer session.

Leave VALUE out to read it from stdin: a hidden prompt on a terminal, otherwise
the whole input with one trailing newline dropped. A VALUE argument is visible
in ps and saved in shell history.
"""

_REKEY_EPILOG = """
Examples:
  pilfer rekey --old-vault-password-file OLD --new-vault-password-file NEW --dry-run
  pilfer rekey --old-vault-password-file OLD --new-vault-password-file NEW --yes
  pilfer rekey --new-vault-id prompt
  pilfer rekey ... --quiet

The old password loads like open: --old-vault-password-file and --old-vault-id
plus Ansible's config. The new password is the one --new-* source. Values keep
their vault-id label unless --new-vault-id names one. A tree on several vault
passwords is refused.

Inline !vault spans are included by default; pass --no-include-encrypted-vars for
whole-file vault YAML only. Rekey refuses a tree with !vault values in a form
pilfer cannot rewrite, which would stay on the old password.
"""


def _hides_unrecognized_set_value(message: str) -> bool:
    """True when argparse would print a single-dash positional as an option.

    `pilfer set file key -secret` is reported as an unrecognized argument, and
    the message quotes the token. A double-dash token is a mistyped flag
    (`--typo`); that one stays in the message.
    """
    marker = "unrecognized arguments:"
    if marker not in message:
        return False
    tokens = message.split(marker, 1)[1].split()
    return any(token.startswith("-") and not token.startswith("--") for token in tokens)


# ansible-vault's own type for --vault-password-file: ~ and $VARS expanded, made
# absolute, a final symlink left alone so an adjacent script config still
# resolves. Built from ansible.utils.path, not ansible.cli's unfrack_path:
# importing ansible.cli exits under a non-UTF-8 locale, and --help and
# --version must not need it.
_UNFRACK_PATH = functools.partial(unfrackpath, follow=False)


def _add_vault_options(parser, help_text: str) -> None:
    """The vault flags of ansible-vault (add_vault_options), plus -p for pilfer's old flag."""
    parser.add_argument(
        "--vault-id",
        action="append",
        default=[],
        dest="vault_ids",
        metavar="VAULT_ID",
        help="vault identity to use, as for ansible-vault: [label@]FILE or [label@]prompt",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p",
        "--vault-password-file",
        "--vault-pass-file",
        action="append",
        default=[],
        dest="vault_password_files",
        metavar="VAULT_PASSWORD_FILE",
        type=_UNFRACK_PATH,
        help=help_text,
    )
    group.add_argument(
        "-J",
        "--ask-vault-password",
        "--ask-vault-pass",
        action="store_true",
        default=C.DEFAULT_ASK_VAULT_PASS,
        dest="ask_vault_pass",
        help="ask for the vault password",
    )


def _sources(args) -> VaultSources:
    return VaultSources(
        password_files=tuple(args.vault_password_files),
        vault_ids=tuple(args.vault_ids),
        ask=args.ask_vault_pass,
    )


def _add_quiet_option(parser) -> None:
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress nested git repo skip messages during discovery",
    )


_DEFAULT_PASSWORD_HELP = (
    "vault password file or script; repeatable (default: Ansible's config, then common paths)"
)


def _build_argument_parser():
    """Build the pilfer CLI parser (subcommands: open, close, rekey, set)."""
    parser = argparse.ArgumentParser(
        prog="pilfer",
        formatter_class=_HELP_FORMATTER,
        description=(
            "Bulk decrypt Ansible vault files in a project tree for editing, then "
            "re-encrypt when done."
        ),
        epilog=_HELP_EPILOG,
    )

    def _parser_error(message: str) -> None:
        # set takes an optional positional. A token that starts with "-" is
        # reported by argparse as an unrecognized argument, and the message
        # quotes it. That is the secret, on stderr, which is what people paste
        # into tickets. Subparsers hand unrecognized arguments to this, the
        # top-level parser, so set needs no hook of its own.
        argv = getattr(parser, "_pilfer_argv", ())
        if "set" in argv and _hides_unrecognized_set_value(message):
            parser.exit(2, f"{parser.prog}: error: put -- before a value that starts with -\n")
        argparse.ArgumentParser.error(parser, message)

    parser.error = _parser_error  # type: ignore[method-assign]
    parser.add_argument("--version", action="version", version=f"pilfer {__version__}")

    subparsers = parser.add_subparsers(
        dest="action",
        metavar="COMMAND",
        required=True,
        title="commands",
        description="valid commands",
    )

    open_parser = subparsers.add_parser(
        "open",
        formatter_class=_HELP_FORMATTER,
        help="decrypt vault targets for editing",
        description="Decrypt whole-file vault YAML (and optionally inline !vault scalars).",
        epilog=_OPEN_EPILOG,
    )
    _add_vault_options(open_parser, _DEFAULT_PASSWORD_HELP)
    open_parser.add_argument(
        "--include-encrypted-vars",
        action="store_true",
        help="Also decrypt inline !vault / encrypt_string scalars",
    )
    _add_quiet_option(open_parser)

    close_parser = subparsers.add_parser(
        "close",
        formatter_class=_HELP_FORMATTER,
        help="re-encrypt everything this session opened",
        description="Re-encrypt session entries (whole-file and inline).",
        epilog=_CLOSE_EPILOG,
    )
    _add_vault_options(
        close_parser, "vault password file or script; repeatable (the sources open used)"
    )
    close_parser.add_argument(
        "--confirm-delete",
        action="store_true",
        dest="confirm_delete",
        help=(
            "Confirm intentional deletion of opened inline vars (marker and secret line removed)"
        ),
    )

    rekey_parser = subparsers.add_parser(
        "rekey",
        formatter_class=_HELP_FORMATTER,
        help="rotate vault password across the tree",
        description="Re-key whole-file and inline vault targets without an open session.",
        epilog=_REKEY_EPILOG,
    )
    rekey_parser.add_argument(
        "--old-vault-password-file",
        action="append",
        default=[],
        dest="old_vault_password_files",
        metavar="OLD_VAULT_PASSWORD_FILE",
        type=_UNFRACK_PATH,
        help="current vault password file or script; repeatable (default: Ansible's config)",
    )
    rekey_parser.add_argument(
        "--old-vault-id",
        action="append",
        default=[],
        dest="old_vault_ids",
        metavar="OLD_VAULT_ID",
        help="current vault identity, [label@]FILE or [label@]prompt; repeatable",
    )
    new_group = rekey_parser.add_mutually_exclusive_group(required=True)
    new_group.add_argument(
        "--new-vault-password-file",
        type=_UNFRACK_PATH,
        help="new vault password file or script",
    )
    new_group.add_argument(
        "--new-vault-id",
        help="new vault identity, [label@]FILE or [label@]prompt; a label relabels every value",
    )
    rekey_parser.add_argument(
        "--include-encrypted-vars",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include inline !vault spans (default: on; --no-include-encrypted-vars "
        "rekeys whole-file vault YAML only)",
    )
    rekey_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Decrypt-check and print plan without writing",
    )
    rekey_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive REKEY confirmation",
    )
    rekey_parser.add_argument(
        "--rotate-password-file",
        action="store_true",
        help=(
            "After 100%% success, move old password file to *_old and write the "
            "new password at the old path"
        ),
    )
    _add_quiet_option(rekey_parser)

    set_parser = subparsers.add_parser(
        "set",
        formatter_class=_HELP_FORMATTER,
        help="set one key in a whole-file vault without opening it",
        description="Add or replace one top-level string in a closed whole-file vault.",
        epilog=_SET_EPILOG,
    )
    set_parser.add_argument("file", help="Whole-file vault YAML")
    set_parser.add_argument("key", help="Top-level key to add or replace")
    set_parser.add_argument(
        "value",
        nargs="?",
        help="New string value. Omit it to read stdin or get a hidden prompt "
        "(use -- before a value with a leading dash)",
    )
    _add_vault_options(set_parser, _DEFAULT_PASSWORD_HELP)

    return parser


def _interrupted_hint(action: str) -> str:
    """What to do after ctrl-c, for the command that was running.

    Static per command: rekey may or may not have started writing, and a
    re-run is safe either way (files already on the new password are skipped).
    """
    if action in ("open", "close") and _session_is_open():
        return " A session is still open: run 'pilfer close' to finish."
    if action == "rekey":
        return " If rekey had started writing, re-run the same command to resume."
    return ""


def main(argv=None):
    """Main CLI entry point for pilfer"""
    parser = _build_argument_parser()
    parser._pilfer_argv = list(argv) if argv is not None else sys.argv[1:]  # type: ignore[attr-defined]
    args = parser.parse_args(argv)

    try:
        if args.action == "set":
            return _run_set(args)
        with project_session_lock():
            if args.action == "open":
                print("🔓 Searching for and decrypting vault files...")
                opened = open_vault_files(
                    _sources(args),
                    include_encrypted_vars=args.include_encrypted_vars,
                    announce_skips=not args.quiet,
                )
                if opened:
                    # ANSI bold around the next command (TTY-friendly; harmless in pipes).
                    print(
                        "✅ All vault files decrypted. Edit as needed, "
                        "then run '\033[1mpilfer close\033[0m' to re-encrypt."
                    )
            elif args.action == "close":
                print("🔒 Re-encrypting vault files...")
                modified_count = recrypt_vault_files(
                    _sources(args), confirm_delete=args.confirm_delete
                )
                print(
                    f"✅ Vault files re-encrypted. "
                    f"{modified_count} modified files have been updated."
                )
            elif args.action == "rekey":
                print("🔐 Re-keying vault files...")
                new_file = args.new_vault_password_file
                count = rekey_vault_files(
                    VaultSources(
                        password_files=tuple(args.old_vault_password_files),
                        vault_ids=tuple(args.old_vault_ids),
                    ),
                    VaultSources(
                        password_files=(new_file,) if new_file else (),
                        vault_ids=(args.new_vault_id,) if args.new_vault_id else (),
                    ),
                    include_encrypted_vars=args.include_encrypted_vars,
                    dry_run=args.dry_run,
                    yes=args.yes,
                    rotate_password_file=args.rotate_password_file,
                    announce_skips=not args.quiet,
                )
                if not args.dry_run:
                    print(f"✅  Rekeyed {count} file(s).")
    except KeyboardInterrupt:
        # ctrl-c at a prompt, during a slow password script or part way through
        # a write. The finally blocks have already run; what open or close left
        # is kept for the next close, as after any other failure.
        print(f"Interrupted.{_interrupted_hint(args.action)}", file=sys.stderr)
        return 130
    except Exception as exc:
        # PilferError for refusals, OSError and anything else for the rest.
        # Blank line after per-file ⚠️ blocks; keep a plain Error: summary line.
        print(file=sys.stderr)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def _run_set(args) -> int:
    # Imported here: vault_set imports helpers from this module.
    from pilfer.vault_set import read_value, set_keys

    value = args.value
    # Before the password loads: a mistyped path should not cost a prompt or a
    # script run, and should name the vault, not its x.yml.pilfer-lock sibling.
    if not os.path.isfile(args.file):
        raise PilferError(f"Vault file does not exist or is not a regular file: {args.file}")
    # Loaded once: the check and the write both need it, and a password
    # script or prompt should run one time.
    vault = load_vault(_sources(args))
    if value is None:
        # Refuse before asking for the secret, not after someone has pasted it.
        set_keys(args.file, {args.key: "pilfer-set-check-placeholder"}, vault, check_only=True)
        value = read_value(args.key)
    actions = set_keys(args.file, {args.key: value}, vault)
    print(f"{actions[args.key]} {args.key} in {args.file}")
    _warn_unused_sources(vault, args.file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
