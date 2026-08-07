#!/usr/bin/env python3
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# heavily borrows from this excellent repo https://github.com/dellis23/ansible-toolkit

# pilfer - decrypt all ansible vault files recursively for search/editing
# pilfer [open|close]

import argparse
import configparser
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

from pilfer import __version__
from pilfer.inline import (
    MARKER_PREFIX,
    decrypt_inline_content,
    find_inline_vault_spans,
    is_whole_file_vault,
    normalize_whole_file_vault,
    recrypt_inline_content,
    unsafe_missing_marker_names,
)

temp_vault_file_list_path = "vaultedFileList.json"
temp_hidden_encrypted_copies_directory_path = ".vault"
SESSION_META_NAME = "session.json"
SESSION_VERSION = 2
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


class PilferError(Exception):
    """Operational failure that should produce a non-zero exit."""


def get_vault_password_file():
    """Get vault password file from ansible.cfg or fall back to default locations"""
    try:
        config = configparser.ConfigParser()
        config.read("ansible.cfg")
        if "defaults" in config and "vault_password_file" in config["defaults"]:
            vault_file = os.path.expanduser(config["defaults"]["vault_password_file"])
            if os.path.exists(vault_file):
                return vault_file
    except Exception:
        pass

    fallback_locations = [
        "../../vault_password_file",
        "~/.ansible-vault/.vault-file",
        ".vault_password",
        "vault_password_file",
    ]

    for location in fallback_locations:
        expanded_location = os.path.expanduser(location)
        if os.path.exists(expanded_location):
            return expanded_location

    raise FileNotFoundError(
        "Could not find vault password file. Please ensure it exists or specify with -p argument."
    )


def _resolve_password_file(vault_password_file_path=None):
    if vault_password_file_path:
        path = os.path.expanduser(vault_password_file_path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Vault password file not found: {path}")
        return path
    return get_vault_password_file()


def _password_fingerprint(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _load_password(vault_password_file_path=None):
    vault_file = _resolve_password_file(vault_password_file_path)
    with open(vault_file, "r") as vault_password_file:
        password = vault_password_file.read().strip()
    return password, vault_file


def _make_vault(password: str, vault_ids=None) -> VaultLib:
    secret = VaultSecret(password.encode("utf-8"))
    secrets = [(DEFAULT_VAULT_ID_MATCH, secret)]
    seen = {DEFAULT_VAULT_ID_MATCH, "default", None, ""}
    for vault_id in vault_ids or []:
        if vault_id not in seen:
            secrets.append((vault_id, secret))
            seen.add(vault_id)
    return VaultLib(secrets)


def _session_is_open() -> bool:
    return Path(temp_vault_file_list_path).is_file()


def _backup_dir_for(vaulted_file_path: str) -> str:
    parts = Path(vaulted_file_path).parts
    if parts and parts[0] == os.sep:
        parts = parts[1:]
    elif parts and len(parts[0]) == 2 and parts[0][1] == ":":
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
    sidecar = _open_sidecar_path(vaulted_file_path)
    with open(sidecar, "w") as f:
        json.dump({"kind": kind, "path": vaulted_file_path}, f)
    _restrict_private(sidecar)


def _remove_open_sidecar(vaulted_file_path: str) -> None:
    sidecar = _open_sidecar_path(vaulted_file_path)
    try:
        if os.path.isfile(sidecar):
            os.remove(sidecar)
    except OSError:
        pass


def _find_orphan_sidecar_files():
    """Leftover *.pilfer-open locks from a deleted session."""
    hits = []
    for file_path in _walk_project_files():
        if file_path.endswith(OPEN_SIDECAR_SUFFIX):
            hits.append(file_path)
    return hits


def _session_meta_path() -> str:
    return os.path.join(temp_hidden_encrypted_copies_directory_path, SESSION_META_NAME)


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
        raise PilferError(
            f"Refusing path outside project directory: {vaulted_file_path}"
        ) from exc
    return resolved


def _is_vault_ciphertext(data: bytes) -> bool:
    return is_whole_file_vault(data)


def _restrict_private(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _normalize_entries(data):
    """Return (entries, password_sha256, version) from session JSON (v1 or v2)."""
    if isinstance(data, list):
        return [{"kind": "file", "path": p} for p in data], None, 1
    if not isinstance(data, dict):
        raise PilferError(
            f"Unrecognized {temp_vault_file_list_path} format; refuse to continue."
        )

    version = int(data.get("version") or 1)
    password_sha256 = data.get("password_sha256")
    if "entries" in data:
        return data["entries"], password_sha256, version
    if "files" in data:
        return [{"kind": "file", "path": p} for p in data["files"]], password_sha256, version
    raise PilferError(
        f"Unrecognized {temp_vault_file_list_path} format; refuse to continue."
    )


def _load_session():
    with open(temp_vault_file_list_path, "r") as vault_list_file:
        data = json.load(vault_list_file)
    return _normalize_entries(data)


def _require_session_password_binding(session_password_fp, password_fp, version):
    """Refuse close when password binding is missing or mismatched."""
    if version >= 2:
        if not session_password_fp:
            raise PilferError(
                "Session is missing password binding (password_sha256). "
                "Refuse to close to avoid re-keying secrets. "
                "Remove vaultedFileList.json / .vault if this is a corrupt session, "
                "or re-open with a current pilfer."
            )
        if session_password_fp != password_fp:
            raise PilferError(
                "Vault password does not match the password used for 'pilfer open'. "
                "Refusing to close (would re-key modified files under a different password). "
                "Use the same -p / ansible.cfg password file as open."
            )
        return

    # Legacy v1 sessions have no fingerprint - refuse to avoid silent re-key.
    raise PilferError(
        "Legacy pilfer session without password binding. "
        "Re-run 'pilfer open' with this pilfer version, then 'pilfer close'."
    )


def _write_session(entries, password_sha256: str) -> None:
    payload = {
        "version": SESSION_VERSION,
        "password_sha256": password_sha256,
        "entries": entries,
    }
    with open(temp_vault_file_list_path, "w") as open_file:
        json.dump(payload, open_file, indent=2)
    _restrict_private(temp_vault_file_list_path)


def _should_skip_by_extension(file_path: str) -> bool:
    """True for known binary / non-text extensions we never treat as vault YAML."""
    _, ext = os.path.splitext(os.path.basename(file_path))
    return ext.lower() in _SKIP_FILE_EXTENSIONS


def _is_nested_git_checkout(path: str) -> bool:
    """True if path is its own git checkout (.git directory or submodule gitfile)."""
    git_meta = os.path.join(path, ".git")
    return os.path.isdir(git_meta) or os.path.isfile(git_meta)


def _classify_file(file_path: str, include_encrypted_vars: bool = False):
    """Return 'file', 'inline', or None.

    Inline encrypt_string (!vault) targets are only returned when
    include_encrypted_vars is True (see --include-encrypted-vars on open).

    Whole-file vaults are detected from a small header read. Full file reads
    happen only when include_encrypted_vars is set and the header is not a
    whole-file vault (needed to find mid-file !vault spans).
    """
    try:
        if os.path.islink(file_path):
            return None
        if file_path.endswith(OPEN_SIDECAR_SUFFIX):
            return None
        if _should_skip_by_extension(file_path):
            return None
        with open(file_path, "rb") as open_file:
            header = open_file.read(_VAULT_HEADER_READ_SIZE)
            if not header:
                return None
            if is_whole_file_vault(header):
                return "file"
            if not include_encrypted_vars:
                return None
            # Inline search requires the rest of the file.
            data = header + open_file.read()
    except (IOError, OSError, PermissionError):
        return None

    if b"$ANSIBLE_VAULT;" in data and find_inline_vault_spans(data):
        return "inline"
    return None


def _walk_project_files():
    """Yield absolute file paths under cwd, applying the same prune rules as open."""
    walk_dir = os.path.abspath(os.getcwd())
    for dirpath, dirnames, filenames in os.walk(walk_dir):
        pruned = []
        for d in dirnames:
            if d in _SKIP_DIR_NAMES:
                continue
            child = os.path.join(dirpath, d)
            if _is_nested_git_checkout(child):
                print(
                    f"⏭️ Skipping nested git repo: {child}"
                    f" (run 'pilfer open' from that directory instead)"
                )
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for name in filenames:
            file_path = os.path.join(dirpath, name)
            if os.path.islink(file_path):
                continue
            if _should_skip_by_extension(file_path):
                continue
            yield file_path


def _find_orphan_marker_files():
    """Files that still contain # pilfer:vault: markers (open session leftover)."""
    marker = MARKER_PREFIX.encode("utf-8")
    hits = []
    for file_path in _walk_project_files():
        try:
            with open(file_path, "rb") as open_file:
                data = open_file.read()
        except (IOError, OSError, PermissionError):
            continue
        if marker in data:
            hits.append(file_path)
    return hits


def _vault_dir_has_artifacts() -> bool:
    root = Path(temp_hidden_encrypted_copies_directory_path)
    if not root.is_dir():
        return False
    try:
        next(root.rglob("*"))
        return True
    except StopIteration:
        return False


def assert_no_orphaned_open_state():
    """Fail closed if a prior open left plaintext markers, sidecars, or .vault.

    Without this, deleting vaultedFileList.json after open leaves secrets in
    plaintext and a subsequent open exits 0 with 'No vault files found'.
    Whole-file opens leave no # pilfer:vault: markers, so *.pilfer-open
    sidecars are required for that case.
    """
    if _session_is_open():
        return

    marker_files = _find_orphan_marker_files()
    sidecar_files = _find_orphan_sidecar_files()
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
        details.append(
            f"leftover {temp_hidden_encrypted_copies_directory_path}/ backups"
        )
    raise PilferError(
        "Orphaned open state detected (no vaultedFileList.json session) but "
        + "; ".join(details)
        + ". Restore vaultedFileList.json from backup if you have it and run "
        "'pilfer close', or manually re-encrypt / restore secrets before opening."
    )


def discover_vaulted_files(include_encrypted_vars: bool = False):
    """Find vault targets without writing a session."""
    found = []
    for file_path in _walk_project_files():
        kind = _classify_file(
            file_path, include_encrypted_vars=include_encrypted_vars
        )
        if kind:
            found.append({"kind": kind, "path": file_path})
    return found


def write_vaulted_file_list(
    include_encrypted_vars: bool = False, password_sha256: str | None = None
):
    """Find vault targets and write the session list.

    By default only whole-file vaults are discovered. Pass
    include_encrypted_vars=True (CLI: --include-encrypted-vars) to also
    open inline !vault / encrypt_string scalars. Close always re-encrypts
    whatever the session recorded - no flag needed.

    password_sha256 should be set by open before decrypt so close never sees
    an unbound v2 session. Discovery-only callers may omit it (decrypt then
    rewrites the session with the fingerprint).
    """
    found = discover_vaulted_files(include_encrypted_vars=include_encrypted_vars)
    _write_session(found, password_sha256=password_sha256 or "")
    return found


def _decrypt_whole_file(vaulted_file_path: str, vault: VaultLib, cwd: Path) -> None:
    _validate_target_path(vaulted_file_path, cwd)

    with open(vaulted_file_path, "rb") as f:
        encrypted_data = f.read()

    # Tolerate BOM / leading whitespace on whole-file vaults (editors).
    encrypted_data = normalize_whole_file_vault(encrypted_data)

    if not _is_vault_ciphertext(encrypted_data):
        raise PilferError(
            "Input is not vault encrypted data "
            "(refusing to overwrite encrypted backup)"
        )

    decrypted_bytes = vault.decrypt(encrypted_data)

    backup_dir = _backup_dir_for(vaulted_file_path)
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)

    encrypted_backup = _encrypted_backup_path(vaulted_file_path)
    with open(encrypted_backup, "wb") as f:
        f.write(encrypted_data)
    _restrict_private(encrypted_backup)

    file_hash = hashlib.sha256(decrypted_bytes).hexdigest()
    hash_path = _hash_backup_path(vaulted_file_path)
    with open(hash_path, "w") as decrypted_vault_file_hash:
        decrypted_vault_file_hash.write(file_hash)
    _restrict_private(hash_path)

    # Sidecar before plaintext so a crash/failure never leaves unmarked plaintext.
    _write_open_sidecar(vaulted_file_path, "file")
    try:
        with open(vaulted_file_path, "wb") as decrypted_vault_file:
            decrypted_vault_file.write(decrypted_bytes)
        _restrict_private(vaulted_file_path)
    except Exception:
        try:
            with open(vaulted_file_path, "wb") as f:
                f.write(encrypted_data)
        finally:
            _remove_open_sidecar(vaulted_file_path)
            for path in (encrypted_backup, hash_path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        raise


def _decrypt_inline_file(vaulted_file_path: str, vault: VaultLib, cwd: Path) -> int:
    """Decrypt inline spans. Returns number of spans opened."""
    _validate_target_path(vaulted_file_path, cwd)

    with open(vaulted_file_path, "rb") as f:
        original = f.read()

    new_content, records = decrypt_inline_content(original, vault)
    if not records:
        raise PilferError(f"No inline vault spans found in {vaulted_file_path}")

    backup_dir = _backup_dir_for(vaulted_file_path)
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)

    # Full original backup for unchanged whole-file restore shortcut.
    encrypted_backup = _encrypted_backup_path(vaulted_file_path)
    with open(encrypted_backup, "wb") as f:
        f.write(original)
    _restrict_private(encrypted_backup)

    file_hash = hashlib.sha256(new_content).hexdigest()
    hash_path = _hash_backup_path(vaulted_file_path)
    with open(hash_path, "w") as f:
        f.write(file_hash)
    _restrict_private(hash_path)

    meta_path = _inline_meta_path(vaulted_file_path)
    with open(meta_path, "w") as f:
        json.dump({"spans": records}, f, indent=2)
    _restrict_private(meta_path)

    _write_open_sidecar(vaulted_file_path, "inline")
    try:
        with open(vaulted_file_path, "wb") as f:
            f.write(new_content)
        _restrict_private(vaulted_file_path)
    except Exception:
        try:
            with open(vaulted_file_path, "wb") as f:
                f.write(original)
        finally:
            _remove_open_sidecar(vaulted_file_path)
            for path in (encrypted_backup, hash_path, meta_path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        raise

    return len(records)


def decrypt_vault_files(vault_password_file_path=None):
    """Decrypt all vault entries listed in the current session.

    Returns the number of successfully decrypted entries.
    Raises PilferError if any entry fails (session list retained for recovery).
    """
    entries, _existing_fp, _version = _load_session()
    password, _vault_file = _load_password(vault_password_file_path)
    password_fp = _password_fingerprint(password)
    vault = _make_vault(password)
    cwd = Path.cwd().resolve()

    os.makedirs(temp_hidden_encrypted_copies_directory_path, mode=0o700, exist_ok=True)
    try:
        os.chmod(temp_hidden_encrypted_copies_directory_path, 0o700)
    except OSError:
        pass

    failed = []
    succeeded = []
    inline_span_total = 0

    for entry in entries:
        path = entry["path"]
        kind = entry.get("kind", "file")
        try:
            if kind == "inline":
                inline_span_total += _decrypt_inline_file(path, vault, cwd)
            else:
                _decrypt_whole_file(path, vault, cwd)
            succeeded.append({"kind": kind, "path": path})
        except Exception as e:
            print(f"Failed to decrypt {path}: {e}")
            failed.append(path)

    _write_session(succeeded, password_sha256=password_fp)

    with open(_session_meta_path(), "w") as meta:
        json.dump({"password_sha256": password_fp}, meta)
    _restrict_private(_session_meta_path())

    if failed:
        if not succeeded:
            # Total failure - clear the empty session so open can be retried.
            try:
                os.remove(temp_vault_file_list_path)
            except OSError:
                pass
            try:
                shutil.rmtree(
                    temp_hidden_encrypted_copies_directory_path, ignore_errors=True
                )
            except OSError:
                pass
        raise PilferError(
            f"Failed to decrypt {len(failed)} of {len(entries)} file(s). "
            f"Session kept for {len(succeeded)} decrypted file(s); "
            "fix errors then run 'pilfer close' or retry carefully."
        )

    return len(succeeded)


def _recrypt_whole_file(vaulted_file_path: str, vault: VaultLib, cwd: Path) -> bool:
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

    with open(hash_path, "r") as f:
        old_hash = f.read().strip()

    with open(vaulted_file_path, "rb") as f:
        new_data_bytes = f.read()
    new_hash = hashlib.sha256(new_data_bytes).hexdigest()

    if old_hash != new_hash:
        if _is_vault_ciphertext(new_data_bytes):
            normalized = normalize_whole_file_vault(new_data_bytes)
            # Interrupted close already wrote ciphertext - treat as done.
            if normalized == normalize_whole_file_vault(old_encrypted_data):
                return False
            try:
                vault.decrypt(normalized)
            except Exception as exc:
                raise PilferError(
                    "File is already vault-encrypted but not with the session password; "
                    "refusing to continue"
                ) from exc
            print(f"Already re-encrypted (retrying close): {vaulted_file_path}")
            return True
        new_encrypted_data = vault.encrypt(new_data_bytes)
        print(f"Re-encrypting modified file: {vaulted_file_path}")
        modified = True
    else:
        new_encrypted_data = old_encrypted_data
        modified = False

    with open(vaulted_file_path, "wb") as f:
        f.write(new_encrypted_data)

    return modified


def _recrypt_inline_file(
    vaulted_file_path: str, password: str, cwd: Path
) -> bool:
    """Re-encrypt inline spans. Returns True if any span was modified/removed.

    Idempotent if a prior close already restored/re-encrypted the file (no markers).
    """
    from pilfer.inline import MARKER_RE

    _validate_target_path(vaulted_file_path, cwd)

    encrypted_backup = _encrypted_backup_path(vaulted_file_path)
    hash_path = _hash_backup_path(vaulted_file_path)
    meta_path = _inline_meta_path(vaulted_file_path)

    with open(hash_path, "r") as f:
        old_hash = f.read().strip()

    with open(vaulted_file_path, "rb") as f:
        current = f.read()
    new_hash = hashlib.sha256(current).hexdigest()

    if old_hash == new_hash:
        with open(encrypted_backup, "rb") as f:
            original = f.read()
        with open(vaulted_file_path, "wb") as f:
            f.write(original)
        return False

    # Interrupted close: working copy already matches backup ciphertext.
    with open(encrypted_backup, "rb") as f:
        backup = f.read()
    if current == backup:
        return False

    # Interrupted close after successful recrypt: no markers left. Only treat as
    # done when none of the opened secrets still appear as plaintext and any
    # remaining keys hold decryptable !vault ciphertext (not garbage tags).
    if MARKER_RE.search(current) is None:
        with open(meta_path, "r") as f:
            meta = json.load(f)
        spans = meta.get("spans", [])
        if not spans:
            raise PilferError(
                "Inline session metadata has no spans; refusing to treat file as "
                "already re-encrypted (would clear session while plaintext may remain)."
            )
        vault_ids = [s.get("vault_id") for s in spans]
        check_vault = _make_vault(password, vault_ids)
        unsafe = unsafe_missing_marker_names(current, spans, check_vault)
        if unsafe:
            raise PilferError(
                "Missing # pilfer:vault markers but opened secrets are still "
                f"present (plaintext or non-vault key) for: {', '.join(unsafe)}. "
                "Restore the markers on the secrets (or delete the secret keys/"
                "values entirely) before close."
            )
        print(f"Already re-encrypted inline file (retrying close): {vaulted_file_path}")
        return True

    with open(meta_path, "r") as f:
        meta = json.load(f)
    vault_ids = [s.get("vault_id") for s in meta.get("spans", [])]
    vault = _make_vault(password, vault_ids)
    result = recrypt_inline_content(current, meta["spans"], vault)
    with open(vaulted_file_path, "wb") as f:
        f.write(result.content)

    if result.removed_vars:
        print(
            f"🔍 Detected removal of {len(result.removed_vars)} encrypted vars:"
        )
        for name in result.removed_vars:
            print(f"  - {name}")

    if result.modified_count > len(result.removed_vars):
        changed = result.modified_count - len(result.removed_vars)
        print(
            f"Re-encrypting modified inline vault string(s) in: {vaulted_file_path}"
            f" ({changed} changed)"
        )

    return result.modified_count > 0


def _cleanup_entry_backups(vaulted_file_path: str) -> None:
    encrypted_backup = _encrypted_backup_path(vaulted_file_path)
    hash_path = _hash_backup_path(vaulted_file_path)
    meta_path = _inline_meta_path(vaulted_file_path)
    try:
        if os.path.isfile(encrypted_backup):
            os.remove(encrypted_backup)
        if os.path.isfile(hash_path):
            os.remove(hash_path)
        if os.path.isfile(meta_path):
            os.remove(meta_path)
        os.removedirs(_backup_dir_for(vaulted_file_path))
    except Exception as e:
        print(f"Warning: Failed to clean temp files for {vaulted_file_path}: {e}")
    _remove_open_sidecar(vaulted_file_path)


def recrypt_vault_files(vault_password_file_path=None):
    """Re-encrypt vault entries. Only clears the session if every file succeeds.

    Successfully closed entries are removed from the session immediately so a
    later failure leaves a retryable list of remaining plaintext files only.

    Returns the number of modified files (whole-file or inline with changes).
    Raises PilferError on any failure without deleting remaining session artifacts.
    """
    if not _session_is_open():
        raise PilferError("No vault file list found. Run 'pilfer open' first.")

    entries, session_password_fp, version = _load_session()
    password, _vault_file = _load_password(vault_password_file_path)
    password_fp = _password_fingerprint(password)
    _require_session_password_binding(session_password_fp, password_fp, version)

    vault = _make_vault(password)
    cwd = Path.cwd().resolve()

    modified_count = 0
    failed = []
    remaining = list(entries)

    for entry in entries:
        path = entry["path"]
        kind = entry.get("kind", "file")
        try:
            if kind == "inline":
                if _recrypt_inline_file(path, password, cwd):
                    modified_count += 1
            else:
                if _recrypt_whole_file(path, vault, cwd):
                    modified_count += 1
            # Persist session removal before deleting backups so a crash mid-close
            # leaves a retryable list (already-closed files are not re-listed).
            remaining = [e for e in remaining if e["path"] != path]
            _write_session(remaining, password_sha256=password_fp)
            _cleanup_entry_backups(path)
        except Exception as e:
            print(f"Failed to process {path}: {e}")
            failed.append(path)
            _write_session(remaining, password_sha256=password_fp)
            # Continue attempting other files; all failures reported at end.

    if failed:
        raise PilferError(
            f"Failed to re-encrypt {len(failed)} file(s); session NOT cleared. "
            "Plaintext may remain for failed paths - fix and re-run 'pilfer close'."
        )

    try:
        meta = _session_meta_path()
        if os.path.isfile(meta):
            os.remove(meta)
    except OSError:
        pass

    try:
        os.removedirs(temp_hidden_encrypted_copies_directory_path)
    except Exception:
        shutil.rmtree(temp_hidden_encrypted_copies_directory_path, ignore_errors=True)

    try:
        os.remove(temp_vault_file_list_path)
    except OSError:
        pass

    return modified_count


def main(argv=None):
    """Main CLI entry point for pilfer"""
    parser = argparse.ArgumentParser(
        prog="pilfer",
        description=(
            "Decrypt all ansible vault files in a project recursively for "
            "search/editing, then re-encrypt when done. Optionally also open "
            "inline encrypt_string (!vault) scalars."
        ),
        epilog="""
Examples:
  pilfer open                           # Whole-file vaults only
  pilfer open --include-encrypted-vars  # Also decrypt inline !vault strings
  pilfer open -p ~/.vault-pass
  pilfer close                          # Re-encrypt everything the session opened

Inline !vault strings (with --include-encrypted-vars) are replaced with quoted
plaintext plus a `# pilfer:vault:N` marker - leave the marker until close.
Close always re-encrypts every entry recorded in the session (no flag needed).

Never commit while a session is open. Add vaultedFileList.json and .vault/ to
your project's .gitignore. Check the exit code of 'pilfer close' in scripts.
        """,
    )
    parser.add_argument(
        "action",
        choices=["open", "close"],
        help="'open' to decrypt vault files, 'close' to re-encrypt modified files",
    )
    parser.add_argument(
        "-p",
        "--vault-password-file",
        type=str,
        help="Path to vault password file",
    )
    parser.add_argument(
        "--include-encrypted-vars",
        action="store_true",
        help=(
            "On open: also decrypt inline !vault / encrypt_string scalars. "
            "Ignored on close (close always re-encrypts session entries)."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"pilfer {__version__}"
    )
    args = parser.parse_args(argv)

    try:
        if args.action == "open":
            print("🔓 Searching for and decrypting vault files...")
            if _session_is_open():
                raise PilferError(
                    f"Session already open ({temp_vault_file_list_path} exists). "
                    "Run 'pilfer close' first. Re-running open would destroy "
                    "encrypted backups and can leave secrets in plaintext."
                )

            # Fail closed on leftover plaintext markers / .vault without a session.
            assert_no_orphaned_open_state()

            found = discover_vaulted_files(
                include_encrypted_vars=args.include_encrypted_vars
            )
            if not found:
                print("No vault files found in current directory tree.")
                return 0

            password, _vault_file = _load_password(args.vault_password_file)
            password_fp = _password_fingerprint(password)
            _write_session(found, password_sha256=password_fp)

            whole = sum(1 for e in found if e["kind"] == "file")
            inline = sum(1 for e in found if e["kind"] == "inline")
            print(
                f"ℹ️ Found {len(found)} vault target(s) "
                f"({whole} whole-file, {inline} with inline encrypt_string)"
            )
            if not args.include_encrypted_vars:
                print(
                    "(inline !vault strings skipped - pass "
                    "--include-encrypted-vars to open them)"
                )
            decrypt_vault_files(args.vault_password_file)
            print(
                "✅ All vault files decrypted. Edit as needed, "
                "then run 'pilfer close' to re-encrypt."
            )
            return 0

        if args.action == "close":
            if args.include_encrypted_vars:
                print(
                    "Note: --include-encrypted-vars is only used on open; "
                    "close always re-encrypts session entries."
                )
            print("🔒 Re-encrypting vault files...")
            if not _session_is_open():
                print("No vault file list found. Run 'pilfer open' first.")
                return 1
            modified_count = recrypt_vault_files(args.vault_password_file)
            print(
                f"✅ Vault files re-encrypted. "
                f"{modified_count} modified files have been updated."
            )
            return 0

    except PilferError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
