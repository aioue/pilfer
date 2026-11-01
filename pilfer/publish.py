# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared publish helpers for open, close, rekey, and set.

Every file pilfer writes goes through write_atomic: a same-directory temp,
fsync, an optional compare against the bytes the edit was based on, then
os.replace and a directory fsync. A crash leaves either the old file or the
new one, never a truncated one.

os.replace swaps in a new inode, so a lock on the vault file does not cover
the file another pilfer process is about to publish. The lock lives on a
sibling that is never replaced.
"""

from __future__ import annotations

import errno
import fcntl
import functools
import os
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from pilfer.errors import PilferError

# Empty sibling of the vault. Scan skips it. Not the temp prefix:
# open deletes extensionless .pilfer-rekey-* leftovers, which would drop a
# lock another process is waiting on.
LOCK_SUFFIX = ".pilfer-lock"
# Prefix of every write_atomic temp. The name predates set and close using it;
# scan and stale-temp cleanup match it, and leftovers from older releases have it.
TEMP_PREFIX = ".pilfer-rekey-"
# Session files, backups, sidecars, and opened plaintext.
PRIVATE_MODE = 0o600


def write_atomic(
    path: str | os.PathLike,
    data: bytes,
    *,
    mode: int = PRIVATE_MODE,
    gid: int | None = None,
    expected: bytes | None = None,
    publish: bool = True,
    action: str = "the edit",
) -> None:
    """Replace path with data, or leave it exactly as it was.

    mode and gid are set on the temp before any data is written, so the bytes
    never sit in a file with looser permissions. A vault keeps its own mode and
    group (pass them from os.stat); everything else is private.

    expected: the bytes this edit was based on. If the file no longer holds
    them, nothing is written. That catches an editor or another tool saving in
    between; pilfer processes also exclude each other with vault_file_lock.

    publish=False runs every step except the rename, then removes the temp:
    set's check_only uses it to report a read-only directory or a full disk
    before the caller does something it cannot undo. A mode or os.access check
    would miss ACLs, read-only mounts and sandbox denials. Not covered: a
    sticky directory where the vault belongs to another user, which refuses
    only the rename itself.
    """
    path = os.fspath(path)
    if os.path.islink(path):
        # open('wb') would follow the link; os.replace would swap the link
        # itself. Both write somewhere other than the file pilfer means.
        raise PilferError(f"Refusing to operate on symlink (write would follow it): {path}")
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=TEMP_PREFIX, dir=directory)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as handle:
            try:
                os.fchmod(handle.fileno(), mode)
            except OSError:
                pass  # mkstemp already made it 0600, the tighter choice
            if gid is not None and gid != os.fstat(handle.fileno()).st_gid:
                try:
                    os.fchown(handle.fileno(), -1, gid)
                except OSError:
                    # Only a member of the group (or root) can set it. The file
                    # holds ciphertext, so the editor's group is an acceptable
                    # fallback; refusing would block the edit for no safety gain.
                    pass
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if expected is not None and (os.path.islink(path) or Path(path).read_bytes() != expected):
            raise PilferError(f"{path} changed during {action}; nothing written. Retry")
        if publish:
            os.replace(tmp, path)
            replaced = True
            _fsync_directory(directory)
    finally:
        # BaseException too: KeyboardInterrupt must not leave the temp behind,
        # and for open the temp holds plaintext.
        if not replaced:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def vault_mode_and_group(path: str | os.PathLike) -> dict:
    """The mode and group a vault should keep when pilfer rewrites it."""
    st = os.stat(path)
    return {"mode": stat.S_IMODE(st.st_mode), "gid": st.st_gid}


def publish_vault(
    path: str | os.PathLike,
    ciphertext: bytes,
    *,
    expected: bytes,
    action: str,
    restore: dict | None = None,
    publish: bool = True,
) -> None:
    """Write ciphertext to a vault path, keeping the vault's mode and group.

    restore: the mode and group to put back. close passes the ones recorded at
    open, because open replaced the file with 0600 plaintext. rekey and set
    leave it out and the file's own are read. Sessions opened by pilfer < 2.31
    recorded neither; those files stay 0600.
    """
    restore = restore if restore is not None else vault_mode_and_group(path)
    write_atomic(
        path,
        ciphertext,
        mode=restore.get("mode", PRIVATE_MODE),
        gid=restore.get("gid"),
        expected=expected,
        publish=publish,
        action=action,
    )


def _fsync_directory(directory: str) -> None:
    """Make the rename durable.

    Without it a power cut can undo the rename after later steps (deleting the
    .vault backup and the sidecar on close) have landed, which would bring
    plaintext back with nothing marking it.
    """
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


@contextmanager
def vault_file_lock(path: str | os.PathLike) -> Iterator[None]:
    """Block other pilfer publishes of this path until the with-block ends.

    flock is on a sibling, held from the first read through os.replace.
    Two threads in one process do not exclude each other: flock is per
    process. pilfer runs one publish at a time in each process.
    """
    path = Path(path)
    lock_path = path.parent / f"{path.name}{LOCK_SUFFIX}"
    # O_NOFOLLOW: a planted sibling symlink must not be chmod'd or created through.
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError(exc.errno, f"refusing symlink lock file {lock_path}") from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            # A FIFO or device opened here is not ours to chmod.
            raise OSError(errno.EINVAL, f"pilfer lock is not a regular file: {lock_path}")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def locked_by_path(func: Callable) -> Callable:
    """Run func(path, ...) holding vault_file_lock(path), from its first read to its replace."""

    @functools.wraps(func)
    def wrapper(path, *args, **kwargs):
        with vault_file_lock(path):
            return func(path, *args, **kwargs)

    return wrapper


@contextmanager
def project_session_lock() -> Iterator[None]:
    """One open, close, or rekey at a time in this directory.

    The per-file lock does not cover vaultedFileList.json or .vault. Without
    this, two opens can both pass the session check. The one that finds every
    file already decrypted clears the session list, or rewrites it, and the
    other open's plaintext is left with no session to close it.
    """
    with vault_file_lock(Path.cwd() / ".pilfer-session"):
        yield
