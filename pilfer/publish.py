# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared publish helpers for open, close, rekey, and set.

os.replace swaps in a new inode, so a lock on the vault file does not cover
the file another pilfer process is about to publish. The lock lives on a
sibling that is never replaced. Owner, group, and ACLs have to be copied
onto that new inode or a mode such as 0640 starts applying to the editor's
primary group instead of the vault's group.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Empty sibling of the vault. Scan skips it. Not the rekey temp prefix:
# open deletes extensionless .pilfer-rekey-* leftovers, which would drop a
# lock another process is waiting on.
LOCK_SUFFIX = ".pilfer-lock"

# macOS acl_get_fd() is unsupported. acl_*_fd_np takes this type.
_ACL_TYPE_EXTENDED = 0x00000100

_ACL_MISSING = object()
_acl_lib: ctypes.CDLL | object | None = _ACL_MISSING


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
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def project_session_lock() -> Iterator[None]:
    """One open, close, or rekey at a time in this directory.

    The per-file lock does not cover vaultedFileList.json or .vault. Two
    opens can both pass the session check. The one whose decrypt then fails
    because the other already published plaintext deletes .vault, which is
    the only remaining ciphertext.
    """
    with vault_file_lock(Path.cwd() / ".pilfer-session"):
        yield


def _load_acl() -> ctypes.CDLL | None:
    """libc on macOS, libacl on Linux. None when this host has no ACL calls."""
    global _acl_lib
    if _acl_lib is not _ACL_MISSING:
        return _acl_lib  # type: ignore[return-value]
    names: list[str] = []
    libc = ctypes.util.find_library("c")
    if libc:
        names.append(libc)
    names.extend(["libacl.so.1", "libacl.so"])
    found: ctypes.CDLL | None = None
    for name in names:
        try:
            lib = ctypes.CDLL(name, use_errno=True)
            lib.acl_get_fd.argtypes = [ctypes.c_int]
            lib.acl_get_fd.restype = ctypes.c_void_p
            lib.acl_set_fd.argtypes = [ctypes.c_int, ctypes.c_void_p]
            lib.acl_set_fd.restype = ctypes.c_int
            lib.acl_free.argtypes = [ctypes.c_void_p]
            lib.acl_free.restype = ctypes.c_int
        except (OSError, AttributeError):
            continue
        try:
            get_np = lib.acl_get_fd_np
            set_np = lib.acl_set_fd_np
        except AttributeError:
            get_np = None
            set_np = None
        else:
            get_np.argtypes = [ctypes.c_int, ctypes.c_int]
            get_np.restype = ctypes.c_void_p
            set_np.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
            set_np.restype = ctypes.c_int
        lib._pilfer_get_np = get_np  # type: ignore[attr-defined]
        lib._pilfer_set_np = set_np  # type: ignore[attr-defined]
        found = lib
        break
    _acl_lib = found
    return found


def copy_owner_group_and_acls(source: Path, dest_fd: int, mode: int) -> None:
    """Give a new inode the source file's uid, gid, mode, and ACLs.

    Mode is applied before ACLs. On macOS, chmod after an ACL is set can
    drop the ACL. Raises OSError when ownership or mode cannot be copied,
    or when an ACL is present and cannot be copied. The caller must not
    publish: a 0640 temp owned by the editor's primary group is readable
    by a wider set of accounts than the vault was.
    """
    st = source.stat()
    os.fchown(dest_fd, st.st_uid, st.st_gid)
    os.fchmod(dest_fd, mode)
    lib = _load_acl()
    if lib is None:
        return
    src_fd = os.open(source, os.O_RDONLY)
    try:
        # The fd is open, so a NULL ACL means this file has no entries.
        # macOS acl_get_fd() returns that with errno ENOENT; it is not a
        # missing path.
        ctypes.set_errno(0)
        get_np = lib._pilfer_get_np  # type: ignore[attr-defined]
        set_np = lib._pilfer_set_np  # type: ignore[attr-defined]
        if get_np is not None and set_np is not None:
            acl = get_np(src_fd, _ACL_TYPE_EXTENDED)
        else:
            acl = lib.acl_get_fd(src_fd)
            set_np = lib.acl_set_fd
        if not acl:
            # macOS: no ACL is NULL and errno ENOENT. Any other errno is a
            # failed read. Publishing would drop an ACL the mode bits do not show.
            err = ctypes.get_errno()
            if err in (0, errno.ENOENT):
                return
            raise OSError(err, os.strerror(err) or "acl_get failed", str(source))
        try:
            rc = (
                set_np(dest_fd, acl, _ACL_TYPE_EXTENDED)
                if get_np is not None
                else set_np(dest_fd, acl)
            )
            if rc != 0:
                err = ctypes.get_errno() or errno.EIO
                raise OSError(err, os.strerror(err), str(source))
        finally:
            lib.acl_free(acl)
    finally:
        os.close(src_fd)
