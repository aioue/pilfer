# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pilfer - Bulk De/recrypt all ansible vault files in a project recursively for search/editing.

This package provides a command-line tool for decrypting all Ansible vault files
in a project recursively for search/editing, then re-encrypting them when done.

Borrows from the excellent, but no longer supported Ansible Toolkit
(https://github.com/dellis23/ansible-toolkit)
"""

__version__ = "3.1.0"
__author__ = "Tom Paine"
__email__ = "github@aioue.net"
__description__ = (
    "Decrypt all ansible vault files in a project recursively for "
    "search/editing, then re-encrypt when done."
)

# ansible.constants creates ~/.ansible/tmp on import and raises AnsibleError
# when HOME is read-only, which broke every command, even --version. Import it
# here, first, and only on that failure point ANSIBLE_LOCAL_TEMP at a fresh
# private directory (mkdtemp: unpredictable name, mode 0700). A location the
# user already chose (ANSIBLE_LOCAL_TEMP in the environment) is never replaced:
# its failure is theirs to fix. An ansible.cfg local_tmp is never overridden in
# the normal case because nothing is exported unless the import fails.
import atexit as _atexit
import importlib as _importlib
import os as _os
import shutil as _shutil
import sys as _sys
import tempfile as _tempfile

from ansible.errors import AnsibleError as _AnsibleError


def _import_constants() -> None:
    try:
        _importlib.import_module("ansible.constants")
        return
    except _AnsibleError:
        if "ANSIBLE_LOCAL_TEMP" in _os.environ:
            raise
    fallback = _tempfile.mkdtemp(prefix="pilfer-")
    _os.environ["ANSIBLE_LOCAL_TEMP"] = fallback
    try:
        _importlib.import_module("ansible.constants")
    except BaseException:
        # Do not leave the directory or the variable behind for a failed retry.
        del _os.environ["ANSIBLE_LOCAL_TEMP"]
        _shutil.rmtree(fallback, ignore_errors=True)
        raise
    # Remove it when pilfer exits, so a run leaves nothing behind.
    _atexit.register(_shutil.rmtree, fallback, ignore_errors=True)


try:
    _import_constants()
except _AnsibleError as _exc:
    # A clean line, not a traceback: the cause is the user's environment.
    print(f"pilfer: {_exc}", file=_sys.stderr)
    raise SystemExit(2) from None
