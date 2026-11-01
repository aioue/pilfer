# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pilfer - Bulk De/recrypt all ansible vault files in a project recursively for search/editing.

This package provides a command-line tool for decrypting all Ansible vault files
in a project recursively for search/editing, then re-encrypting them when done.

Borrows from the excellent, but no longer supported Ansible Toolkit
(https://github.com/dellis23/ansible-toolkit)
"""

__version__ = "2.30.0"
__author__ = "Tom Paine"
__email__ = "github@aioue.net"
__description__ = (
    "Decrypt all ansible vault files in a project recursively for "
    "search/editing, then re-encrypt when done."
)
