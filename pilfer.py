#!/usr/bin/env python3
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Borrows from this excellent, now unmaintained, repo https://github.com/dellis23/ansible-toolkit

"""
Pilfer - Decrypt all ansible vault files in a project recursively for search/editing

Thin entry script that delegates to the packaged implementation (pilfer.cli).

Usage (from a clone of this repository):
    python pilfer.py [open|close] [-p VAULT_PASSWORD_FILE]

For installation (recommended):
    pipx install pilfer
"""

import sys

# Keep a literal assignment so release CI can triangulate versions across
# pyproject.toml, pilfer/__init__.py, and this file.
__version__ = "2.24.0"

from pilfer.cli import main

if __name__ == "__main__":
    sys.exit(main())
