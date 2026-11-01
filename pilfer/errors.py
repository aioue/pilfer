# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""PilferError lives here so publish.py can raise it without importing cli.py.

cli.py re-exports it; `from pilfer.cli import PilferError` keeps working.
"""


class PilferError(Exception):
    """Operational failure that should produce a non-zero exit."""
