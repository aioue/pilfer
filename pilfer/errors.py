# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""PilferError and the terminal-safe text helpers live here so publish.py can use
them without importing cli.py.

cli.py re-exports them; `from pilfer.cli import PilferError, safe_text` keeps working.
"""


class PilferError(Exception):
    """Operational failure that should produce a non-zero exit."""


def safe_text(text: str) -> str:
    """Escape characters that are not printable so a file or key name cannot drive the terminal.

    str.isprintable covers C0 and C1 controls, bidi overrides, U+2028, zero-width
    characters and lone surrogates. Ordinary non-ASCII letters stay as they are.
    Escaping is idempotent: a backslash is left alone, so escaping an already
    escaped string changes nothing and a printed key path stays pasteable into
    `update`. The cost is that a literal `\\x1b` in a name prints the same as a
    real ESC; that is accepted because escaped output is for reading, and doubling
    backslashes made every Windows-style or regex-like name unreadable.
    """
    return _escape(text, keep="")


def safe_multiline(text: str) -> str:
    """safe_text that keeps newlines, for a message that already spans lines."""
    return _escape(text, keep="\n")


def _escape(text: str, keep: str) -> str:
    return "".join(
        char
        if char in keep
        else char
        if char.isprintable()
        else char.encode("unicode_escape").decode("ascii")
        for char in text
    )
