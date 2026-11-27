# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Key paths in Jinja syntax: `aws.prod.secret_key`, `users[0].password`, `aws['a.b']`.

A path is a list of segments: a str for a mapping key, an int for a list index.
Top-level variable names are identifiers, so the first segment never needs
quoting to hold a dot. Anything else (a dot, a dash, a space) is written as a
quoted subscript, which is also what render_key_path prints, so a path that
find-keys shows can be pasted into update or set.

Error messages never quote the text they reject: the key slot is where a
pasted secret tends to land.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass

import yaml

from pilfer.errors import PilferError

IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INDEX_RE = re.compile(r"\[\s*(\d+)\s*\]")

PathSegment = str | int

# The usual cause is a dash or dot inside a name (`my-key`, `a.b` meaning one key).
# Brackets reach an existing or nested key; a new top-level key must be an
# identifier (set refuses to create a bracketed one), so the hint says both.
_BAD_PATH = (
    "refusing key; not a valid key path; write an existing or nested key whose name has "
    "dashes or dots as ['my-key']; a new top-level key must be a plain identifier"
)


def parse_key_path(text: str) -> list[PathSegment]:
    """Parse a Jinja-style key path. Raises PilferError without quoting the text."""
    if not isinstance(text, str):
        raise PilferError("refusing key; not a valid key path")
    path: list[PathSegment] = []
    pos = 0
    length = len(text)
    first = IDENTIFIER_RE.match(text)
    if first:
        path.append(first.group(0))
        pos = first.end()
    elif not text.startswith("["):
        # (A leading subscript names a top-level key that is not an identifier,
        # as find-keys prints one. Parsed here; set refuses to create it.)
        raise PilferError("refusing key; use a YAML identifier or a path such as a.b[0]['c']")
    while pos < length:
        char = text[pos]
        if char == ".":
            match = IDENTIFIER_RE.match(text, pos + 1)
            if not match:
                raise PilferError("refusing key; a name must follow '.'")
            path.append(match.group(0))
            pos = match.end()
        elif char == "[":
            index = _INDEX_RE.match(text, pos)
            if index:
                path.append(int(index.group(1)))
                pos = index.end()
                continue
            name, pos = _read_quoted(text, pos)
            path.append(name)
        else:
            raise PilferError(_BAD_PATH)
    if not path:
        raise PilferError(_BAD_PATH)
    if isinstance(path[0], int):
        raise PilferError("refusing key; a path starts with a name")
    return path


def _read_quoted(text: str, pos: int) -> tuple[str, int]:
    """Read `['name']` or `["name"]` starting at the `[`. Backslash escapes the quote and itself."""
    bad = PilferError("refusing key; unterminated or malformed ['name']")
    match = re.compile(r"\[\s*(['\"])").match(text, pos)
    if not match:
        raise bad
    quote = match.group(1)
    pos = match.end()
    chars = []
    while pos < len(text):
        char = text[pos]
        if char == "\\" and pos + 1 < len(text):
            chars.append(text[pos + 1])
            pos += 2
        elif char == quote:
            close = re.compile(r"\s*\]").match(text, pos + 1)
            if not close:
                raise bad
            # An empty name is allowed: render_key_path prints an empty key as ['']
            # and must read back.
            return "".join(chars), close.end()
        else:
            chars.append(char)
            pos += 1
    raise bad


def render_key_path(path: list[PathSegment]) -> str:
    """The Jinja form of a path; parse_key_path reads it back."""
    out = []
    for position, segment in enumerate(path):
        if isinstance(segment, int):
            out.append(f"[{segment}]")
        elif IDENTIFIER_RE.fullmatch(segment):
            out.append(segment if position == 0 else f".{segment}")
        else:
            escaped = segment.replace("\\", "\\\\").replace("'", "\\'")
            out.append(f"['{escaped}']")
    return "".join(out)


@dataclass
class KeyNode:
    """One mapping key in a composed YAML document, with its value node."""

    path: list[PathSegment]
    key: str
    key_node: yaml.Node
    value_node: yaml.Node


_MERGE_TAG = "tag:yaml.org,2002:merge"


def walk_keys(root: yaml.Node | None, path: list[PathSegment] | None = None) -> Iterator[KeyNode]:
    """Every mapping key under root, with its path. Nothing is constructed, so no value is read.

    Non-scalar keys and `<<` merge keys are skipped: a key a merge supplies is
    listed where its anchor defines it, not again under each mapping that merges
    it. Keys are compared by text, so `yes` and `true` are two names here although
    YAML loads them as one key.

    An alias reaches the anchor's node again. A node is walked once, under the
    first path that reaches it: that cuts recursive anchors and stops an alias
    bomb (a chain of anchors that each list the previous one twice) from being
    walked 2**n times.
    """
    seen: set[int] = set()

    def visit(node, here):
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode) and key.tag != _MERGE_TAG:
                    child = [*here, key.value]
                    yield KeyNode(child, key.value, key, value)
                    yield from visit(value, child)
        elif isinstance(node, yaml.SequenceNode):
            for index, item in enumerate(node.value):
                yield from visit(item, [*here, index])

    yield from visit(root, path or [])
