# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""In-place handling of ansible-vault encrypt_string (!vault) blobs."""

from __future__ import annotations

import base64
import bisect
import hashlib
import itertools
import json
import re
from dataclasses import dataclass, field

import yaml
from ansible.parsing.vault import VaultLib

# Marker comment left beside a decrypted value so close can find spans after edits.
# It is a YAML comment: close reads the value itself with the YAML parser.
MARKER_PREFIX = "# pilfer:vault:"
# Inline session metadata format. 2: values are rendered and read back as YAML.
# Close refuses metadata without it: an older pilfer rendered some secrets in a
# form YAML reads differently, and guessing would re-encrypt the wrong value.
INLINE_FORMAT = 2
MARKER_RE = re.compile(re.escape(MARKER_PREFIX.encode("utf-8")) + rb"(?P<id>\d+)[ \t]*(?=\r?\n|\Z)")
_MARKER_TEXT_RE = re.compile(re.escape(MARKER_PREFIX) + r"(?P<id>\d+)[ \t]*(?=\r?\n|\Z)")

_HEX_LINE = re.compile(rb"^[ \t]*[0-9a-fA-F]+\s*$")
# Only plain literal block style for now (!vault |). Other styles are skipped.
_VAULT_TAG_LINE = re.compile(rb"^(?P<prefix>[ \t]*[^:\n#][^:\n]*:\s*)!vault\s*\|\s*\r?\n$")

UTF8_BOM = b"\xef\xbb\xbf"
VAULT_HEADER_PREFIX = b"$ANSIBLE_VAULT;"
# ansible-vault encrypt_string indents the !vault body by ten spaces.
DEFAULT_BODY_INDENT = b"          "


class VaultLabelError(ValueError):
    """The vault-id label cannot be written back.

    Ansible's is_encrypted() rejects any non-ASCII byte in the blob, so a
    UTF-8 label (or a U+FFFD substituted for one) becomes a file Ansible
    will not decrypt. Callers leave the original ciphertext in place.
    """


def strip_leading_vault_noise(data: bytes) -> bytes:
    """Remove UTF-8 BOM and leading whitespace so vault magic can be detected."""
    data = data.removeprefix(UTF8_BOM)
    return data.lstrip(b" \t\r\n")


def is_whole_file_vault(data: bytes) -> bool:
    """True if data is (or starts as) an Ansible whole-file vault ciphertext."""
    return strip_leading_vault_noise(data).startswith(VAULT_HEADER_PREFIX)


def normalize_whole_file_vault(data: bytes) -> bytes:
    """Return ciphertext VaultLib accepts if this is a whole-file vault."""
    stripped = strip_leading_vault_noise(data)
    if stripped.startswith(VAULT_HEADER_PREFIX):
        return stripped
    return data


@dataclass
class InlineSpan:
    """One inline vault ciphertext region inside a plaintext file."""

    span_id: int
    start: int
    end: int
    encrypted: bytes
    ciphertext: bytes
    line_prefix: bytes
    body_indent: bytes
    vault_id: str | None = None


@dataclass
class RecryptInlineResult:
    content: bytes
    modified_count: int
    removed_vars: list[str] = field(default_factory=list)


class OpenedFileError(ValueError):
    """The opened file cannot be read back as YAML. Messages never quote its text."""


@dataclass
class MarkedValue:
    """A `key: value  # pilfer:vault:N` pair as the YAML parser reads it."""

    span_id: int
    key_text: str
    value: bytes
    start: int  # byte offset of the key's line
    end: int  # byte offset just past the value's last line


class InlineCloseRefusal(Exception):
    """Structured inline close failure for formatted CLI output."""


@dataclass
class MarkerMissingSecretPresent(InlineCloseRefusal):
    """Opened marker gone but the secret is still present in the file."""

    var_name: str
    span_id: int


@dataclass
class SecretLineDeleted(InlineCloseRefusal):
    """Opened secret line appears intentionally deleted."""

    var_name: str
    span_id: int


def _line_start(content: bytes, index: int) -> int:
    nl = content.rfind(b"\n", 0, index)
    return 0 if nl < 0 else nl + 1


def _line_end(content: bytes, index: int) -> int:
    nl = content.find(b"\n", index)
    return len(content) if nl < 0 else nl + 1


def var_name_from_prefix(line_prefix: str) -> str:
    """Extract YAML key name from a stored line prefix like '  db_password: '."""
    return line_prefix.rstrip().removesuffix(":").strip()


def normalize_vault_ciphertext(indented_block: bytes) -> bytes:
    """Strip per-line indentation so VaultLib.decrypt accepts the blob."""
    lines = []
    for raw in indented_block.splitlines():
        stripped = raw.lstrip(b" \t")
        if stripped:
            lines.append(stripped)
    return b"\n".join(lines) + b"\n"


def _vault_id_from_ciphertext(ciphertext: bytes) -> str | None:
    """Parse vault-id from `$ANSIBLE_VAULT;1.2;AES256;prod` headers (if present)."""
    first = ciphertext.splitlines()[0] if ciphertext else b""
    parts = first.split(b";")
    # $ANSIBLE_VAULT;1.2;AES256;vault_id
    if len(parts) >= 4 and parts[0] == b"$ANSIBLE_VAULT":
        try:
            vault_id = parts[3].decode("ascii").strip()
        except UnicodeDecodeError:
            raise VaultLabelError(
                "vault header label is not ASCII; Ansible would reject the re-encrypted file"
            ) from None
        return vault_id or None
    return None


def find_inline_vault_spans(content: bytes) -> list[InlineSpan]:
    """Locate `key: !vault |` encrypt_string regions (not whole-file vaults).

    Bare `$ANSIBLE_VAULT;` blobs without a matching key binding (docs, fences,
    unsupported styles) are skipped - never opened into plaintext.
    """
    if is_whole_file_vault(content):
        return []

    spans: list[InlineSpan] = []
    pos = 0
    span_id = 0

    while True:
        header_idx = content.find(VAULT_HEADER_PREFIX, pos)
        if header_idx < 0:
            break

        header_line_start = _line_start(content, header_idx)
        header_line_end = _line_end(content, header_idx)
        header_line = content[header_line_start:header_line_end]
        body_indent_match = re.match(rb"^([ \t]*)", header_line)
        body_indent = body_indent_match.group(1) if body_indent_match else b""

        cursor = header_line_end
        while cursor < len(content):
            next_end = _line_end(content, cursor)
            line = content[cursor:next_end]
            if not line.strip():
                break
            if body_indent and not line.startswith(body_indent):
                break
            if not _HEX_LINE.match(line.rstrip(b"\r\n")):
                break
            cursor = next_end

        vault_body_start = header_line_start
        vault_body_end = cursor

        if header_line_start == 0:
            pos = vault_body_end
            continue

        prev_nl = content.rfind(b"\n", 0, header_line_start - 1)
        prev_line_start = 0 if prev_nl < 0 else prev_nl + 1
        prev_line = content[prev_line_start:header_line_start]
        vault_tag = _VAULT_TAG_LINE.search(prev_line)
        if not vault_tag:
            # No `key: !vault |` binding - do not open (list items, docs, etc.).
            pos = vault_body_end
            continue

        line_prefix = vault_tag.group("prefix")
        region_start = prev_line_start
        encrypted = content[region_start:vault_body_end]
        ciphertext = normalize_vault_ciphertext(content[vault_body_start:vault_body_end])
        if not ciphertext.startswith(VAULT_HEADER_PREFIX):
            pos = header_idx + 1
            continue

        spans.append(
            InlineSpan(
                span_id=span_id,
                start=region_start,
                end=vault_body_end,
                encrypted=encrypted,
                ciphertext=ciphertext,
                line_prefix=line_prefix,
                body_indent=body_indent or DEFAULT_BODY_INDENT,
                vault_id=_vault_id_from_ciphertext(ciphertext),
            )
        )
        span_id += 1
        pos = vault_body_end

    return spans


def _yaml_double_quoted(text: str) -> str:
    """A YAML double-quoted scalar that reads back as exactly text.

    json.dumps escapes quotes, backslashes and C0 controls the way YAML does.
    Everything else that is not printable is escaped too: DEL and C1 controls
    fail the YAML reader, and NEL, U+2028 and U+2029 are YAML 1.1 line breaks
    that would fold to a space.
    """
    body = json.dumps(text, ensure_ascii=False)[1:-1]
    escaped = "".join(
        ch
        if ch.isprintable()
        else (f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
        for ch in body
    )
    return f'"{escaped}"'


def _block_literal_safe(text: str) -> bool:
    """True when a `|` or `|-` block shows text exactly and survives common editor saves.

    Anything else is shown double-quoted on one line. A literal block cannot
    hold: a carriage return (YAML normalises line breaks), more than one final
    newline (`|` keeps one), leading whitespace on the first line (it would set
    the indentation), or trailing whitespace (editors strip it on save, which
    silently changed the secret).
    """
    if "\r" in text or text.endswith("\n\n") or not text.rstrip("\n"):
        return False
    lines = text.removesuffix("\n").split("\n")
    first = next(line for line in lines if line)
    if first[0] in " \t":
        return False
    for line in lines:
        if line != line.rstrip(" \t"):
            return False
        if not all(ch.isprintable() or ch == "\t" for ch in line):
            return False
    return True


def format_open_value(plaintext: bytes, span: InlineSpan) -> bytes:
    """Render decrypted plaintext as YAML with a pilfer close marker.

    The rendering must read back as exactly plaintext through the YAML parser;
    decrypt_inline_content checks that before anything is written.
    """
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        name = var_name_from_prefix(span.line_prefix.decode("utf-8", errors="replace"))
        raise ValueError(
            f"Inline vault secret {name!r} is not valid UTF-8; "
            "pilfer cannot safely open binary inline secrets"
        ) from exc

    marker = MARKER_PREFIX.encode("utf-8") + str(span.span_id).encode("utf-8")

    if "\n" in text and _block_literal_safe(text):
        indent = span.body_indent or b"  "
        # `|` keeps the one final newline, `|-` strips it. Empty lines carry no
        # indent, so there is no whitespace for an editor to trim.
        chomp = b"|" if text.endswith("\n") else b"|-"
        lines = text.removesuffix("\n").split("\n")
        body = b"".join((indent + line.encode("utf-8") if line else b"") + b"\n" for line in lines)
        return span.line_prefix + chomp + b" " + marker + b"\n" + body

    quoted = _yaml_double_quoted(text).encode("utf-8")
    return span.line_prefix + quoted + b"  " + marker + b"\n"


def ensure_vault_label(vault: VaultLib, data: bytes) -> None:
    """Register this ciphertext's label when Ansible matches vault ids strictly.

    DEFAULT_VAULT_ID_MATCH is a bool. When it is true, a secret registered
    under that bool does not decrypt a `prod` or `default` header.
    """
    from ansible.constants import DEFAULT_VAULT_ID_MATCH

    if not DEFAULT_VAULT_ID_MATCH or not vault.secrets:
        return
    label = _vault_id_from_ciphertext(data) or "default"
    if any(vault_id == label for vault_id, _secret in vault.secrets):
        return
    vault.secrets.append((label, vault.secrets[0][1]))


def vault_decrypt(vault: VaultLib, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext, registering its vault-id label first (see ensure_vault_label)."""
    ensure_vault_label(vault, ciphertext)
    return vault.decrypt(ciphertext)


def decrypts(vault: VaultLib, ciphertext: bytes) -> bool:
    """True if vault_decrypt succeeds. Ansible raises several types for a wrong password."""
    try:
        vault_decrypt(vault, ciphertext)
    except Exception:
        return False
    return True


def splice(content: bytes, replacements: list[tuple[int, int, bytes]]) -> bytes:
    """Replace each (start, end) byte range with its blob. Ranges must not overlap."""
    ordered = sorted(replacements)
    for prev, nxt in itertools.pairwise(ordered):
        if prev[1] > nxt[0]:
            raise ValueError("overlapping vault values; refusing to splice the file")
    for start, end, blob in reversed(ordered):
        content = content[:start] + blob + content[end:]
    return content


def decrypt_inline_content(content: bytes, vault: VaultLib) -> tuple[bytes, list[dict]]:
    """Decrypt all inline vault spans. Returns (new_content, span_records)."""
    spans = find_inline_vault_spans(content)
    if not spans:
        return content, []

    records = []
    plaintexts = []
    for span in spans:
        plaintext = vault_decrypt(vault, span.ciphertext)
        plaintexts.append(plaintext)
        records.append(
            {
                "id": span.span_id,
                "encrypted_b64": base64.b64encode(span.encrypted).decode("ascii"),
                # Ciphertext alone for decrypt (encrypted_b64 is the full !vault YAML block).
                "ciphertext_b64": base64.b64encode(span.ciphertext).decode("ascii"),
                "plain_hash": hashlib.sha256(plaintext).hexdigest(),
                "line_prefix": span.line_prefix.decode("utf-8", errors="surrogateescape"),
                "body_indent": span.body_indent.decode("utf-8", errors="surrogateescape"),
                "vault_id": span.vault_id,
            }
        )

    new_content = splice(
        content,
        [
            (span.start, span.end, format_open_value(plaintext, span))
            for span, plaintext in zip(spans, plaintexts, strict=True)
        ],
    )

    # close reads values back with the YAML parser. Prove now, before any
    # plaintext is written, that it would read every untouched secret exactly.
    try:
        reread = {mv.span_id: mv.value for mv in read_marked_values(new_content)}
    except OpenedFileError as exc:
        raise ValueError(f"cannot open inline secrets in this file: {exc}") from None
    for span, plaintext in zip(spans, plaintexts, strict=True):
        if reread.get(span.span_id) != plaintext:
            name = var_name_from_prefix(span.line_prefix.decode("utf-8", errors="replace"))
            raise ValueError(
                f"inline secret {name!r} would not read back exactly from the opened "
                "file; left encrypted"
            )

    return new_content, records


def _nodes(root: yaml.Node):
    """Every node under root, once each (an alias reuses a node already walked)."""
    stack, seen = [root], set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                stack.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)


def _compose(content: bytes) -> tuple[str, list[yaml.Node]]:
    """Parse every YAML document in content.

    Raises OpenedFileError, whose message never quotes the file: YAML errors
    normally quote the offending line, and in an opened file that is a secret.
    Tags such as !vault and !unsafe stay on the nodes; nothing is constructed.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise OpenedFileError("file is not UTF-8") from None
    try:
        documents = [root for root in yaml.compose_all(text, Loader=yaml.SafeLoader) if root]
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise OpenedFileError(f"file does not parse as YAML{where}") from None
    except Exception:
        raise OpenedFileError("file does not parse as YAML") from None
    return text, documents


def read_marked_values(content: bytes) -> list[MarkedValue]:
    """Read every `key: value  # pilfer:vault:N` the way Ansible's YAML parser would.

    The marker is a comment: on the value's last line for a quoted or plain
    scalar, on the header line for a `|` or `>` block. The value is the
    scalar's YAML value, so quoting style and escapes mean what they mean to
    Ansible. The region runs from the start of the key's line to the end of the
    value's last non-blank line, so blank lines after a block stay in the file.

    Raises OpenedFileError (see _compose).
    """
    if not MARKER_RE.search(content):
        return []
    text, documents = _compose(content)

    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]

    def line_of(index: int) -> int:
        return bisect.bisect_right(line_starts, index) - 1

    def line_end(index: int) -> int:
        nl = text.find("\n", index)
        return len(text) if nl < 0 else nl + 1

    pairs = [
        pair
        for root in documents
        for node in _nodes(root)
        if isinstance(node, yaml.MappingNode)
        for pair in node.value
    ]
    found = []
    for match in _MARKER_TEXT_RE.finditer(text):
        marker_line = line_of(match.start())
        owner = None
        for key, value in pairs:
            if not isinstance(value, yaml.ScalarNode):
                continue
            if value.style in ("|", ">"):
                hit = (
                    line_of(key.start_mark.index) == marker_line
                    and match.start() > value.start_mark.index
                )
            else:
                hit = (
                    line_of(value.end_mark.index) == marker_line
                    and match.start() >= value.end_mark.index
                )
            if hit:
                owner = (key, value)
                break
        if owner is None:
            raise OpenedFileError(
                f"marker pilfer:vault:{match.group('id')} on line {marker_line + 1} is not "
                "after a single `key: value`"
            )
        key, value = owner
        start = line_starts[line_of(key.start_mark.index)]
        if value.style in ("|", ">"):
            span_text = text[value.start_mark.index : value.end_mark.index]
            last = value.start_mark.index + len(span_text.rstrip())
            end = line_end(last - 1)
        else:
            end = line_end(match.start())
        found.append(
            MarkedValue(
                span_id=int(match.group("id")),
                key_text=text[key.start_mark.index : key.end_mark.index],
                value=value.value.encode("utf-8"),
                start=len(text[:start].encode("utf-8")),
                end=len(text[:end].encode("utf-8")),
            )
        )
    return found


def format_encrypted_block(
    encrypted_ciphertext: bytes,
    line_prefix: bytes,
    body_indent: bytes,
) -> bytes:
    """Format VaultLib.encrypt output as a !vault | block (encrypt_string style)."""
    indent = body_indent or DEFAULT_BODY_INDENT
    lines = encrypted_ciphertext.strip().splitlines()
    body = b"".join(indent + line + b"\n" for line in lines)
    return line_prefix + b"!vault |\n" + body


def _yaml_key_present(content: bytes, var_name: str) -> bool:
    """True if a YAML key `var_name:` still exists in content."""
    pattern = re.compile(
        rb"^[ \t]*" + re.escape(var_name.encode("utf-8")) + rb"\s*:",
        re.MULTILINE,
    )
    return pattern.search(content) is not None


def _hash_text_matches(text: str, plain_hash: str) -> bool:
    """Match plain_hash allowing trailing-newline variance between forms."""
    candidates = {text, text + "\n"}
    stripped = text.rstrip("\r\n")
    candidates.add(stripped)
    candidates.add(stripped + "\n")
    for candidate in candidates:
        if hashlib.sha256(candidate.encode("utf-8")).hexdigest() == plain_hash:
            return True
    return False


def _secret_in_yaml_scalars(content: bytes, plain_hash: str) -> bool:
    """True if any scalar in the file, key or value, in any style, is the opened secret.

    The YAML parser reads it however it was re-quoted, escaped, or moved: under
    another key, into a list, into a block. Comments are not scalars;
    plaintext_still_in_content covers those. A file that does not parse raises
    OpenedFileError: close cannot tell whether the secret is gone, so it stops.
    """
    _text, documents = _compose(content)
    return any(
        isinstance(node, yaml.ScalarNode) and _hash_text_matches(node.value, plain_hash)
        for root in documents
        for node in _nodes(root)
    )


def _yaml_key_has_vault_value(content: bytes, var_name: str) -> bool:
    """True if `var_name:` is present and its value starts with !vault."""
    pattern = re.compile(
        rb"^[ \t]*" + re.escape(var_name.encode("utf-8")) + rb"\s*:\s*!vault\b",
        re.MULTILINE,
    )
    return pattern.search(content) is not None


def plaintext_still_in_content(content: bytes, plaintext: bytes) -> bool:
    """True if the exact opened secret bytes still appear anywhere in content.

    Covers comments, bare lines, nested flow, and other shapes the structured
    YAML scalar scanner can miss. Fail closed: short tokens may false-positive.
    """
    if not plaintext:
        return False
    if plaintext in content:
        return True
    stripped = plaintext.rstrip(b"\r\n")
    if stripped and stripped in content:
        return True
    return False


def _original_plaintext_from_record(record: dict, vault: VaultLib) -> bytes | None:
    """Recover the opened plaintext from session meta, or None if it no longer decrypts."""
    try:
        return vault_decrypt(vault, base64.b64decode(record["ciphertext_b64"]))
    except Exception:
        return None


def _secret_still_present(content: bytes, record: dict, plaintext: bytes) -> bool:
    """True if the opened secret is still in the file: as raw bytes anywhere
    (comments included), or as any YAML scalar however it was re-quoted or moved.
    """
    return plaintext_still_in_content(content, plaintext) or _secret_in_yaml_scalars(
        content, record["plain_hash"]
    )


def _key_has_decryptable_vault(content: bytes, var_name: str, vault: VaultLib) -> bool:
    """True if var_name has a !vault span that decrypts with the session vault."""
    for span in find_inline_vault_spans(content):
        try:
            prefix = span.line_prefix.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if var_name_from_prefix(prefix) != var_name:
            continue
        return decrypts(vault, span.ciphertext)
    return False


def intentional_removal_candidate_names(content: bytes, span_records: list[dict]) -> list[str]:
    """Opened var names whose YAML keys are gone (candidate intentional removals)."""
    names = []
    for record in span_records:
        name = var_name_from_prefix(record["line_prefix"])
        if not _yaml_key_present(content, name):
            names.append(name)
    return names


def unsafe_missing_marker_names(
    content: bytes, span_records: list[dict], vault: VaultLib
) -> list[str]:
    """Opened vars unsafe to treat as already-closed / intentionally removed.

    Includes exact plaintext still present anywhere in the file, structured
    scalar matches, keys that remain without a decryptable !vault value, and
    garbage !vault placeholders that do not decrypt.
    """
    unsafe = []
    for record in span_records:
        name = var_name_from_prefix(record["line_prefix"])
        plaintext = _original_plaintext_from_record(record, vault)
        if plaintext is None:
            # Corrupt/undecryptable session meta - refuse fail-open removal.
            unsafe.append(name)
            continue
        if _secret_still_present(content, record, plaintext):
            unsafe.append(name)
            continue
        if _yaml_key_present(content, name):
            if not _yaml_key_has_vault_value(content, name):
                unsafe.append(name)
                continue
            if not _key_has_decryptable_vault(content, name, vault):
                unsafe.append(name)
    return unsafe


def recrypt_inline_content(
    content: bytes,
    span_records: list[dict],
    vault: VaultLib,
    confirm_delete: bool = False,
) -> RecryptInlineResult:
    """Re-encrypt marked inline values.

    Missing markers whose YAML key was also deleted are treated as intentional
    deletes only when confirm_delete is True and the secret value is gone too.
    Missing markers whose key remains, or whose plaintext still appears under
    another key, are errors.
    """
    records = {int(r["id"]): r for r in span_records}
    if len(records) != len(span_records):
        raise ValueError("Duplicate span ids in session metadata")

    modified = 0
    replacements = []
    seen_ids: set[int] = set()

    for marked in read_marked_values(content):
        span_id = marked.span_id
        if span_id not in records:
            raise ValueError(f"Unknown pilfer vault marker id {span_id}")
        if span_id in seen_ids:
            raise ValueError(
                f"Duplicate pilfer vault marker id {span_id}. "
                "Each opened secret must keep exactly one # pilfer:vault:N comment."
            )
        seen_ids.add(span_id)
        record = records[span_id]

        stored_name = var_name_from_prefix(record["line_prefix"])
        # A list item's prefix is "- key: "; the YAML key is just "key".
        if marked.key_text != stored_name.removeprefix("-").strip():
            raise ValueError(
                f"Marker # pilfer:vault:{span_id} is on key {marked.key_text!r} "
                f"but was opened as {stored_name!r}. Move the marker back to "
                f"{stored_name!r} (or restore the line) before close."
            )

        plaintext = marked.value
        plain_hash = hashlib.sha256(plaintext).hexdigest()
        if not plaintext and plain_hash != record["plain_hash"]:
            # An emptied value is more likely a slip than a new secret.
            raise ValueError(
                f"{stored_name} is empty. Put a value back, or delete the whole line "
                "and close with --confirm-delete."
            )
        original_encrypted = base64.b64decode(record["encrypted_b64"])

        # Open proved the parser reads the untouched rendering as exactly the
        # secret, so a hash match means the user did not change it: put the
        # original ciphertext back rather than a new one.
        if plain_hash == record["plain_hash"]:
            replacements.append((marked.start, marked.end, original_encrypted))
        else:
            # vault_id=None writes a 1.1 header, the same as leaving it out.
            new_cipher = vault.encrypt(plaintext, vault_id=record.get("vault_id") or None)
            line_prefix = record["line_prefix"].encode("utf-8")
            body_indent = record["body_indent"].encode("utf-8")
            replacements.append(
                (
                    marked.start,
                    marked.end,
                    format_encrypted_block(new_cipher, line_prefix, body_indent),
                )
            )
            modified += 1

    missing = set(records) - seen_ids
    removed_vars: list[str] = []
    for span_id in sorted(missing):
        record = records[span_id]
        name = var_name_from_prefix(record["line_prefix"])
        if _yaml_key_present(content, name):
            raise MarkerMissingSecretPresent(name, span_id)
        plaintext = _original_plaintext_from_record(record, vault)
        if plaintext is None:
            raise ValueError(
                f"Missing # pilfer:vault:{span_id} marker for {name!r}, and the "
                "session ciphertext for that span could not be decrypted. Refuse "
                "to treat as intentional removal; restore meta/backups or the "
                "marker before close."
            )
        if _secret_still_present(content, record, plaintext):
            raise MarkerMissingSecretPresent(name, span_id)
        if not confirm_delete:
            raise SecretLineDeleted(name, span_id)
        removed_vars.append(name)

    return RecryptInlineResult(
        content=splice(content, replacements),
        modified_count=modified + len(removed_vars),
        removed_vars=removed_vars,
    )
