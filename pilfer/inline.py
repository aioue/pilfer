# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""In-place handling of ansible-vault encrypt_string (!vault) blobs."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

from ansible.parsing.vault import VaultLib

# Marker left beside a decrypted value so close can find spans after edits.
MARKER_PREFIX = "# pilfer:vault:"
MARKER_RE = re.compile(
    rb"^(?P<indent>[ \t]*)(?P<lhs>.+?):\s+(?P<value>.+?)\s+"
    + re.escape(MARKER_PREFIX.encode("utf-8"))
    + rb"(?P<id>\d+)\s*$",
    re.MULTILINE,
)

_HEX_LINE = re.compile(rb"^[ \t]*[0-9a-fA-F]+\s*$")
# Only plain literal block style for now (!vault |). Other styles are skipped.
_VAULT_TAG_LINE = re.compile(rb"^(?P<prefix>[ \t]*[^:\n#][^:\n]*:\s*)!vault\s*\|\s*\r?\n$")

UTF8_BOM = b"\xef\xbb\xbf"
VAULT_HEADER_PREFIX = b"$ANSIBLE_VAULT;"


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
    text = line_prefix.rstrip()
    text = text.removesuffix(":")
    return text.strip().lstrip()


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
        vault_id = parts[3].decode("ascii", errors="replace").strip()
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
        header_idx = content.find(b"$ANSIBLE_VAULT;", pos)
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
        if not ciphertext.startswith(b"$ANSIBLE_VAULT;"):
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
                body_indent=body_indent or b"          ",
                vault_id=_vault_id_from_ciphertext(ciphertext),
            )
        )
        span_id += 1
        pos = vault_body_end

    return spans


def _yaml_escape_double(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def format_open_value(plaintext: bytes, span: InlineSpan) -> bytes:
    """Render decrypted plaintext as YAML with a pilfer close marker."""
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        name = var_name_from_prefix(span.line_prefix.decode("utf-8", errors="replace"))
        raise ValueError(
            f"Inline vault secret {name!r} is not valid UTF-8; "
            "pilfer cannot safely open binary inline secrets"
        ) from exc

    marker = MARKER_PREFIX.encode("utf-8") + str(span.span_id).encode("utf-8")

    if "\n" in text or "\r" in text:
        indent = span.body_indent or b"  "
        # splitlines() keeps interior blank lines; drops a single trailing newline.
        lines = text.splitlines()
        body = b"".join(indent + line.encode("utf-8") + b"\n" for line in lines)
        return span.line_prefix + b"| " + marker + b"\n" + body

    quoted = '"' + _yaml_escape_double(text) + '"'
    return span.line_prefix + quoted.encode("utf-8") + b"  " + marker + b"\n"


def decrypt_inline_content(content: bytes, vault: VaultLib) -> tuple[bytes, list[dict]]:
    """Decrypt all inline vault spans. Returns (new_content, span_records)."""
    spans = find_inline_vault_spans(content)
    if not spans:
        return content, []

    records = []
    plaintexts = []
    for span in spans:
        plaintext = vault.decrypt(span.ciphertext)
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

    new_content = content
    for span, plaintext in sorted(
        zip(spans, plaintexts, strict=True),
        key=lambda pair: pair[0].start,
        reverse=True,
    ):
        replacement = format_open_value(plaintext, span)
        new_content = new_content[: span.start] + replacement + new_content[span.end :]

    return new_content, records


def _parse_marked_value(content: bytes, match: re.Match) -> tuple[bytes, int, int]:
    """Return (plaintext_bytes, region_start, region_end) for an open marker match."""
    indent = match.group("indent")
    value = match.group("value")
    region_start = match.start()

    if value.strip() == b"|" or value.startswith(b"|"):
        line_end = content.find(b"\n", match.end())
        cursor = len(content) if line_end < 0 else line_end + 1
        body_lines = []
        base_indent_len = len(indent)
        while cursor < len(content):
            next_end = _line_end(content, cursor)
            line = content[cursor:next_end]
            if not line.strip():
                # Blank lines are part of YAML literal block scalars - keep them.
                body_lines.append(b"")
                cursor = next_end
                continue
            line_indent = len(line) - len(line.lstrip(b" \t"))
            if line_indent <= base_indent_len:
                break
            body_lines.append(line.lstrip(b" \t").rstrip(b"\r\n"))
            cursor = next_end
        plaintext = b"\n".join(body_lines)
        return plaintext, region_start, cursor

    raw = value
    if raw.startswith(b'"') and raw.endswith(b'"') and len(raw) >= 2:
        text = raw[1:-1].decode("utf-8")
        text = (
            text.replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace('\\"', '"')
            .replace("\\\\", "\\")
        )
        plaintext = text.encode("utf-8")
    else:
        plaintext = raw

    region_end = _line_end(content, match.start())
    return plaintext, region_start, region_end


def format_encrypted_block(
    encrypted_ciphertext: bytes,
    line_prefix: bytes,
    body_indent: bytes,
) -> bytes:
    """Format VaultLib.encrypt output as a !vault | block (encrypt_string style)."""
    indent = body_indent or b"          "
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


def _yaml_unescape_double(text: str) -> str:
    return (
        text.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )


def _yaml_unescape_single(text: str) -> str:
    # YAML single-quoted: '' → '
    return text.replace("''", "'")


def _hash_block_scalar_body(body: bytes) -> str | None:
    if not body:
        return None
    lines = body.splitlines()
    indents = [len(line) - len(line.lstrip(b" \t")) for line in lines if line.strip()]
    if not indents:
        return None
    min_indent = min(indents)
    parts = []
    for line in lines:
        if not line.strip():
            parts.append(b"")
            continue
        parts.append(line[min_indent:] if len(line) >= min_indent else line.lstrip(b" \t"))
    plaintext = b"\n".join(parts)
    return hashlib.sha256(plaintext).hexdigest()


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


def _strip_yaml_tag_anchor(raw: bytes) -> bytes:
    """Strip leading &anchor / !!tag / !tag tokens from a plain scalar."""
    value = raw.strip()
    while True:
        match = re.match(rb"(?:&\S+\s+|!!?\S+\s+)(.*)$", value)
        if not match:
            return value
        value = match.group(1).strip()


def _plain_hash_still_present(content: bytes, plain_hash: str) -> bool:
    """True if any plausible YAML scalar in content still hashes to plain_hash.

    Used to refuse "intentional removal" when a marker was dropped but the
    secret value remains (e.g. key renamed). Avoids stranding plaintext.
    """
    # Double-quoted scalars: key: "value" (block or flow)
    for match in re.finditer(rb'"((?:\\.|[^"\\])*)"', content):
        try:
            text = _yaml_unescape_double(match.group(1).decode("utf-8"))
        except UnicodeDecodeError:
            continue
        if _hash_text_matches(text, plain_hash):
            return True

    # Single-quoted scalars: 'value' ('' is escaped quote)
    for match in re.finditer(rb"'((?:[^']|'')*)'", content):
        try:
            text = _yaml_unescape_single(match.group(1).decode("utf-8"))
        except UnicodeDecodeError:
            continue
        if _hash_text_matches(text, plain_hash):
            return True

    # Single-line plain scalars after ':' (mapping) — block or flow
    for match in re.finditer(
        rb":\s*(?![\|'\"|>[{])([^\s#\n,}\]][^#\n,}\]]*?)(?=\s*(?:[,}\]\n#]|$))",
        content,
    ):
        raw = _strip_yaml_tag_anchor(match.group(1))
        if not raw or raw.startswith(b"!"):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _hash_text_matches(text, plain_hash):
            return True

    # Sequence items: - value (not block indicators)
    for match in re.finditer(
        rb"(?m)^[ \t]*-\s*(?![\|'\"|>[{])([^\s#\n][^#\n]*?)\s*(?:#[^\n]*)?$",
        content,
    ):
        raw = _strip_yaml_tag_anchor(match.group(1))
        if not raw or raw.startswith(b"!"):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _hash_text_matches(text, plain_hash):
            return True

    # Flow sequence entries: [value, ...] (unquoted) — after [ or ,, not nested '['
    for match in re.finditer(
        rb"[\[\,][ \t]*(?!\[)([^\s'\"#,\]][^\s,\]]*)(?=[ \t]*[,\]])",
        content,
    ):
        raw = _strip_yaml_tag_anchor(match.group(1))
        if not raw or raw.startswith(b"!") or raw in (b"{", b"}"):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _hash_text_matches(text, plain_hash):
            return True

    # Literal / folded block scalars after mapping ':' or sequence '-'
    # Supports chomp (+/-) and indent indicator (e.g. >+, |-, |2, >-1).
    # '(?:^|[ \\t])-' covers column-0 list items as well as indented ones.
    for match in re.finditer(
        rb"(?::|(?:^|[ \t])-)\s*[|>][+-]?(?:\d+)?\s*(?:#[^\n]*)?\r?\n"
        rb"((?:(?:[ \t]+.*)?\r?\n)*)",
        content,
        re.MULTILINE,
    ):
        body = match.group(1)
        digest = _hash_block_scalar_body(body)
        if digest == plain_hash:
            return True
        indents = [
            len(line) - len(line.lstrip(b" \t")) for line in body.splitlines() if line.strip()
        ]
        if not indents:
            continue
        min_indent = min(indents)
        parts = []
        for line in body.splitlines():
            if not line.strip():
                parts.append(b"")
                continue
            parts.append(line[min_indent:] if len(line) >= min_indent else line.lstrip(b" \t"))
        try:
            text = b"\n".join(parts).decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _hash_text_matches(text, plain_hash):
            return True

    return False


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
    """Recover opened plaintext from session meta (ciphertext or full !vault block)."""
    try:
        if record.get("ciphertext_b64"):
            ciphertext = base64.b64decode(record["ciphertext_b64"])
        else:
            blob = base64.b64decode(record["encrypted_b64"])
            idx = blob.find(b"$ANSIBLE_VAULT;")
            if idx < 0:
                return None
            ciphertext = normalize_vault_ciphertext(blob[idx:])
        return vault.decrypt(ciphertext)
    except Exception:
        return None


def _key_has_decryptable_vault(content: bytes, var_name: str, vault: VaultLib) -> bool:
    """True if var_name has a !vault span that decrypts with the session vault."""
    for span in find_inline_vault_spans(content):
        try:
            prefix = span.line_prefix.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if var_name_from_prefix(prefix) != var_name:
            continue
        try:
            vault.decrypt(span.ciphertext)
            return True
        except Exception:
            return False
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
        if plaintext_still_in_content(content, plaintext):
            unsafe.append(name)
            continue
        if _plain_hash_still_present(content, record["plain_hash"]):
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

    for match in MARKER_RE.finditer(content):
        span_id = int(match.group("id"))
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
        current_name = match.group("lhs").decode("utf-8", errors="replace").strip()
        if stored_name != current_name:
            raise ValueError(
                f"Marker # pilfer:vault:{span_id} is on key {current_name!r} "
                f"but was opened as {stored_name!r}. Move the marker back to "
                f"{stored_name!r} (or restore the line) before close."
            )

        plaintext, region_start, region_end = _parse_marked_value(content, match)
        plain_hash = hashlib.sha256(plaintext).hexdigest()
        original_encrypted = base64.b64decode(record["encrypted_b64"])

        if plain_hash == record["plain_hash"]:
            replacements.append((region_start, region_end, original_encrypted))
        else:
            vault_id = record.get("vault_id") or None
            if vault_id:
                new_cipher = vault.encrypt(plaintext, vault_id=vault_id)
            else:
                new_cipher = vault.encrypt(plaintext)
            line_prefix = record["line_prefix"].encode("utf-8")
            body_indent = record["body_indent"].encode("utf-8")
            replacements.append(
                (
                    region_start,
                    region_end,
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
        if plaintext_still_in_content(content, plaintext):
            raise MarkerMissingSecretPresent(name, span_id)
        if _plain_hash_still_present(content, record["plain_hash"]):
            raise MarkerMissingSecretPresent(name, span_id)
        if not confirm_delete:
            raise SecretLineDeleted(name, span_id)
        removed_vars.append(name)

    new_content = content
    for start, end, blob in sorted(replacements, key=lambda t: t[0], reverse=True):
        new_content = new_content[:start] + blob + new_content[end:]

    if removed_vars:
        modified += len(removed_vars)

    return RecryptInlineResult(
        content=new_content,
        modified_count=modified,
        removed_vars=removed_vars,
    )
