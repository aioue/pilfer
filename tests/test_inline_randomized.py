#!/usr/bin/env python3
"""Randomized open -> edit -> close check for pilfer's inline !vault path.

Ground truth, independent of pilfer's marker and splice code:
- what the user meant: PyYAML's reading of each value in the edited, opened file;
- what was stored: the closed file read as YAML, each !vault value decrypted.
Every close must either store exactly what the user meant, or refuse and leave
the edited file and session alone. Wrong values, leaks and crashes are bugs.

Seeds are fixed, so a failure names a seed that reproduces it. Run more cases
locally with PILFER_RANDOM_CASES=5000 (and PILFER_RANDOM_SEED to start
elsewhere). This found the two 2.31 bugs fixed in 2.32: a trailing newline lost
from a `|` block at the end of the file, and a tab-only line left behind after
a closed block.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import re
import shutil
import sys
import tempfile
import traceback
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

from pilfer import cli as pilfer_cli

PASSWORD = "test_password"
VAULT = VaultLib([("default", VaultSecret(PASSWORD.encode()))])

AWKWARD = [
    "yes",
    "no",
    "on",
    "null",
    "~",
    "0123",
    "0x1F",
    "1e3",
    "5432",
    "3.14",
    "2026-11-01",
    "- item",
    "key: value",
    "#hash",
    "a #b",
    "&anchor",
    "*alias",
    "!tag",
    "%",
    "@",
    "`",
    "{a: 1}",
    "[1, 2]",
    "{{ var }}",
    "{% x %}",
    "'",
    '"',
    "\\",
    "\\n",
    "|",
    ">",
    "---",
    "...",
    " lead",
    "trail ",
    "\ttab",
    "é",
    "中文",
    "😀",
    "a\u00a0b",
    "\u2028",
    "\x01",
    "\x7f",
]
CHARS = "abcdefghijklmnopqrstuvwxyzABCXYZ0123456789 \t'\"\\:#{}[],&*!|>%@`-?=+/é中😀\u00a0"


def random_secret(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.25:
        return rng.choice(AWKWARD) + rng.choice(["", "", "zz", " Q"])
    if kind < 0.45:
        lines = [
            "".join(rng.choice(CHARS) for _ in range(rng.randint(0, 12)))
            for _ in range(rng.randint(2, 4))
        ]
        text = "\n".join(lines)
        return text + rng.choice(["", "\n", "\n\n"])
    return "".join(rng.choice(CHARS) for _ in range(rng.randint(1, 24)))


# ---- independent YAML helpers ------------------------------------------------


class _VaultReader(yaml.SafeLoader):
    pass


def _vault_ctor(loader, node):
    return ("!vault", loader.construct_scalar(node))


_VaultReader.add_constructor("!vault", _vault_ctor)


def stored_values(closed: bytes) -> dict:
    """Closed file -> {dotted key: decrypted str} for every !vault value."""
    data = yaml.load(closed.decode("utf-8"), Loader=_VaultReader)
    out = {}

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, tuple) and node[0] == "!vault":
            out[path] = VAULT.decrypt(node[1].encode()).decode("utf-8")

    walk(data, "")
    return out


def scalar_nodes(text: str) -> dict:
    """Opened file -> {dotted key: (key node, value node)} for every scalar value."""
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    out = {}

    def walk(node, path):
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                p = f"{path}.{k.value}" if path else k.value
                if isinstance(v, yaml.ScalarNode):
                    out[p] = (k, v)
                else:
                    walk(v, p)
        elif isinstance(node, yaml.SequenceNode):
            for i, v in enumerate(node.value):
                walk(v, f"{path}[{i}]")

    walk(root, "")
    return out


def render_new_value(rng: random.Random, secret: str, marker: str, indent: str) -> str | None:
    """A random YAML style for secret, followed by the pilfer marker. None if it cannot."""
    styles = ["double", "double_ascii", "single", "plain", "block"]
    rng.shuffle(styles)
    for style in styles:
        if style.startswith("double"):
            r = json.dumps(secret, ensure_ascii=style == "double_ascii")
            cand = (f"{r}  {marker}", "")
        elif style == "single":
            r = "'" + secret.replace("'", "''") + "'"
            cand = (f"{r}  {marker}", "")
        elif style == "plain":
            cand = (f"{secret}  {marker}", "")
        else:
            if not secret.rstrip("\n") or "\r" in secret:
                continue
            chomp = "|" if secret.endswith("\n") and not secret.endswith("\n\n") else "|-"
            if secret.endswith("\n\n"):
                chomp = "|+"
            lines = secret.split("\n")
            if chomp != "|-":
                lines = lines[:-1]
            body = "".join((indent + line if line else "") + "\n" for line in lines)
            cand = (f"{chomp}  {marker}", body)
        head, body = cand
        try:
            node = yaml.compose(f"k: {head}\n{body}", Loader=yaml.SafeLoader).value[0][1]
        except Exception:
            continue
        if isinstance(node, yaml.ScalarNode) and node.value == secret:
            return head + "\n" + body
    return None


# ---- one case ----------------------------------------------------------------


def build_file(rng: random.Random):
    """Return (text, {dotted key: secret}) for a vars file with inline vaults."""
    secrets = {}
    lines = ["---", "plain_key: visible  # ordinary comment"]
    n = rng.randint(1, 4)
    for i in range(n):
        secret = random_secret(rng)
        nested = rng.random() < 0.3
        vault_id = rng.choice([None, None, "prod"])
        cipher = (
            VAULT.encrypt(secret.encode("utf-8"), vault_id=vault_id).decode().strip().splitlines()
        )
        if nested:
            name = f"group{i}"
            lines.append(f"{name}:")
            key_indent, body_indent = "  ", " " * rng.choice([4, 6, 12])
            lines.append(f"{key_indent}secret{i}: !vault |")
            path = f"{name}.secret{i}"
        else:
            key_indent, body_indent = "", " " * rng.choice([2, 4, 10])
            lines.append(f"secret{i}: !vault |")
            path = f"secret{i}"
        lines.extend(body_indent + c for c in cipher)
        secrets[path] = secret
        if rng.random() < 0.4:
            lines.append(f"{key_indent}after{i}: plain  # after")
    return "\n".join(lines) + "\n", secrets


EDITS = ["none", "replace", "replace", "replace", "delete", "drop_marker", "rename_key"]
TRANSFORMS = [
    "strip_trailing_ws",
    "final_newline",
    "drop_final_newline",
    "crlf",
    "comment_line",
    "blank_lines",
]


def transform(rng, text: str, applied: list) -> str:
    for t in TRANSFORMS:
        if rng.random() < 0.25:
            applied.append(t)
            if t == "strip_trailing_ws":
                text = "\n".join(line.rstrip(" \t") for line in text.split("\n"))
            elif t == "final_newline" and not text.endswith("\n"):
                text += "\n"
            elif t == "drop_final_newline":
                text = text.rstrip("\n")
            elif t == "crlf":
                text = text.replace("\r\n", "\n").replace("\n", "\r\n")
            elif t == "comment_line":
                text = text + ("" if text.endswith("\n") else "\n") + "# edited by hand\n"
            elif t == "blank_lines":
                text = text.replace("\nplain_key", "\n\nplain_key", 1)
    return text


def run_case(seed: int) -> tuple[str, str]:
    rng = random.Random(seed)
    original, secrets = build_file(rng)
    with open("vars.yml", "w", encoding="utf-8", newline="") as f:
        f.write(original)
    with open("vault_pass", "w") as f:
        f.write(PASSWORD)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            pilfer_cli.open_vault_files("vault_pass", include_encrypted_vars=True)
        except pilfer_cli.PilferError as exc:
            with open("vars.yml", encoding="utf-8", newline="") as f:
                if f.read() != original:
                    return "BUG", f"open refused but changed the file: {exc}"
            return "open_refused", str(exc)[:80]
    with open("vars.yml", encoding="utf-8", newline="") as f:
        opened = f.read()

    # The opened file must say exactly the original secrets.
    nodes = scalar_nodes(opened)
    for path, secret in secrets.items():
        if nodes[path][1].value != secret:
            return "BUG", f"open rendered {path} as {nodes[path][1].value!r}, secret {secret!r}"

    edit = rng.choice(EDITS)
    new_secrets = {}
    text = opened
    if edit == "replace":
        path = rng.choice(sorted(secrets))
        new = random_secret(rng)
        key_node, value_node = nodes[path]
        marker_start = text.find("# pilfer:vault:", value_node.start_mark.index)
        marker = text[marker_start : text.find("\n", marker_start)].rstrip()
        indent = " " * (key_node.start_mark.column + 2)
        rendered = render_new_value(rng, new, marker, indent)
        if rendered is not None:
            start = value_node.start_mark.index
            if value_node.style in ("|", ">"):
                end = value_node.end_mark.index
            else:
                end = text.find("\n", value_node.end_mark.index) + 1
            text = text[:start] + rendered + text[end:]
            new_secrets[path] = new
        else:
            edit = "none"
    elif edit in ("delete", "drop_marker", "rename_key"):
        path = rng.choice(sorted(secrets))
        key_node, value_node = nodes[path]
        line_start = text.rfind("\n", 0, key_node.start_mark.index) + 1
        if value_node.style in ("|", ">"):
            end = value_node.end_mark.index
        else:
            end = text.find("\n", value_node.end_mark.index) + 1
        region = text[line_start:end]
        if edit == "delete":
            text = text[:line_start] + text[end:]
        elif edit == "drop_marker":
            text = (
                text[:line_start]
                + re.sub(r"[ \t]*# pilfer:vault:\d+", "", region, count=1)
                + text[end:]
            )
        else:
            text = (
                text[: key_node.start_mark.index] + "renamed_" + text[key_node.start_mark.index :]
            )
        target = path
    applied: list = []
    text = transform(rng, text, applied)
    with open("vars.yml", "w", encoding="utf-8", newline="") as f:
        f.write(text)

    # What the user meant, per PyYAML.
    meant_nodes = scalar_nodes(text)
    if edit in ("delete", "drop_marker", "rename_key"):
        return check_structural(edit, target, text, secrets, sink)
    meant = {p: meant_nodes[p][1].value for p in secrets}
    for p, secret in secrets.items():
        if p not in new_secrets and meant[p] != secret:
            return (
                "BUG",
                f"editor transform {applied} changed untouched {p}: {secret!r} -> {meant[p]!r}",
            )

    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            pilfer_cli.recrypt_vault_files("vault_pass")
        except pilfer_cli.PilferError as exc:
            with open("vars.yml", encoding="utf-8", newline="") as f:
                if f.read() != text or not os.path.exists("vaultedFileList.json"):
                    return "BUG", f"close refused but changed state: {exc}"
            return (
                "close_refused",
                f"{edit} {applied}: {sink.getvalue().strip().splitlines()[-1][:120]}",
            )
    with open("vars.yml", "rb") as f:
        closed = f.read()
    if edit == "none" and not applied and closed != original.encode():
        return "BUG", "unchanged open/close did not restore the exact bytes"
    got = stored_values(closed)
    for p in secrets:
        if got.get(p) != meant[p]:
            return "BUG", f"{edit} {applied}: {p} stored {got.get(p)!r}, meant {meant[p]!r}"
    for s in list(secrets.values()) + list(new_secrets.values()):
        if (
            len(s.strip()) >= 6
            and any(c not in "0123456789abcdef\n" for c in s)
            and s.encode() in closed
        ):
            return "BUG", f"secret {s!r} still in closed file"
    if os.path.exists("vaultedFileList.json") or os.path.exists(".vault"):
        return "BUG", "session left behind after a successful close"
    return "ok", edit


def _close(confirm_delete=False):
    try:
        pilfer_cli.recrypt_vault_files("vault_pass", confirm_delete=confirm_delete)
        return None
    except pilfer_cli.PilferError as exc:
        return exc


def check_structural(edit, target, text, secrets, sink):
    """Delete, marker removal and rename must refuse; a confirmed delete must remove only that secret."""
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        exc = _close()
    with open("vars.yml", encoding="utf-8", newline="") as f:
        after = f.read()
    if exc is None:
        return "BUG", f"{edit} of {target}: close succeeded without --confirm-delete"
    if after != text or not os.path.exists("vaultedFileList.json"):
        return "BUG", f"{edit}: refused close changed the file or dropped the session"
    if edit != "delete":
        return "ok", edit
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        exc = _close(confirm_delete=True)
    if exc is not None:
        return "close_refused", f"confirmed delete refused, deleted secret {secrets[target]!r}"
    with open("vars.yml", "rb") as f:
        closed = f.read()
    got = stored_values(closed)
    if target in got:
        return "BUG", f"deleted {target} still stored"
    for p, secret in secrets.items():
        if p != target and got.get(p) != secret:
            return "BUG", f"confirmed delete changed {p}: {got.get(p)!r} != {secret!r}"
    for s in secrets.values():
        if (
            len(s.strip()) >= 6
            and any(c not in "0123456789abcdef\n" for c in s)
            and s.encode() in closed
        ):
            return "BUG", f"secret {s!r} still in closed file"
    return "ok", edit


CASES = int(os.environ.get("PILFER_RANDOM_CASES", "300"))
FIRST_SEED = int(os.environ.get("PILFER_RANDOM_SEED", "0"))


def _run_isolated(seed: int) -> tuple[str, str]:
    directory = tempfile.mkdtemp()
    cwd = os.getcwd()
    os.chdir(directory)
    try:
        return run_case(seed)
    except Exception:
        return "BUG", "crash: " + traceback.format_exc().strip().splitlines()[-1]
    finally:
        os.chdir(cwd)
        shutil.rmtree(directory)


class TestInlineRandomized(unittest.TestCase):
    def test_open_edit_close(self):
        problems = []
        for seed in range(FIRST_SEED, FIRST_SEED + CASES):
            outcome, detail = _run_isolated(seed)
            # A confirmed delete of a one- or two-character secret is refused
            # when the same text appears elsewhere in the file: fail closed.
            if outcome == "ok" or detail.startswith("confirmed delete refused"):
                continue
            problems.append(f"seed {seed}: {outcome}: {detail}")
        self.assertEqual(problems, [], "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
