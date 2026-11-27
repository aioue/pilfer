"""Escaping in error paths, and session entries that are not what open wrote."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_find_keys import PASSWORD, FindKeysBase
from test_vault_set import _vault

from pilfer import cli
from pilfer.cli import safe_multiline, safe_text

ESC = "\x1b"


class TestSafeText(unittest.TestCase):
    def test_escaping_is_idempotent(self) -> None:
        # A printed key path must stay pasteable into update. A literal `\x1b` in a
        # name reads the same as an escaped ESC; that trade-off is accepted.
        for text in (f"a{ESC}b", "a\\x1b", "back\\slash", f"\u202e{ESC}\n"):
            with self.subTest(text=text):
                once = safe_text(text)
                self.assertEqual(safe_text(once), once)
                self.assertEqual(safe_multiline(safe_multiline(text)), safe_multiline(text))
        self.assertEqual(safe_text("a\\x1b"), "a\\x1b")
        self.assertEqual(safe_text(f"a{ESC}"), "a\\x1b")

    def test_multiline_keeps_only_the_newline(self) -> None:
        self.assertEqual(safe_multiline(f"one\\two\n{ESC}[2J\r"), "one\\two\n\\x1b[2J\\r")
        self.assertEqual(safe_text("a\nb"), "a\\nb")


class TestEscapedErrorPaths(FindKeysBase):
    def test_lock_wait_message_escapes_the_path(self) -> None:
        import io

        from pilfer import publish

        calls = []

        def flock(fd, how):
            calls.append(how)
            if len(calls) == 1:
                raise BlockingIOError

        target = self.directory / f"we{ESC}ird.yml"
        err = io.StringIO()
        with mock.patch.object(publish.fcntl, "flock", flock), mock.patch("sys.stderr", err):
            with publish.vault_file_lock(target):
                pass
        self.assertNotIn(ESC, err.getvalue())
        self.assertIn("we\\x1bird.yml", err.getvalue())

    def test_main_error_line_escapes_a_planted_name(self) -> None:
        name = f"we{ESC}ird.yml"
        code, _, err = self._main("set", "-p", str(self.password), name, "a")
        self.assertEqual(code, 1)
        self.assertNotIn(ESC, err)
        self.assertIn("we\\x1bird.yml", err)

    def test_set_unused_source_note_escapes_the_file_name(self) -> None:
        name = f"we{ESC}ird.yml"
        (self.directory / name).write_bytes(self.vault.read_bytes())
        wrong = self._password_file("wrong-password", "not-the-password")
        code, out, err = self._main(
            "set", "-p", str(wrong), "-p", str(self.password), name, "tail", "x"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("decrypted none of", err)
        self.assertNotIn(ESC, out + err)
        self.assertIn("we\\x1bird.yml", err)

    def test_close_failure_block_escapes_the_file_name(self) -> None:
        name = f"we{ESC}ird.yml"
        odd = self.directory / name
        odd.write_bytes(self.vault.read_bytes())
        self.assertEqual(self._main("open", "-p", str(self.password))[0], 0)
        odd_plain = self.directory / name
        self.assertTrue(odd_plain.exists())
        # Break the hash backup so this entry fails and prints its block.
        for hash_file in (self.directory / ".vault").rglob("hash"):
            hash_file.unlink()
        code, out, err = self._main("close", "-p", str(self.password))
        self.assertEqual(code, 1)
        self.assertNotIn(ESC, out + err)
        self.assertIn("\\x1b", err)

    def test_open_decrypt_failure_escapes_the_file_name(self) -> None:
        name = f"we{ESC}ird.yml"
        (self.directory / name).write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\nzzzz\n")
        code, out, err = self._main("open", "-p", str(self.password))
        self.assertEqual(code, 1, err)
        self.assertNotIn(ESC, out + err)
        self.assertIn("Failed to decrypt", out)
        self.assertIn("we\\x1bird.yml", out)


class TestUnreadableVaults(FindKeysBase):
    def _rekey(self, *extra: str):
        new = self._password_file("new-password", "new-password-value")
        return self._main(
            "rekey",
            "--yes",
            "--old-vault-password-file",
            str(self.password),
            "--new-vault-password-file",
            str(new),
            *extra,
        )

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode 000 file")
    def test_rekey_refuses_when_a_vault_is_unreadable(self) -> None:
        hidden = self.directory / "hidden.yml"
        hidden.write_bytes(self.before)
        os.chmod(hidden, 0)
        try:
            code, out, err = self._rekey("--rotate-password-file")
        finally:
            os.chmod(hidden, 0o600)
        self.assertEqual(code, 1, out + err)
        self.assertIn("hidden.yml", err)
        self.assertIn("could not read", err)
        self.assertEqual(self.vault.read_bytes(), self.before)  # nothing re-keyed
        self.assertEqual(self.password.read_text(encoding="utf-8").strip(), PASSWORD)

    def test_rekey_refuses_an_oversized_vault(self) -> None:
        limit = 16
        with mock.patch.object(cli, "MAX_READ_BYTES", limit):
            code, out, err = self._rekey("--rotate-password-file")
        self.assertEqual(code, 1, out + err)
        self.assertIn("secrets.yml", err)
        self.assertIn("secrets.yml (too large", err)
        self.assertEqual(self.vault.read_bytes(), self.before)
        self.assertEqual(self.password.read_text(encoding="utf-8").strip(), PASSWORD)

    def test_open_warns_about_an_oversized_vault(self) -> None:
        small = self.directory / "small.yml"
        small.write_bytes(_vault().encrypt(b"a: 1\n"))
        limit = len(small.read_bytes()) + 1
        self.assertGreater(len(self.before), limit)
        with mock.patch.object(cli, "MAX_READ_BYTES", limit):
            code, _out, err = self._main("open", "-p", str(self.password))
        self.assertEqual(code, 0, err)
        self.assertIn("Could not read", err)
        self.assertIn("secrets.yml", err)
        self.assertEqual(self.vault.read_bytes(), self.before)

    def test_open_caps_the_unreadable_warnings(self) -> None:
        for i in range(7):
            (self.directory / f"big{i}.yml").write_bytes(self.before)
        with mock.patch.object(cli, "MAX_READ_BYTES", 16):
            _code, _out, err = self._main("open", "-p", str(self.password))
        self.assertEqual(err.count("Could not read"), 5, err)
        self.assertIn("and 3 more (fix these and run again to see the rest)", err)


class TestNestedTooDeeply(FindKeysBase):
    def _deep_inline(self) -> Path:
        path = self._inline("deep.yml")
        path.write_text(
            path.read_text(encoding="utf-8") + "a: " + "[" * 3000 + "]" * 3000 + "\n",
            encoding="utf-8",
        )
        return path

    def test_update_file_refuses_a_deep_inline_file(self) -> None:
        self._deep_inline()
        code, _out, err = self._main(
            "update",
            "--include-encrypted-vars",
            "--file",
            "deep.yml",
            "-p",
            str(self.password),
            "api.token",
            "new",
        )
        self.assertEqual(code, 1, err)
        self.assertIn("nested too deeply", err)
        self.assertNotIn("Traceback", err)

    def test_open_refuses_a_deep_inline_file(self) -> None:
        deep = self._deep_inline()
        before = deep.read_bytes()
        code, out, err = self._main("open", "--include-encrypted-vars", "-p", str(self.password))
        self.assertNotIn("Traceback", out + err)
        self.assertIn("nested too deeply", out + err)
        self.assertEqual(deep.read_bytes(), before)
        self.assertNotEqual(code, 0)


def _spans_in_subprocess(data: bytes) -> tuple[int, float]:
    """(number of inline spans in data, seconds the search took), run with a timeout.

    The 20 s timeout only stops a catastrophic regex from hanging the suite.
    The time is measured around the search alone, inside the child, so callers
    can assert it is linear: the quadratic versions took about 10 s on this
    input, which a 20 s timeout alone would not have caught.
    """
    root = os.path.join(os.path.dirname(__file__), "..")
    code = (
        "import sys, time; from pilfer.inline import find_inline_vault_spans\n"
        "data = sys.stdin.buffer.read()\n"
        "start = time.monotonic()\n"
        "count = len(find_inline_vault_spans(data))\n"
        "print(count, time.monotonic() - start)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        input=data,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": root},
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode(errors="replace"))
    count, elapsed = result.stdout.split()
    return int(count), float(elapsed)


class TestInlineHardening(FindKeysBase):
    def test_long_whitespace_line_before_a_vault_block_is_fast(self) -> None:
        from pilfer.inline import find_inline_vault_spans

        path = self._inline()
        data = path.read_bytes()
        # A `!vault |` line with no key but 100 KB of leading spaces, directly
        # before the header, used to take quadratic time in the tag-line regex.
        evil = data.replace(b"  token: !vault |\n", b" " * 100_000 + b"!vault |\n", 1)
        self.assertNotEqual(evil, data)
        count, elapsed = _spans_in_subprocess(evil)
        self.assertEqual(count, 0)
        self.assertLess(elapsed, 3)
        self.assertEqual(len(find_inline_vault_spans(data)), 1)  # normal detection unchanged

    def test_oversized_inline_file_is_refused_before_parsing(self) -> None:
        from pilfer import inline

        path = self._inline()
        before = path.read_bytes()
        with mock.patch.object(inline, "MAX_COMPOSE_BYTES", 16):
            code, out, err = self._main(
                "update", "--include-encrypted-vars", "--file", "inline.yml",
                "-p", str(self.password), "api.token", "new",
            )  # fmt: skip
        self.assertEqual(code, 1, out + err)
        self.assertIn(inline.TOO_LARGE_TO_PARSE, err)
        self.assertEqual(path.read_bytes(), before)

    def test_real_compose_cap_refuses_before_composing(self) -> None:
        from pilfer import inline

        # A small patched cap: composing a real multi-MiB document is slow.
        with mock.patch.object(inline, "MAX_COMPOSE_BYTES", 64):
            with self.assertRaises(inline.OpenedFileError) as ctx:
                inline._compose(b"#" * 65)
            self.assertEqual(str(ctx.exception), inline.TOO_LARGE_TO_PARSE)
            # limit=False is for decrypted whole-file plaintext: no cap.
            inline._compose(b"#" * 65, limit=False)

    def test_repeated_headers_on_one_line_are_linear(self) -> None:
        from pilfer.inline import find_inline_vault_spans

        data = self._inline().read_bytes()
        # A non-matching header followed by N more headers on its line used to
        # rescan that line from every header (800 KB took 39 s).
        evil = b"k: !vault |\nx" + b"$ANSIBLE_VAULT;" * 27_000
        count, elapsed = _spans_in_subprocess(evil)
        self.assertEqual(count, 0)
        self.assertLess(elapsed, 3)
        self.assertEqual(len(find_inline_vault_spans(data)), 1)

    def test_inline_update_keeps_a_crlf_file_all_crlf(self) -> None:
        path = self._inline()
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        code, out, err = self._main(
            "update", "--include-encrypted-vars", "--file", "inline.yml",
            "-p", str(self.password), "api.token", "new",
        )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        data = path.read_bytes()
        self.assertEqual(data.count(b"\n"), data.count(b"\r\n"), data)

    def test_close_and_rekey_keep_a_crlf_file_all_crlf(self) -> None:
        path = self._inline()
        crlf = path.read_bytes().replace(b"\n", b"\r\n")

        def assert_all_crlf(label: str) -> None:
            data = path.read_bytes()
            self.assertEqual(data.count(b"\n"), data.count(b"\r\n"), (label, data))

        path.write_bytes(crlf)
        code, out, err = self._main("open", "-p", str(self.password), "--include-encrypted-vars")
        self.assertEqual(code, 0, out + err)
        assert_all_crlf("open")
        path.write_bytes(path.read_bytes().replace(b"inline-secret-do", b"edited-secret-do"))
        assert_all_crlf("edit")
        code, out, err = self._main("close", "-p", str(self.password))
        self.assertEqual(code, 0, out + err)
        assert_all_crlf("close")
        self.assertIn(b"!vault |\r\n", path.read_bytes())
        new = self._password_file("new-password", "new-password-value")
        code, out, err = self._main(
            "rekey", "--yes", "--include-encrypted-vars",
            "--old-vault-password-file", str(self.password),
            "--new-vault-password-file", str(new),
        )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        assert_all_crlf("rekey")
        self.assertIn(b"!vault |\r\n", path.read_bytes())

    def _escaped_vault_file(self, header: str) -> bytes:
        """A double-quoted !vault scalar whose header is spelled with header."""
        from ansible.parsing.vault import VaultLib, VaultSecret

        cipher = VaultLib([]).encrypt(b"s3cret", secret=VaultSecret(b"pw"), vault_id=None)
        body = cipher.decode().split(";", 1)[1].replace("\n", "\\n")
        return f'k: !vault "{header}{body}"\n'.encode()

    def test_escaped_vault_headers_count_as_skipped(self) -> None:
        from pilfer.inline import find_inline_vault_spans, vault_values_pilfer_skips

        # Ansible reads these as vaults, but they never contain "$ANSIBLE_VAULT;".
        for name, header in {
            "hex escape": "\\x24ANSIBLE_VAULT;",
            "unicode escape": "\\u0024ANSIBLE_VAULT;",
            "long unicode escape": "\\U00000024ANSIBLE_VAULT;",
            "line continuation": "$ANSIBLE_\\\n    VAULT;",
            "plain": "$ANSIBLE_VAULT;",
        }.items():
            with self.subTest(name):
                content = self._escaped_vault_file(header)
                self.assertEqual(find_inline_vault_spans(content), [])
                self.assertEqual(vault_values_pilfer_skips(content), 1, content)

    def test_many_markers_are_read_in_linear_time(self) -> None:
        import time

        from pilfer.inline import read_marked_values

        count = 8000
        content = "".join(f"k{i}: v{i}  # pilfer:vault:{i}\n" for i in range(count)).encode()
        start = time.monotonic()
        marked = read_marked_values(content)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual([m.span_id for m in marked], list(range(count)))
        # Offsets are byte offsets: check a multibyte key shifts later ones.
        text = "é: a  # pilfer:vault:0\nk: b  # pilfer:vault:1\n"
        first, second = read_marked_values(text.encode())
        self.assertEqual((first.start, first.end), (0, len("é: a  # pilfer:vault:0\n".encode())))
        self.assertEqual(second.start, first.end)
        self.assertEqual(second.end, len(text.encode()))

    def test_duplicate_keys_print_no_ansible_warning(self) -> None:
        path = self._inline()
        # Raw terminal escapes in a key that appears twice: Ansible's loader
        # warned with the key text once per duplicate. The scan only composes.
        path.write_bytes(path.read_bytes() + b'"x\\e[2Jy": 1\n"x\\e[2Jy": 2\n')
        root = os.path.join(os.path.dirname(__file__), "..")
        result = subprocess.run(
            [sys.executable, os.path.join(root, "pilfer.py"), "find-keys",
             "--include-encrypted-vars", "-p", str(self.password)],
            capture_output=True, text=True, cwd=self.directory, timeout=60, check=False,
            stdin=subprocess.DEVNULL,
        )  # fmt: skip
        self.assertNotIn("duplicate", result.stderr.lower())
        self.assertNotIn(ESC, result.stdout + result.stderr)
        self.assertIn("inline.yml", result.stdout + result.stderr)

    def test_open_names_unsupported_vault_values_when_nothing_else_is_found(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tree:
            (Path(tree) / "odd.yml").write_text(
                "k: !vault |-\n  $ANSIBLE_VAULT;1.1;AES256\n  3030\n", encoding="utf-8"
            )
            here = os.getcwd()
            os.chdir(tree)
            try:
                code, out, err = self._main(
                    "open", "--include-encrypted-vars", "-p", str(self.password)
                )
            finally:
                os.chdir(here)
        self.assertEqual(code, 0, out + err)
        self.assertIn("No vault files found", out)
        self.assertIn("odd.yml (1)", err)

    def test_update_refuses_a_target_over_the_read_cap(self) -> None:
        from pilfer import vault_set

        before = self.vault.read_bytes()
        with mock.patch.object(vault_set, "MAX_READ_BYTES", 16):
            code, out, err = self._main("update", "-p", str(self.password), "tail", "new")
        self.assertEqual(code, 1, out + err)
        self.assertIn("too large", err)
        self.assertEqual(self.vault.read_bytes(), before)

    def test_update_refuses_an_anchor_shared_inline_key(self) -> None:
        path = self._inline()
        body = path.read_text(encoding="utf-8").split("token: !vault |\n", 1)[1]
        path.write_text(
            f"xdb: &db\n  password: !vault |\n{body}svc:\n  <<: *db\n", encoding="utf-8"
        )
        before = path.read_bytes()
        code, out, err = self._main(
            "update", "--include-encrypted-vars", "--file", "inline.yml",
            "-p", str(self.password), "xdb.password", "new",
        )  # fmt: skip
        self.assertEqual(code, 1, out + err)
        self.assertIn("shared through a YAML anchor", err)
        self.assertEqual(path.read_bytes(), before)


class TestSkippedVaultForms(FindKeysBase):
    """Every spelling of a vault value that pilfer does not handle counts as skipped."""

    def _cipher(self) -> str:
        from ansible.parsing.vault import VaultLib, VaultSecret

        cipher = VaultLib([]).encrypt(b"s3cret", secret=VaultSecret(b"pw"), vault_id=None)
        return cipher.decode()

    def _flow(self) -> str:
        """The ciphertext as the inside of a double-quoted scalar."""
        return self._cipher().replace("\n", "\\n")

    def _block(self, indent: int = 10) -> str:
        return "".join(f"{' ' * indent}{line}\n" for line in self._cipher().splitlines())

    def _forms(self) -> dict[str, tuple[str, str]]:
        flow, block = self._flow(), self._block()
        return {
            "escaped tag on a block": ("yml", f"k: !v%61ult |\n{block}"),
            "escaped tag, no key binding": ("yml", f"k: !%76ault |\n{block}"),
            "verbatim escaped tag": ("yml", f'k: !<!v%61ult> "{flow}"\n'),
            "verbatim tag escaping the bang": ("yml", f'k: !<%21vault> "{flow}"\n'),
            "vault-encrypted tag": ("yml", f'k: !vault-encrypted "{flow}"\n'),
            "tag handle": ("yml", f'%TAG !a! !va\n---\nk: !a!ult "{flow}"\n'),
            "json vault": ("json", json.dumps({"db": {"__ansible_vault": self._cipher()}})),
            "mapping key": ("yml", f'? !vault "{flow}"\n: value\n'),
            "set member": ("yml", f's: !!set\n  ? !vault "{flow}"\n'),
            "omap value": ("yml", f'o: !!omap\n  - a: !vault "{flow}"\n'),
            "list item": ("yml", f"- !vault |\n{block}"),
            # libyaml (which Ansible uses) reads these; pure-Python PyYAML does not,
            # so a compose with it fails and counted 0 next to a handled block.
            "trailing tab, handled block, list item": (
                "yml",
                f"k: !vault |\n{block}note: x\t\nlist:\n  - !vault |\n{block}",
            ),
            "tab after the tag, handled block, list item": (
                "yml",
                f"k: !vault |\n{block}list:\n  - !vault\t|\n{block}",
            ),
            "BOM at column 0 of a later line, handled block, list item": (
                "yml",
                f"k: !vault |\n{block}list:\n\ufeff  - !vault |\n{block}",
            ),
            "decoy in a block scalar": (
                "yml",
                f'real: !vault "{flow}"\ntext: |\n  key: !vault |\n{block}',
            ),
        }

    def test_each_form_counts_as_skipped(self) -> None:
        from pilfer.inline import vault_values_pilfer_skips

        for name, (_ext, text) in self._forms().items():
            with self.subTest(name):
                self.assertEqual(vault_values_pilfer_skips(text.encode()), 1, text)

    def test_handled_forms_count_as_zero(self) -> None:
        from pilfer.inline import vault_values_pilfer_skips

        block = self._block()
        for name, text in {
            "key block": f"k: !vault |\n{block}",
            "key block after a plain key": f"a: 1\nnested:\n  k: !vault |\n{block}",
            "key block in a file with non-ASCII text": f"é: ü\nk: !vault |\n{block}",
            "no vault": "a: 1\n",
            # Marks are character counts in the file, spans are byte counts.
            "long non-ASCII prefix before a handled block": f"{'ü' * 200}: v\nk: !vault |\n{block}",
            "CRLF file": f"k: !vault |\r\n{block.replace(chr(10), chr(13) + chr(10))}",
            "BOM at the start": f"\ufeffk: !vault |\n{block}",
        }.items():
            with self.subTest(name):
                self.assertEqual(vault_values_pilfer_skips(text.encode()), 0, text)

    def test_rekey_refuses_each_form(self) -> None:
        new = self._password_file("new-password", "new-password-value")
        for name, (ext, text) in self._forms().items():
            path = self.directory / f"form.{ext}"
            path.write_text(text, encoding="utf-8")
            try:
                with self.subTest(name):
                    code, out, err = self._main(
                        "rekey", "--yes", "--include-encrypted-vars",
                        "--old-vault-password-file", str(self.password),
                        "--new-vault-password-file", str(new),
                    )  # fmt: skip
                    self.assertEqual(code, 1, out + err)
                    self.assertIn("Rekey refused", err)
                    self.assertEqual(self.vault.read_bytes(), self.before)
            finally:
                path.unlink()

    def test_may_hold_vault_value_matches_every_spelling_and_skips_plain_text(self) -> None:
        from pilfer.inline import may_hold_vault_value

        for text in (
            "k: !vault |",
            "k: !vault-encrypted x",
            "k: !v%61ult x",
            "k: !%76ault x",
            "k: !<!vault> x",
            "k: !<%21vault> x",
            "%TAG !a! !va\n---\nk: !a!ult x\n",
            # YAML line breaks other than LF, and a BOM, before the directive or tag.
            "a: b\x85%TAG !a! !va\n---\nk: !a!ult x\n",
            "a: b\u2028%TAG !a! !va\n---\nk: !a!ult x\n",
            "a: b\u2029%TAG !a! !va\n---\nk: !a!ult x\n",
            "\ufeff%TAG !a! !va\n---\nk: !a!ult x\n",
            '[\u2028!<%21vault> "x"]',
            '{"__ansible_vault": "x"}',
        ):
            with self.subTest(text):
                self.assertTrue(may_hold_vault_value(text.encode()))
        # "y=!0%10" is a tag-shaped run with a real %XX escape, so the regex may
        # answer yes: a false positive costs only a parse, so it is not asserted.
        # The word "vault" in a JSON string, and "!" with "%" in code or a log, are
        # ordinary text: a real %XX escape is needed inside the tag.
        tokenizer = json.dumps({"model": {"vocab": {"vault": 1, "x": 3}}})
        self.assertIn("vault", tokenizer)
        for text in (
            tokenizer,
            "return!e%2?a:b",
            "if(!n%2)x()",
            'printf("Done!%s")',
            "50% sure!",
            '{"!<": 1, "a!<b": 2}',
            # Minified JS: "!" then a non-tag character before any "%XX".
            'x=!0,a="%2F";',
            'if(!n)a(b,"%20")',
        ):
            with self.subTest(text):
                self.assertFalse(may_hold_vault_value(text.encode()))

    def test_template_and_placeholder_bodies_are_not_vaults_to_rekey(self) -> None:
        from pilfer.inline import vault_values_pilfer_skips

        # A .j2 or .example file: Ansible would build a vault from the text, but
        # it holds no ciphertext, so rekey has nothing to strand.
        for name, text in {
            "jinja body": "k: !vault |\n  {{ lookup('env', 'X') }}\n",
            "placeholder body": "k: !vault |\n  <paste ciphertext here>\n",
            "placeholder in a list": "- !vault |\n  <paste ciphertext here>\n",
            "flow placeholder": 'k: !vault "<paste ciphertext here>"\n',
        }.items():
            with self.subTest(name):
                self.assertEqual(vault_values_pilfer_skips(text.encode()), 0, text)

    def test_json_vault_form_follows_ansibles_decoder(self) -> None:
        from pilfer.inline import vault_values_pilfer_skips

        cipher = self._cipher()
        for name, (doc, expected) in {
            "one string vault": ({"a": {"__ansible_vault": cipher}}, 1),
            # Ansible checks __ansible_unsafe first, so this dict is no vault.
            "unsafe wins": ({"a": {"__ansible_unsafe": "x", "__ansible_vault": cipher}}, 0),
            # A non-string value makes Ansible's JSON decoder raise, so the text is
            # read as YAML: the JSON dict is a plain mapping there, not a vault.
            "non-string vault": ({"a": {"__ansible_vault": 5}}, 0),
            "non-string unsafe": (
                {"a": {"__ansible_unsafe": 5}, "b": {"__ansible_vault": cipher}},
                0,
            ),
        }.items():
            with self.subTest(name):
                self.assertEqual(vault_values_pilfer_skips(json.dumps(doc).encode()), expected)
        # The failed JSON parse falls back to YAML, which still finds a real tag.
        text = f'{{"a": {{"__ansible_vault": 5}}, "b": !vault "{self._flow()}"}}'
        self.assertEqual(vault_values_pilfer_skips(text.encode()), 1)

    def test_json_placeholder_vault_strings_count_zero(self) -> None:
        from pilfer.inline import vault_values_pilfer_skips

        # Only a string that starts with the envelope magic is a vault, as in YAML.
        for text in (
            '{"a": {"__ansible_vault": "{{ vault_value }}"}}',
            '{"__ansible_vault": ""}',
            '[{"__ansible_vault": "x"}]',
        ):
            with self.subTest(text):
                self.assertEqual(vault_values_pilfer_skips(text.encode()), 0)
        self.assertEqual(
            vault_values_pilfer_skips(
                json.dumps({"a": {"__ansible_vault": self._cipher()}}).encode()
            ),
            1,
        )

    def test_edited_vault_header_still_counts_as_a_vault(self) -> None:
        from pilfer.inline import (
            find_inline_vault_spans,
            is_whole_file_vault,
            normalize_whole_file_vault,
            vault_values_pilfer_skips,
        )

        # Ansible needs only "$ANSIBLE_VAULT" and ignores header field 0, so an
        # edited header must not hide the value from rekey's skip count.
        cipher = self._cipher().replace("$ANSIBLE_VAULT;", "$ANSIBLE_VAULTx;", 1)
        self.assertIn("VAULTx;", cipher)
        body = "".join(f"    {line}\n" for line in cipher.splitlines())
        for name, text in {
            "list item": f"- !vault |\n{body}",
            "key value": f"k: !vault |\n{body}",
        }.items():
            with self.subTest(name):
                data = text.encode()
                self.assertEqual(find_inline_vault_spans(data), [])
                self.assertEqual(vault_values_pilfer_skips(data), 1)
        whole = cipher.encode()
        self.assertTrue(is_whole_file_vault(whole))
        self.assertEqual(normalize_whole_file_vault(b"\n" + whole), whole)
        self.assertEqual(vault_values_pilfer_skips(whole), 0)

    def test_decoy_on_a_line_with_other_yaml_breaks_does_not_cancel_a_real_vault(self) -> None:
        from pilfer.inline import find_inline_vault_spans, vault_values_pilfer_skips

        cipher = self._cipher()
        for name, brk in {"CR": "\r", "NEL": "\x85", "LS": "\u2028", "PS": "\u2029"}.items():
            # A list item (skipped) and, on the same "\n"-line after YAML breaks, a
            # decoy `key: !vault |` inside a quoted scalar carrying the same ciphertext.
            lines = [f"    {line}" for line in cipher.splitlines()]
            real = "- !vault |" + brk + brk.join(lines) + brk + '- "q' + brk + "key: !vault |"
            text = (
                "top:\n"
                + real
                + "\n"
                + "".join(f"          {line}\n" for line in cipher.splitlines())
                + '"\n'
            )
            with self.subTest(name):
                data = text.encode()
                self.assertEqual(len(find_inline_vault_spans(data)), 1)
                self.assertEqual(vault_values_pilfer_skips(data), 1)

    def test_compose_falls_back_to_ansibles_loader_only_when_asked(self) -> None:
        from pilfer.inline import (
            OpenedFileError,
            _compose,
            _compose_as_ansible,
            count_vault_values,
        )

        data = b"db_port: 5432\t# default\n"
        if _compose_as_ansible(data.decode()) is None:
            self.skipTest("this PyYAML build is as strict as Ansible's loader")
        with self.assertRaises(OpenedFileError) as raised:
            _compose(data)
        self.assertIn("though Ansible reads it", str(raised.exception))
        _text, documents = _compose(data, ansible_fallback=True)
        self.assertEqual(len(documents), 1)
        self.assertEqual(count_vault_values(f"a: !vault |\n{self._block()}"), 1)
        self.assertEqual(count_vault_values("a: [\n"), 0)

    def test_rekey_of_a_real_size_tree_with_minified_js_and_a_printf_log_succeeds(self) -> None:
        from pilfer import inline

        new = self._password_file("new-password", "new-password-value")
        # Both files carry "!" and "%" in the shapes real code and logs do, and
        # are over the compose cap: a wrong "may hold a vault" answer would
        # refuse the whole rekey as "too large to parse". No patching.
        js = b"function f(e,n){return!e%2?a:b;if(!n%2)x();y=!0%3}\n"
        log = b'printf("Done!%s %d%% of !%x");\n'
        (self.directory / "app.min.txt").write_bytes(js * (1_300_000 // len(js)))
        (self.directory / "run.log.txt").write_bytes(log * (1_300_000 // len(log)))
        self.assertGreater(
            (self.directory / "app.min.txt").stat().st_size, inline.MAX_COMPOSE_BYTES
        )
        code, out, err = self._main(
            "rekey", "--yes", "--include-encrypted-vars",
            "--old-vault-password-file", str(self.password),
            "--new-vault-password-file", str(new),
        )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        self.assertNotEqual(self.vault.read_bytes(), self.before)

    def test_rekey_of_a_real_size_file_with_an_escaped_tag_refuses(self) -> None:
        from pilfer import inline

        new = self._password_file("new-password", "new-password-value")
        # A tag spelled with a %XX escape reads as !vault to Ansible; the file is
        # too big to compose, so rekey cannot count it and must refuse.
        data = b"k: !v%61ult x\n" + b"# padding line to reach a real size\n" * 40_000
        self.assertGreater(len(data), inline.MAX_COMPOSE_BYTES)
        (self.directory / "big.yml").write_bytes(data)
        code, out, err = self._main(
            "rekey", "--yes", "--include-encrypted-vars",
            "--old-vault-password-file", str(self.password),
            "--new-vault-password-file", str(new),
        )  # fmt: skip
        self.assertEqual(code, 1, out + err)
        self.assertIn("too large to parse", err)
        self.assertEqual(self.vault.read_bytes(), self.before)

    def test_a_large_file_of_vault_encrypted_tags_is_fast_and_silent(self) -> None:
        from pilfer import inline

        # An envelope body: a tag with no ciphertext is no vault to rekey.
        line = b"- !vault-encrypted $ANSIBLE_VAULT;1.1;AES256\n"
        data = line * (inline.MAX_COMPOSE_BYTES // len(line))
        script = (
            "import sys, time\n"
            "from pilfer.inline import vault_values_pilfer_skips\n"
            "start = time.monotonic()\n"
            "print(vault_values_pilfer_skips(sys.stdin.buffer.read()), time.monotonic() - start)\n"
        )
        here = os.path.dirname(os.path.abspath(__file__))
        result = subprocess.run(
            [sys.executable, "-c", script],
            input=data,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": os.pathsep.join([here, os.path.dirname(here)])},
            timeout=120,
            check=True,
        )
        count, elapsed = result.stdout.split()
        self.assertEqual(int(count), data.count(b"\n"))
        self.assertLess(float(elapsed), 20)
        # Ansible's own loader printed a deprecation warning per !vault-encrypted.
        self.assertEqual(result.stderr, b"")


class TestClassifyBytes(unittest.TestCase):
    def test_a_vault_after_long_whitespace_is_still_a_vault(self) -> None:
        data = b" " * 1000 + b"$ANSIBLE_VAULT;1.1;AES256\n6162\n"
        self.assertEqual(cli._classify_file_bytes("x.yml", data), "file")


class TestSessionEntryKinds(FindKeysBase):
    def _damaged(self, entry: dict) -> None:
        self._session(entry)
        code, _, err = self._status()
        self.assertEqual(code, 2, err)
        self.assertIn("malformed entry", err)

    def _status(self):
        return self._main("status")

    def test_unknown_kind_and_nul_path_are_malformed(self) -> None:
        for entry in (
            {"kind": "weird", "path": "secrets.yml"},
            {"kind": 5, "path": "secrets.yml"},
            {"kind": f"{ESC}[2J", "path": "secrets.yml"},
            {"path": "se\0crets.yml"},
        ):
            with self.subTest(entry=entry):
                self._damaged(entry)

    def test_a_kind_less_entry_for_a_whole_file_vault_closes_to_a_vault(self) -> None:
        self.assertEqual(self._main("open", "-p", str(self.password))[0], 0)
        self.assertNotEqual(self.vault.read_bytes(), self.before)  # plaintext now
        session = Path(cli.temp_vault_file_list_path)
        data = json.loads(session.read_text(encoding="utf-8"))
        for entry in data["entries"]:
            entry.pop("kind", None)
        session.write_text(json.dumps(data), encoding="utf-8")
        code, _out, err = self._main("close", "-p", str(self.password))
        self.assertEqual(code, 0, err)
        self.assertFalse(session.exists())
        closed = self.vault.read_bytes()
        self.assertTrue(closed.startswith(b"$ANSIBLE_VAULT;"))
        self.assertNotIn(b"password", closed)  # no plaintext left

    def test_malformed_entry_names_the_index_and_how_to_recover(self) -> None:
        self._session({"kind": "file", "path": "ok.yml"}, {"kind": "weird", "path": "b.yml"})
        code, _, err = self._main("status")
        self.assertEqual(code, 2)
        self.assertIn("index 1", err)
        self.assertIn("b.yml", err)
        self.assertIn(".vault/", err)
        self.assertIn("pilfer close", err)

    def test_read_session_entry_survives_a_nul_path(self) -> None:
        self.assertIsNone(cli._read_session_entry({"kind": "file", "path": "a\0b"}))


class TestFifoSessionEntry(FindKeysBase):
    def test_close_refuses_a_fifo_entry_instead_of_blocking(self) -> None:
        pipe = self.directory / "pipe.yml"
        os.mkfifo(pipe)
        # A planted backup and hash make close get as far as the target.
        backup_dir = Path(cli._backup_dir_for(str(pipe)))
        backup_dir.mkdir(parents=True)
        (backup_dir / "encrypted").write_bytes(self.vault.read_bytes())
        (backup_dir / "hash").write_text("0" * 64)
        self._session({"kind": "file", "path": str(pipe)})
        self._guard()
        code, _out, err = self._main("close", "-p", str(self.password))
        self.assertEqual(code, 1)
        self.assertIn("non-regular", err)


if __name__ == "__main__":
    unittest.main()
