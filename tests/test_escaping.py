"""Escaping in error paths, and inline vault values pilfer skips."""

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
from pilfer.cli import safe_text

ESC = "\x1b"


class TestSafeText(unittest.TestCase):
    def test_escapes_what_could_drive_the_terminal(self) -> None:
        self.assertEqual(safe_text(f"a{ESC}b"), "a\\x1bb")
        self.assertEqual(safe_text("a\nb"), "a\\nb")
        self.assertEqual(safe_text("caf\u00e9"), "caf\u00e9")


class TestEscapedErrorPaths(FindKeysBase):
    def test_main_error_line_escapes_a_planted_name(self) -> None:
        name = f"we{ESC}ird.yml"
        code, _, err = self._main("set", "-p", str(self.password), name, "a")
        self.assertEqual(code, 1)
        self.assertNotIn(ESC, err)
        self.assertIn("we\\x1bird.yml", err)


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


class TestInlineHardening(FindKeysBase):
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
        self.assertIn("touches a YAML anchor, alias or << merge", err)
        self.assertEqual(path.read_bytes(), before)


class TestSkippedVaultForms(FindKeysBase):
    """Vault values pilfer does not open count as skipped, and rekey refuses them."""

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
            "list item": ("yml", f"- !vault |\n{block}"),
            "double-quoted flow value": ("yml", f'k: !vault "{flow}"\n'),
            "json vault": ("json", json.dumps({"db": {"__ansible_vault": self._cipher()}})),
            # libyaml (which Ansible uses) reads this; pure-Python PyYAML does not,
            # so a compose with it fails and counted 0 next to a handled block.
            "trailing tab, handled block, list item": (
                "yml",
                f"k: !vault |\n{block}note: x\t\nlist:\n  - !vault |\n{block}",
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
            "no vault": "a: 1\n",
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

    def test_template_body_is_not_a_vault_to_rekey(self) -> None:
        from pilfer.inline import vault_values_pilfer_skips

        # A .j2 file: Ansible would build a vault from the text, but it holds no
        # ciphertext, so rekey has nothing to strand.
        text = "k: !vault |\n  {{ lookup('env', 'X') }}\n"
        self.assertEqual(vault_values_pilfer_skips(text.encode()), 0)


class TestClassifyBytes(unittest.TestCase):
    def test_a_vault_after_long_whitespace_is_still_a_vault(self) -> None:
        data = b" " * 1000 + b"$ANSIBLE_VAULT;1.1;AES256\n6162\n"
        self.assertEqual(cli._classify_file_bytes("x.yml", data), "file")


class TestSessionEntryKinds(FindKeysBase):
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


if __name__ == "__main__":
    unittest.main()
