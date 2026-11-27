"""pilfer status, --dry-run and unchanged-value skipping for set and update."""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_find_keys import INLINE_SECRET, SECRETS, FindKeysBase

from pilfer import cli, vault_secrets
from pilfer.vault_set import DRY_RUN_UNCHECKED


class TestStatus(FindKeysBase):
    def _status(self, *args: str):
        return self._main("status", *args)

    def test_no_session(self) -> None:
        code, out, err = self._status()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, "No session open.\n")
        code, out, _ = self._status("--json")
        self.assertEqual(
            (code, json.loads(out)),
            (0, {"open": False, "incomplete": False, "orphaned": False, "files": []}),
        )

    def test_backups_without_a_session_list_are_reported_as_orphaned(self) -> None:
        self.assertEqual(self._main("open", "-p", str(self.password))[0], 0)
        os.unlink(cli.temp_vault_file_list_path)
        code, out, err = self._status()
        self.assertEqual((code, err), (0, ""))
        self.assertIn("No session list, but .vault/ holds backups", out)
        self.assertIn("pilfer open", out)
        self.assertNotIn("No session open.", out)
        code, out, _ = self._status("--json")
        report = json.loads(out)
        self.assertEqual((code, report["open"], report["orphaned"]), (0, False, True))

    def test_help_explains_orphaned_and_option_order(self) -> None:
        for command, text in (("status", "Orphaned means"), ("find-keys", "between patterns")):
            with self.subTest(command=command):
                out = io.StringIO()
                with mock.patch("sys.stdout", out), self.assertRaises(SystemExit):
                    cli.main([command, "--help"])
                self.assertIn(text, " ".join(out.getvalue().split()))

    def test_lists_files_that_hold_plaintext_without_values(self) -> None:
        self._inline()
        self.assertEqual(
            self._main("open", "-p", str(self.password), "--include-encrypted-vars")[0], 0
        )
        code, out, err = self._status()
        self.assertEqual(code, 0, err)
        self.assertEqual(
            out.splitlines()[0],
            "Session open: 2 files hold plaintext. Run 'pilfer close' to re-encrypt them.",
        )
        self.assertIn("secrets.yml  (whole-file)", out)
        self.assertIn("inline.yml  (inline)", out)
        _, out, _ = self._status("--json")
        report = json.loads(out)
        self.assertEqual((report["open"], report["incomplete"]), (True, False))
        self.assertEqual(
            sorted((f["file"], f["kind"]) for f in report["files"]),
            [("inline.yml", "inline"), ("secrets.yml", "file")],
        )
        self.assertNotIn(INLINE_SECRET, out)
        self.assertNotIn(SECRETS[0], out)
        self.assertEqual(self._main("close", "-p", str(self.password))[0], 0)
        self.assertEqual(self._status()[1], "No session open.\n")

    def test_planted_entries_do_not_hang_status(self) -> None:
        pipe = self.directory / "pipe.yml"
        os.mkfifo(pipe)
        self._session(
            {"kind": "file", "path": str(pipe)},
            {"kind": "file", "path": str(self.directory / "we\x1bird.yml")},
        )
        self._guard()
        code, out, err = self._status()
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_session_entry_reads_are_capped(self) -> None:
        from pilfer import cli

        # A regular file larger than the cap: only the leading bytes come back.
        big = self.directory / "big.yml"
        big.write_bytes(b"x" * (cli._SESSION_INLINE_READ_CAP + 10))
        inline = cli._read_session_entry({"kind": "inline", "path": str(big)})
        self.assertEqual(len(inline), cli._SESSION_INLINE_READ_CAP)
        whole = cli._read_session_entry({"kind": "file", "path": str(big)})
        self.assertEqual(len(whole), cli._HEADER_READ_BYTES)

    def test_long_leading_whitespace_before_the_header_is_still_ciphertext(self) -> None:
        # More than the old 256-byte read: the entry was misreported as plaintext.
        padded = self.directory / "padded.yml"
        padded.write_bytes(b" " * 1000 + self.vault.read_bytes())
        self._session({"kind": "file", "path": str(padded)})
        code, out, err = self._status("--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            json.loads(out), {"open": True, "incomplete": True, "orphaned": False, "files": []}
        )

    def test_interrupted_open_is_incomplete(self) -> None:
        # open lists its targets before decrypting any; killed there, all still ciphertext.
        (self.directory / "vaultedFileList.json").write_text(
            json.dumps({"version": 1, "entries": [{"kind": "file", "path": "secrets.yml"}]})
        )
        code, out, _ = self._status("--json")
        self.assertEqual(
            (code, json.loads(out)),
            (0, {"open": True, "incomplete": True, "orphaned": False, "files": []}),
        )
        self.assertIn("incomplete", self._status()[1])

    def test_damaged_session_list_exits_2(self) -> None:
        (self.directory / "vaultedFileList.json").write_text("not json")
        code, out, err = self._status()
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("pilfer:"), err)


class TestDryRun(FindKeysBase):
    def _snapshot(self):
        stat = self.vault.stat()
        return self.vault.read_bytes(), stat.st_mtime_ns

    def test_set_says_what_it_would_do_and_writes_nothing(self) -> None:
        snapshot = self._snapshot()
        with self._no_value_read():
            for key, expected in (
                ("aws.prod.secret_key", "would update aws.prod.secret_key in secrets.yml"),
                ("brand.new", "would add brand.new in secrets.yml"),
            ):
                with self.subTest(key=key):
                    code, out, err = self._main(
                        "set", "--dry-run", "-p", str(self.password), "secrets.yml", key
                    )
                    self.assertEqual((code, out.splitlines()[0], err), (0, expected, ""))
        self.assertEqual(self._snapshot(), snapshot)

    def test_set_dry_run_checks_a_value_given_on_the_command_line(self) -> None:
        snapshot = self._snapshot()
        base = ("set", "--dry-run", "-p", str(self.password), "secrets.yml")
        code, out, err = self._main(*base, "brand.new", "")
        self.assertEqual(code, 1)
        self.assertIn("empty value", err)
        code, out, err = self._main(*base, "brand.new", "fine")
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines()[0], "would add brand.new in secrets.yml")
        self.assertNotIn("not checked", out)
        self.assertIn("visible in ps", err)
        code, out, _ = self._main(*base, "tail", "done")
        self.assertEqual((code, out.splitlines()[0]), (0, "unchanged tail in secrets.yml"))
        # No VALUE: stdin is not read, and the output says the value went unchecked.
        with self._no_value_read():
            code, out, err = self._main(*base, "brand.new")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines()[-1], DRY_RUN_UNCHECKED)
        self.assertEqual(self._snapshot(), snapshot)

    def test_set_refuses_what_a_real_run_refuses(self) -> None:
        snapshot = self._snapshot()
        for target, key in (("nope.yml", "a"), ("secrets.yml", "a..b"), ("secrets.yml", "tail.x")):
            with self.subTest(target=target, key=key):
                code, _, _ = self._main("set", "--dry-run", "-p", str(self.password), target, key)
                self.assertEqual(code, 1)
        self.assertEqual(self._main("open", "-p", str(self.password))[0], 0)
        code, _, err = self._main(
            "set", "--dry-run", "-p", str(self.password), "secrets.yml", "tail"
        )
        self.assertEqual(code, 1)
        self.assertIn("open in a pilfer session", err)
        self.assertEqual(self._main("close", "-p", str(self.password))[0], 0)
        self.assertEqual(self.vault.read_bytes(), snapshot[0])

    def test_update_previews_whole_file_and_inline_keys(self) -> None:
        inline = self._inline()
        before = inline.read_bytes()
        snapshot = self._snapshot()
        base = ("update", "--dry-run", "-p", str(self.password))
        with self._no_value_read():
            code, out, err = self._main(*base, "aws.prod.secret_key")
            self.assertEqual(
                (code, out.splitlines()[0]),
                (0, "would update aws.prod.secret_key in secrets.yml"),
                err,
            )
            code, out, err = self._main(*base, "--include-encrypted-vars", "api.token")
            self.assertEqual(
                (code, out.splitlines()[0]), (0, "would update api.token in inline.yml"), err
            )
        self.assertEqual(self._snapshot(), snapshot)
        self.assertEqual(inline.read_bytes(), before)

    def test_update_refuses_missing_and_ambiguous_keys(self) -> None:
        self._encrypt("tail: other\n", "other.yml")
        base = ("update", "--dry-run", "-p", str(self.password))
        code, _, err = self._main(*base, "nope.key")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)
        code, _, err = self._main(*base, "tail")
        self.assertEqual(code, 1)
        self.assertIn("--file", err)
        self._assert_untouched()


class TestUnchanged(FindKeysBase):
    def _same_value_leaves_the_file(self, path, argv, expected_line) -> None:
        before = path.read_bytes()
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        code, out, err = self._main(*argv)
        self.assertEqual((code, out.splitlines()[0]), (0, expected_line), err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mtime_ns, 1_000_000_000)

    def test_set_and_update_skip_a_value_already_stored(self) -> None:
        base = ("-p", str(self.password))
        self._same_value_leaves_the_file(
            self.vault,
            ("set", *base, "secrets.yml", "tail", "done"),
            "unchanged tail in secrets.yml",
        )
        self._same_value_leaves_the_file(
            self.vault, ("update", *base, "tail", "done"), "unchanged tail in secrets.yml"
        )

    def test_unsafe_tag_counts_as_part_of_the_value(self) -> None:
        text = "plain: !unsafe 'a{{b'\nother: v\n"
        path = self._encrypt(text, "tagged.yml")
        base = ("-p", str(self.password))
        self._same_value_leaves_the_file(
            path, ("set", *base, "tagged.yml", "plain", "a{{b"), "unchanged plain in tagged.yml"
        )
        # Same text, different representation: a plain value that now needs !unsafe is a change.
        path = self._encrypt("plain: 'a{{b'\n", "plain.yml")
        code, out, _ = self._main("set", *base, "plain.yml", "plain", "a{{b")
        self.assertEqual((code, out.split()[0]), (0, "updated"))
        self.assertIn(b"!unsafe", self._view_text(path))

    def _view_text(self, path) -> bytes:
        from test_vault_set import _vault

        return _vault().decrypt(path.read_bytes())

    def test_inline_value_already_stored_is_skipped_and_other_values_are_not(self) -> None:
        inline = self._inline()
        base = ("update", "-p", str(self.password), "--include-encrypted-vars")
        self._same_value_leaves_the_file(
            inline, (*base, "api.token", INLINE_SECRET), "unchanged api.token in inline.yml"
        )
        code, out, _ = self._main(*base, "api.token", "different")
        self.assertEqual((code, out.split()[0]), (0, "updated"))


class TestNoTerminal(FindKeysBase):
    def test_empty_stdin_names_the_alternative(self) -> None:
        stdin = io.TextIOWrapper(io.BytesIO(b""))
        with mock.patch.object(sys, "stdin", stdin):
            code, _, err = self._main("update", "-p", str(self.password), "tail")
        self.assertEqual(code, 1)
        self.assertIn("Pipe the value on stdin", err)
        self._assert_untouched()

    def test_prompt_without_a_terminal_names_password_file_options(self) -> None:
        with mock.patch.object(vault_secrets, "_can_prompt", return_value=False):
            for argv in (
                ("set", "-J", "secrets.yml", "tail"),
                ("update", "--vault-id", "x@prompt", "tail"),
            ):
                with self.subTest(argv=argv):
                    code, _, err = self._main(*argv)
                    self.assertEqual(code, 1)
                    self.assertIn("-p FILE or --vault-id LABEL@FILE", err)
        self._assert_untouched()

    def test_prompt_is_allowed_with_a_terminal(self) -> None:
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        with mock.patch.object(sys, "stdin", stdin):
            self.assertTrue(vault_secrets._can_prompt())

    def test_rekey_confirmation_needs_a_terminal_or_yes(self) -> None:
        from pilfer.cli import PilferError, _confirm_rekey

        _confirm_rekey(True, action="x")
        with mock.patch.object(sys, "stdin", io.StringIO("REKEY\n")):
            with self.assertRaisesRegex(PilferError, "pass --yes"):
                _confirm_rekey(False, action="x")
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        with (
            mock.patch.object(sys, "stdin", stdin),
            mock.patch("builtins.input", return_value="REKEY"),
        ):
            _confirm_rekey(False, action="x")


if __name__ == "__main__":
    unittest.main()
