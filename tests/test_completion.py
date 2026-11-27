"""pilfer completion: the generated scripts parse, and --install writes where the shell looks."""

import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Before anything imports ansible: see _ansible_isolation.
import _ansible_isolation  # noqa: F401

from pilfer.cli import _build_argument_parser, main

COMMANDS = ("open", "close", "find-keys", "set", "update", "rekey", "completion")


def _script(shell: str) -> str:
    import shtab

    return shtab.complete(_build_argument_parser(), shell=shell)


class CompletionScriptTests(unittest.TestCase):
    def _check(self, shell: str) -> None:
        script = _script(shell)
        for name in COMMANDS:
            # A subcommand's own entry, not the word inside another command's text:
            # zsh lists `  name:'help'`, bash a `_subparsers=(a b c)` array.
            entry = (
                rf"^\s+{re.escape(name)}:'"
                if shell == "zsh"
                else rf"_subparsers=\(.*\b{re.escape(name)}\b"
            )
            self.assertRegex(script, re.compile(entry, re.M))
        if shutil.which(shell) is None:
            self.skipTest(f"{shell} is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "script"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                [shell, "-n", str(path)], capture_output=True, text=True, check=False
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bash_script_parses(self):
        self._check("bash")

    def test_zsh_script_parses(self):
        self._check("zsh")


class CompletionInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        env = {"HOME": str(self.home), "SHELL": "/bin/fish"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("XDG_DATA_HOME", None)
        quiet = contextlib.ExitStack()
        quiet.enter_context(contextlib.redirect_stdout(io.StringIO()))
        quiet.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.addCleanup(quiet.close)

    def test_bash_defaults_to_local_share(self):
        self.assertEqual(main(["completion", "--install", "bash"]), 0)
        target = self.home / ".local/share/bash-completion/completions/pilfer"
        self.assertTrue(target.is_file())

    def test_zsh_goes_under_zfunc(self):
        self.assertEqual(main(["completion", "--install", "zsh"]), 0)
        self.assertTrue((self.home / ".zfunc/_pilfer").is_file())

    def test_unsupported_shell_is_refused_and_writes_nothing(self):
        self.assertEqual(main(["completion", "--install"]), 1)  # $SHELL is fish
        self.assertEqual(list(self.home.iterdir()), [])

    def test_install_refuses_a_symlink_target(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.write_text("keep", encoding="utf-8")
        target = self.home / ".local/share/bash-completion/completions/pilfer"
        target.parent.mkdir(parents=True)
        target.symlink_to(elsewhere)
        self.assertEqual(main(["completion", "--install", "bash"]), 1)
        self.assertEqual(elsewhere.read_text(encoding="utf-8"), "keep")
        self.assertTrue(target.is_symlink())

    def test_install_names_a_dangling_zfunc_symlink(self):
        (self.home / ".zfunc").symlink_to(self.home / "gone")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main(["completion", "--install", "zsh"]), 1)
        self.assertIn(str(self.home / ".zfunc"), err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()
