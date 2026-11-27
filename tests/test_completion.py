"""pilfer completion: the generated scripts parse, and --install writes where the shell looks."""

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pilfer import completion
from pilfer.cli import _build_argument_parser, main

COMMANDS = ("open", "close", "find-keys", "set", "update", "rekey", "completion")


def _script(shell: str) -> str:
    import shtab

    return shtab.complete(_build_argument_parser(), shell=shell)


class CompletionScriptTests(unittest.TestCase):
    def _check(self, shell: str) -> None:
        script = _script(shell)
        for name in COMMANDS:
            self.assertIn(name, script)
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

    def test_bash_goes_under_xdg_data_home_when_set(self):
        os.environ["XDG_DATA_HOME"] = str(self.home / "xdg")
        self.assertEqual(main(["completion", "--install", "bash"]), 0)
        self.assertTrue((self.home / "xdg/bash-completion/completions/pilfer").is_file())

    def test_bash_defaults_to_local_share(self):
        self.assertEqual(main(["completion", "--install", "bash"]), 0)
        target = self.home / ".local/share/bash-completion/completions/pilfer"
        self.assertTrue(target.is_file())

    def test_zsh_uses_a_writable_fpath_dir_under_home(self):
        site = self.home / "zsh-site"
        site.mkdir()
        with mock.patch.object(completion, "_zsh_fpath_dir", return_value=site):
            self.assertEqual(main(["completion", "--install", "zsh"]), 0)
        self.assertTrue((site / "_pilfer").is_file())

    def test_zsh_falls_back_to_zfunc(self):
        with mock.patch.object(completion, "_zsh_fpath_dir", return_value=None):
            self.assertEqual(main(["completion", "--install", "zsh"]), 0)
        self.assertTrue((self.home / ".zfunc/_pilfer").is_file())

    def test_unsupported_shell_is_refused_and_writes_nothing(self):
        self.assertEqual(main(["completion", "--install"]), 1)  # $SHELL is fish
        self.assertEqual(list(self.home.iterdir()), [])

    def test_fpath_probe_failure_means_no_directory(self):
        with mock.patch.object(completion.subprocess, "run", side_effect=OSError):
            self.assertIsNone(completion._zsh_fpath_dir(self.home))


if __name__ == "__main__":
    unittest.main()
