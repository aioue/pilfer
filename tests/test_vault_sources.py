"""Vault password sources, loaded as ansible-vault loads them (issue #18).

Each test is a project in a temporary directory, driven through pilfer.py in a
subprocess: ansible.constants reads the config at import, so ansible.cfg and
ANSIBLE_* changes need a fresh process. Results are checked with VaultLib
holding one secret at a time, so a value under the wrong password fails.
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Before anything imports ansible: see the module.
import _ansible_isolation  # noqa: F401
import yaml
from ansible.errors import AnsibleError
from ansible.parsing.vault import VaultLib, VaultSecret

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PILFER_SCRIPT = Path(__file__).resolve().parents[1] / "pilfer.py"


class _VaultTagLoader(yaml.SafeLoader):
    """Reads a closed file: !vault values stay ciphertext strings."""


_VaultTagLoader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))


def only(password: str, label: str = "default") -> VaultLib:
    """A VaultLib with exactly one secret."""
    return VaultLib([(label, VaultSecret(password.encode("utf-8")))])


def inline(name: str, ciphertext: bytes) -> str:
    body = "\n".join("  " + line for line in ciphertext.decode().strip().splitlines())
    return f"{name}: !vault |\n{body}\n"


class ProjectTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        # The test's own ansible.cfg, or none: ANSIBLE_CONFIG would beat ./ansible.cfg.
        self.env = {k: v for k, v in os.environ.items() if k != "ANSIBLE_CONFIG"}
        self.write_cfg("")

    def write(self, name: str, data, mode: int | None = None) -> Path:
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        if mode is not None:
            os.chmod(path, mode)
        return path

    def write_cfg(self, defaults: str) -> None:
        self.write("ansible.cfg", "[defaults]\n" + textwrap.dedent(defaults))

    def password_file(self, name: str, password: str) -> Path:
        return self.write(name, password + "\n", 0o600)

    def script(self, name: str, password: str) -> Path:
        """A password script that logs each run (and its arguments) to <name>.log."""
        log = self.dir / f"{name}.log"
        return self.write(
            name,
            f'#!/bin/sh\necho "$*" >> "{log}"\nprintf "%s\\n" "{password}"\n',
            0o700,
        )

    def runs(self, script: Path) -> list[str]:
        log = script.parent / f"{script.name}.log"
        return log.read_text().splitlines() if log.exists() else []

    def pilfer(
        self,
        *args: str,
        env: dict | None = None,
        answers: str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess:
        """Run pilfer.py in cwd (the project). answers is piped to stdin for a prompt."""
        return subprocess.run(
            [sys.executable, str(PILFER_SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=cwd or self.dir,
            input=answers,
            stdin=None if answers is not None else subprocess.DEVNULL,
            env={**self.env, **(env or {})},
            # No controlling terminal, so a prompt reads the piped answers
            # instead of /dev/tty (which would hang a test run from a terminal).
            start_new_session=True,
            # A test run in the background inherits SIGINT ignored, and then
            # Python never turns ctrl-c into KeyboardInterrupt.
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
        )

    def ok(self, result: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def refused(self, result: subprocess.CompletedProcess, text: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(text, result.stderr)

    def edit(self, name: str, old: str, new: str) -> None:
        path = self.dir / name
        content = path.read_text()
        self.assertIn(old, content)
        path.write_text(content.replace(old, new))

    def inline_values(self, name: str) -> dict:
        return yaml.load((self.dir / name).read_text(), Loader=_VaultTagLoader)


class TestPasswordScripts(ProjectTest):
    def test_script_from_ansible_cfg_opens_and_closes(self):
        # Issue #18: an executable vault_password_file is run, not read.
        script = self.script("vault-pass.sh", "from-the-keyring")
        self.write_cfg(f"vault_password_file = {script.name}\n")
        self.write("secret.yml", only("from-the-keyring").encrypt(b"token: old\n"))

        self.ok(self.pilfer("open"))
        self.assertEqual((self.dir / "secret.yml").read_text(), "token: old\n")
        self.assertEqual(len(self.runs(script)), 1, "open must run the script once")
        self.edit("secret.yml", "old", "new")
        self.ok(self.pilfer("close"))
        self.assertEqual(len(self.runs(script)), 2, "close must run the script once")

        closed = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(only("from-the-keyring").decrypt(closed), b"token: new\n")

    def test_script_given_with_dash_p(self):
        script = self.script("vault-pass.sh", "scripted")
        self.write("secret.yml", only("scripted").encrypt(b"token: x\n"))
        self.ok(self.pilfer("open", "-p", str(script)))
        self.ok(self.pilfer("close", "-p", str(script)))
        self.assertEqual(len(self.runs(script)), 2)

    def test_client_script_is_passed_its_vault_id(self):
        client = self.script("keyring-client.sh", "prod-password")
        self.write(
            "secret.yml",
            only("prod-password", "prod").encrypt(b"token: x\n", vault_id="prod"),
        )
        self.ok(self.pilfer("open", "--vault-id", f"prod@{client}"))
        self.ok(self.pilfer("close", "--vault-id", f"prod@{client}"))
        self.assertEqual(self.runs(client), ["--vault-id prod", "--vault-id prod"])

    def test_failing_script_is_an_error_not_a_wrong_password(self):
        failing = self.write("vault-pass.sh", "#!/bin/sh\nexit 3\n", 0o700)
        self.write("secret.yml", only("x").encrypt(b"token: x\n"))
        # The script's path and a failed open: the exit-code wording is ansible-core's.
        self.refused(self.pilfer("open", "-p", str(failing)), failing.name)
        self.assertFalse((self.dir / "vaultedFileList.json").exists())

    def test_set_runs_the_script_once(self):
        script = self.script("vault-pass.sh", "scripted")
        self.write("secret.yml", only("scripted").encrypt(b"token: old\n"))
        self.ok(self.pilfer("set", "-p", str(script), "secret.yml", "token", "new"))
        self.assertEqual(len(self.runs(script)), 1)
        decrypted = only("scripted").decrypt((self.dir / "secret.yml").read_bytes())
        self.assertEqual(yaml.safe_load(decrypted), {"token": "new"})


class TestAnsibleConfig(ProjectTest):
    def test_ansible_vault_password_file_variable(self):
        pass_file = self.password_file("from-env", "env-password")
        self.write("secret.yml", only("env-password").encrypt(b"token: x\n"))
        self.ok(self.pilfer("open", env={"ANSIBLE_VAULT_PASSWORD_FILE": str(pass_file)}))
        self.assertEqual((self.dir / "secret.yml").read_text(), "token: x\n")

    def test_ansible_config_variable_points_elsewhere(self):
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere)
        (elsewhere / "pass").write_text("cfg-password\n")
        (elsewhere / "ansible.cfg").write_text("[defaults]\nvault_password_file = pass\n")
        self.write("secret.yml", only("cfg-password").encrypt(b"token: x\n"))
        self.ok(self.pilfer("open", env={"ANSIBLE_CONFIG": str(elsewhere / "ansible.cfg")}))

    def test_no_source_at_all_is_refused(self):
        self.write("secret.yml", only("x").encrypt(b"token: x\n"))
        # HOME without ~/.ansible-vault/.vault-file, so no fallback path exists.
        self.refused(self.pilfer("open", env={"HOME": str(self.dir)}), "No vault password source")


class TestTwoVaultIds(ProjectTest):
    """vault_identity_list with dev and prod: each value stays under its own password."""

    def setUp(self):
        super().setUp()
        self.password_file("dev-pass", "dev-password")
        self.password_file("prod-pass", "prod-password")
        self.write_cfg("vault_identity_list = dev@dev-pass, prod@prod-pass\n")
        self.dev, self.prod = only("dev-password", "dev"), only("prod-password", "prod")
        self.write("dev.yml", self.dev.encrypt(b"where: dev\n", vault_id="dev"))
        self.write("prod.yml", self.prod.encrypt(b"where: prod\n", vault_id="prod"))
        self.write(
            "mixed.yml",
            inline("dev_token", self.dev.encrypt(b"dev-old", vault_id="dev"))
            + inline("prod_token", self.prod.encrypt(b"prod-old", vault_id="prod")),
        )

    def test_close_encrypts_each_value_with_its_own_password(self):
        self.ok(self.pilfer("open", "--include-encrypted-vars"))
        self.edit("dev.yml", "where: dev", "where: dev-edited")
        self.edit("prod.yml", "where: prod", "where: prod-edited")
        self.edit("mixed.yml", "dev-old", "dev-new")
        self.edit("mixed.yml", "prod-old", "prod-new")
        self.ok(self.pilfer("close"))

        for name, vault, other, label in (
            ("dev.yml", self.dev, self.prod, "dev"),
            ("prod.yml", self.prod, self.dev, "prod"),
        ):
            data = (self.dir / name).read_bytes()
            self.assertTrue(data.startswith(f"$ANSIBLE_VAULT;1.2;AES256;{label}\n".encode()))
            self.assertEqual(vault.decrypt(data), f"where: {label}-edited\n".encode())
            with self.assertRaises(AnsibleError):
                other.decrypt(data)

        values = self.inline_values("mixed.yml")
        self.assertEqual(self.dev.decrypt(values["dev_token"]), b"dev-new")
        self.assertEqual(self.prod.decrypt(values["prod_token"]), b"prod-new")
        self.assertTrue(values["prod_token"].startswith("$ANSIBLE_VAULT;1.2;AES256;prod"))
        with self.assertRaises(AnsibleError):
            self.dev.decrypt(values["prod_token"])

    def test_close_without_one_of_the_ids_writes_nothing(self):
        self.ok(self.pilfer("open"))
        self.edit("dev.yml", "where: dev", "where: changed")
        before = (self.dir / "prod.yml").read_bytes()
        # Only dev's password: the prod backup cannot be proved, so nothing closes.
        self.write_cfg("vault_identity_list = dev@dev-pass\n")
        self.refused(self.pilfer("close"), "does not match")
        self.assertEqual((self.dir / "dev.yml").read_text(), "where: changed\n")
        self.assertEqual((self.dir / "prod.yml").read_bytes(), before)
        self.assertTrue((self.dir / "vaultedFileList.json").exists())

    def test_rekey_refuses_a_tree_on_two_passwords(self):
        before = (self.dir / "dev.yml").read_bytes()
        self.password_file("new-pass", "new-password")
        self.refused(
            self.pilfer("rekey", "--new-vault-password-file", "new-pass", "--yes"),
            "2 different vault passwords",
        )
        self.assertEqual((self.dir / "dev.yml").read_bytes(), before)


class TestRekeySources(ProjectTest):
    def setUp(self):
        super().setUp()
        self.old = self.password_file("old-pass", "old-password")
        self.new = self.password_file("new-pass", "new-password")
        self.write("plain.yml", only("old-password").encrypt(b"a: 1\n"))
        self.write("labelled.yml", only("old-password", "prod").encrypt(b"b: 2\n", vault_id="prod"))

    def rekey(self, *args: str) -> subprocess.CompletedProcess:
        return self.pilfer("rekey", "--old-vault-password-file", "old-pass", *args, "--yes")

    def test_password_file_keeps_each_label(self):
        self.ok(self.rekey("--new-vault-password-file", "new-pass"))
        plain = (self.dir / "plain.yml").read_bytes()
        labelled = (self.dir / "labelled.yml").read_bytes()
        self.assertTrue(plain.startswith(b"$ANSIBLE_VAULT;1.1;AES256\n"))
        self.assertTrue(labelled.startswith(b"$ANSIBLE_VAULT;1.2;AES256;prod\n"))
        self.assertEqual(only("new-password").decrypt(plain), b"a: 1\n")
        self.assertEqual(only("new-password", "prod").decrypt(labelled), b"b: 2\n")

    def test_new_vault_id_label_relabels(self):
        self.ok(self.rekey("--new-vault-id", "next@new-pass"))
        for name in ("plain.yml", "labelled.yml"):
            data = (self.dir / name).read_bytes()
            self.assertTrue(data.startswith(b"$ANSIBLE_VAULT;1.2;AES256;next\n"), name)
            only("new-password", "next").decrypt(data)

    def test_new_password_from_a_script(self):
        script = self.script("new.sh", "scripted-new")
        self.ok(self.rekey("--new-vault-password-file", str(script)))
        self.assertEqual(len(self.runs(script)), 1)
        only("scripted-new").decrypt((self.dir / "plain.yml").read_bytes())

    def test_new_vault_id_without_a_label_passes_the_client_no_vault_id(self):
        # ansible-vault hands a -client script --vault-id only for a label; a
        # password file given by flag is the default label, so it gets one.
        client = self.script("log-client", "scripted-new")
        self.ok(self.rekey("--new-vault-id", "./log-client"))
        self.assertEqual(self.runs(client), [""])
        only("scripted-new").decrypt((self.dir / "plain.yml").read_bytes())

    def test_new_vault_password_file_client_gets_the_default_vault_id(self):
        client = self.script("log-client", "scripted-new")
        self.ok(self.rekey("--new-vault-password-file", str(client)))
        self.assertEqual(self.runs(client), ["--vault-id default"])

    def test_new_vault_id_label_that_core_cannot_write_back_is_refused(self):
        # ';' ends the header, a non-ASCII byte makes is_encrypted reject the
        # blob, and spaces at the ends are stripped on read (so "   " would
        # silently become no label).
        before = (self.dir / "plain.yml").read_bytes()
        for label in ("a;b", "a\x01b", "a\nb", "a\tb", "é", " dev", "dev ", "   "):
            with self.subTest(label=label):
                result = self.rekey("--new-vault-id", f"{label}@new-pass")
                self.refused(result, "labels must be ASCII")
                self.assertEqual((self.dir / "plain.yml").read_bytes(), before)

    def test_new_vault_id_labels_core_can_write_back_are_accepted(self):
        for label in ("dev", "prod-1", "a.b"):
            with self.subTest(label=label):
                self.ok(
                    self.pilfer(
                        "rekey",
                        "--old-vault-password-file",
                        "old-pass",
                        "--yes",
                        "--new-vault-id",
                        f"{label}@new-pass",
                    )
                )
                data = (self.dir / "plain.yml").read_bytes()
                self.assertTrue(data.startswith(f"$ANSIBLE_VAULT;1.2;AES256;{label}\n".encode()))
                # Back to the old password for the next label.
                self.ok(
                    self.pilfer(
                        "rekey",
                        "--old-vault-password-file",
                        "new-pass",
                        "--yes",
                        "--new-vault-password-file",
                        "old-pass",
                    )
                )

    def test_new_equal_to_the_ansible_cfg_password_is_refused(self):
        # ansible.cfg's password loads on the old side too; equal to new, rekey
        # would take every old file for one already on the new password.
        self.write_cfg("vault_password_file = new-pass\n")
        before = (self.dir / "plain.yml").read_bytes()
        self.refused(self.rekey("--new-vault-password-file", "new-pass"), "same as an old one")
        self.assertEqual((self.dir / "plain.yml").read_bytes(), before)

    def test_mistyped_new_password_file_is_refused(self):
        # setup_vault_secrets would warn and carry on with ansible.cfg's
        # password; the new side is loaded on its own so a typo stops rekey.
        self.write_cfg("vault_password_file = old-pass\n")
        self.refused(self.rekey("--new-vault-password-file", "no-such-file"), "no-such-file")

    def test_rotation_refuses_a_password_script(self):
        script = self.script("old.sh", "old-password")
        before = {n: (self.dir / n).read_bytes() for n in ("plain.yml", "labelled.yml")}
        script_before = script.read_bytes()
        for old, new in ((str(script), "new-pass"), ("old-pass", str(self.script("n.sh", "n")))):
            with self.subTest(old=old, new=new):
                result = self.pilfer(
                    "rekey",
                    "--old-vault-password-file",
                    old,
                    "--new-vault-password-file",
                    new,
                    "--rotate-password-file",
                    "--yes",
                )
                self.refused(result, "is a script")
        self.assertEqual(script.read_bytes(), script_before)
        self.assertTrue(os.access(script, os.X_OK))
        self.assertFalse((self.dir / "old.sh_old").exists())
        for name, data in before.items():
            self.assertEqual((self.dir / name).read_bytes(), data)

    def test_rotation_still_works_with_plain_files(self):
        self.ok(self.rekey("--new-vault-password-file", "new-pass", "--rotate-password-file"))
        self.assertEqual(self.old.read_text().strip(), "new-password")
        self.assertEqual((self.dir / "old-pass_old").read_text().strip(), "old-password")


class TestValuesPilferSkips(ProjectTest):
    """Ansible's own loader lists the !vault values; pilfer says which it cannot handle."""

    def setUp(self):
        super().setUp()
        self.password_file("pass", "pw")
        self.write_cfg("vault_password_file = pass\n")
        vault = only("pw")
        list_item = "\n".join(
            "      " + line for line in vault.encrypt(b"in-a-list").decode().strip().splitlines()
        )
        self.content = (
            inline("handled", vault.encrypt(b"plain-block"))
            + f"items:\n  - !vault |\n{list_item}\n"
        )
        self.write("vars.yml", self.content)

    def test_open_warns_and_leaves_them_encrypted(self):
        result = self.ok(self.pilfer("open", "--include-encrypted-vars"))
        self.assertIn("1 !vault value(s)", result.stderr)
        self.assertIn("vars.yml (1)", result.stderr)
        opened = (self.dir / "vars.yml").read_text()
        self.assertIn('handled: "plain-block"', opened)
        self.assertNotIn("in-a-list", opened)
        self.ok(self.pilfer("close"))
        self.assertEqual((self.dir / "vars.yml").read_text(), self.content)

    def test_rekey_refuses(self):
        self.password_file("new", "new-pw")
        self.refused(
            self.pilfer("rekey", "--new-vault-password-file", "new", "--yes"),
            "would stay on the old password",
        )
        self.assertEqual((self.dir / "vars.yml").read_text(), self.content)

    def test_set_on_a_file_with_inline_values_points_at_open(self):
        result = self.pilfer("set", "vars.yml", "k", "v")
        self.refused(result, "pilfer open --include-encrypted-vars")
        self.assertNotIn("pilfer close", result.stderr)
        self.assertEqual((self.dir / "vars.yml").read_text(), self.content)

    def test_whole_file_open_does_not_check(self):
        # Inline values are not opened without --include-encrypted-vars, so the
        # check is not run and nothing is said about them.
        self.write("whole.yml", only("pw").encrypt(b"a: 1\n"))
        result = self.ok(self.pilfer("open"))
        self.assertNotIn("!vault value(s)", result.stderr)
        self.ok(self.pilfer("close"))


class TestUnusedExplicitPassword(ProjectTest):
    """ansible.cfg's password always loads beside -p, so a wrong -p no longer fails alone."""

    def setUp(self):
        super().setUp()
        self.cfg_pass = self.password_file("cfg-pass", "cfg-password")
        self.other = self.password_file("other-pass", "other-password")
        self.write_cfg("vault_password_file = cfg-pass\n")
        self.write("secret.yml", only("cfg-password").encrypt(b"token: old\n"))

    def test_close_refuses_a_password_that_opened_nothing(self):
        self.ok(self.pilfer("open"))
        self.edit("secret.yml", "old", "new")
        result = self.pilfer("close", "-p", "other-pass")
        # The unused-flag refusal, not the one for a password that decrypts no backup
        # ("Use the same -p").
        self.refused(result, "drop the flag")
        self.assertEqual((self.dir / "secret.yml").read_text(), "token: new\n")
        self.assertTrue((self.dir / "vaultedFileList.json").exists())
        # The password open used, given explicitly or not, closes.
        self.ok(self.pilfer("close", "-p", "cfg-pass"))
        data = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(only("cfg-password").decrypt(data), b"token: new\n")

    def test_close_refuses_a_password_file_that_failed_to_load(self):
        self.ok(self.pilfer("open"))
        self.edit("secret.yml", "old", "new")
        result = self.pilfer("close", "-p", "no-such-file")
        self.refused(result, "fix or drop the flag")
        self.assertTrue((self.dir / "vaultedFileList.json").exists())

    def test_close_refuses_a_vault_id_that_opened_nothing(self):
        self.ok(self.pilfer("open"))
        # No label, or the default one: could be a rotation attempt.
        for slug in ("other-pass", "default@other-pass"):
            with self.subTest(slug=slug):
                self.refused(self.pilfer("close", "--vault-id", slug), f"--vault-id {slug}")
        # A label no backup carries cannot be the password of any of them: warn.
        result = self.ok(self.pilfer("close", "--vault-id", "new@other-pass"))
        self.assertIn("--vault-id new@other-pass decrypted none", result.stderr)

    def test_open_warns_for_a_wrong_or_missing_dash_p(self):
        for flag in ("other-pass", "no-such-file"):
            with self.subTest(flag=flag):
                result = self.ok(self.pilfer("open", "-p", flag))
                # The path as Ansible unfracks it: /var is /private/var on macOS.
                self.assertIn(f"/{flag} decrypted none", result.stderr)
                self.ok(self.pilfer("close"))

    def test_set_warns_for_a_wrong_dash_p(self):
        result = self.ok(self.pilfer("set", "-p", "other-pass", "secret.yml", "token", "set"))
        self.assertIn("decrypted none of secret.yml", result.stderr)
        data = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(yaml.safe_load(only("cfg-password").decrypt(data)), {"token": "set"})

    def test_no_warning_when_dash_p_is_the_config_password(self):
        # Loaded twice (-p and ansible.cfg); either copy counts.
        opened = self.ok(self.pilfer("open", "-p", "cfg-pass"))
        closed = self.ok(self.pilfer("close", "-p", "cfg-pass"))
        self.assertNotIn("decrypted none", opened.stderr + closed.stderr)

    def test_no_warning_when_each_dash_p_decrypts_something(self):
        self.write("other.yml", only("other-password").encrypt(b"x: 1\n"))
        opened = self.ok(self.pilfer("open", "-p", "other-pass"))
        self.assertNotIn("decrypted none", opened.stderr)
        self.ok(self.pilfer("close", "-p", "other-pass"))


class TestFallbackPasswordFiles(ProjectTest):
    """With no flag and no config, the fallback files are read as data, never run."""

    def setUp(self):
        super().setUp()
        # An empty home: no ~/.ansible-vault/.vault-file unless a test makes one.
        self.home = self.dir / "home"
        self.home.mkdir()
        self.env["HOME"] = str(self.home)

    def test_an_executable_fallback_is_read_not_run(self):
        # A cloned repo can ship an executable vault_password_file. Its text is
        # the password here, so opening proves it was read; the marker proves
        # it was not run.
        marker = self.dir / "ran"
        text = f'#!/bin/sh\ntouch "{marker}"\n'
        self.write("vault_password_file", text, 0o700)
        self.write("secret.yml", only(text.strip()).encrypt(b"token: old\n"))
        self.ok(self.pilfer("open"))
        self.assertEqual((self.dir / "secret.yml").read_text(), "token: old\n")
        self.edit("secret.yml", "old", "new")
        self.ok(self.pilfer("close"))
        self.assertFalse(marker.exists(), "the fallback file was run")
        data = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(only(text.strip()).decrypt(data), b"token: new\n")

    def test_fallback_order_with_real_files(self):
        project = self.dir / "x" / "y"
        project.mkdir(parents=True)
        (self.home / ".ansible-vault").mkdir()
        (self.home / ".ansible-vault" / ".vault-file").write_text("home-password\n")
        (project / ".vault_password").write_text("dot-password\n")
        (project / "vault_password_file").write_text("local-password\n")
        (self.dir / "vault_password_file").write_text("far-password\n")
        (project / "secret.yml").write_bytes(only("home-password").encrypt(b"token: x\n"))
        self.ok(self.pilfer("open", cwd=project))
        self.assertEqual((project / "secret.yml").read_text(), "token: x\n")
        self.ok(self.pilfer("close", cwd=project))
        # Without the home file, the next name in the list wins.
        (self.home / ".ansible-vault" / ".vault-file").unlink()
        (project / "secret.yml").write_bytes(only("dot-password").encrypt(b"token: x\n"))
        self.ok(self.pilfer("open", cwd=project))
        self.ok(self.pilfer("close", cwd=project))
        # And the parent-relative file is last.
        (project / ".vault_password").unlink()
        (project / "vault_password_file").unlink()
        (project / "secret.yml").write_bytes(only("far-password").encrypt(b"token: x\n"))
        self.ok(self.pilfer("open", cwd=project))


class TestCloseUnusedFlags(ProjectTest):
    """One -client script, several --vault-id flags: each flag is judged on its own."""

    def setUp(self):
        super().setUp()
        self.client = self.write(
            "x-client",
            '#!/bin/sh\ncase "$2" in\n  dev) echo dev-password;;\n  prod) echo prod-password;;\nesac\n',
            0o700,
        )
        # Absolute: some tests run from the sub directory.
        self.dev_flag = f"--vault-id dev@{self.client}"
        self.prod_flag = f"--vault-id prod@{self.client}"
        self.flags = (*self.dev_flag.split(), *self.prod_flag.split())
        self.dev, self.prod = only("dev-password", "dev"), only("prod-password", "prod")
        self.write("prod.yml", self.prod.encrypt(b"where: prod\n", vault_id="prod"))
        self.write("sub/dev.yml", self.dev.encrypt(b"where: dev\n", vault_id="dev"))
        self.sub = self.dir / "sub"

    def test_a_flag_is_judged_by_its_own_secret(self):
        # A tree with only a prod file: the dev flag is unused, the prod flag is not.
        (self.sub / "dev.yml").unlink()
        opened = self.ok(self.pilfer("open", *self.flags))
        self.assertIn(f"{self.dev_flag} decrypted none", opened.stderr)
        self.assertNotIn(f"{self.prod_flag} decrypted none", opened.stderr)
        self.edit("prod.yml", "prod", "prod-edited")
        closed = self.ok(self.pilfer("close", *self.flags))
        self.assertIn(f"{self.dev_flag} decrypted none", closed.stderr)
        self.assertNotIn(f"{self.prod_flag} decrypted none", closed.stderr)
        data = (self.dir / "prod.yml").read_bytes()
        self.assertEqual(self.prod.decrypt(data), b"where: prod-edited\n")

    def test_a_label_the_session_does_not_hold_is_a_warning_on_close(self):
        # A session of dev files only, opened from a subdirectory.
        opened = self.ok(self.pilfer("open", *self.flags, cwd=self.sub))
        self.assertIn(f"{self.prod_flag} decrypted none", opened.stderr)
        self.assertNotIn(f"{self.dev_flag} decrypted none", opened.stderr)
        closed = self.ok(self.pilfer("close", *self.flags, cwd=self.sub))
        self.assertIn(f"{self.prod_flag} decrypted none", closed.stderr)
        self.assertFalse((self.sub / "vaultedFileList.json").exists())

    def test_a_wrong_password_for_a_label_in_the_session_is_refused(self):
        self.password_file("wrong-pass", "wrong")
        identities = {"ANSIBLE_VAULT_IDENTITY_LIST": f"dev@{self.client}"}
        self.ok(self.pilfer("open", env=identities, cwd=self.sub))
        self.edit("sub/dev.yml", "dev", "dev-edited")
        result = self.pilfer(
            "close", "--vault-id", "dev@../wrong-pass", env=identities, cwd=self.sub
        )
        self.refused(result, "--vault-id dev@../wrong-pass")
        self.assertTrue((self.sub / "vaultedFileList.json").exists())
        self.assertEqual((self.sub / "dev.yml").read_text(), "where: dev-edited\n")

    def test_a_wrong_dash_p_is_still_refused(self):
        self.password_file("wrong-pass", "wrong")
        identities = {"ANSIBLE_VAULT_IDENTITY_LIST": f"dev@{self.client},prod@{self.client}"}
        self.ok(self.pilfer("open", env=identities))
        result = self.pilfer("close", "-p", "wrong-pass", env=identities)
        self.refused(result, "-p ")


class TestInteractiveSources(ProjectTest):
    """Prompts, driven through pilfer with the answers piped to stdin."""

    def test_dash_J_opens_and_closes(self):
        self.write("secret.yml", only("typed").encrypt(b"token: old\n"))
        self.ok(self.pilfer("open", "-J", answers="typed\n"))
        self.assertEqual((self.dir / "secret.yml").read_text(), "token: old\n")
        self.edit("secret.yml", "old", "new")
        self.ok(self.pilfer("close", "-J", answers="typed\n"))
        data = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(only("typed").decrypt(data), b"token: new\n")

    def test_labelled_prompt_vault_id(self):
        self.write("secret.yml", only("typed", "lbl").encrypt(b"token: old\n", vault_id="lbl"))
        self.ok(self.pilfer("open", "--vault-id", "lbl@prompt", answers="typed\n"))
        self.edit("secret.yml", "old", "new")
        self.ok(self.pilfer("close", "--vault-id", "lbl@prompt", answers="typed\n"))
        data = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(only("typed", "lbl").decrypt(data), b"token: new\n")

    def test_rekey_old_vault_id_file_and_new_vault_id_prompt(self):
        self.password_file("old-pass", "old-password")
        self.write("secret.yml", only("old-password").encrypt(b"a: 1\n"))
        # The prompt asks twice (new, then confirm), so two answers.
        self.ok(
            self.pilfer(
                "rekey",
                "--old-vault-id",
                "old-pass",
                "--new-vault-id",
                "prompt",
                "--yes",
                answers="new-password\nnew-password\n",
            )
        )
        data = (self.dir / "secret.yml").read_bytes()
        self.assertEqual(only("new-password").decrypt(data), b"a: 1\n")

    def test_rekey_refuses_a_new_password_typed_differently_twice(self):
        self.password_file("old-pass", "old-password")
        before = self.write("secret.yml", only("old-password").encrypt(b"a: 1\n")).read_bytes()
        result = self.pilfer(
            "rekey",
            "--old-vault-id",
            "old-pass",
            "--new-vault-id",
            "prompt",
            "--yes",
            answers="one\ntwo\n",
        )
        self.refused(result, "Passwords do not match")
        self.assertEqual((self.dir / "secret.yml").read_bytes(), before)

    def test_two_prompts_for_one_id_are_judged_one_each(self):
        # Both flags would map to the first prompt's secret, and the second
        # password, which decrypts nothing, would go unreported.
        self.write("secret.yml", only("pw1", "a").encrypt(b"token: x\n", vault_id="a"))
        result = self.ok(
            self.pilfer(
                "open",
                "--vault-id",
                "a@prompt",
                "--vault-id",
                "a@prompt",
                answers="pw1\npw2\n",
            )
        )
        self.assertEqual(result.stderr.count("decrypted none"), 1, result.stderr)
        self.ok(self.pilfer("close", "--vault-id", "a@prompt", answers="pw1\n"))


class TestRekeyPreconditions(ProjectTest):
    """Rotation preconditions are checked before any file is rewritten."""

    def setUp(self):
        super().setUp()
        self.password_file("old-pass", "old-password")
        self.password_file("new-pass", "new-password")
        self.write("a.yml", only("old-password").encrypt(b"a: 1\n"))
        self.write("b.yml", only("old-password").encrypt(b"b: 2\n"))
        self.before = {n: (self.dir / n).read_bytes() for n in ("a.yml", "b.yml")}

    def rotate(self, *extra: str) -> subprocess.CompletedProcess:
        return self.pilfer(
            "rekey",
            "--old-vault-password-file",
            "old-pass",
            "--new-vault-password-file",
            "new-pass",
            "--rotate-password-file",
            "--yes",
            *extra,
        )

    def assert_untouched(self):
        for name, data in self.before.items():
            self.assertEqual((self.dir / name).read_bytes(), data)
        self.assertEqual((self.dir / "old-pass").read_text().strip(), "old-password")

    def test_an_existing_backup_refuses_before_any_file_is_written(self):
        # The second rotation: the first left old-pass_old.
        self.write("old-pass_old", "older\n", 0o600)
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                result = self.rotate(*extra)
                self.refused(result, "old-pass_old")
                self.assertEqual(result.returncode, 1)
                self.assert_untouched()

    def test_a_symlinked_password_file_refuses_before_any_file_is_written(self):
        (self.dir / "old-pass").rename(self.dir / "real-pass")
        (self.dir / "old-pass").symlink_to("real-pass")
        result = self.rotate()
        self.refused(result, "symlink")
        self.assertEqual(result.returncode, 1)
        self.assert_untouched()

    @unittest.skipIf(os.geteuid() == 0, "root writes to a 0500 directory")
    def test_an_unwritable_password_directory_refuses_before_any_file_is_written(self):
        keys = self.dir / "keys"
        keys.mkdir()
        (self.dir / "old-pass").rename(keys / "old-pass")
        os.chmod(keys, 0o500)
        self.addCleanup(os.chmod, keys, 0o700)
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                result = self.pilfer(
                    "rekey",
                    "--old-vault-password-file",
                    "keys/old-pass",
                    "--new-vault-password-file",
                    "new-pass",
                    "--rotate-password-file",
                    "--yes",
                    *extra,
                )
                self.refused(result, "not writable")
                self.assertEqual(result.returncode, 1)
                for name, data in self.before.items():
                    self.assertEqual((self.dir / name).read_bytes(), data)
                self.assertEqual((keys / "old-pass").read_text().strip(), "old-password")

    def test_a_vault_encrypted_new_password_file_cannot_be_rotated_in(self):
        # Rotation copies the file as it is: Ansible could not use the blob.
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere)
        encrypted = elsewhere / "new-pass.vault"
        encrypted.write_bytes(only("old-password").encrypt(b"brand-new\n"))
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                result = self.pilfer(
                    "rekey",
                    "--old-vault-password-file",
                    "old-pass",
                    "--new-vault-password-file",
                    str(encrypted),
                    "--rotate-password-file",
                    "--yes",
                    *extra,
                )
                self.refused(result, "must be plain text")
                self.assertEqual(result.returncode, 1)
                self.assert_untouched()
                self.assertFalse((self.dir / "old-pass_old").exists())

    def test_a_vault_encrypted_password_file_with_a_leading_blank_line_is_refused(self):
        # Core strips the file before reading it, so the blank line does not
        # make it plain text; the blob must not be installed as a password.
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere)
        encrypted = elsewhere / "new-pass.vault"
        encrypted.write_bytes(b"\n" + only("old-password").encrypt(b"brand-new\n"))
        result = self.pilfer(
            "rekey",
            "--old-vault-password-file",
            "old-pass",
            "--new-vault-password-file",
            str(encrypted),
            "--rotate-password-file",
            "--yes",
        )
        self.refused(result, "must be plain text")
        self.assert_untouched()
        self.assertFalse((self.dir / "old-pass_old").exists())

    def test_a_new_password_file_named_by_an_env_var_inside_the_tree_is_refused(self):
        # Ansible expands "$VAR" in a password file path; a comparison of the
        # flag's text with the targets' paths missed it.
        encrypted = self.write("new-pass.vault", only("old-password").encrypt(b"brand-new\n"))
        before = encrypted.read_bytes()
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                result = self.pilfer(
                    "rekey",
                    "--old-vault-password-file",
                    "old-pass",
                    "--new-vault-id",
                    "x@$PILFER_TEST_DIR/new-pass.vault",
                    "--yes",
                    *extra,
                    env={"PILFER_TEST_DIR": str(self.dir)},
                )
                self.refused(result, "move it out first")
                self.assert_untouched()
                self.assertEqual(encrypted.read_bytes(), before)

    def test_an_ansible_cfg_password_file_inside_the_tree_is_refused(self):
        # vault_password_file in ansible.cfg loads beside -p. Here it is itself a
        # vault under the old password, so rekey would re-key the password the
        # tree is on under the new one and leave the config pointing at a blob.
        cfg_pass = self.write("cfg-pass.vault", only("old-password").encrypt(b"cfg-password\n"))
        self.write_cfg("vault_password_file = cfg-pass.vault\n")
        before = cfg_pass.read_bytes()
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                result = self.pilfer(
                    "rekey",
                    "--old-vault-password-file",
                    "old-pass",
                    "--new-vault-password-file",
                    "new-pass",
                    "--yes",
                    *extra,
                )
                self.refused(result, "move it out first")
                self.assert_untouched()
                self.assertEqual(cfg_pass.read_bytes(), before)

    def test_a_new_password_file_inside_the_tree_is_refused(self):
        # It would be re-keyed under itself: the new password would then exist
        # only encrypted with the new password.
        encrypted = self.write("new-pass.vault", only("old-password").encrypt(b"brand-new\n"))
        before = encrypted.read_bytes()
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                result = self.pilfer(
                    "rekey",
                    "--old-vault-password-file",
                    "old-pass",
                    "--new-vault-password-file",
                    "new-pass.vault",
                    "--yes",
                    *extra,
                )
                self.refused(result, "move it out first")
                self.assertEqual(result.returncode, 1)
                self.assert_untouched()
                self.assertEqual(encrypted.read_bytes(), before)


class TestRekeyOldAndNewSources(ProjectTest):
    def setUp(self):
        super().setUp()
        self.password_file("old-pass", "old-password")
        self.password_file("other-pass", "other-password")
        self.password_file("new-pass", "new-password")
        self.write("a.yml", only("old-password").encrypt(b"a: 1\n"))

    def test_an_old_flag_that_decrypts_nothing_is_a_warning(self):
        self.write_cfg("vault_password_file = old-pass\n")
        result = self.ok(
            self.pilfer(
                "rekey",
                "--old-vault-password-file",
                "other-pass",
                "--new-vault-password-file",
                "new-pass",
                "--yes",
            )
        )
        self.assertIn("/other-pass decrypted none", result.stderr)
        data = (self.dir / "a.yml").read_bytes()
        self.assertEqual(only("new-password").decrypt(data), b"a: 1\n")

    def test_an_old_flag_that_decrypts_something_is_not_warned_about(self):
        result = self.ok(
            self.pilfer(
                "rekey",
                "--old-vault-password-file",
                "old-pass",
                "--new-vault-password-file",
                "new-pass",
                "--yes",
            )
        )
        self.assertNotIn("decrypted none", result.stderr)

    def test_new_password_file_may_itself_be_encrypted_with_the_old_password(self):
        # ansible-vault rekey reads it that way. Outside the tree: pilfer rekeys
        # every vault file under the project, this one included.
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere)
        encrypted = elsewhere / "new-pass.vault"
        encrypted.write_bytes(only("old-password").encrypt(b"brand-new\n"))
        self.ok(
            self.pilfer(
                "rekey",
                "--old-vault-password-file",
                "old-pass",
                "--new-vault-password-file",
                str(encrypted),
                "--yes",
            )
        )
        data = (self.dir / "a.yml").read_bytes()
        self.assertEqual(only("brand-new").decrypt(data), b"a: 1\n")


class TestSetBeforePassword(ProjectTest):
    def test_a_missing_target_does_not_run_the_password_script(self):
        script = self.script("vault-pass.sh", "scripted")
        result = self.pilfer("set", "-p", str(script), "missing/x.yml", "token", "v")
        self.refused(result, "missing/x.yml")
        self.assertNotIn("pilfer-lock", result.stderr)
        self.assertEqual(self.runs(script), [])


class TestInterruptAndLocale(ProjectTest):
    def test_ctrl_c_during_a_password_script_exits_130_without_a_traceback(self):
        # The script interrupts its parent, as ctrl-c at the terminal would.
        script = self.write("slow.sh", "#!/bin/sh\nkill -INT $PPID\nsleep 2\necho pw\n", 0o700)
        self.write("secret.yml", only("pw").encrypt(b"token: x\n"))
        result = self.pilfer("open", "-p", str(script))
        self.assertEqual(result.returncode, 130, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("Interrupted", result.stderr)
        self.assertFalse((self.dir / "vaultedFileList.json").exists())

    def test_help_and_version_work_under_a_non_utf8_locale(self):
        c_locale = {"LC_ALL": "C", "LANG": "C"}
        self.ok(self.pilfer("--version", env=c_locale))
        self.ok(self.pilfer("open", "--help", env=c_locale))

    def test_a_non_utf8_locale_is_explained_not_a_traceback(self):
        self.password_file("pass", "pw")
        self.write("secret.yml", only("pw").encrypt(b"token: x\n"))
        result = self.pilfer("open", "-p", "pass", env={"LC_ALL": "C", "LANG": "C"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("UTF-8", result.stderr)
        self.assertNotIn("ERROR: ERROR", result.stderr)
        self.assertNotIn("Error: ERROR", result.stderr)


if __name__ == "__main__":
    unittest.main()
