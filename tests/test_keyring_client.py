"""pilfer-vault-keyring-client: a vault password client script on the system keyring.

The keyring is _file_keyring.FileKeyring, a JSON file per test, or keyring's
own fail and null backends, selected with PYTHON_KEYRING_BACKEND (or patched
in-process), so nothing here reads or writes the real keychain. Lookups run
the client the way Ansible does, as an executable named *-client in its own
process. --set mostly runs main() in-process to feed the prompts; tests that
need the real process pipe the answers to run_client(input=...).
"""

import builtins
import getpass
import io
import json
import os
import subprocess
import sys
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

# Before anything imports ansible: see the module.
import _ansible_isolation  # noqa: F401
import keyring
import keyring.backends.fail
import keyring.backends.null
import keyring.errors
from _file_keyring import FileKeyring
from ansible.parsing.vault import script_is_client
from test_vault_sources import ProjectTest, only

REPO = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from pilfer import keyring_client  # noqa: E402

CLIENT_NAME = "pilfer-vault-keyring-client"
USER = getpass.getuser()


class KeyringTest(ProjectTest):
    def setUp(self):
        super().setUp()
        self.keyring_file = self.dir / "keyring.json"
        self.env.update(
            PYTHON_KEYRING_BACKEND="_file_keyring.FileKeyring",
            PILFER_TEST_KEYRING=str(self.keyring_file),
            PYTHONPATH=os.pathsep.join([str(TESTS), str(REPO)]),
        )
        # What the console script does, under the name Ansible keys on.
        self.client = self.write(
            CLIENT_NAME,
            f"#!{sys.executable}\nimport sys\nfrom pilfer.keyring_client import main\nsys.exit(main())\n",
            0o700,
        )

    def store(self, service: str, password: str, username: str = USER) -> None:
        data = self.stored()
        data[f"{service}/{username}"] = password
        self.keyring_file.write_text(json.dumps(data))

    def stored(self) -> dict:
        return json.loads(self.keyring_file.read_text()) if self.keyring_file.exists() else {}

    def run_client(
        self, *args: str, env: dict | None = None, text: bool = True, input: str | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.client), *args],
            capture_output=True,
            text=text,
            check=False,
            cwd=self.dir,
            input=input,
            stdin=subprocess.DEVNULL if input is None else None,
            env={**self.env, **(env or {})},
            # No controlling terminal, so getpass reads the piped input instead
            # of opening /dev/tty.
            start_new_session=True,
        )

    def set_in_process(
        self, *args: str, typed: tuple = ("pw", "pw"), replace: str | None = None, backend=None
    ) -> tuple[int, str, str]:
        """main(--set ...) with getpass (and the replace question) answered, on this test's keyring."""
        out, err = io.StringIO(), io.StringIO()
        answers = (
            mock.Mock(side_effect=[replace])
            if replace is not None
            else mock.Mock(side_effect=AssertionError)
        )
        # Reset to the null backend, not to get_keyring()'s: reading that first
        # would initialise the machine's real backend.
        self.addCleanup(keyring.set_keyring, keyring.backends.null.Keyring())
        keyring.set_keyring(backend or FileKeyring())
        with (
            mock.patch.dict(os.environ, PILFER_TEST_KEYRING=str(self.keyring_file)),
            mock.patch.object(getpass, "getpass", side_effect=list(typed)),
            mock.patch.object(builtins, "input", answers),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = keyring_client.main(["--set", *args])
        return code, out.getvalue(), err.getvalue()


class TestClientLookup(KeyringTest):
    def test_no_vault_id_uses_service_ansible(self):
        self.store("ansible", "pw")
        result = self.run_client()
        self.assertEqual((result.returncode, result.stdout), (0, "pw\n"), result.stderr)

    def test_vault_id_names_the_service(self):
        self.store("dev", "dev-pw")
        self.assertEqual(self.run_client("--vault-id", "dev").stdout, "dev-pw\n")

    def test_vault_id_default_uses_keyname_from_ansible_cfg(self):
        # Ansible passes --vault-id default for vault_password_file; the
        # contrib original then looked up a service called "default".
        self.write("ansible.cfg", "[defaults]\n[vault]\nkeyname = homelab\nusername = 'ops'\n")
        self.store("homelab", "pw", username="ops")
        self.store("default", "wrong", username="ops")
        result = self.run_client("--vault-id", "default")
        self.assertEqual((result.returncode, result.stdout), (0, "pw\n"), result.stderr)

    def test_configured_vault_identity_also_uses_keyname(self):
        # vault_identity renames the id Ansible gives an unlabelled file.
        self.write("ansible.cfg", "[defaults]\nvault_identity = prod\n[vault]\nkeyname = homelab\n")
        self.store("homelab", "pw")
        self.store("prod", "wrong")
        self.assertEqual(self.run_client("--vault-id", "prod").stdout, "pw\n")

    def test_config_is_parsed_as_ansible_parses_it(self):
        # Quotes, an inline ; comment, and a non-UTF-8 comment Ansible accepts.
        self.write(
            "ansible.cfg",
            b"[defaults]\n# caf\xe9\n[vault]\nkeyname = \"homelab\" ; the service\nusername = 'ops'\n",
        )
        self.store("homelab", "pw", username="ops")
        result = self.run_client()
        self.assertEqual((result.returncode, result.stdout), (0, "pw\n"), result.stderr)

    def test_username_flag_beats_config(self):
        self.write("ansible.cfg", "[defaults]\n[vault]\nusername = ops\n")
        self.store("ansible", "theirs", username="other")
        self.assertEqual(self.run_client("--username", "other").stdout, "theirs\n")

    def test_ansible_config_variable_is_followed(self):
        elsewhere = self.write("conf/ansible.cfg", "[defaults]\n[vault]\nkeyname = from-env\n")
        self.store("from-env", "pw")
        self.assertEqual(self.run_client(env={"ANSIBLE_CONFIG": str(elsewhere)}).stdout, "pw\n")

    def test_password_bytes_are_utf8_whatever_stdout_encoding(self):
        self.store("ansible", " café pw ")
        result = self.run_client(env={"PYTHONIOENCODING": "ascii"}, text=False)
        self.assertEqual(
            (result.returncode, result.stdout), (0, " café pw \n".encode()), result.stderr
        )

    def test_missing_password_exits_2(self):
        # Ansible's ClientScriptVaultSecret.VAULT_ID_UNKNOWN_RC is 2.
        result = self.run_client("--vault-id", "prod")
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not find key='prod'", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_null_backend_is_not_found(self):
        result = self.run_client(env={"PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring"})
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_no_usable_backend_is_one_line_not_a_traceback(self):
        # keyring's fail backend: what a headless box with no keyring daemon gets.
        result = self.run_client(env={"PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("keyring error", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(len(result.stderr.strip().splitlines()), 1, result.stderr)

    def test_stored_empty_password_is_an_error_not_an_empty_line(self):
        self.store("ansible", "")
        result = self.run_client()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("is empty", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_backend_that_fails_to_load_is_one_line(self):
        result = self.run_client(env={"PYTHON_KEYRING_BACKEND": "no.such.Module"})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("cannot load the keyring backend", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_lookup_ctrl_c_exits_130(self):
        err = io.StringIO()
        self.addCleanup(keyring.set_keyring, keyring.backends.null.Keyring())
        keyring.set_keyring(FileKeyring())
        with (
            mock.patch.dict(os.environ, PILFER_TEST_KEYRING=str(self.keyring_file)),
            mock.patch.object(FileKeyring, "get_password", side_effect=KeyboardInterrupt),
            redirect_stderr(err),
        ):
            code = keyring_client.main([])
        self.assertEqual(code, 130)
        self.assertIn("interrupted", err.getvalue())

    def test_names_from_config_are_escaped_in_messages(self):
        self.write("ansible.cfg", "[defaults]\n[vault]\nkeyname = a\n  \x1b[2Jb\n")
        result = self.run_client()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("\x1b", result.stderr)
        self.assertIn("key='a\\n\\x1b[2Jb'", result.stderr)


class TestSet(KeyringTest):
    def test_set_stores_under_the_vault_id(self):
        code, out, _ = self.set_in_process("--vault-id", "prod")
        self.assertEqual(code, 0)
        self.assertIn("key='prod'", out)
        self.assertEqual(self.stored(), {f"prod/{USER}": "pw"})

    def test_set_with_the_default_vault_id_stores_under_keyname(self):
        # The same mapping and config as the lookup, so --set then
        # vault_password_file works. A real process reading the real ansible.cfg.
        self.write(
            "ansible.cfg",
            "[defaults]\nvault_identity = prod\n[vault]\nkeyname = homelab\nusername = ops\n",
        )
        result = self.run_client("--vault-id", "prod", "--set", input="pw\npw\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.stored(), {"homelab/ops": "pw"})
        self.assertEqual(self.run_client("--vault-id", "prod").stdout, "pw\n")

    def test_set_prompts_escape_names_from_config(self):
        self.write("ansible.cfg", "[defaults]\n[vault]\nkeyname = evil\x1b]0;PWNED\x07name\n")
        result = self.run_client("--set", input="pw\npw\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\x1b", result.stdout + result.stderr)
        self.assertIn("evil\\x1b]0;PWNED\\x07name", result.stderr)

    def test_set_then_ansible_reads_it_back(self):
        self.assertEqual(self.set_in_process(typed=(" café pw ", " café pw "))[0], 0)
        # Stripped, as ansible-vault --ask-vault-pass strips a typed password.
        self.assertEqual(self.run_client(text=False).stdout, "café pw\n".encode())

    def test_set_asks_before_replacing_and_keeps_on_no(self):
        self.store("ansible", "old")
        code, _, err = self.set_in_process(replace="n")
        self.assertEqual(code, 1)
        self.assertIn("kept", err)
        self.assertEqual(self.stored(), {f"ansible/{USER}": "old"})

    def test_set_replaces_on_yes(self):
        self.store("ansible", "old")
        self.assertEqual(self.set_in_process(replace="yes")[0], 0)
        self.assertEqual(self.stored(), {f"ansible/{USER}": "pw"})

    def test_set_keeps_the_stored_password_without_an_answer(self):
        # No terminal (EOF) or just Enter: the default is to keep it.
        for answer in (EOFError(), ""):
            self.store("ansible", "old")
            code, _, err = self.set_in_process(replace=answer)
            self.assertEqual(code, 1, answer)
            self.assertIn("kept", err)
            self.assertEqual(self.stored(), {f"ansible/{USER}": "old"})

    def assert_one_line_error(self, err: str) -> None:
        # The text after the prefix is ansible-core's (PromptVaultSecret), and
        # its wording is not pilfer's to pin across core versions.
        self.assertTrue(err.startswith(f"{CLIENT_NAME}: "), err)
        self.assertEqual(len(err.strip().splitlines()), 1, err)

    def test_set_refuses_a_mismatch_an_empty_password_and_ctrl_d(self):
        for typed in (("pw", "typo"), ("", ""), (EOFError(),)):
            with self.subTest(typed=typed):
                code, _, err = self.set_in_process(typed=typed)
                self.assertEqual(code, 1)
                self.assert_one_line_error(err)
                self.assertEqual(self.stored(), {})

    def test_set_refuses_spaces_only_and_keeps_the_old_password(self):
        self.store("ansible", "old")
        code, _, err = self.set_in_process(typed=("   ", "   "), replace="y")
        self.assertEqual(code, 1)
        self.assertIn("empty", err)
        self.assertEqual(self.stored(), {f"ansible/{USER}": "old"})

    def test_set_ctrl_c_exits_130_and_stores_nothing(self):
        for name, kwargs in {
            "replace": {"replace": KeyboardInterrupt()},
            "prompt": {"typed": (KeyboardInterrupt(),), "replace": "y"},
        }.items():
            with self.subTest(name):
                self.store("ansible", "old")
                code, _, err = self.set_in_process(**kwargs)
                self.assertEqual(code, 130)
                self.assertIn("interrupted", err)
                self.assertEqual(self.stored(), {f"ansible/{USER}": "old"})

    def test_set_without_a_usable_backend(self):
        code, _, err = self.set_in_process(backend=keyring.backends.fail.Keyring())
        self.assertEqual(code, 1)
        self.assertIn("keyring error", err)

    def test_set_fails_when_the_backend_drops_the_write(self):
        code, _, err = self.set_in_process(backend=keyring.backends.null.Keyring())
        self.assertEqual(code, 1)
        self.assertIn("could not confirm the new password", err)
        self.assertIn("nothing is stored", err)
        # Nothing was stored before either, so nothing can have been lost.
        self.assertNotIn("old one", err)

    def test_set_says_the_old_password_may_be_gone_when_the_read_back_fails(self):
        # macOS replaces by delete then add: past the write, the old one may be gone.
        class LocksAfterWrite(FileKeyring):
            written = False

            def set_password(self, service, username, password):
                super().set_password(service, username, password)
                self.written = True

            def get_password(self, service, username):
                if self.written:
                    raise keyring.errors.KeyringLocked("locked after the write")
                return super().get_password(service, username)

        self.store("ansible", "old")
        code, _, err = self.set_in_process(replace="y", backend=LocksAfterWrite())
        self.assertEqual(code, 1)
        self.assertIn("the old one may be gone", err)
        self.assertIn("locked after the write", err)
        self.assertEqual(self.stored(), {f"ansible/{USER}": "pw"})

    def test_set_reports_a_different_value_after_the_write(self):
        # First get_password: the replace check sees nothing. Second: the read-back.
        with mock.patch.object(FileKeyring, "get_password", side_effect=[None, "other"]):
            code, _, err = self.set_in_process()
        self.assertEqual(code, 1)
        self.assertIn("a different value is stored", err)


class TestThroughAnsible(KeyringTest):
    def ansible_vault(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(Path(sys.executable).parent / "ansible-vault"), *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.dir,
            stdin=subprocess.DEVNULL,
            env=self.env,
        )

    def test_ansible_vault_with_vault_password_file(self):
        self.write(
            "ansible.cfg",
            f"[defaults]\nvault_password_file = {self.client}\n[vault]\nkeyname = homelab\n",
        )
        self.store("homelab", "kc-password")
        self.write("secret.yml", only("kc-password").encrypt(b"token: x\n"))
        result = self.ansible_vault("view", "secret.yml")
        self.assertEqual((result.returncode, result.stdout), (0, "token: x\n"), result.stderr)

    def test_ansible_vault_with_a_renamed_vault_identity(self):
        self.write(
            "ansible.cfg",
            f"[defaults]\nvault_identity = prod\nvault_password_file = {self.client}\n[vault]\nkeyname = homelab\n",
        )
        self.store("homelab", "kc-password")
        self.write("secret.yml", only("kc-password").encrypt(b"token: x\n"))
        result = self.ansible_vault("view", "secret.yml")
        self.assertEqual((result.returncode, result.stdout), (0, "token: x\n"), result.stderr)

    def test_pilfer_open_and_close_with_vault_identity_list(self):
        self.write_cfg(f"vault_identity_list = homelab@{self.client}\n")
        self.store("homelab", "kc-password")
        vault = only("kc-password", "homelab")
        self.write("secret.yml", vault.encrypt(b"token: old\n", vault_id="homelab"))

        self.ok(self.pilfer("open"))
        self.edit("secret.yml", "old", "new")
        self.ok(self.pilfer("close"))

        closed = (self.dir / "secret.yml").read_bytes()
        self.assertTrue(closed.startswith(b"$ANSIBLE_VAULT;1.2;AES256;homelab\n"))
        self.assertEqual(vault.decrypt(closed), b"token: new\n")

    def test_pilfer_names_the_missing_key(self):
        self.write_cfg(f"vault_password_file = {self.client}\n")
        self.write("secret.yml", only("x").encrypt(b"token: x\n"))
        self.refused(self.pilfer("open"), "did not find a secret")


class TestPackaging(unittest.TestCase):
    def test_entry_point_is_named_as_a_client_script(self):
        # Ansible passes --vault-id only to *-client scripts; a rename would
        # silently drop it and every lookup would use keyname.
        scripts = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["scripts"]
        names = [name for name, target in scripts.items() if target == "pilfer.keyring_client:main"]
        self.assertEqual(len(names), 1, scripts)
        self.assertTrue(script_is_client(names[0]), names[0])

    def test_without_keyring_package_says_what_to_install(self):
        err = io.StringIO()
        with (
            mock.patch.dict(sys.modules, {"keyring": None, "keyring.errors": None}),
            redirect_stderr(err),
        ):
            code = keyring_client.main([])
        self.assertEqual(code, 1)
        self.assertIn("pilfer[keyring]", err.getvalue())


if __name__ == "__main__":
    unittest.main()
