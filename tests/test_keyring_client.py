"""pilfer-vault-keyring-client: a vault password client script on the system keyring.

The keyring is _file_keyring.FileKeyring, a JSON file per test, selected with
PYTHON_KEYRING_BACKEND, so nothing here reads or writes the real keychain.
Most tests run the client the way Ansible does, as an executable named
*-client in its own process; the --set tests call main() in-process to feed
getpass.
"""

import getpass
import io
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

# Before anything imports ansible: see the module.
import _ansible_isolation  # noqa: F401
import yaml
from ansible.parsing.vault import script_is_client
from test_vault_sources import ProjectTest, only

try:
    import keyring
    from _file_keyring import LOCKED, FileKeyring
except ImportError:  # keyring is the optional pilfer[keyring] extra
    keyring = None

REPO = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from pilfer import keyring_client  # noqa: E402

CLIENT_NAME = "pilfer-vault-keyring-client"
USER = getpass.getuser()


@unittest.skipUnless(keyring, "keyring not installed (pip install -e '.[keyring]')")
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
        data = json.loads(self.keyring_file.read_text()) if self.keyring_file.exists() else {}
        data[f"{service}/{username}"] = password
        self.keyring_file.write_text(json.dumps(data))

    def run_client(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.client), *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.dir,
            stdin=subprocess.DEVNULL,
            env=self.env,
        )


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

    def test_username_flag_beats_config(self):
        self.write("ansible.cfg", "[defaults]\n[vault]\nusername = ops\n")
        self.store("ansible", "theirs", username="other")
        self.assertEqual(self.run_client("--username", "other").stdout, "theirs\n")

    def test_ansible_config_variable_is_followed(self):
        elsewhere = self.write("conf/ansible.cfg", "[defaults]\n[vault]\nkeyname = from-env\n")
        self.store("from-env", "pw")
        self.env["ANSIBLE_CONFIG"] = str(elsewhere)
        self.assertEqual(self.run_client().stdout, "pw\n")

    def test_missing_password_exits_2(self):
        result = self.run_client("--vault-id", "prod")
        self.assertEqual(result.returncode, keyring_client.KEYNAME_UNKNOWN_RC)
        self.assertIn('could not find key="prod"', result.stderr)
        self.assertEqual(result.stdout, "")

    def test_locked_keyring_is_one_line_not_a_traceback(self):
        self.keyring_file.write_text(json.dumps({LOCKED: True}))
        result = self.run_client()
        self.assertEqual(result.returncode, 1)
        self.assertIn("keyring error", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class TestThroughAnsible(KeyringTest):
    def test_ansible_vault_with_vault_password_file(self):
        self.write(
            "ansible.cfg",
            f"[defaults]\nvault_password_file = {self.client}\n[vault]\nkeyname = homelab\n",
        )
        self.store("homelab", "kc-password")
        self.write("secret.yml", only("kc-password").encrypt(b"token: x\n"))
        ansible_vault = Path(sys.executable).parent / "ansible-vault"
        result = subprocess.run(
            [str(ansible_vault), "view", "secret.yml"],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.dir,
            stdin=subprocess.DEVNULL,
            env=self.env,
        )
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

    def test_pilfer_set_with_vault_password_file(self):
        self.write_cfg(f"vault_password_file = {self.client}\n")
        self.store("ansible", "kc-password")
        self.write("secret.yml", only("kc-password").encrypt(b"token: old\n"))
        self.ok(self.pilfer("set", "secret.yml", "token", "new"))
        decrypted = only("kc-password").decrypt((self.dir / "secret.yml").read_bytes())
        self.assertEqual(yaml.safe_load(decrypted), {"token": "new"})

    def test_pilfer_names_the_missing_key(self):
        self.write_cfg(f"vault_password_file = {self.client}\n")
        self.write("secret.yml", only("x").encrypt(b"token: x\n"))
        self.refused(self.pilfer("open"), "did not find a secret")


@unittest.skipUnless(keyring, "keyring not installed (pip install -e '.[keyring]')")
class TestSet(unittest.TestCase):
    """--set prompts with getpass, so these call main() in this process."""

    def setUp(self):
        self.keyring_file = Path(self.enterContext(tempfile.TemporaryDirectory())) / "keyring.json"
        self.enterContext(mock.patch.dict(os.environ, PILFER_TEST_KEYRING=str(self.keyring_file)))
        previous = keyring.get_keyring()
        keyring.set_keyring(FileKeyring())
        self.addCleanup(keyring.set_keyring, previous)

    def main(self, *args: str, typed: tuple[str, str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(getpass, "getpass", side_effect=list(typed)),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = keyring_client.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def stored(self) -> dict:
        return json.loads(self.keyring_file.read_text()) if self.keyring_file.exists() else {}

    def test_set_stores_under_the_vault_id(self):
        code, out, _ = self.main("--vault-id", "prod", "--set", typed=("pw", "pw"))
        self.assertEqual(code, 0)
        self.assertIn("key name: prod", out)
        self.assertEqual(self.stored(), {f"prod/{USER}": "pw"})

    def test_set_refuses_a_mismatch(self):
        code, _, err = self.main("--set", typed=("pw", "typo"))
        self.assertEqual(code, 1)
        self.assertIn("do not match", err)
        self.assertEqual(self.stored(), {})

    def test_set_refuses_an_empty_password(self):
        code, _, err = self.main("--set", typed=("", ""))
        self.assertEqual(code, 1)
        self.assertIn("empty", err)
        self.assertEqual(self.stored(), {})


class TestPackaging(unittest.TestCase):
    def test_entry_point_is_named_as_a_client_script(self):
        # Ansible passes --vault-id only to *-client scripts; a rename would
        # silently drop it and every lookup would use keyname.
        scripts = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["scripts"]
        self.assertEqual(scripts.get(CLIENT_NAME), "pilfer.keyring_client:main")
        self.assertTrue(script_is_client(CLIENT_NAME))

    def test_without_keyring_package_says_what_to_install(self):
        err = io.StringIO()
        with (
            mock.patch.dict(sys.modules, {"keyring": None, "keyring.errors": None}),
            redirect_stderr(err),
        ):
            code = keyring_client.main([])
        self.assertEqual(code, 1)
        self.assertIn("pilfer[keyring]", err.getvalue())


class TestVaultSettings(unittest.TestCase):
    def test_no_config_file(self):
        self.assertEqual(keyring_client.vault_settings(None), (None, None))

    def test_quotes_and_inline_comments_are_read_as_ansible_reads_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "ansible.cfg"
            cfg.write_text("[vault]\nkeyname = \"homelab\" ; the service\nusername = 'ops'\n")
            self.assertEqual(keyring_client.vault_settings(str(cfg)), ("homelab", "ops"))

    def test_missing_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "ansible.cfg"
            cfg.write_text("[defaults]\n")
            self.assertEqual(keyring_client.vault_settings(str(cfg)), (None, None))


if __name__ == "__main__":
    unittest.main()
