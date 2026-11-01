"""pilfer set keeps plaintext off disk and out of output, and stores the exact value."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from ansible.parsing.yaml.loader import AnsibleLoader

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.errors import AnsibleError
from ansible.parsing.vault import VaultLib, VaultSecret

from pilfer import vault_set
from pilfer.cli import PilferError
from pilfer.vault_set import set_keys

PILFER_SCRIPT = Path(__file__).resolve().parents[1] / "pilfer.py"
PASSWORD = "test-vault-password"
SENTINEL = "sentinel-secret-value-do-not-print"
OTHER = "other-secret-leave-alone"
# Comments, a nested mapping, a coercible plain scalar, and an inline comment on the
# line being edited. Every byte outside the edited scalar must survive.
FIXTURE = (
    "# keep this comment\n"
    f"alpha: {json.dumps(OTHER)}  # alpha note\n"
    "flag: yes\n"
    "port: 8080\n"
    "nested:\n"
    "  child: 'keep-child'\n"
    "\n"
    "# section comment\n"
    'target: "old-value"   # target note\n'
    "tail_key: plain-tail\n"
)
# Hostile to quote-stripping, comment-stripping, escaping, and whitespace trimming.
TRICKY = "  p#ss \"q\" \\back\\ 's' ünï ☃ 😀 tab\there  "
COERCIBLE = ("yes", "no", "on", "off", "0123", "1e3", "null", "~", "true")


def _vault(password: str = PASSWORD) -> VaultLib:
    return VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password.encode("utf-8")))])


def _expected_target(value: str) -> str:
    return FIXTURE.replace('"old-value"', json.dumps(value, ensure_ascii=False))


class VaultSetBase(unittest.TestCase):
    def setUp(self) -> None:
        # Temp dir as cwd keeps any real ansible.cfg and password file out of the tests.
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.directory)
        self.addCleanup(os.chdir, self._cwd)
        self.password = self._password_file("vault-password", PASSWORD)
        # ansible-vault view (the independent reader below) must not pick up a real
        # ansible.cfg or ANSIBLE_VAULT_PASSWORD_FILE.
        cfg = self.directory / "empty-ansible.cfg"
        cfg.write_text("[defaults]\n", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANSIBLE_VAULT")}
        env["ANSIBLE_CONFIG"] = str(cfg)
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.vault = self._encrypt(FIXTURE)
        self.before = self.vault.read_bytes()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _password_file(self, name: str, password: str) -> Path:
        path = self.directory / name
        path.write_text(password + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def _encrypt(self, text: str, name: str = "secrets.yml") -> Path:
        target = self.directory / name
        target.write_bytes(_vault().encrypt(text.encode("utf-8")))
        return target

    def _set(self, key: str, value: str, path: Path | None = None) -> str:
        return set_keys(path or self.vault, {key: value}, str(self.password))[key]

    def _view(self, path: Path | None = None) -> str:
        """Read through the ansible-vault CLI, not the code under test."""
        ansible_vault = shutil.which("ansible-vault")
        assert ansible_vault, "ansible-vault not on PATH"
        return subprocess.check_output(
            [
                ansible_vault,
                "view",
                str(path or self.vault),
                "--vault-password-file",
                str(self.password),
            ],
        ).decode("utf-8")

    def _assert_no_temp(self) -> None:
        self.assertEqual([p.name for p in self.directory.glob(".pilfer-rekey-*")], [])

    def _assert_untouched(self, path: Path | None = None, before: bytes | None = None) -> None:
        self.assertEqual((path or self.vault).read_bytes(), before or self.before)
        self._assert_no_temp()


class TestVaultSet(VaultSetBase):
    # Data accuracy

    def test_tricky_value_is_exact_and_nothing_else_changes(self) -> None:
        self.assertEqual(self._set("target", TRICKY), "updated")
        text = self._view()
        self.assertEqual(text, _expected_target(TRICKY))
        loaded = yaml.safe_load(text)
        self.assertIsInstance(loaded["target"], str)
        self.assertEqual(loaded["target"], TRICKY)
        self.assertTrue(self.vault.read_bytes().startswith(b"$ANSIBLE_VAULT;1.1;AES256\n"))
        self._assert_no_temp()

    def test_coercible_values_stay_strings(self) -> None:
        for value in COERCIBLE:
            with self.subTest(value=value):
                self._set("target", value)
                text = self._view()
                self.assertEqual(text, _expected_target(value))
                self.assertEqual(yaml.safe_load(text)["target"], value)

    def test_edit_plaintext_exact_for_many_values(self) -> None:
        # Pure-text check of the same edit, for values too many to run through ansible-vault.
        values = [*COERCIBLE, TRICKY, "line\nbreak", "\x07bell", "- dash", ": colon", "{a: 1}"]
        values += ["[x]", "&a", "*a", "!t", "%p", "@at", "`tick", "'", '"', "\\", "#", " "]
        values += [" nbsp", "﻿bom", "é́", "a b", "\ttab", "trail "]
        for value in values:
            with self.subTest(value=value):
                text, action = vault_set._edit_plaintext(FIXTURE, "target", value)
                self.assertEqual(action, "updated")
                self.assertEqual(text, _expected_target(value))
                # PyYAML is the setter's own check; AnsibleLoader is what playbooks read.
                for loaded in (yaml.safe_load(text), AnsibleLoader(text).get_single_data()):
                    self.assertEqual(loaded["target"], value)
                    self.assertIsInstance(loaded["target"], str)

    def test_adds_key_at_the_end_and_keeps_the_rest(self) -> None:
        self.assertEqual(self._set("beta", SENTINEL), "added")
        self.assertEqual(self._view(), FIXTURE + f"beta: {json.dumps(SENTINEL)}\n")
        self._assert_no_temp()

    def test_add_to_file_without_trailing_newline(self) -> None:
        vault = self._encrypt("alpha: one", name="nonl.yml")
        self._set("beta", SENTINEL, vault)
        self.assertEqual(self._view(vault), f"alpha: one\nbeta: {json.dumps(SENTINEL)}\n")

    def test_add_to_empty_vault(self) -> None:
        vault = self._encrypt("", name="empty.yml")
        self._set("beta", SENTINEL, vault)
        self.assertEqual(self._view(vault), f"beta: {json.dumps(SENTINEL)}\n")

    def test_replaces_unquoted_coerced_and_empty_values(self) -> None:
        self._set("flag", "no")
        self.assertEqual(self._view(), FIXTURE.replace("flag: yes", 'flag: "no"'))
        vault = self._encrypt("empty:  # fill me\nafter: x\n", name="blank.yml")
        self._set("empty", SENTINEL, vault)
        self.assertEqual(self._view(vault), f'empty: "{SENTINEL}"  # fill me\nafter: x\n')

    def test_several_keys_in_one_write(self) -> None:
        actions = set_keys(
            self.vault, {"target": TRICKY, "beta": SENTINEL, "alpha": OTHER}, str(self.password)
        )
        self.assertEqual(actions, {"target": "updated", "beta": "added", "alpha": "unchanged"})
        self.assertEqual(self._view(), _expected_target(TRICKY) + f"beta: {json.dumps(SENTINEL)}\n")

    def test_one_bad_key_writes_none_of_them(self) -> None:
        # All-or-nothing: the good key before the refused one must not land either.
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"beta": SENTINEL, "nested": "x"}, str(self.password))
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"beta": SENTINEL, "target": "a\u0085b"}, str(self.password))
        self._assert_untouched()

    def test_same_value_leaves_ciphertext_alone(self) -> None:
        self.assertEqual(self._set("alpha", OTHER), "unchanged")
        self._assert_untouched()
        self._set("target", SENTINEL)
        updated = self.vault.read_bytes()
        self.assertEqual(self._set("target", SENTINEL), "unchanged")
        self.assertEqual(self.vault.read_bytes(), updated)

    def test_preserves_file_mode(self) -> None:
        self.vault.chmod(0o640)
        self._set("target", SENTINEL)
        self.assertEqual(self.vault.stat().st_mode & 0o777, 0o640)

    def test_unrepresentable_value_is_refused(self) -> None:
        # NEL is a YAML 1.1 line break: inside the quoted scalar it would load as a space.
        # U+FFFE is valid UTF-8 but the YAML reader rejects it.
        for value in ("a\u0085b", "a￾b"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(PilferError):
                    self._set("target", value)
                self._assert_untouched()

    # Password resolution

    def test_dash_p_wins_over_ansible_cfg(self) -> None:
        # pilfer reads ansible.cfg from cwd. A decoy there must not be used when -p is given.
        decoy = self._password_file("decoy-password", "decoy")
        (self.directory / "ansible.cfg").write_text(
            f"[defaults]\nvault_password_file = {decoy}\n", encoding="utf-8"
        )
        self._set("target", SENTINEL)
        self.assertEqual(self._view(), _expected_target(SENTINEL))
        with self.assertRaises(AnsibleError):
            _vault("decoy").decrypt(self.vault.read_bytes())

    def test_ansible_cfg_password_without_dash_p(self) -> None:
        (self.directory / "ansible.cfg").write_text(
            f"[defaults]\nvault_password_file = {self.password}\n", encoding="utf-8"
        )
        set_keys(self.vault, {"target": SENTINEL})
        self.assertEqual(self._view(), _expected_target(SENTINEL))

    # Failure leaves the original ciphertext

    def test_missing_password_file(self) -> None:
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"target": SENTINEL}, str(self.directory / "no-such-password"))
        self._assert_untouched()

    @unittest.skipIf(os.geteuid() == 0, "root reads mode-000 files")
    def test_unreadable_password_file_is_a_pilfer_error(self) -> None:
        # Script callers catch PilferError only; a bare PermissionError escaped them.
        os.chmod(self.password, 0)
        with self.assertRaises(PilferError) as caught:
            self._set("target", SENTINEL)
        self.assertIn(str(self.password), str(caught.exception))
        self._assert_untouched()

    def test_non_utf8_password_file_does_not_echo_bytes(self) -> None:
        self.password.write_bytes(b"pass\xffword\n")
        with self.assertRaises(PilferError) as caught:
            self._set("target", SENTINEL)
        self.assertNotIn("xff", str(caught.exception))
        self.assertNotIn("pass", str(caught.exception).replace("password", ""))
        self._assert_untouched()

    def test_keeps_vault_id_label(self) -> None:
        secret = VaultSecret(PASSWORD.encode("utf-8"))
        labelled = VaultLib([("prod", secret)]).encrypt(FIXTURE.encode("utf-8"), vault_id="prod")
        self.assertTrue(labelled.startswith(b"$ANSIBLE_VAULT;1.2;AES256;prod\n"))
        self.vault.write_bytes(labelled)
        self.assertEqual(self._set("target", SENTINEL), "updated")
        self.assertTrue(self.vault.read_bytes().startswith(b"$ANSIBLE_VAULT;1.2;AES256;prod\n"))
        self.assertEqual(self._view(), _expected_target(SENTINEL))

    def test_wrong_password_file(self) -> None:
        wrong = self._password_file("wrong-password", "not-the-password")
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"target": SENTINEL}, str(wrong))
        self._assert_untouched()

    def test_encrypt_failure(self) -> None:
        with (
            mock.patch.object(VaultLib, "encrypt", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            self._set("target", SENTINEL)
        self._assert_untouched()

    def test_encrypt_returning_non_vault_output(self) -> None:
        with (
            mock.patch.object(VaultLib, "encrypt", return_value=b"target: plaintext\n"),
            self.assertRaises(PilferError),
        ):
            self._set("target", SENTINEL)
        self._assert_untouched()

    def test_encrypt_returning_other_ciphertext(self) -> None:
        # Valid vault bytes that decrypt to something else must not be published.
        other = _vault().encrypt(b"alpha: wrong\n")
        with (
            mock.patch.object(VaultLib, "encrypt", return_value=other),
            self.assertRaises(PilferError),
        ):
            self._set("target", SENTINEL)
        self._assert_untouched()

    def test_replace_failure_removes_temp(self) -> None:
        with (
            mock.patch.object(vault_set.os, "replace", side_effect=OSError(28, "disk full")),
            self.assertRaises(PilferError) as caught,
        ):
            self._set("target", SENTINEL)
        # No filename on the error: name the vault rather than print "None".
        self.assertEqual(str(caught.exception), f"disk full while writing {self.vault}")
        self._assert_untouched()

    def test_interrupt_removes_temp(self) -> None:
        with (
            mock.patch.object(vault_set.os, "replace", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            self._set("target", SENTINEL)
        self._assert_untouched()

    def test_concurrent_change_is_not_overwritten(self) -> None:
        concurrent = _vault().encrypt(b"alpha: concurrent\n")
        real_encrypt = VaultLib.encrypt

        def encrypt_then_race(vault, *args, **kwargs):
            out = real_encrypt(vault, *args, **kwargs)
            self.vault.write_bytes(concurrent)
            return out

        with (
            mock.patch.object(VaultLib, "encrypt", autospec=True, side_effect=encrypt_then_race),
            self.assertRaises(PilferError),
        ):
            self._set("target", SENTINEL)
        self._assert_untouched(before=concurrent)

    # check_only

    def test_check_only_runs_the_edit_without_writing(self) -> None:
        with mock.patch.object(
            VaultLib, "encrypt", autospec=True, side_effect=VaultLib.encrypt
        ) as enc:
            actions = set_keys(
                self.vault,
                {"target": SENTINEL, "new_key": OTHER},
                str(self.password),
                check_only=True,
            )
        self.assertEqual(actions, {"target": "updated", "new_key": "added"})
        enc.assert_called_once()  # the encrypt and round-trip ran
        self._assert_untouched()

    def test_check_only_reports_the_refusals_a_write_would_hit(self) -> None:
        cases = {
            "duplicate": "target: one\ntarget: two\n",
            "block scalar": "target: |\n  line\n",
            "list root": "- target\n",
            "unknown tag": "target: !unsafe '{{ x }}'\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                path = self._encrypt(text, name=f"{label.replace(' ', '-')}.yml")
                before = path.read_bytes()
                with self.assertRaises(PilferError):
                    set_keys(path, {"target": SENTINEL}, str(self.password), check_only=True)
                self._assert_untouched(path, before)

    def test_check_only_refuses_an_open_session(self) -> None:
        (self.directory / "secrets.yml.pilfer-open").touch()
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"target": SENTINEL}, str(self.password), check_only=True)
        self._assert_untouched()

    # Refusals leave the original ciphertext

    def test_refusals_leave_bytes(self) -> None:
        cases = [
            ("empty value", "target", ""),
            ("NUL", "target", "a\0b"),
            ("dotted key", "a.b", SENTINEL),
            ("YAML key syntax", "a: b", SENTINEL),
            ("empty key", "", SENTINEL),
        ]
        for label, key, value in cases:
            with self.subTest(label), self.assertRaises(PilferError):
                self._set(key, value)
            self._assert_untouched()

    def test_refuses_duplicate_block_and_mapping_values(self) -> None:
        for name, text in (
            ("duplicate.yml", "alpha: one\nalpha: two\n"),
            ("block.yml", "alpha: |\n  line\nbeta: x\n"),
            ("folded.yml", "alpha: >\n  line\nbeta: x\n"),
            ("mapping.yml", "alpha:\n  child: x\n"),
            ("list.yml", "- alpha\n"),
            ("multidoc.yml", "alpha: one\n---\nbeta: two\n"),
        ):
            with self.subTest(name):
                vault = self._encrypt(text, name=name)
                before = vault.read_bytes()
                with self.assertRaises(PilferError):
                    self._set("alpha", SENTINEL, vault)
                self._assert_untouched(vault, before)

    def test_refuses_plaintext_symlink_and_pilfer_sidecar(self) -> None:
        plain = self.directory / "plain.yml"
        plain.write_text("alpha: one\n", encoding="utf-8")
        with self.assertRaises(PilferError):
            self._set("beta", SENTINEL, plain)
        self.assertEqual(plain.read_text(encoding="utf-8"), "alpha: one\n")

        link = self.directory / "link.yml"
        link.symlink_to(self.vault)
        with self.assertRaises(PilferError):
            self._set("beta", SENTINEL, link)
        self.assertTrue(link.is_symlink())
        self._assert_untouched()

        # The sidecar keeps the full name (secrets.yml.pilfer-open), not with_suffix.
        sidecar = self.directory / "secrets.yml.pilfer-open"
        sidecar.write_text(json.dumps({"kind": "file", "path": "secrets.yml"}), encoding="utf-8")
        with self.assertRaises(PilferError):
            self._set("beta", SENTINEL)
        self._assert_untouched()


class TestVaultSetCLI(VaultSetBase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(PILFER_SCRIPT), "set", *args],
            capture_output=True,
            check=False,
            cwd=self.directory,
        )

    def test_cli_sets_exact_value_and_does_not_print_it(self) -> None:
        result = self._run("-p", str(self.password), str(self.vault), "target", TRICKY)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        combined = result.stdout + result.stderr
        self.assertNotIn(TRICKY.strip().encode(), combined)
        self.assertNotIn(OTHER.encode(), combined)
        self.assertIn(b"updated target", result.stdout)
        self.assertEqual(self._view(), _expected_target(TRICKY))

    def test_cli_value_with_leading_dash_after_double_dash(self) -> None:
        result = self._run("-p", str(self.password), str(self.vault), "target", "--", "-dash")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self._view(), _expected_target("-dash"))

    def test_cli_refusal_does_not_print_plaintext(self) -> None:
        # A parser error quotes the line. An impossible date raises a plain ValueError
        # that names its digits, outside yaml.YAMLError.
        for name, text, leaked in (
            ("broken.yml", f"alpha: {OTHER}\n  bad: [\n", OTHER),
            ("date.yml", "when: 1987-02-30\nalpha: x\n", "1987"),
        ):
            with self.subTest(name):
                broken = self._encrypt(text, name=name)
                before = broken.read_bytes()
                result = self._run("-p", str(self.password), str(broken), "alpha", SENTINEL)
                self.assertEqual(result.returncode, 1)
                combined = result.stdout + result.stderr
                self.assertNotIn(leaked.encode(), combined)
                self.assertNotIn(SENTINEL.encode(), combined)
                self.assertEqual(broken.read_bytes(), before)
                self._assert_no_temp()

    def test_cli_wrong_password_does_not_print_value(self) -> None:
        wrong = self._password_file("wrong-password", "not-the-password")
        result = self._run("-p", str(wrong), str(self.vault), "target", SENTINEL)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(SENTINEL.encode(), result.stdout + result.stderr)
        self._assert_untouched()


if __name__ == "__main__":
    unittest.main()
