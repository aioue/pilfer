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

    def test_preserves_group(self) -> None:
        groups = [g for g in os.getgroups() if g != self.vault.stat().st_gid]
        if not groups:
            self.skipTest("no supplementary group to assign")
        os.chown(self.vault, -1, groups[0])
        gid = self.vault.stat().st_gid
        self.vault.chmod(0o640)
        self._set("target", SENTINEL)
        stat_result = self.vault.stat()
        self.assertEqual(stat_result.st_gid, gid)
        self.assertEqual(stat_result.st_mode & 0o777, 0o640)

    def test_keeps_the_group_when_the_user_is_a_member(self) -> None:
        other = [g for g in os.getgroups() if g != self.vault.stat().st_gid]
        if not other:
            self.skipTest("user is in no second group")
        os.chown(self.vault, -1, other[0])
        self._set("target", SENTINEL)
        self.assertEqual(self.vault.stat().st_gid, other[0])

    def test_still_writes_when_the_group_cannot_be_kept(self) -> None:
        # Only a group member or root can set the group. The vault holds ciphertext,
        # so the editor's group is an acceptable fallback; the mode is still kept.
        import pilfer.publish

        target = self.directory / "grouped.bin"
        target.write_bytes(b"old")
        with mock.patch(
            "pilfer.publish.os.fchown", side_effect=PermissionError(1, "Operation not permitted")
        ):
            pilfer.publish.write_atomic(target, b"new", mode=0o640, gid=os.getgid() + 12345)
        self.assertEqual(target.read_bytes(), b"new")
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)

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

    def test_non_ascii_vault_label_is_refused(self) -> None:
        secret = VaultSecret(PASSWORD.encode("utf-8"))
        labelled = VaultLib([("prod", secret)]).encrypt(FIXTURE.encode("utf-8"), vault_id="prod")
        first, nl, rest = labelled.partition(b"\n")
        self.assertTrue(first.endswith(b";prod"))
        for label in (b"caf\xc3\xa9", b"bad\xff"):
            with self.subTest(label=label):
                blob = first[: -len(b"prod")] + label + nl + rest
                self.vault.write_bytes(blob)
                before = self.vault.read_bytes()
                with self.assertRaises(PilferError) as caught:
                    self._set("target", SENTINEL)
                self.assertIn("ASCII", str(caught.exception))
                self.assertEqual(self.vault.read_bytes(), before)

    def test_wrong_password_file(self) -> None:
        wrong = self._password_file("wrong-password", "not-the-password")
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"target": SENTINEL}, str(wrong))
        self._assert_untouched()

    def test_encrypt_failure(self) -> None:
        # Script callers catch PilferError only; an Ansible error must not escape raw.
        with (
            mock.patch.object(VaultLib, "encrypt", side_effect=RuntimeError(SENTINEL)),
            self.assertRaises(PilferError) as caught,
        ):
            self._set("target", SENTINEL)
        self.assertNotIn(SENTINEL, str(caught.exception))
        self.assertIn("RuntimeError", str(caught.exception))
        self._assert_untouched()

    def test_round_trip_decrypt_failure(self) -> None:
        real = VaultLib.decrypt
        calls = []

        def decrypt_then_fail(vault, data, *args, **kwargs):
            calls.append(data)
            if len(calls) > 1:
                raise AnsibleError("round-trip boom")
            return real(vault, data, *args, **kwargs)

        with (
            mock.patch.object(VaultLib, "decrypt", autospec=True, side_effect=decrypt_then_fail),
            self.assertRaises(PilferError) as caught,
        ):
            self._set("target", SENTINEL)
        self.assertIn("round-trip", str(caught.exception))
        self.assertNotIn("could not encrypt", str(caught.exception))
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
            "unknown tag": "target: !custom 'x'\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                path = self._encrypt(text, name=f"{label.replace(' ', '-')}.yml")
                before = path.read_bytes()
                with self.assertRaises(PilferError):
                    set_keys(path, {"target": SENTINEL}, str(self.password), check_only=True)
                self._assert_untouched(path, before)

    @unittest.skipIf(os.geteuid() == 0, "root writes to mode-555 directories")
    def test_check_only_refuses_a_read_only_directory(self) -> None:
        # The real write needs a temp next to the vault. check_only must hit the same
        # refusal, or a caller mints a token the write then cannot store.
        os.chmod(self.directory, 0o555)
        try:
            for check_only in (True, False):
                with self.subTest(check_only=check_only):
                    with self.assertRaises(PilferError):
                        set_keys(
                            self.vault,
                            {"target": SENTINEL},
                            str(self.password),
                            check_only=check_only,
                        )
                    self._assert_untouched()
        finally:
            # tearDown removes the directory before addCleanup callbacks run.
            os.chmod(self.directory, 0o755)

    @unittest.skipIf(os.geteuid() == 0, "root writes to mode-555 directories")
    def test_check_only_unchanged_value_still_probes_the_directory(self) -> None:
        placeholder = "pilfer-set-check-placeholder"
        self._set("target", placeholder)
        current = self.vault.read_bytes()
        os.chmod(self.directory, 0o555)
        try:
            with self.assertRaises(PilferError):
                set_keys(
                    self.vault,
                    {"target": placeholder},
                    str(self.password),
                    check_only=True,
                )
            self.assertEqual(self.vault.read_bytes(), current)
        finally:
            os.chmod(self.directory, 0o755)

    def test_check_only_sees_a_concurrent_change(self) -> None:
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
            set_keys(self.vault, {"target": SENTINEL}, str(self.password), check_only=True)
        self._assert_untouched(before=concurrent)

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

    def test_refuses_keys_yaml_reads_as_bool_or_null(self) -> None:
        for key in ("yes", "No", "on", "OFF", "true", "null", "Null"):
            with self.subTest(key=key):
                with self.assertRaises(PilferError) as caught:
                    self._set(key, SENTINEL)
                self.assertIn("bool or null", str(caught.exception))
        self._assert_untouched()
        # Look-alikes YAML 1.1 keeps as strings still work.
        self.assertEqual(self._set("y", SENTINEL), "added")

    def test_refused_key_is_not_in_the_error(self) -> None:
        pasted = "super-secret-token"
        with self.assertRaises(PilferError) as caught:
            self._set(pasted, SENTINEL)
        self.assertNotIn(pasted, str(caught.exception))
        self._assert_untouched()

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


class TestVaultSetUnsafe(VaultSetBase):
    """Ansible templates vaulted strings; a value with a Jinja delimiter must stay literal."""

    JINJA = "ab{{ 7*6 }}cd{% x %}{# y #}"

    def _template(self, path: Path, key: str) -> str:
        """What a play sees for key, through ansible-playbook and the vault password."""
        playbook = self.directory / "show.yml"
        playbook.write_text(
            "- hosts: localhost\n"
            "  gather_facts: false\n"
            f"  vars_files: [{path.name}]\n"
            "  tasks:\n"
            f"    - copy: {{content: '{{{{ {key} }}}}', dest: ./rendered.txt}}\n",
            encoding="utf-8",
        )
        ansible_playbook = shutil.which("ansible-playbook")
        assert ansible_playbook, "ansible-playbook not on PATH"
        subprocess.run(
            [
                ansible_playbook,
                "-i",
                "localhost,",
                "-c",
                "local",
                "--vault-password-file",
                str(self.password),
                str(playbook),
            ],
            check=True,
            capture_output=True,
            cwd=self.directory,
        )
        return (self.directory / "rendered.txt").read_text(encoding="utf-8")

    def test_jinja_value_is_written_unsafe_and_reaches_ansible_as_typed(self) -> None:
        self.assertEqual(self._set("target", self.JINJA), "updated")
        rendered = f"!unsafe {json.dumps(self.JINJA)}"
        self.assertEqual(self._view(), FIXTURE.replace('"old-value"', rendered))
        self.assertEqual(self._template(self.vault, "target"), self.JINJA)

    def test_plain_value_without_delimiters_is_not_tagged(self) -> None:
        # Single braces are not Jinja; homelab's line readers expect key: "...".
        for value in ("{a: 1}", "a{b}c", "%{x}", "{ {x} }"):
            with self.subTest(value=value):
                self._set("target", value)
                self.assertEqual(self._view(), _expected_target(value))

    def test_vault_with_unsafe_values_can_be_edited_and_they_stay_byte_exact(self) -> None:
        text = "keep: !unsafe 'x{{ y }}'  # note\nitems: !unsafe ['{{ a }}', b]\ntarget: old\n"
        vault = self._encrypt(text, name="unsafe.yml")
        self.assertEqual(self._set("target", SENTINEL, vault), "updated")
        self.assertEqual(self._view(vault), text.replace("target: old", f'target: "{SENTINEL}"'))

    def test_existing_unsafe_tag_is_kept_on_replace(self) -> None:
        vault = self._encrypt("target: !unsafe 'x{{ y }}'  # note\n", name="tagged.yml")
        self.assertEqual(self._set("target", SENTINEL, vault), "updated")
        self.assertEqual(self._view(vault), f'target: !unsafe "{SENTINEL}"  # note\n')
        self.assertEqual(self._set("target", SENTINEL, vault), "unchanged")

    def test_existing_unsafe_tag_is_dropped_when_ansible_would_retype(self) -> None:
        # !unsafe re-resolves the scalar. Current Ansible turns quoted 0123
        # into int 83, so the tag has to go. An older Ansible that still
        # returns the string keeps the tag.
        vault = self._encrypt("target: !unsafe 'old'\n", name="retype.yml")
        for value in ("0123", "yes", "null", "1:30", "2024-01-01"):
            with self.subTest(value=value):
                self.assertEqual(self._set("target", value, vault), "updated")
                text = self._view(vault)
                loaded = AnsibleLoader(text).get_single_data()["target"]
                self.assertIsInstance(loaded, str)
                self.assertEqual(loaded, value)
                if vault_set._ansible_keeps_string(value):
                    self.assertIn("!unsafe", text)
                else:
                    self.assertNotIn("!unsafe", text)
                    self.assertEqual(text, f"target: {json.dumps(value)}\n")

    def test_unsafe_jinja_that_ansible_would_retype_is_refused(self) -> None:
        # A natural Jinja value stays a string. Lock the refuse branch.
        with mock.patch.object(vault_set, "_ansible_keeps_string", return_value=False):
            with self.assertRaises(PilferError) as caught:
                self._set("target", "ab{{x}}")
        self.assertIn("!unsafe", str(caught.exception))
        self.assertNotIn("ab{{x}}", str(caught.exception))
        self._assert_untouched()

    def test_same_jinja_value_gains_the_tag(self) -> None:
        # Stored untagged, Ansible would template it; the same value is not "unchanged".
        vault = self._encrypt(f"target: {json.dumps(self.JINJA)}\n", name="untagged.yml")
        self.assertEqual(self._set("target", self.JINJA, vault), "updated")
        self.assertEqual(self._view(vault), f"target: !unsafe {json.dumps(self.JINJA)}\n")
        self.assertEqual(self._set("target", self.JINJA, vault), "unchanged")

    def test_new_key_with_jinja_is_added_unsafe(self) -> None:
        self.assertEqual(self._set("beta", self.JINJA), "added")
        self.assertEqual(self._view(), FIXTURE + f"beta: !unsafe {json.dumps(self.JINJA)}\n")
        self.assertEqual(self._template(self.vault, "beta"), self.JINJA)

    def test_safe_load_is_not_patched(self) -> None:
        # The !unsafe constructor lives on pilfer's own loader only.
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.safe_load("a: !unsafe x\n")

    def test_open_leaves_a_file_changed_during_decrypt(self) -> None:
        from pilfer.cli import _decrypt_whole_file

        other = _vault().encrypt(b"target: other\n")
        real = VaultLib.decrypt

        def decrypt_and_replace(vault, data, *args, **kwargs):
            self.vault.write_bytes(other)
            return real(vault, data, *args, **kwargs)

        with (
            mock.patch.object(VaultLib, "decrypt", autospec=True, side_effect=decrypt_and_replace),
            self.assertRaises(PilferError),
        ):
            _decrypt_whole_file(str(self.vault), _vault(), self.directory.resolve())
        self.assertEqual(self.vault.read_bytes(), other)
        self.assertFalse((self.directory / f"{self.vault.name}.pilfer-open").exists())
        self._assert_no_temp()

    def test_set_waits_while_another_process_holds_the_lock(self) -> None:
        import pilfer.publish

        repo = str(Path(__file__).resolve().parents[1])
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        child = (
            "import os\n"
            "from pilfer.vault_set import set_keys\n"
            f"os.write({write_fd}, b'1')\n"
            f"set_keys({str(self.vault)!r}, {{'target': 'from-other-process'}}, "
            f"{str(self.password)!r})\n"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = repo + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            [sys.executable, "-c", child],
            cwd=self.directory,
            env=env,
            pass_fds=(write_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(write_fd)
        finished = None
        try:
            with pilfer.publish.vault_file_lock(self.vault):
                self.assertEqual(os.read(read_fd, 1), b"1")
                try:
                    proc.wait(timeout=0.4)
                except subprocess.TimeoutExpired:
                    blocked = True
                else:
                    blocked = False
                self.assertTrue(blocked, "set finished while the vault lock was held")
            finished = proc.wait(timeout=30)
        finally:
            os.close(read_fd)
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        stderr = b""
        if proc.stderr is not None:
            stderr = proc.stderr.read()
            proc.stderr.close()
        if proc.stdout is not None:
            proc.stdout.close()
        self.assertEqual(finished, 0, stderr)
        self.assertEqual(self._view(), _expected_target("from-other-process"))

    def test_home_password_path_beats_the_parent_fallback(self) -> None:
        from pilfer.cli import get_vault_password_file

        home = os.path.expanduser("~/.ansible-vault/.vault-file")
        parent = os.path.normpath(os.path.join(os.getcwd(), "../../vault_password_file"))

        def exists(path: str) -> bool:
            return path in (home, parent, "../../vault_password_file")

        with mock.patch("pilfer.cli.os.path.exists", side_effect=exists):
            self.assertEqual(get_vault_password_file(), home)

    def test_parent_password_fallback_is_last(self) -> None:
        from pilfer.cli import get_vault_password_file

        parent = "../../vault_password_file"

        def exists(path: str) -> bool:
            return path == parent

        with mock.patch("pilfer.cli.os.path.exists", side_effect=exists):
            self.assertEqual(get_vault_password_file(), parent)


class TestReadValue(unittest.TestCase):
    """The CLI value source when VALUE is left out."""

    def _stdin(self, data: bytes, tty: bool = False):
        stream = mock.Mock()
        stream.isatty.return_value = tty
        stream.buffer.read.side_effect = lambda n=-1: data if n < 0 else data[:n]
        return mock.patch.object(sys, "stdin", stream)

    def test_pipe_drops_one_trailing_line_ending(self) -> None:
        for data, expected in (
            (b"tok\n", "tok"),
            (b"tok\r\n", "tok"),
            (b"tok", "tok"),
            (b"tok\n\n", "tok\n"),
            (b"multi\nline\n", "multi\nline"),
            ("ünï\n".encode(), "ünï"),
        ):
            with self.subTest(data=data), self._stdin(data):
                self.assertEqual(vault_set.read_value("k"), expected)

    def test_pipe_refuses_non_utf8_without_echoing_it(self) -> None:
        with self._stdin(b"pass\xffword"), self.assertRaises(PilferError) as caught:
            vault_set.read_value("k")
        self.assertNotIn("xff", str(caught.exception))

    def test_pipe_refuses_oversized_input(self) -> None:
        with self._stdin(b"x" * (vault_set.MAX_STDIN_VALUE_BYTES + 1)):
            with self.assertRaises(PilferError):
                vault_set.read_value("k")

    def test_terminal_prompts_without_echo(self) -> None:
        with (
            self._stdin(b"", tty=True),
            mock.patch.object(vault_set.getpass, "getpass", return_value="typed") as prompt,
        ):
            self.assertEqual(vault_set.read_value("k"), "typed")
        self.assertIn("k", prompt.call_args.args[0])


class TestVaultSetCLI(VaultSetBase):
    def _run(self, *args: str, stdin: bytes = b"") -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(PILFER_SCRIPT), "set", *args],
            capture_output=True,
            check=False,
            cwd=self.directory,
            input=stdin,
        )

    def test_cli_reads_value_from_stdin(self) -> None:
        result = self._run(
            "-p", str(self.password), str(self.vault), "target", stdin=TRICKY.encode() + b"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(TRICKY.strip().encode(), result.stdout + result.stderr)
        self.assertEqual(self._view(), _expected_target(TRICKY))

    def test_cli_empty_stdin_is_refused(self) -> None:
        for stdin in (b"", b"\n"):
            with self.subTest(stdin=stdin):
                result = self._run("-p", str(self.password), str(self.vault), "target", stdin=stdin)
                self.assertEqual(result.returncode, 1)
                self._assert_untouched()

    def test_cli_refuses_before_reading_stdin(self) -> None:
        # A refusal must come before the secret is typed or pasted, not after.
        (self.directory / "secrets.yml.pilfer-open").touch()
        with mock.patch.object(vault_set, "read_value") as read_value:
            from pilfer.cli import main

            self.assertEqual(main(["set", "-p", str(self.password), str(self.vault), "target"]), 1)
        read_value.assert_not_called()
        self._assert_untouched()

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

    def test_cli_leading_dash_without_separator_does_not_echo_the_value(self) -> None:
        secret = "-s3cret-value"
        result = self._run("-p", str(self.password), str(self.vault), "target", secret)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        self.assertIn(b"put -- before", result.stderr)

    def test_cli_unknown_long_option_names_the_flag(self) -> None:
        result = self._run("-p", str(self.password), str(self.vault), "target", "--typo")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"--typo", result.stderr)
        self.assertNotIn(b"put -- before", result.stderr)
        mixed = self._run("-p", str(self.password), str(self.vault), "target", "--typo", "-s3cret")
        self.assertEqual(mixed.returncode, 2)
        self.assertNotIn(b"-s3cret", mixed.stdout + mixed.stderr)
        self.assertIn(b"put -- before", mixed.stderr)
        before = subprocess.run(
            [sys.executable, str(PILFER_SCRIPT), "--typo", "set", "file", "key"],
            capture_output=True,
            check=False,
        )
        self.assertEqual(before.returncode, 2)
        self.assertIn(b"--typo", before.stderr)
        self.assertNotIn(b"put -- before", before.stderr)
        self._assert_untouched()

    def test_close_without_a_session_reports_on_stderr(self) -> None:
        result = subprocess.run(
            [sys.executable, str(PILFER_SCRIPT), "close"],
            capture_output=True,
            check=False,
            cwd=self.directory,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"No vault file list found", result.stderr)
        self.assertNotIn(b"No vault file list found", result.stdout)

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


class TestReviewFollowups(VaultSetBase):
    def test_failed_decrypt_leaves_another_opens_backup(self) -> None:
        from pilfer import cli

        plain = self.directory / "open.yml"
        plain.write_text("target: already-open\n", encoding="utf-8")
        backup = Path(cli._encrypted_backup_path(str(plain)))
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\nkeep-this-backup\n")
        cli._write_session([{"path": str(plain), "kind": "file"}])
        with self.assertRaises(PilferError) as caught:
            cli.decrypt_vault_files(str(self.password))
        self.assertIn("another open", str(caught.exception))
        self.assertEqual(backup.read_bytes(), b"$ANSIBLE_VAULT;1.1;AES256\nkeep-this-backup\n")
        self.assertTrue((self.directory / "vaultedFileList.json").is_file())

    def test_symlink_lock_is_refused(self) -> None:
        import pilfer.publish

        lock = self.directory / f"{self.vault.name}.pilfer-lock"
        lock.symlink_to(self.directory / "missing-lock-target")
        with self.assertRaises(OSError):
            with pilfer.publish.vault_file_lock(self.vault):
                pass
        self._assert_untouched()
        self.assertTrue(lock.is_symlink())

    def test_planted_lock_symlink_keeps_the_target_mode(self) -> None:
        victim = self.directory / "victim.sh"
        victim.write_text("#!/bin/sh\n", encoding="utf-8")
        victim.chmod(0o755)
        (self.directory / f"{self.vault.name}.pilfer-lock").symlink_to(victim)
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"target": SENTINEL}, str(self.password))
        self.assertEqual(victim.stat().st_mode & 0o777, 0o755)
        self._assert_untouched()

    def test_lock_refuses_a_fifo(self) -> None:
        import pilfer.publish

        lock = self.directory / f"{self.vault.name}.pilfer-lock"
        os.mkfifo(lock)
        mode = lock.stat().st_mode & 0o777
        with self.assertRaises(OSError) as caught:
            with pilfer.publish.vault_file_lock(self.vault):
                pass
        self.assertIn("not a regular file", str(caught.exception))
        self.assertEqual(lock.stat().st_mode & 0o777, mode)
        self._assert_untouched()

    def test_project_lock_blocks_a_second_process(self) -> None:
        import pilfer.publish

        repo = str(Path(__file__).resolve().parents[1])
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        child = (
            "import os\n"
            "from pilfer.publish import project_session_lock\n"
            f"os.write({write_fd}, b'1')\n"
            "with project_session_lock():\n"
            f"    os.write({write_fd}, b'2')\n"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = repo + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            [sys.executable, "-c", child],
            cwd=self.directory,
            env=env,
            pass_fds=(write_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(write_fd)
        try:
            with pilfer.publish.project_session_lock():
                self.assertEqual(os.read(read_fd, 1), b"1")
                with self.assertRaises(subprocess.TimeoutExpired):
                    proc.wait(timeout=0.4)
            self.assertEqual(os.read(read_fd, 1), b"2")
            self.assertEqual(proc.wait(timeout=30), 0)
        finally:
            os.close(read_fd)
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if proc.stderr is not None:
                proc.stderr.close()
            if proc.stdout is not None:
                proc.stdout.close()

    def test_password_file_decode_error_hides_the_byte(self) -> None:
        from pilfer.cli import _load_password

        bad = self.directory / "bad-pass"
        bad.write_bytes(b"\xff\xfe")
        with self.assertRaises(PilferError) as caught:
            _load_password(str(bad))
        self.assertNotIn("xff", str(caught.exception).lower())
        self.assertIn("not valid text", str(caught.exception))

    def test_password_rotate_refuses_a_symlink_backup(self) -> None:
        from pilfer.cli import _rotate_password_file

        old = self._password_file("old-pass", "old-secret")
        new = self._password_file("new-pass", "new-secret")
        outside = self.directory / "outside"
        outside.write_text("keep", encoding="utf-8")
        (self.directory / "old-pass_old").symlink_to(outside)
        with self.assertRaises(PilferError) as caught:
            _rotate_password_file(str(old), str(new))
        self.assertIn("symlink", str(caught.exception))
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep")
        self.assertEqual(old.read_text(encoding="utf-8").strip(), "old-secret")

    def test_strict_vault_id_match_still_decrypts_a_label(self) -> None:
        import ansible.constants as C

        from pilfer import cli

        secret = VaultSecret(PASSWORD.encode("utf-8"))
        blob = VaultLib([("prod", secret)]).encrypt(b"target: labeled\n", vault_id="prod")
        with (
            mock.patch.object(C, "DEFAULT_VAULT_ID_MATCH", True),
            mock.patch.object(cli, "DEFAULT_VAULT_ID_MATCH", True),
        ):
            vault = cli._make_vault(PASSWORD)
            cli.ensure_vault_label(vault, blob)
            self.assertEqual(vault.decrypt(blob), b"target: labeled\n")


if __name__ == "__main__":
    unittest.main()
