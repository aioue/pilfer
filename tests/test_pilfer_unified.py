#!/usr/bin/env python3
"""
Unified tests for pilfer - whole-file vaults, session safety, and inline encrypt_string.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from abc import ABC, abstractmethod
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.errors import AnsibleError
from ansible.parsing.vault import VaultLib, VaultSecret

from pilfer import __version__ as pilfer_version
from pilfer import cli as pilfer_cli
from pilfer import inline as pilfer_inline


def make_vault(password: str = "test_password") -> VaultLib:
    return VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password.encode("utf-8")))])


def encrypt_string_yaml(
    vault: VaultLib,
    name: str,
    value: bytes,
    indent: str = "          ",
    vault_id: str | None = None,
) -> str:
    """Build YAML matching ansible-vault encrypt_string --name output."""
    encrypted = vault.encrypt(value, vault_id=vault_id) if vault_id else vault.encrypt(value)
    enc = encrypted.decode("utf-8").strip().splitlines()
    body = "\n".join(indent + line for line in enc)
    return f"{name}: !vault |\n{body}\n"


PILFER_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")


class ProjectDirTest(unittest.TestCase):
    """Each test runs in its own temp project: cwd, a vault_pass file, and self.vault."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        # Cleanups run last-in first-out: leave the directory, then delete it.
        self.addCleanup(shutil.rmtree, self.test_dir)
        self.addCleanup(os.chdir, self.original_cwd)
        with open("vault_pass", "w") as f:
            f.write("test_password")
        self.vault = make_vault()

    def run_pilfer(self, *args):
        """Run pilfer.py in a subprocess. stdin is closed: rekey without --yes
        would otherwise wait at its REKEY prompt for as long as the test runs."""
        return subprocess.run(
            [sys.executable, PILFER_SCRIPT, *args],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
        )


class PilferTestBase(ProjectDirTest, ABC):
    """Shared happy-path tests for CLI function API and standalone script."""

    def setUp(self):
        super().setUp()
        self.vault_password = "test_password"

        self.vault_content_unix = "test_secret: value1\nother_secret: value2\n"
        self.vault_content_windows = "test_secret: value1\r\nother_secret: value2\r\n"
        self.vault_content_mixed = "test_secret: value1\nother_secret: value2\r\n"

        vault = make_vault(self.vault_password)
        self.vault_files = {
            "unix_vault.yml": vault.encrypt(self.vault_content_unix.encode("utf-8")),
            "windows_vault.yml": vault.encrypt(self.vault_content_windows.encode("utf-8")),
            "mixed_vault.yml": vault.encrypt(self.vault_content_mixed.encode("utf-8")),
        }

        for filename, encrypted_content in self.vault_files.items():
            with open(filename, "wb") as f:
                f.write(encrypted_content)

        self.original_hashes = {}
        for filename in self.vault_files:
            with open(filename, "rb") as f:
                self.original_hashes[filename] = hashlib.sha256(f.read()).hexdigest()

    @abstractmethod
    def pilfer_open(self, vault_pass_file="vault_pass"):
        pass

    @abstractmethod
    def pilfer_close(self, vault_pass_file="vault_pass"):
        pass

    def test_unchanged_files_same_hash(self):
        self.pilfer_open()
        modified_count = self.pilfer_close()
        self.assertEqual(modified_count, 0)
        for filename in self.vault_files:
            with open(filename, "rb") as f:
                new_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(self.original_hashes[filename], new_hash)

    def test_line_endings_preserved(self):
        self.pilfer_open()
        with open("unix_vault.yml", "rb") as f:
            self.assertEqual(f.read(), self.vault_content_unix.encode("utf-8"))
        with open("windows_vault.yml", "rb") as f:
            self.assertEqual(f.read(), self.vault_content_windows.encode("utf-8"))
        with open("mixed_vault.yml", "rb") as f:
            self.assertEqual(f.read(), self.vault_content_mixed.encode("utf-8"))
        self.assertEqual(self.pilfer_close(), 0)
        self.pilfer_open()
        with open("unix_vault.yml", "rb") as f:
            self.assertEqual(f.read(), self.vault_content_unix.encode("utf-8"))

    def test_modified_file_detection(self):
        self.pilfer_open()
        with open("unix_vault.yml", "w") as f:
            f.write("modified_secret: new_value\n")
        self.assertEqual(self.pilfer_close(), 1)
        with open("unix_vault.yml", "rb") as f:
            self.assertNotEqual(
                self.original_hashes["unix_vault.yml"],
                hashlib.sha256(f.read()).hexdigest(),
            )
        for filename in ["windows_vault.yml", "mixed_vault.yml"]:
            with open(filename, "rb") as f:
                self.assertEqual(
                    self.original_hashes[filename],
                    hashlib.sha256(f.read()).hexdigest(),
                )

    def test_multiple_modifications(self):
        self.pilfer_open()
        with open("unix_vault.yml", "w") as f:
            f.write("modified_secret1: new_value1\n")
        with open("windows_vault.yml", "w") as f:
            f.write("modified_secret2: new_value2\r\n")
        self.assertEqual(self.pilfer_close(), 2)


class TestPilferCLI(PilferTestBase):
    def pilfer_open(self, vault_pass_file="vault_pass"):
        pilfer_cli.open_vault_files(vault_pass_file)

    def pilfer_close(self, vault_pass_file="vault_pass"):
        return pilfer_cli.recrypt_vault_files(vault_pass_file)


class TestPilferStandalone(ProjectDirTest):
    """Smoke: standalone entry delegates (full matrix covered by TestPilferCLI)."""

    def test_standalone_open_close_smoke(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"a: 1\n"))
        opened = self.run_pilfer("open", "-p", "vault_pass")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        closed = self.run_pilfer("close", "-p", "vault_pass")
        self.assertEqual(closed.returncode, 0, closed.stderr)


class TestSessionSafety(ProjectDirTest):
    """Regression tests for critical session / integrity behaviour."""

    def setUp(self):
        super().setUp()
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))


    def _run(self, *args, password_file="vault_pass"):
        return self.run_pilfer(*args, "-p", password_file)

    def test_double_open_refused(self):
        first = self._run("open")
        self.assertEqual(first.returncode, 0, first.stderr)
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")

        second = self._run("open")
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("Session already open", second.stderr)

        backups = [
            os.path.join(r, "encrypted")
            for r, _, files in os.walk(".vault")
            if "encrypted" in files
        ]
        self.assertTrue(backups)
        with open(backups[0], "rb") as f:
            self.assertTrue(f.read().startswith(b"$ANSIBLE_VAULT;"))

    def test_partial_close_keeps_session(self):
        self.assertEqual(self._run("open").returncode, 0)
        hash_path = next(
            os.path.join(r, "hash") for r, _, files in os.walk(".vault") if "hash" in files
        )
        os.remove(hash_path)
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")

    def test_retry_close_after_partial_failure(self):
        """After a failed close, restoring the missing hash sidecar allows a clean close."""
        with open("other.yml", "wb") as f:
            f.write(self.vault.encrypt(b"other: 1\n"))
        self.assertEqual(self._run("open").returncode, 0)

        target_hash = next(
            os.path.join(r, "hash") for r, _, files in os.walk(".vault") if "hash" in files
        )
        with open(target_hash) as f:
            saved_hash = f.read()
        os.remove(target_hash)

        self.assertNotEqual(self._run("close").returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

        with open(target_hash, "w") as f:
            f.write(saved_hash)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))
        with open("secret.yml", "rb") as f:
            self.assertTrue(f.read().startswith(b"$ANSIBLE_VAULT;"))
        with open("other.yml", "rb") as f:
            self.assertTrue(f.read().startswith(b"$ANSIBLE_VAULT;"))

    def test_session_holds_no_password_hash(self):
        # pilfer < 2.31 stored an unsalted SHA-256 of the vault password here,
        # far cheaper to guess offline than the vault's own key derivation.
        self.assertEqual(self._run("open").returncode, 0)
        with open("vaultedFileList.json") as f:
            session = json.load(f)
        self.assertNotIn("password_sha256", session)
        self.assertNotIn(hashlib.sha256(b"test_password").hexdigest(), json.dumps(session))
        self.assertEqual(self._run("close").returncode, 0)

    def test_open_close_keeps_the_vault_mode(self):
        for edit in (False, True):
            with self.subTest(edit=edit):
                os.chmod("secret.yml", 0o644)
                self.assertEqual(self._run("open").returncode, 0)
                # Plaintext is private while the session is open.
                self.assertEqual(stat.S_IMODE(os.stat("secret.yml").st_mode), 0o600)
                if edit:
                    with open("secret.yml", "w") as f:
                        f.write("secret_key: changed\n")
                closed = self._run("close")
                self.assertEqual(closed.returncode, 0, closed.stderr)
                self.assertEqual(stat.S_IMODE(os.stat("secret.yml").st_mode), 0o644)

    def test_close_from_an_older_session_without_a_hash_still_proves_the_password(self):
        self.assertEqual(self._run("open").returncode, 0)
        with open("vaultedFileList.json") as f:
            session = json.load(f)
        session["password_sha256"] = "left-by-an-older-pilfer"
        with open("vaultedFileList.json", "w") as f:
            json.dump(session, f)
        with open("wrong_pass", "w") as f:
            f.write("not-the-password")
        refused = self._run("close", password_file="wrong_pass")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("does not match", refused.stderr)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)

    def test_password_mismatch_on_close_refused(self):
        self.assertEqual(self._run("open").returncode, 0)
        with open("secret.yml", "w") as f:
            f.write("secret_key: changed\n")
        with open("other_pass", "w") as f:
            f.write("different_password")
        closed = self._run("close", password_file="other_pass")
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn("does not match", closed.stderr)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_wrong_password_on_open_exits_nonzero(self):
        with open("bad_pass", "w") as f:
            f.write("wrong")
        result = self._run("open", password_file="bad_pass")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nothing was opened", result.stderr)
        with open("secret.yml", "rb") as f:
            self.assertTrue(f.read().startswith(b"$ANSIBLE_VAULT;"))
        self.assertFalse(os.path.isfile("vaultedFileList.json"))
        self.assertFalse(os.path.isdir(".vault"))
        self.assertFalse(os.path.isfile("secret.yml.pilfer-open"))

    def test_session_symlink_refused(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        victim = os.path.join(outside, "victim.json")
        with open(victim, "w") as handle:
            handle.write("keep-me")
        os.symlink(victim, "vaultedFileList.json")
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("symlink", (opened.stderr + opened.stdout).lower())
        with open(victim) as handle:
            self.assertEqual(handle.read(), "keep-me")
        with open("secret.yml", "rb") as handle:
            self.assertTrue(handle.read().startswith(b"$ANSIBLE_VAULT;"))

    def test_dangling_session_symlink_does_not_create_target(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        victim = os.path.join(outside, "created-by-pilfer")
        os.symlink(victim, "vaultedFileList.json")
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertFalse(os.path.lexists(victim))

    def test_vault_dir_symlink_refused(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        os.symlink(outside, ".vault")
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("symlink", (opened.stderr + opened.stdout).lower())
        self.assertEqual(os.listdir(outside), [])
        with open("secret.yml", "rb") as handle:
            self.assertTrue(handle.read().startswith(b"$ANSIBLE_VAULT;"))

    def test_open_sidecar_symlink_refused(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        victim = os.path.join(outside, "victim")
        with open(victim, "w") as handle:
            handle.write("keep-me")
        os.symlink(victim, "secret.yml.pilfer-open")
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("symlink", (opened.stderr + opened.stdout).lower())
        with open(victim) as handle:
            self.assertEqual(handle.read(), "keep-me")
        with open("secret.yml", "rb") as handle:
            self.assertTrue(handle.read().startswith(b"$ANSIBLE_VAULT;"))

    def test_symlink_vault_target_refused(self):
        outside_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside_dir, True)
        victim = os.path.join(outside_dir, "victim.yml")
        with open(victim, "wb") as f:
            f.write(self.vault.encrypt(b"pwned: data\n"))
        os.remove("secret.yml")
        os.symlink(victim, "secret.yml")
        abs_link = os.path.abspath("secret.yml")
        with open("vaultedFileList.json", "w") as f:
            json.dump(
                {
                    "version": 2,
                    "password_sha256": "",
                    "entries": [{"kind": "file", "path": abs_link}],
                },
                f,
            )
        with self.assertRaises(pilfer_cli.PilferError):
            pilfer_cli.decrypt_vault_files("vault_pass")
        with open(victim, "rb") as f:
            self.assertTrue(f.read().startswith(b"$ANSIBLE_VAULT;"))

    def test_close_without_open_exits_nonzero(self):
        self.assertNotEqual(self._run("close").returncode, 0)

    def test_empty_tree_open_succeeds(self):
        os.remove("secret.yml")
        result = self._run("open")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No vault files found", result.stdout)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))

    def test_skips_dot_vault_during_scan(self):
        self.assertEqual(self._run("open").returncode, 0)
        os.remove("vaultedFileList.json")
        backup = next(
            os.path.join(r, "encrypted")
            for r, _, files in os.walk(".vault")
            if "encrypted" in files
        )
        shutil.copy2(backup, "secret.yml")
        found = pilfer_cli.scan_project().targets
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["path"].endswith("secret.yml"))
        self.assertFalse(any(".vault" in e["path"] for e in found))

    def test_skips_nested_git_repo(self):
        nested = os.path.join("nested_project")
        os.makedirs(os.path.join(nested, ".git"))
        with open(os.path.join(nested, "nested_secret.yml"), "wb") as f:
            f.write(self.vault.encrypt(b"nested: 1\n"))
        found = pilfer_cli.scan_project().targets
        paths = [e["path"] for e in found]
        self.assertTrue(any(p.endswith("secret.yml") for p in paths))
        self.assertFalse(any("nested_secret.yml" in p for p in paths))

    def test_skips_nested_git_submodule_gitfile(self):
        """Submodules use a .git *file* pointing at the superproject - still skip."""
        nested = os.path.join("submodule_project")
        os.makedirs(nested)
        with open(os.path.join(nested, ".git"), "w") as f:
            f.write("gitdir: ../.git/modules/submodule_project\n")
        with open(os.path.join(nested, "nested_secret.yml"), "wb") as f:
            f.write(self.vault.encrypt(b"nested: 1\n"))
        found = pilfer_cli.scan_project().targets
        paths = [e["path"] for e in found]
        self.assertTrue(any(p.endswith("secret.yml") for p in paths))
        self.assertFalse(any("nested_secret.yml" in p for p in paths))

    def test_decrypted_files_are_private_mode(self):
        self.assertEqual(self._run("open").returncode, 0)
        mode = stat.S_IMODE(os.stat("secret.yml").st_mode)
        self.assertEqual(mode, 0o600)

    def test_missing_password_file_exits_nonzero(self):
        result = self._run("open", password_file="does-not-exist")
        self.assertNotEqual(result.returncode, 0)

    def test_session_list_from_an_old_release_is_refused(self):
        """List and {"files": ...} sessions predate releases that can close safely here."""
        abs_path = os.path.abspath("secret.yml")
        with open("secret.yml", "rb") as f:
            before = f.read()
        for old in ([abs_path], {"files": [abs_path]}):
            with self.subTest(old=old):
                with open("vaultedFileList.json", "w") as f:
                    json.dump(old, f)
                for action in (pilfer_cli.decrypt_vault_files, pilfer_cli.recrypt_vault_files):
                    with self.assertRaises(pilfer_cli.PilferError) as caught:
                        action("vault_pass")
                    self.assertIn("older pilfer", str(caught.exception))
                with open("secret.yml", "rb") as f:
                    self.assertEqual(f.read(), before)

    def test_failed_open_removes_only_what_it_wrote(self):
        real_write = pilfer_cli.write_atomic

        def fail_on_hash(path, data, **kwargs):
            if path.endswith("hash"):
                raise OSError(28, "No space left on device")
            return real_write(path, data, **kwargs)

        with open("secret.yml", "rb") as f:
            before = f.read()
        with mock.patch.object(pilfer_cli, "write_atomic", side_effect=fail_on_hash):
            result = pilfer_cli.main(["open", "-p", "vault_pass"])
        self.assertEqual(result, 1)
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertFalse(os.path.exists(".vault"))
        self.assertFalse(os.path.exists("vaultedFileList.json"))
        self.assertFalse(os.path.exists("secret.yml.pilfer-open"))

    def test_close_leaves_unexpected_vault_contents_and_says_so(self):
        self.assertEqual(self._run("open").returncode, 0)
        with open(os.path.join(".vault", "stray"), "wb") as f:
            f.write(b"$ANSIBLE_VAULT;1.1;AES256\nnot-ours\n")
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertIn("Left .vault/ in place", closed.stderr)
        with open(os.path.join(".vault", "stray"), "rb") as f:
            self.assertIn(b"not-ours", f.read())

    def test_empty_password_fingerprint_close_proves_and_succeeds(self):
        """Empty password_sha256 can close when backups prove the password."""
        self.assertEqual(self._run("open").returncode, 0)
        with open("vaultedFileList.json") as f:
            data = json.load(f)
        data["password_sha256"] = ""
        with open("vaultedFileList.json", "w") as f:
            json.dump(data, f)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))

    def test_incomplete_session_abandoned_on_reopen(self):
        """Crash after writing session list but before decrypt must not deadlock."""
        abs_path = os.path.abspath("secret.yml")
        with open("vaultedFileList.json", "w") as f:
            json.dump(
                {
                    "version": 2,
                    "password_sha256": "deadbeef",
                    "entries": [{"kind": "file", "path": abs_path}],
                },
                f,
            )
        # Still ciphertext, no .vault backups / sidecars -> incomplete open.
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertIn("Cleared incomplete session", opened.stdout)
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")
        self.assertTrue(os.path.isfile("vaultedFileList.json"))
        self.assertTrue(os.path.isfile("secret.yml.pilfer-open"))

    def test_plaintext_session_without_artifacts_not_abandoned(self):
        """Deleting backups/sidecars after open must not clear a live session."""
        self.assertEqual(self._run("open").returncode, 0)
        shutil.rmtree(".vault", ignore_errors=True)
        for name in os.listdir("."):
            if name.endswith(".pilfer-open"):
                os.remove(name)
        # Session list remains; file is plaintext - must refuse re-open.
        blocked = self._run("open")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("Session already open", blocked.stderr + blocked.stdout)
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")

    def test_orphan_markers_without_session_refuse_open(self):
        """Deleting the session after open must not let a later open exit 0."""
        self.assertEqual(self._run("open").returncode, 0)
        with open("secret.yml", "w") as f:
            f.write("secret_key: hunter2  # pilfer:vault:0\n")
        os.remove("vaultedFileList.json")
        shutil.rmtree(".vault", ignore_errors=True)
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("Orphaned open state", opened.stderr)
        with open("secret.yml") as f:
            self.assertIn("hunter2", f.read())

    def test_extensionless_marker_blocks_open(self):
        """group_vars/all style files are opened, so a leftover marker must block."""
        with open("group_vars_all", "w") as handle:
            handle.write('db_password: "secret"  # pilfer:vault:0\n')
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("Orphaned open state", opened.stderr)
        self.assertTrue(os.path.isfile("group_vars_all"))

    def test_cancelled_open_staging_file_is_removed(self):
        """Extensionless .pilfer-rekey-* temps can hold decrypted inline text."""
        with open(".pilfer-rekey-cancelled", "w") as handle:
            handle.write('db_password: "secret"  # pilfer:vault:0\n')
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertFalse(os.path.exists(".pilfer-rekey-cancelled"))

    def test_killed_whole_file_plaintext_temp_removed_on_open(self):
        """SIGKILL skips finally. Whole-file plaintext has no inline marker."""
        with open(".pilfer-rekey-killed", "w") as handle:
            handle.write("secret_key: hunter2\n")
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertFalse(os.path.exists(".pilfer-rekey-killed"))

    def test_ciphertext_temp_is_removed_on_open(self):
        """A leftover temp never holds the only copy: its rename never happened."""
        with open(".pilfer-rekey-deadbeef", "wb") as handle:
            handle.write(self.vault.encrypt(b"orphan: true\n"))
        os.makedirs(".vault/nested")
        with open(".vault/nested/.pilfer-rekey-backup1", "wb") as handle:
            handle.write(b"killed backup write")
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertFalse(os.path.exists(".pilfer-rekey-deadbeef"))
        self.assertFalse(os.path.exists(".vault/nested/.pilfer-rekey-backup1"))

    def test_renamed_yaml_under_rekey_prefix_still_blocks(self):
        with open(".pilfer-rekey-hidden.yml", "w") as handle:
            handle.write('db_password: "secret"  # pilfer:vault:0\n')
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("Orphaned open state", opened.stderr)
        self.assertTrue(os.path.isfile(".pilfer-rekey-hidden.yml"))

    def test_marker_mention_in_docs_does_not_block_open(self):
        """Quoting the marker prefix in non-YAML files must not look like orphan state."""
        with open("README.md", "w") as f:
            f.write("Refuse staged # pilfer:vault: markers in YAML.\n")
        with open("hook.sh", "w") as f:
            f.write("grep --cached -l '# pilfer:vault:'\n")
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)

    def test_orphan_vault_dir_without_session_refuse_open(self):
        self.assertEqual(self._run("open").returncode, 0)
        os.remove("vaultedFileList.json")
        # Leave .vault backups and plaintext in place.
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("Orphaned open state", opened.stderr)

    def test_orphan_whole_file_sidecar_without_session_refuse_open(self):
        """Whole-file opens leave no markers; *.pilfer-open must block re-open."""
        self.assertEqual(self._run("open").returncode, 0)
        self.assertTrue(os.path.isfile("secret.yml.pilfer-open"))
        os.remove("vaultedFileList.json")
        shutil.rmtree(".vault", ignore_errors=True)
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertIn("Orphaned open state", opened.stderr)
        self.assertIn(".pilfer-open", opened.stderr)
        with open("secret.yml") as f:
            self.assertIn("hunter2", f.read())

    def test_close_keeps_vault_id_label(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n", vault_id="prod"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("secret.yml", "w") as f:
            f.write("secret_key: changed\n")
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        with open("secret.yml", "rb") as f:
            body = f.read()
        self.assertTrue(body.startswith(b"$ANSIBLE_VAULT;1.2;AES256;prod\n"))
        self.assertEqual(self.vault.decrypt(body), b"secret_key: changed\n")

    def test_close_retry_after_already_encrypted_write(self):
        """Interrupted close that wrote ciphertext must be idempotent on retry."""
        self.assertEqual(self._run("open").returncode, 0)
        with open("secret.yml", "w") as f:
            f.write("secret_key: changed\n")
        # Simulate crash after encrypt write: ciphertext on disk, session still open.
        encrypted = self.vault.encrypt(b"secret_key: changed\n")
        with open("secret.yml", "wb") as f:
            f.write(encrypted)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))
        with open("secret.yml", "rb") as f:
            body = f.read()
        self.assertTrue(body.startswith(b"$ANSIBLE_VAULT;"))
        self.assertEqual(self.vault.decrypt(body), b"secret_key: changed\n")


class TestInlineVault(ProjectDirTest):
    """Issue #3: in-place encrypt_string / !vault handling."""

    def _run(
        self,
        *args,
        password_file="vault_pass",
        include_encrypted_vars=None,
        confirm_delete=False,
        extra=None,
    ):
        args = list(args)
        # Inline tests default to opening encrypt_string blobs.
        if include_encrypted_vars is None:
            include_encrypted_vars = bool(args) and args[0] == "open"
        if include_encrypted_vars:
            args.append("--include-encrypted-vars")
        if confirm_delete:
            args.append("--confirm-delete")
        return self.run_pilfer(*args, *(extra or []), "-p", password_file)

    def _write_vars_file(self, *pairs):
        """pairs: (name, plaintext_bytes)"""
        chunks = ["---\n", "plain_key: visible\n"]
        for name, value in pairs:
            chunks.append(encrypt_string_yaml(self.vault, name, value))
        with open("group_vars.yml", "w") as f:
            f.write("".join(chunks))
        with open("group_vars.yml", "rb") as f:
            return f.read()

    def _open_edit_close(self, secret, edit):
        self._write_vars_file(("db_password", secret))
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        with open("group_vars.yml") as f:
            text = f.read()
        with open("group_vars.yml", "w") as f:
            f.write(edit(text))
        return self._run("close")

    def _stored(self):
        with open("group_vars.yml", "rb") as f:
            return [self.vault.decrypt(span.ciphertext) for span in pilfer_inline.find_inline_vault_spans(f.read())]

    def test_close_reads_an_edit_the_way_yaml_does(self):
        # Each of these was stored as the raw text (quotes, escapes, comment
        # and all) before close read values with the YAML parser.
        cases = {
            "single quotes": ("'new'", b"new"),
            "unicode escape": ('"caf\\u00e9"', "caf\u00e9".encode()),
            "hex escape": ('"\\x41BC"', b"ABC"),
            "comment before the marker": ('"new"  # rotated 2026-11', b"new"),
            "plain": ("new value", b"new value"),
        }
        for label, (replacement, expected) in cases.items():
            with self.subTest(label):
                closed = self._open_edit_close(b"old", lambda t, r=replacement: t.replace('"old"', r))
                self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
                self.assertEqual(self._stored(), [expected])

    def test_editor_stripping_trailing_whitespace_changes_no_secret(self):
        secrets = [b"line1\nline2\n\n", b"trail  \nx\n", b"a\n\nb\n", b"line1\nline2\n"]
        self._write_vars_file(*[(f"s{i}", v) for i, v in enumerate(secrets)])
        with open("group_vars.yml", "rb") as f:
            original = f.read()
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            text = f.read()
        stripped = "\n".join(line.rstrip() for line in text.split("\n"))
        # Something else in the file changes too, so close cannot take the
        # whole-file shortcut and has to read every value back.
        stripped = stripped.replace("plain_key: visible", "plain_key: edited")
        with open("group_vars.yml", "w") as f:
            f.write(stripped)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        self.assertEqual(self._stored(), secrets)
        with open("group_vars.yml", "rb") as f:
            # Untouched spans get their original ciphertext back.
            self.assertEqual(f.read(), original.replace(b"plain_key: visible", b"plain_key: edited"))

    def test_broken_yaml_keeps_the_session_and_does_not_print_the_secret(self):
        closed = self._open_edit_close(
            b"hunter2-secret", lambda t: t.replace('"hunter2-secret"', '"hunter2-secret')
        )
        self.assertNotEqual(closed.returncode, 0)
        self.assertNotIn("hunter2", closed.stdout + closed.stderr)
        self.assertIn("YAML", closed.stdout + closed.stderr)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_emptied_value_is_refused(self):
        closed = self._open_edit_close(b"old", lambda t: t.replace('"old"', '""'))
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn("empty", closed.stdout + closed.stderr)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_session_opened_by_an_older_pilfer_is_refused_not_guessed(self):
        self._write_vars_file(("db_password", b"old"))
        self.assertEqual(self._run("open").returncode, 0)
        meta = next(
            os.path.join(root, "inline.json") for root, _, files in os.walk(".vault") if "inline.json" in files
        )
        with open(meta) as f:
            data = json.load(f)
        del data["format"]
        with open(meta, "w") as f:
            json.dump(data, f)
        with open("group_vars.yml") as f:
            text = f.read().replace('"old"', '"new"')
        with open("group_vars.yml", "w") as f:
            f.write(text)
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn("older pilfer", closed.stdout + closed.stderr)
        with open("group_vars.yml") as f:
            self.assertEqual(f.read(), text)

    def test_open_leaves_a_file_that_is_not_yaml_encrypted(self):
        self._write_vars_file(("db_password", b"hunter2-secret"))
        with open("group_vars.yml", "a") as f:
            f.write("broken: [\n")
        with open("group_vars.yml", "rb") as f:
            before = f.read()
        opened = self._run("open")
        self.assertNotEqual(opened.returncode, 0)
        self.assertNotIn("hunter2", opened.stdout + opened.stderr)
        with open("group_vars.yml", "rb") as f:
            self.assertEqual(f.read(), before)

    def test_inline_file_keeps_its_mode(self):
        self._write_vars_file(("db_password", b"old"))
        os.chmod("group_vars.yml", 0o644)
        closed = self._open_edit_close(b"old", lambda t: t.replace('"old"', '"new"'))
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertEqual(stat.S_IMODE(os.stat("group_vars.yml").st_mode), 0o644)

    def test_secret_moved_under_another_key_with_an_escape_is_refused(self):
        # The old regex scan unescaped only \\n \\r \\t \\\\ and \\", so \\x65 slipped past.
        closed = self._open_edit_close(
            b"hunter2",
            lambda t: t.replace('db_password: "hunter2"  # pilfer:vault:0', 'renamed: "hunt\\x65r2"'),
        )
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn("marker missing", closed.stdout + closed.stderr)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_marker_removed_and_yaml_broken_stops_close(self):
        first = self._open_edit_close(
            b"hunter2",
            lambda t: t.replace('db_password: "hunter2"  # pilfer:vault:0', "broken: ["),
        )
        self.assertNotEqual(first.returncode, 0)
        # Not even a confirmed delete: close cannot tell whether the secret is gone.
        closed = self._run("close", confirm_delete=True)
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn("YAML", closed.stdout + closed.stderr)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_inline_skipped_without_flag(self):
        self._write_vars_file(("db_password", b"super-secret"))
        found = pilfer_cli.scan_project(include_encrypted_vars=False).targets
        self.assertEqual(found, [])
        opened = self._run("open", include_encrypted_vars=False)
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertIn("No vault files found", opened.stdout)
        with open("group_vars.yml", "rb") as f:
            self.assertIn(b"!vault", f.read())

    def test_find_inline_spans(self):
        original = self._write_vars_file(
            ("db_password", b"super-secret"),
            ("api_token", b"token-value"),
        )
        spans = pilfer_inline.find_inline_vault_spans(original)
        self.assertEqual(len(spans), 2)
        self.assertTrue(spans[0].ciphertext.startswith(b"$ANSIBLE_VAULT;"))

    def test_open_close_unchanged_restores_exact_bytes(self):
        original = self._write_vars_file(("db_password", b"super-secret"))
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        with open("group_vars.yml", "rb") as f:
            decrypted = f.read()
        self.assertIn(b"super-secret", decrypted)
        self.assertIn(b"# pilfer:vault:0", decrypted)
        self.assertNotIn(b"$ANSIBLE_VAULT;", decrypted)
        self.assertIn(b"plain_key: visible", decrypted)

        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        with open("group_vars.yml", "rb") as f:
            restored = f.read()
        self.assertEqual(restored, original)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))

    def test_open_close_modified_reencrypts(self):
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            text = f.read()
        text = text.replace("super-secret", "new-secret")
        with open("group_vars.yml", "w") as f:
            f.write(text)

        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertIn("1 modified files", closed.stdout)

        with open("group_vars.yml", "rb") as f:
            after = f.read()
        self.assertIn(b"!vault", after)
        self.assertIn(b"$ANSIBLE_VAULT;", after)
        self.assertNotIn(b"new-secret", after)
        self.assertNotIn(b"# pilfer:vault:", after)

        # Re-open and confirm new value
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            opened = f.read()
        self.assertIn("new-secret", opened)

    def test_multiple_inline_spans_independent(self):
        original = self._write_vars_file(
            ("db_password", b"pass-one"),
            ("api_token", b"token-two"),
        )
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            text = f.read()
        self.assertIn("pass-one", text)
        self.assertIn("token-two", text)
        # Modify only the second secret
        text = text.replace("token-two", "token-CHANGED")
        with open("group_vars.yml", "w") as f:
            f.write(text)
        self.assertEqual(self._run("close").returncode, 0)

        with open("group_vars.yml", "rb") as f:
            after = f.read()
        # Unchanged span should restore exact original ciphertext for that region;
        # file as a whole changes because span 1 was re-encrypted.
        self.assertNotEqual(after, original)
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            opened = f.read()
        self.assertIn("pass-one", opened)
        self.assertIn("token-CHANGED", opened)

    def test_neighbor_edit_preserves_lossy_inline_secrets(self):
        """Editing another key must not re-encrypt an unedited inline secret.

        The opened form turns CRLF into LF, and a quoted backslash-n used to
        parse as a real newline once close left the whole-file shortcut.
        """
        chunks = ["---\n", "plain_key: visible\n"]
        chunks.append(encrypt_string_yaml(self.vault, "token", b"a\\nb"))
        chunks.append(encrypt_string_yaml(self.vault, "note", b"hello\n"))
        chunks.append(encrypt_string_yaml(self.vault, "win", b"line1\r\nline2\r\n"))
        chunks.append("\n")
        chunks.append(encrypt_string_yaml(self.vault, "second", b"line1\nline2"))
        with open("group_vars.yml", "w") as handle:
            handle.write("".join(chunks))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        text = text.replace("plain_key: visible", "plain_key: edited")
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        got = [self.vault.decrypt(span.ciphertext) for span in spans]
        self.assertEqual(
            got,
            [b"a\\nb", b"hello\n", b"line1\r\nline2\r\n", b"line1\nline2"],
        )
        self.assertIn(b"plain_key: edited", data)

    def test_edited_quoted_backslash_n_round_trips(self):
        self._write_vars_file(("token", b"a\\nb"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        self.assertIn('"a\\\\nb"', text)
        text = text.replace('"a\\\\nb"', '"a\\\\nc"')
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(len(spans), 1)
        self.assertEqual(self.vault.decrypt(spans[0].ciphertext), b"a\\nc")

    def test_neighbor_edit_preserves_indented_and_newline_secrets(self):
        self._write_vars_file(
            ("code", b"  return 1;\n"),
            ("blank", b"\n"),
        )
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        text = text.replace("plain_key: visible", "plain_key: edited")
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        got = [self.vault.decrypt(span.ciphertext) for span in spans]
        self.assertEqual(got, [b"  return 1;\n", b"\n"])

    def test_edited_indented_multiline_secret_keeps_relative_indent(self):
        secret = b"  return 1;\n    return 2;\n"
        self._write_vars_file(("code", secret))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        self.assertIn("return 1;", text)
        text = text.replace("return 1;", "return 9;", 1)
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(len(spans), 1)
        self.assertEqual(
            self.vault.decrypt(spans[0].ciphertext), b"  return 9;\n    return 2;\n"
        )

    def test_edited_multiline_without_trailing_newline_does_not_gain_one(self):
        secret = b"  return 1;\n    return 2;"
        self._write_vars_file(("code", secret))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        # A first line that starts with spaces would set a block's indentation,
        # so the secret is shown as one double-quoted line instead.
        self.assertIn('"  return 1;\\n    return 2;"', text)
        text = text.replace("return 1;", "return 9;", 1)
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(self.vault.decrypt(spans[0].ciphertext), b"  return 9;\n    return 2;")

    def test_edited_multiline_keeps_a_trailing_blank_line(self):
        secret = b"line1\n\n"
        self._write_vars_file(("code", secret))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        text = text.replace("line1", "line9", 1)
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(self.vault.decrypt(spans[0].ciphertext), b"line9\n\n")

    def test_edited_whitespace_only_line_is_kept(self):
        secret = b"line1\n   \nline3\n"
        self._write_vars_file(("code", secret))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        # Trailing whitespace would not survive an editor's save inside a block,
        # so this secret is shown double-quoted.
        self.assertIn('"line1\\n   \\nline3\\n"', text)
        text = text.replace("\\n   \\n", "\\n \\n", 1)
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(len(spans), 1)
        self.assertEqual(self.vault.decrypt(spans[0].ciphertext), b"line1\n \nline3\n")

    def test_neighbor_edit_preserves_whitespace_only_line(self):
        secret = b"line1\n   \nline3\n"
        self._write_vars_file(("code", secret))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as handle:
            text = handle.read()
        text = text.replace("plain_key: visible", "plain_key: edited")
        with open("group_vars.yml", "w") as handle:
            handle.write(text)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(self.vault.decrypt(spans[0].ciphertext), secret)

    def test_mixed_whole_file_and_inline(self):
        with open("whole.yml", "wb") as f:
            f.write(self.vault.encrypt(b"whole: file\n"))
        self._write_vars_file(("inline_secret", b"inline-value"))
        opened = self._run("open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertIn("whole-file", opened.stdout)
        self.assertIn("inline", opened.stdout)
        with open("whole.yml") as f:
            self.assertEqual(f.read(), "whole: file\n")
        with open("group_vars.yml") as f:
            self.assertIn("inline-value", f.read())
        self.assertEqual(self._run("close").returncode, 0)

    def test_missing_marker_but_key_remains_fails(self):
        """Stripping the marker while leaving the key must fail closed."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write('---\nplain_key: visible\ndb_password: "super-secret"\n')
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))
        combined = closed.stderr + closed.stdout
        self.assertIn("cannot close (marker missing)", combined)
        self.assertIn("Variable:     db_password", combined)
        self.assertIn("marker was removed but the secret is still", combined)

    def test_rename_key_and_strip_marker_fails(self):
        """Renaming the key and dropping the marker must not look like removal."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write("---\nplain_key: visible\n" 'database_password: "super-secret"\n')
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        combined = closed.stderr + closed.stdout
        self.assertIn("cannot close (marker missing)", combined)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))
        with open("group_vars.yml") as f:
            self.assertIn("super-secret", f.read())

    def test_rename_secret_shapes_fail_closed(self):
        """Renamed/relocated secrets without markers must not look like removal."""
        cases = [
            (
                "single_quoted",
                "---\nplain_key: visible\ndatabase_password: 'super-secret'\n",
            ),
            (
                "folded",
                "---\nplain_key: visible\ndatabase_password: >\n  super-secret\n",
            ),
            (
                "folded_keep",
                "---\nplain_key: visible\ndatabase_password: >+\n  super-secret\n",
            ),
            ("list_item", "---\nplain_key: visible\nsecrets:\n  - super-secret\n"),
            (
                "flow_mapping",
                "---\nplain_key: visible\ncreds: {database_password: super-secret}\n",
            ),
            (
                "flow_sequence",
                "---\nplain_key: visible\npasswords: [super-secret, backup]\n",
            ),
            (
                "sequence_block",
                "---\nplain_key: visible\nitems:\n  - |\n    super-secret\n",
            ),
        ]
        for name, body in cases:
            with self.subTest(shape=name):
                self._write_vars_file(("db_password", b"super-secret"))
                self.assertEqual(self._run("open").returncode, 0)
                with open("group_vars.yml", "w") as f:
                    f.write(body)
                closed = self._run("close")
                self.assertNotEqual(closed.returncode, 0)
                combined = closed.stderr + closed.stdout
                self.assertIn("cannot close (marker missing)", combined)
                # Reset tree for next subTest
                for artifact in ("vaultedFileList.json", "group_vars.yml"):
                    if os.path.isfile(artifact):
                        os.remove(artifact)
                if os.path.isdir(".vault"):
                    shutil.rmtree(".vault", ignore_errors=True)
                for name in os.listdir("."):
                    if name.endswith(".pilfer-open"):
                        os.remove(name)

    def test_strip_marker_with_vault_doc_comment_fails(self):
        """A doc mention of !vault must not satisfy the already-encrypted shortcut."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write(
                "---\nplain_key: visible\n"
                "# docs mention !vault here\n"
                'database_password: "super-secret"\n'
            )
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        combined = closed.stderr + closed.stdout
        self.assertIn("cannot close (marker missing)", combined)

    def test_strip_marker_changed_value_same_key_fails(self):
        """Changing the value after stripping markers must not clear the session."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write('---\nplain_key: visible\ndb_password: "new-secret"\n')
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))
        with open("group_vars.yml") as f:
            self.assertIn("new-secret", f.read())

    def test_empty_inline_spans_meta_refuses_close(self):
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        meta_path = next(
            os.path.join(r, "inline.json")
            for r, _, files in os.walk(".vault")
            if "inline.json" in files
        )
        with open(meta_path, "w") as f:
            json.dump({"spans": []}, f)
        with open("group_vars.yml", "w") as f:
            f.write('---\ndb_password: "super-secret"\n')
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_corrupt_inline_meta_refuses_no_marker_close(self):
        """Undecryptable session ciphertext must not fail-open as removal."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        meta_path = next(
            os.path.join(r, "inline.json")
            for r, _, files in os.walk(".vault")
            if "inline.json" in files
        )
        with open(meta_path) as f:
            meta = json.load(f)
        meta["spans"][0]["ciphertext_b64"] = "bm90LXZhbGlk"
        meta["spans"][0]["encrypted_b64"] = "bm90LXZhbGlk"
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        with open("group_vars.yml", "w") as f:
            f.write("---\n# super-secret\n")
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_secret_relocated_to_comment_fails(self):
        """Exact secret in a YAML comment must not clear the session."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write("---\nplain_key: visible\n# super-secret\n")
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_garbage_vault_tag_same_key_fails(self):
        """A non-decryptable !vault placeholder must not satisfy already-closed."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write(
                "---\nplain_key: visible\n"
                "db_password: !vault |\n"
                "          $ANSIBLE_VAULT;1.1;AES256\n"
                "          deadbeef\n"
            )
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_inline_close_retry_after_already_reencrypted(self):
        """Interrupted inline close (no markers, !vault present) must retry cleanly."""
        original = self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            text = f.read()
        text = text.replace("super-secret", "new-secret")
        with open("group_vars.yml", "w") as f:
            f.write(text)
        # Simulate successful recrypt write before session/backup cleanup: vault
        # ciphertext without markers, differing from the open-time backup.
        reencrypted = "---\nplain_key: visible\n" + encrypt_string_yaml(
            self.vault, "db_password", b"new-secret"
        )
        with open("group_vars.yml", "w") as f:
            f.write(reencrypted)
        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertIn("Already re-encrypted inline", closed.stdout)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))
        with open("group_vars.yml", "rb") as f:
            after = f.read()
        self.assertIn(b"!vault", after)
        self.assertNotIn(b"# pilfer:vault:", after)
        # Original backup bytes are intentionally not restored once recrypt wrote.
        self.assertNotEqual(after, original)

    def test_deleted_var_line_reports_removal(self):
        """Deleting the whole opened var line is treated as intentional removal."""
        self._write_vars_file(
            ("db_password", b"super-secret"),
            ("api_token", b"keep-me"),
        )
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            lines = f.readlines()
        # Drop the db_password line entirely; keep api_token marker line.
        kept = [ln for ln in lines if "db_password" not in ln]
        with open("group_vars.yml", "w") as f:
            f.writelines(kept)

        refused = self._run("close")
        self.assertNotEqual(refused.returncode, 0)
        combined = refused.stderr + refused.stdout
        self.assertIn("⚠️", combined)
        self.assertIn("cannot close (secret line deleted)", combined)
        self.assertIn("Variable:     db_password", combined)
        self.assertIn("--confirm-delete", combined)
        self.assertNotIn("Failed to process", combined)
        closed = self._run("close", confirm_delete=True)
        self.assertEqual(closed.returncode, 0, closed.stderr)
        self.assertIn("🔍 Detected removal of 1 encrypted vars:", closed.stdout)
        self.assertIn("- db_password", closed.stdout)
        with open("group_vars.yml", "rb") as f:
            after = f.read()
        self.assertNotIn(b"db_password", after)
        self.assertIn(b"api_token", after)
        self.assertIn(b"!vault", after)

    def test_multiline_blank_lines_survive_unrelated_edit(self):
        """Interior blank lines in multiline secrets must not truncate on close."""
        secret = b"line1\n\nline3"
        self._write_vars_file(("cert_body", secret))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            text = f.read()
        text = text.replace("plain_key: visible", "plain_key: changed")
        with open("group_vars.yml", "w") as f:
            f.write(text)

        closed = self._run("close")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        # Re-open and confirm full secret including blank line
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            opened = f.read()
        self.assertIn("line1", opened)
        self.assertIn("line3", opened)
        # No leftover plaintext after the vault block from a truncated close
        self.assertNotIn("\nline3\n", opened.split("cert_body:")[0])

    def test_marker_moved_to_wrong_key_fails(self):
        self._write_vars_file(
            ("db_password", b"pass-one"),
            ("api_token", b"token-two"),
        )
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml") as f:
            text = f.read()
        # Swap marker ids between keys
        text = text.replace("# pilfer:vault:0", "# pilfer:vault:TMP")
        text = text.replace("# pilfer:vault:1", "# pilfer:vault:0")
        text = text.replace("# pilfer:vault:TMP", "# pilfer:vault:1")
        with open("group_vars.yml", "w") as f:
            f.write(text)
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn("but was opened as", closed.stderr + closed.stdout)

    def test_bare_vault_blob_not_opened(self):
        """Docs/fences with bare $ANSIBLE_VAULT must not become inline targets."""
        enc = self.vault.encrypt(b"secret").decode()
        with open("README.md", "w") as f:
            f.write("# docs\n\n```\n" + enc + "```\n")
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        self.assertEqual(found, [])

    def test_whole_file_not_treated_as_inline(self):
        with open("only_whole.yml", "wb") as f:
            f.write(self.vault.encrypt(b"a: 1\n"))
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")


class TestDiscoveryOptimizations(ProjectDirTest):
    """Header-only classify, extension gates, and include-encrypted-vars coverage."""

    def test_header_only_finds_whole_file_vault(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"a: 1\n"))
        # Large non-vault sibling should not need full reads in default mode;
        # presence alone shouldn't break discovery.
        with open("big.txt", "wb") as f:
            f.write(b"x" * (1024 * 1024))
        found = pilfer_cli.scan_project(include_encrypted_vars=False).targets
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")

    def test_extension_gate_skips_db_even_with_vault_bytes(self):
        with open("noise.db", "wb") as f:
            f.write(self.vault.encrypt(b"should-not-open\n"))
        with open("real.yml", "wb") as f:
            f.write(self.vault.encrypt(b"ok: 1\n"))
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        paths = [os.path.basename(e["path"]) for e in found]
        self.assertEqual(paths, ["real.yml"])

    def test_compound_archive_suffix_is_denylisted(self):
        """backup.tar.zst must not be a vault target. splitext only sees .zst."""
        self.assertTrue(pilfer_cli._should_skip_by_extension("backup.tar.zst"))
        self.assertTrue(pilfer_cli._should_skip_by_extension("dump.zst"))
        self.assertFalse(pilfer_cli._should_skip_by_extension("group_vars.yml"))
        self.assertFalse(pilfer_cli._should_skip_by_extension("weirdname"))
        with open("backup.tar.zst", "wb") as f:
            f.write(self.vault.encrypt(b"should-not-open\n"))
        with open("real.yml", "wb") as f:
            f.write(self.vault.encrypt(b"ok: 1\n"))
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        paths = [os.path.basename(e["path"]) for e in found]
        self.assertEqual(paths, ["real.yml"])

    def test_include_encrypted_vars_still_finds_inline_yaml(self):
        body = encrypt_string_yaml(self.vault, "db_password", b"super-secret")
        with open("group_vars.yml", "w") as f:
            f.write("---\n" + body)
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "inline")

    def test_include_encrypted_vars_finds_inline_in_extensionless_file(self):
        """Denylist must not exclude unknown / extensionless text files."""
        body = encrypt_string_yaml(self.vault, "db_password", b"super-secret")
        with open("weirdname", "w") as f:
            f.write("---\n" + body)
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "inline")

    def test_include_finds_both_whole_file_and_inline(self):
        with open("whole.yml", "wb") as f:
            f.write(self.vault.encrypt(b"whole: 1\n"))
        with open("inline.yml", "w") as f:
            f.write("---\n" + encrypt_string_yaml(self.vault, "tok", b"v"))
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        kinds = sorted(e["kind"] for e in found)
        self.assertEqual(kinds, ["file", "inline"])

    def test_bom_prefixed_whole_file_vault_discovered(self):
        ciphertext = self.vault.encrypt(b"a: 1\n")
        with open("bom_secret.yml", "wb") as f:
            f.write(b"\xef\xbb\xbf" + ciphertext)
        found = pilfer_cli.scan_project(include_encrypted_vars=False).targets
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")

    def test_whitespace_prefixed_whole_file_vault_discovered(self):
        ciphertext = self.vault.encrypt(b"a: 1\n")
        with open("ws_secret.yml", "wb") as f:
            f.write(b"\n\n  " + ciphertext)
        found = pilfer_cli.scan_project(include_encrypted_vars=False).targets
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")

    def test_bom_whole_file_open_close_round_trip(self):
        ciphertext = self.vault.encrypt(b"secret_key: hunter2\n")
        with open("vault_pass", "w") as f:
            f.write("test_password")
        with open("bom_secret.yml", "wb") as f:
            f.write(b"\xef\xbb\xbf" + ciphertext)
        pilfer_cli.open_vault_files("vault_pass")
        with open("bom_secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")
        self.assertEqual(pilfer_cli.recrypt_vault_files("vault_pass"), 0)
        with open("bom_secret.yml", "rb") as f:
            # An unchanged close puts back the exact bytes, BOM included.
            self.assertEqual(f.read(), b"\xef\xbb\xbf" + ciphertext)


class TestCompatibility(ProjectDirTest):
    def setUp(self):
        super().setUp()
        with open("test_vault.yml", "wb") as f:
            f.write(self.vault.encrypt(b"test: value\n"))

    def test_identical_behavior(self):
        pilfer_cli.open_vault_files("vault_pass")
        with open("test_vault.yml", "rb") as f:
            cli_decrypted = f.read()
        self.assertEqual(pilfer_cli.recrypt_vault_files("vault_pass"), 0)
        self.assertEqual(cli_decrypted, b"test: value\n")

        opened = self.run_pilfer("open", "-p", "vault_pass")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        with open("test_vault.yml", "rb") as f:
            script_decrypted = f.read()
        self.assertEqual(script_decrypted, cli_decrypted)
        closed = self.run_pilfer("close", "-p", "vault_pass")
        self.assertEqual(closed.returncode, 0, closed.stderr)


class TestInlineUnit(unittest.TestCase):
    """Pure unit tests for span finding / normalize without full CLI."""

    def test_normalize_strips_indent(self):
        block = b"          $ANSIBLE_VAULT;1.1;AES256\n          aabb\n"
        out = pilfer_inline.normalize_vault_ciphertext(block)
        self.assertTrue(out.startswith(b"$ANSIBLE_VAULT;"))
        self.assertNotIn(b"          $", out)

    def test_no_spans_in_plain_yaml(self):
        self.assertEqual(pilfer_inline.find_inline_vault_spans(b"foo: bar\n"), [])

    def _read_one(self, content):
        (marked,) = pilfer_inline.read_marked_values(content)
        return marked

    def test_read_block_keeps_blank_lines(self):
        content = b"db_password: |  # pilfer:vault:0\n  line1\n\n  line3\nother: x\n"
        marked = self._read_one(content)
        self.assertEqual(marked.value, b"line1\n\nline3\n")
        self.assertTrue(content[marked.end :].startswith(b"other:"))

    def test_read_block_keeps_spaces_past_the_indent(self):
        content = b"db_password: |  # pilfer:vault:0\n  line1\n     \n  line3\nother: x\n"
        self.assertEqual(self._read_one(content).value, b"line1\n   \nline3\n")

    def test_read_strip_chomp_does_not_add_a_newline(self):
        content = b"db_password: |-  # pilfer:vault:0\n  line1\n  line2\nother: x\n"
        marked = self._read_one(content)
        self.assertEqual(marked.value, b"line1\nline2")
        self.assertTrue(content[marked.end :].startswith(b"other:"))

    def test_read_leaves_the_blank_line_after_a_block(self):
        content = b"db_password: |  # pilfer:vault:0\n  a\n\nother: x\n"
        marked = self._read_one(content)
        self.assertEqual(marked.value, b"a\n")
        self.assertEqual(content[marked.start : marked.end], b"db_password: |  # pilfer:vault:0\n  a\n")

    def test_read_quoted_values_the_way_yaml_does(self):
        cases = {
            b"k: 'it''s'  # pilfer:vault:0\n": b"it's",
            b'k: "caf\\u00e9"  # pilfer:vault:0\n': "caf\u00e9".encode(),
            b'k: "\\x41BC"  # pilfer:vault:0\n': b"ABC",
            b'k: "new"  # rotated 2026-11  # pilfer:vault:0\n': b"new",
            b"k: plain value  # pilfer:vault:0\n": b"plain value",
            b"- k: listed  # pilfer:vault:0\n": b"listed",
        }
        for content, expected in cases.items():
            with self.subTest(content=content):
                marked = self._read_one(content)
                self.assertEqual(marked.value, expected)
                self.assertEqual(marked.key_text, "k")
                self.assertEqual(marked.end, len(content))

    def test_marker_that_is_not_after_a_value_is_refused(self):
        for content in (
            b"# pilfer:vault:0\nk: v\n",
            b"outer: |  # pilfer:vault:1\n  inner: x  # pilfer:vault:2\n",
        ):
            with self.subTest(content=content):
                with self.assertRaises(pilfer_inline.OpenedFileError):
                    pilfer_inline.read_marked_values(content)

    def test_yaml_error_does_not_quote_the_file(self):
        content = b'k: "hunter2-secret  # pilfer:vault:0\nother: [\n'
        with self.assertRaises(pilfer_inline.OpenedFileError) as caught:
            pilfer_inline.read_marked_values(content)
        self.assertNotIn("hunter2", str(caught.exception))

    def test_every_rendering_reads_back_exactly(self):
        # Open refuses a span whose rendering does not; this pins the renderer.
        secrets = [
            b"plain", b"", b"line1\nline2\n", b"line1\nline2", b"a\n\nb\n", b"a\n\n",
            b"  lead\nx", b"trail  \nx\n", b"cr\r\nlf\n", b"tab\there", b'q"uote\\back',
            "nel\x85 ls\u2028 bom\ufeff del\x7f c1\x9f".encode(), "\U0001f600 \u00e9".encode(),
            b"# pilfer:vault:9 inside", b"{{ jinja }}", b"- dash", b": colon", b"\n\nlead",
        ]
        for secret in secrets:
            with self.subTest(secret=secret):
                span = pilfer_inline.InlineSpan(0, 0, 0, b"", b"", b"key: ", b"  ")
                rendered = pilfer_inline.format_open_value(secret, span) + b"next: 1\n"
                try:
                    (marked,) = pilfer_inline.read_marked_values(rendered)
                except pilfer_inline.OpenedFileError:
                    # Only a secret that contains the marker text itself may refuse.
                    self.assertIn(b"# pilfer:vault:", secret)
                    continue
                self.assertEqual(marked.value, secret)

    def test_is_whole_file_vault_tolerates_bom_and_whitespace(self):
        body = b"$ANSIBLE_VAULT;1.1;AES256\naabb\n"
        self.assertTrue(pilfer_inline.is_whole_file_vault(body))
        self.assertTrue(pilfer_inline.is_whole_file_vault(b"\xef\xbb\xbf" + body))
        self.assertTrue(pilfer_inline.is_whole_file_vault(b"\n  " + body))
        self.assertFalse(pilfer_inline.is_whole_file_vault(b"---\nfoo: bar\n"))


class TestScanOnce(ProjectDirTest):
    """Nested git skips must print once per open (single project walk)."""

    def test_nested_skip_announced_once(self):
        for name in ("nested_a", "nested_b"):
            os.makedirs(name)
            with open(os.path.join(name, ".git"), "w") as f:
                f.write("gitdir: ../.git\n")
        result = self.run_pilfer("open", "-p", "vault_pass")
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("nested_a", "nested_b"):
            needle = f"Skipping nested git repo: {os.path.abspath(name)}"
            self.assertEqual(result.stdout.count(needle), 1, result.stdout)

    def test_quiet_suppresses_nested_skip_messages(self):
        for name in ("nested_a", "nested_b"):
            os.makedirs(name)
            with open(os.path.join(name, ".git"), "w") as f:
                f.write("gitdir: ../.git\n")
        result = self.run_pilfer("open", "-p", "vault_pass", "--quiet")
        self.assertEqual(result.returncode, 0, result.stderr)
        combined = result.stdout + result.stderr
        self.assertNotIn("Skipping nested git repo:", combined)


class TestAllowRemovalsAndRekey(ProjectDirTest):
    def setUp(self):
        super().setUp()
        with open("vault_pass_new", "w") as f:
            f.write("new_password")

    def test_rekey_dry_run_and_apply(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        dry = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--dry-run",
            "--yes",
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("Dry run only", dry.stdout)
        applied = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
        )
        self.assertEqual(applied.returncode, 0, applied.stderr)
        new_vault = make_vault("new_password")
        with open("secret.yml", "rb") as f:
            body = f.read()
        self.assertEqual(new_vault.decrypt(body), b"secret_key: hunter2\n")

    def test_rekey_keeps_the_mode(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        os.chmod("secret.yml", 0o644)
        applied = self.run_pilfer(
            "rekey", "--old-vault-password-file", "vault_pass",
            "--new-vault-password-file", "vault_pass_new", "--yes",
        )
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(stat.S_IMODE(os.stat("secret.yml").st_mode), 0o644)

    def test_rekey_refuses_ciphertext_that_decrypts_to_something_else(self):
        real_encrypt = VaultLib.encrypt

        def wrong_secret(vault, plaintext, *args, **kwargs):
            return real_encrypt(vault, b"something else", *args, **kwargs)

        for kind in ("file", "inline"):
            with self.subTest(kind=kind):
                if kind == "file":
                    body = self.vault.encrypt(b"secret_key: hunter2\n")
                else:
                    body = ("plain: x\n" + encrypt_string_yaml(self.vault, "db_password", b"hunter2")).encode()
                with open("secret.yml", "wb") as f:
                    f.write(body)
                new_vault = make_vault("new_password")
                with mock.patch.object(VaultLib, "encrypt", autospec=True, side_effect=wrong_secret):
                    with self.assertRaises(pilfer_cli.PilferError):
                        if kind == "file":
                            pilfer_cli._rekey_whole_file("secret.yml", self.vault, new_vault)
                        else:
                            pilfer_cli._rekey_inline_file("secret.yml", self.vault, new_vault)
                with open("secret.yml", "rb") as f:
                    self.assertEqual(f.read(), body)

    def test_close_refuses_ciphertext_that_decrypts_to_something_else(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        pilfer_cli.open_vault_files("vault_pass")
        with open("secret.yml", "wb") as f:
            f.write(b"secret_key: edited\n")
        real_encrypt = VaultLib.encrypt

        def wrong_secret(vault, plaintext, *args, **kwargs):
            return real_encrypt(vault, b"something else", *args, **kwargs)

        with mock.patch.object(VaultLib, "encrypt", autospec=True, side_effect=wrong_secret):
            with self.assertRaises(pilfer_cli.PilferError):
                pilfer_cli.recrypt_vault_files("vault_pass")
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: edited\n")
        self.assertTrue(os.path.isfile("vaultedFileList.json"))

    def test_rekey_keeps_vault_id_label(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n", vault_id="prod"))
        applied = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
        )
        self.assertEqual(applied.returncode, 0, applied.stderr)
        with open("secret.yml", "rb") as f:
            body = f.read()
        self.assertTrue(body.startswith(b"$ANSIBLE_VAULT;1.2;AES256;prod\n"))
        self.assertEqual(make_vault("new_password").decrypt(body), b"secret_key: hunter2\n")

    def test_rekey_inline_vault_keeps_plaintext_and_label(self):
        chunks = [
            "---\n",
            encrypt_string_yaml(self.vault, "db_password", b"s3cret\n"),
            encrypt_string_yaml(self.vault, "script", b"line1\nline2\n", vault_id="prod"),
        ]
        with open("group_vars.yml", "w") as handle:
            handle.write("".join(chunks))
        applied = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
        )
        self.assertEqual(applied.returncode, 0, applied.stderr)
        new_vault = make_vault("new_password")
        with open("group_vars.yml", "rb") as handle:
            data = handle.read()
        spans = pilfer_inline.find_inline_vault_spans(data)
        self.assertEqual(len(spans), 2)
        self.assertIsNone(spans[0].vault_id)
        self.assertEqual(new_vault.decrypt(spans[0].ciphertext), b"s3cret\n")
        self.assertEqual(spans[1].vault_id, "prod")
        self.assertTrue(spans[1].ciphertext.startswith(b"$ANSIBLE_VAULT;1.2;AES256;prod\n"))
        self.assertEqual(new_vault.decrypt(spans[1].ciphertext), b"line1\nline2\n")
        with self.assertRaises(AnsibleError):
            self.vault.decrypt(spans[0].ciphertext)

    def test_rekey_resumes_after_partial_success(self):
        """Files already on the new password are skipped so rekey can finish."""
        with open("a.yml", "wb") as f:
            f.write(self.vault.encrypt(b"a: 1\n"))
        with open("b.yml", "wb") as f:
            f.write(self.vault.encrypt(b"b: 2\n"))
        new_vault = make_vault("new_password")
        with open("a.yml", "rb") as f:
            plain_a = self.vault.decrypt(f.read())
        with open("a.yml", "wb") as f:
            f.write(new_vault.encrypt(plain_a))
        resumed = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertIn("Already on new password", resumed.stdout)
        with open("a.yml", "rb") as f:
            self.assertEqual(new_vault.decrypt(f.read()), b"a: 1\n")
        with open("b.yml", "rb") as f:
            self.assertEqual(new_vault.decrypt(f.read()), b"b: 2\n")

    def test_rekey_rotate_refuses_without_inline(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        result = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
            "--no-include-encrypted-vars",
            "--rotate-password-file",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--rotate-password-file", result.stderr + result.stdout)
        self.assertIn("inline", (result.stderr + result.stdout).lower())

    def test_stale_rekey_temp_not_discovered_and_cleaned(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        # Crash leftover: vault ciphertext under staging name next to target.
        with open(".pilfer-rekey-deadbeef", "wb") as f:
            f.write(self.vault.encrypt(b"orphan: true\n"))
        found = pilfer_cli.scan_project(include_encrypted_vars=True).targets
        paths = [e["path"] for e in found]
        self.assertTrue(any(p.endswith("secret.yml") for p in paths))
        self.assertFalse(any(".pilfer-rekey-" in p for p in paths))
        dry = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--dry-run",
            "--yes",
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        # Leftover temps are removed even on a dry run: they are never the only
        # copy, and one from a killed open holds plaintext.
        self.assertFalse(os.path.exists(".pilfer-rekey-deadbeef"))
        with open("secret.yml", "rb") as f:
            self.assertEqual(self.vault.decrypt(f.read()), b"secret_key: hunter2\n")
        result = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(".pilfer-rekey-deadbeef"))
        new_vault = make_vault("new_password")
        with open("secret.yml", "rb") as f:
            self.assertEqual(new_vault.decrypt(f.read()), b"secret_key: hunter2\n")

    def test_rekey_temp_prefix_does_not_hide_orphan_sidecar(self):
        """Renaming a sidecar behind the rekey prefix must still block open."""
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        opened = self.run_pilfer("open", "-p", "vault_pass")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        # Simulate destroyed session while plaintext + renamed sidecar remain.
        os.remove("vaultedFileList.json")
        shutil.rmtree(".vault", ignore_errors=True)
        os.rename("secret.yml.pilfer-open", ".pilfer-rekey-hidden.pilfer-open")
        blocked = self.run_pilfer("open", "-p", "vault_pass")
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("pilfer-open", (blocked.stderr + blocked.stdout).lower())

    def test_rekey_rotate_already_done_requires_yes(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        self.assertEqual(
            self.run_pilfer(
                "rekey",
                "--old-vault-password-file",
                "vault_pass",
                "--new-vault-password-file",
                "vault_pass_new",
                "--yes",
            ).returncode,
            0,
        )
        # Resume-only rotate without --yes in non-interactive mode must refuse.
        refused = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--rotate-password-file",
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("Confirmation required", refused.stderr + refused.stdout)
        self.assertTrue(os.path.exists("vault_pass"))
        self.assertFalse(os.path.exists("vault_pass_old"))

    def test_rekey_rotate_refuses_when_nested_git_skipped(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        os.makedirs("nested")
        with open(os.path.join("nested", ".git"), "w") as f:
            f.write("gitdir: ../.git\n")
        with open(os.path.join("nested", "nested.yml"), "wb") as f:
            f.write(self.vault.encrypt(b"nested: 1\n"))
        result = self.run_pilfer(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--yes",
            "--rotate-password-file",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nested git", (result.stderr + result.stdout).lower())
        self.assertTrue(os.path.exists("vault_pass"))
        self.assertFalse(os.path.exists("vault_pass_old"))

    def test_denylisted_extension_still_detects_orphan_markers(self):
        """Marker orphans renamed to denylisted extensions must still block open."""
        with open("group_vars.yml", "w") as f:
            f.write("---\n" 'db_password: "super-secret"  # pilfer:vault:0\n')
        with open("group_vars.yml.pilfer-open", "w") as f:
            f.write("lock\n")
        os.rename("group_vars.yml", "leak.pyc")
        os.remove("group_vars.yml.pilfer-open")
        blocked = self.run_pilfer("open", "-p", "vault_pass")
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("pilfer:vault", (blocked.stderr + blocked.stdout).lower())

    def test_emoji_messages_have_trailing_space(self):
        """User-facing emoji prefixes must be followed by a space."""
        import re

        cli_text = (Path(__file__).resolve().parents[1] / "pilfer" / "cli.py").read_text()
        vs16 = "️"
        for emoji in ("🔓", "🔒", "✅", "⏭️", "🔍", "ℹ️", "🔐", "⚠️"):
            for match in re.finditer(re.escape(emoji), cli_text):
                rest = cli_text[match.end() :]
                rest = rest.removeprefix(vs16)
                self.assertTrue(
                    rest[:1] == " ",
                    f"{emoji!r} not followed by space near "
                    f"{cli_text[match.start() : match.start() + 24]!r}",
                )


class TestVersion(unittest.TestCase):
    """Verify --version on packaged CLI and standalone script."""

    def test_cli_version(self):
        from io import StringIO
        from unittest.mock import patch

        with patch("sys.argv", ["pilfer", "--version"]):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                with self.assertRaises(SystemExit) as cm:
                    pilfer_cli.main()
                self.assertEqual(cm.exception.code, 0)
                self.assertIn(f"pilfer {pilfer_version}", fake_out.getvalue())

    def test_standalone_version(self):
        result = subprocess.run(
            [sys.executable, PILFER_SCRIPT, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"pilfer {pilfer_version}", result.stdout)


if __name__ == "__main__":
    unittest.main()
