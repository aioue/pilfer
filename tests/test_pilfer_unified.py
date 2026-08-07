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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

from pilfer import __version__ as pilfer_version
from pilfer import cli as pilfer_cli
from pilfer import inline as pilfer_inline


def make_vault(password: str = "test_password") -> VaultLib:
    return VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password.encode("utf-8")))])


def encrypt_string_yaml(
    vault: VaultLib, name: str, value: bytes, indent: str = "          "
) -> str:
    """Build YAML matching ansible-vault encrypt_string --name output."""
    enc = vault.encrypt(value).decode("utf-8").strip().splitlines()
    body = "\n".join(indent + line for line in enc)
    return f"{name}: !vault |\n{body}\n"


class PilferTestBase(unittest.TestCase, ABC):
    """Shared happy-path tests for CLI function API and standalone script."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

        self.vault_password = "test_password"
        with open("vault_pass", "w") as f:
            f.write(self.vault_password)

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

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

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
        pilfer_cli.write_vaulted_file_list()
        pilfer_cli.decrypt_vault_files(vault_pass_file)

    def pilfer_close(self, vault_pass_file="vault_pass"):
        return pilfer_cli.recrypt_vault_files(vault_pass_file)


class TestPilferStandalone(unittest.TestCase):
    """Smoke: standalone entry delegates (full matrix covered by TestPilferCLI)."""

    def test_standalone_open_close_smoke(self):
        test_dir = tempfile.mkdtemp()
        original = os.getcwd()
        try:
            os.chdir(test_dir)
            with open("vault_pass", "w") as f:
                f.write("test_password")
            vault = make_vault()
            with open("secret.yml", "wb") as f:
                f.write(vault.encrypt(b"a: 1\n"))
            script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")
            opened = subprocess.run(
                [sys.executable, script, "open", "-p", "vault_pass"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(opened.returncode, 0, opened.stderr)
            closed = subprocess.run(
                [sys.executable, script, "close", "-p", "vault_pass"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(closed.returncode, 0, closed.stderr)
        finally:
            os.chdir(original)
            shutil.rmtree(test_dir)


class TestSessionSafety(unittest.TestCase):
    """Regression tests for critical session / integrity behaviour."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

        with open("vault_pass", "w") as f:
            f.write("test_password")

        self.vault = make_vault()
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))

        self.pilfer_script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def _run(self, *args, password_file="vault_pass"):
        cmd = [sys.executable, self.pilfer_script, *args, "-p", password_file]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

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
        # Should not leave a successful open claiming plaintext secrets without session.
        # File may stay encrypted if decrypt failed before write.
        with open("secret.yml", "rb") as f:
            data = f.read()
        self.assertTrue(
            data.startswith(b"$ANSIBLE_VAULT;") or os.path.isfile("vaultedFileList.json")
        )

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
        found = pilfer_cli.write_vaulted_file_list()
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["path"].endswith("secret.yml"))
        self.assertFalse(any(".vault" in e["path"] for e in found))

    def test_skips_nested_git_repo(self):
        nested = os.path.join("nested_project")
        os.makedirs(os.path.join(nested, ".git"))
        with open(os.path.join(nested, "nested_secret.yml"), "wb") as f:
            f.write(self.vault.encrypt(b"nested: 1\n"))
        found = pilfer_cli.write_vaulted_file_list()
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
        found = pilfer_cli.write_vaulted_file_list()
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

    def test_legacy_v1_session_list_still_loads(self):
        """Bare JSON list sessions from older pilfer remain readable for decrypt."""
        abs_path = os.path.abspath("secret.yml")
        with open("vaultedFileList.json", "w") as f:
            json.dump([abs_path], f)
        count = pilfer_cli.decrypt_vault_files("vault_pass")
        self.assertEqual(count, 1)
        with open("secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")

    def test_legacy_v1_session_close_proves_and_succeeds(self):
        """Unbound legacy sessions close after password is proven against backups."""
        abs_path = os.path.abspath("secret.yml")
        with open("vaultedFileList.json", "w") as f:
            json.dump([abs_path], f)
        pilfer_cli.decrypt_vault_files("vault_pass")
        # decrypt rewrote a v2 session with binding; simulate legacy by rewriting.
        with open("vaultedFileList.json", "w") as f:
            json.dump([abs_path], f)
        modified = pilfer_cli.recrypt_vault_files("vault_pass")
        self.assertEqual(modified, 0)
        self.assertFalse(os.path.isfile("vaultedFileList.json"))

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


class TestInlineVault(unittest.TestCase):
    """Issue #3: in-place encrypt_string / !vault handling."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        with open("vault_pass", "w") as f:
            f.write("test_password")
        self.vault = make_vault()
        self.pilfer_script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def _run(
        self,
        *args,
        password_file="vault_pass",
        include_encrypted_vars=None,
        allow_removals=False,
        extra=None,
    ):
        cmd = [sys.executable, self.pilfer_script, *args]
        # Inline tests default to opening encrypt_string blobs.
        if include_encrypted_vars is None:
            include_encrypted_vars = bool(args) and args[0] == "open"
        if include_encrypted_vars:
            cmd.append("--include-encrypted-vars")
        if allow_removals:
            cmd.append("--allow-removals")
        if extra:
            cmd.extend(extra)
        cmd.extend(["-p", password_file])
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def _write_vars_file(self, *pairs):
        """pairs: (name, plaintext_bytes)"""
        chunks = ["---\n", "plain_key: visible\n"]
        for name, value in pairs:
            chunks.append(encrypt_string_yaml(self.vault, name, value))
        with open("group_vars.yml", "w") as f:
            f.write("".join(chunks))
        with open("group_vars.yml", "rb") as f:
            return f.read()

    def test_inline_skipped_without_flag(self):
        self._write_vars_file(("db_password", b"super-secret"))
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=False)
        self.assertEqual(found, [])
        os.remove("vaultedFileList.json")
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
        self.assertTrue(
            "Missing # pilfer:vault" in combined
            or "still appears in the file" in combined
            or "still present" in combined,
            combined,
        )

    def test_rename_key_and_strip_marker_fails(self):
        """Renaming the key and dropping the marker must not look like removal."""
        self._write_vars_file(("db_password", b"super-secret"))
        self.assertEqual(self._run("open").returncode, 0)
        with open("group_vars.yml", "w") as f:
            f.write("---\nplain_key: visible\n" 'database_password: "super-secret"\n')
        closed = self._run("close")
        self.assertNotEqual(closed.returncode, 0)
        combined = closed.stderr + closed.stdout
        self.assertTrue(
            "still appears in the file" in combined or "still present" in combined,
            combined,
        )
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
                self.assertTrue(
                    "still appears in the file" in combined or "still present" in combined,
                    combined,
                )
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
        self.assertTrue(
            "still appears in the file" in combined or "still present" in combined,
            combined,
        )

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
        self.assertIn("Failed to process", combined)
        self.assertIn("'db_password'", combined)
        self.assertIn("--allow-removals", combined)
        closed = self._run("close", allow_removals=True)
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
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=True)
        self.assertEqual(found, [])
        os.remove("vaultedFileList.json")

    def test_whole_file_not_treated_as_inline(self):
        with open("only_whole.yml", "wb") as f:
            f.write(self.vault.encrypt(b"a: 1\n"))
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=True)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")


class TestDiscoveryOptimizations(unittest.TestCase):
    """Header-only classify, extension gates, and include-encrypted-vars coverage."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        self.vault = make_vault()

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_header_only_finds_whole_file_vault(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"a: 1\n"))
        # Large non-vault sibling should not need full reads in default mode;
        # presence alone shouldn't break discovery.
        with open("big.txt", "wb") as f:
            f.write(b"x" * (1024 * 1024))
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=False)
        os.remove("vaultedFileList.json")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")

    def test_extension_gate_skips_db_even_with_vault_bytes(self):
        with open("noise.db", "wb") as f:
            f.write(self.vault.encrypt(b"should-not-open\n"))
        with open("real.yml", "wb") as f:
            f.write(self.vault.encrypt(b"ok: 1\n"))
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=True)
        os.remove("vaultedFileList.json")
        paths = [os.path.basename(e["path"]) for e in found]
        self.assertEqual(paths, ["real.yml"])

    def test_include_encrypted_vars_still_finds_inline_yaml(self):
        body = encrypt_string_yaml(self.vault, "db_password", b"super-secret")
        with open("group_vars.yml", "w") as f:
            f.write("---\n" + body)
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=True)
        os.remove("vaultedFileList.json")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "inline")

    def test_include_encrypted_vars_finds_inline_in_extensionless_file(self):
        """Denylist must not exclude unknown / extensionless text files."""
        body = encrypt_string_yaml(self.vault, "db_password", b"super-secret")
        with open("weirdname", "w") as f:
            f.write("---\n" + body)
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=True)
        os.remove("vaultedFileList.json")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "inline")

    def test_include_finds_both_whole_file_and_inline(self):
        with open("whole.yml", "wb") as f:
            f.write(self.vault.encrypt(b"whole: 1\n"))
        with open("inline.yml", "w") as f:
            f.write("---\n" + encrypt_string_yaml(self.vault, "tok", b"v"))
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=True)
        os.remove("vaultedFileList.json")
        kinds = sorted(e["kind"] for e in found)
        self.assertEqual(kinds, ["file", "inline"])

    def test_bom_prefixed_whole_file_vault_discovered(self):
        ciphertext = self.vault.encrypt(b"a: 1\n")
        with open("bom_secret.yml", "wb") as f:
            f.write(b"\xef\xbb\xbf" + ciphertext)
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=False)
        os.remove("vaultedFileList.json")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")

    def test_whitespace_prefixed_whole_file_vault_discovered(self):
        ciphertext = self.vault.encrypt(b"a: 1\n")
        with open("ws_secret.yml", "wb") as f:
            f.write(b"\n\n  " + ciphertext)
        found = pilfer_cli.write_vaulted_file_list(include_encrypted_vars=False)
        os.remove("vaultedFileList.json")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "file")

    def test_bom_whole_file_open_close_round_trip(self):
        ciphertext = self.vault.encrypt(b"secret_key: hunter2\n")
        with open("vault_pass", "w") as f:
            f.write("test_password")
        with open("bom_secret.yml", "wb") as f:
            f.write(b"\xef\xbb\xbf" + ciphertext)
        pilfer_cli.write_vaulted_file_list()
        pilfer_cli.decrypt_vault_files("vault_pass")
        with open("bom_secret.yml", "rb") as f:
            self.assertEqual(f.read(), b"secret_key: hunter2\n")
        self.assertEqual(pilfer_cli.recrypt_vault_files("vault_pass"), 0)
        with open("bom_secret.yml", "rb") as f:
            after = f.read()
        self.assertTrue(
            after.startswith(b"$ANSIBLE_VAULT;") or after.lstrip().startswith(b"$ANSIBLE_VAULT;")
        )


class TestCompatibility(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        with open("vault_pass", "w") as f:
            f.write("test_password")
        vault = make_vault()
        with open("test_vault.yml", "wb") as f:
            f.write(vault.encrypt(b"test: value\n"))

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_identical_behavior(self):
        pilfer_cli.write_vaulted_file_list()
        pilfer_cli.decrypt_vault_files("vault_pass")
        with open("test_vault.yml", "rb") as f:
            cli_decrypted = f.read()
        self.assertEqual(pilfer_cli.recrypt_vault_files("vault_pass"), 0)
        self.assertEqual(cli_decrypted, b"test: value\n")


class TestInlineUnit(unittest.TestCase):
    """Pure unit tests for span finding / normalize without full CLI."""

    def test_normalize_strips_indent(self):
        block = b"          $ANSIBLE_VAULT;1.1;AES256\n          aabb\n"
        out = pilfer_inline.normalize_vault_ciphertext(block)
        self.assertTrue(out.startswith(b"$ANSIBLE_VAULT;"))
        self.assertNotIn(b"          $", out)

    def test_no_spans_in_plain_yaml(self):
        self.assertEqual(pilfer_inline.find_inline_vault_spans(b"foo: bar\n"), [])

    def test_parse_block_keeps_blank_lines(self):
        content = (
            b"db_password: |  # pilfer:vault:0\n" b"  line1\n" b"\n" b"  line3\n" b"other: x\n"
        )
        match = pilfer_inline.MARKER_RE.search(content)
        self.assertIsNotNone(match)
        plaintext, _start, end = pilfer_inline._parse_marked_value(content, match)
        self.assertEqual(plaintext, b"line1\n\nline3")
        self.assertTrue(content[end:].startswith(b"other:"))

    def test_is_whole_file_vault_tolerates_bom_and_whitespace(self):
        body = b"$ANSIBLE_VAULT;1.1;AES256\naabb\n"
        self.assertTrue(pilfer_inline.is_whole_file_vault(body))
        self.assertTrue(pilfer_inline.is_whole_file_vault(b"\xef\xbb\xbf" + body))
        self.assertTrue(pilfer_inline.is_whole_file_vault(b"\n  " + body))
        self.assertFalse(pilfer_inline.is_whole_file_vault(b"---\nfoo: bar\n"))


class TestScanOnce(unittest.TestCase):
    """Nested git skips must print once per open (single project walk)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        with open("vault_pass", "w") as f:
            f.write("test_password")
        self.pilfer_script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_nested_skip_announced_once(self):
        for name in ("nested_a", "nested_b"):
            os.makedirs(name)
            with open(os.path.join(name, ".git"), "w") as f:
                f.write("gitdir: ../.git\n")
        result = subprocess.run(
            [sys.executable, self.pilfer_script, "open", "-p", "vault_pass"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("nested_a", "nested_b"):
            needle = f"Skipping nested git repo: {os.path.abspath(name)}"
            self.assertEqual(result.stdout.count(needle), 1, result.stdout)


class TestAllowRemovalsAndRekey(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        with open("vault_pass", "w") as f:
            f.write("test_password")
        with open("vault_pass_new", "w") as f:
            f.write("new_password")
        self.vault = make_vault()
        self.pilfer_script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, self.pilfer_script, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_rekey_dry_run_and_apply(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        dry = self._run(
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
        applied = self._run(
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
        resumed = self._run(
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
        result = self._run(
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
        dry = self._run(
            "rekey",
            "--old-vault-password-file",
            "vault_pass",
            "--new-vault-password-file",
            "vault_pass_new",
            "--dry-run",
            "--yes",
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertTrue(
            os.path.exists(".pilfer-rekey-deadbeef"),
            "dry-run must not delete rekey temps",
        )
        result = self._run(
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
        opened = subprocess.run(
            [sys.executable, self.pilfer_script, "open", "-p", "vault_pass"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(opened.returncode, 0, opened.stderr)
        # Simulate destroyed session while plaintext + renamed sidecar remain.
        os.remove("vaultedFileList.json")
        shutil.rmtree(".vault", ignore_errors=True)
        os.rename("secret.yml.pilfer-open", ".pilfer-rekey-hidden.pilfer-open")
        blocked = subprocess.run(
            [sys.executable, self.pilfer_script, "open", "-p", "vault_pass"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("pilfer-open", (blocked.stderr + blocked.stdout).lower())

    def test_rekey_rotate_already_done_requires_yes(self):
        with open("secret.yml", "wb") as f:
            f.write(self.vault.encrypt(b"secret_key: hunter2\n"))
        self.assertEqual(
            self._run(
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
        refused = self._run(
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
        result = self._run(
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
        blocked = subprocess.run(
            [sys.executable, self.pilfer_script, "open", "-p", "vault_pass"],
            capture_output=True,
            text=True,
            check=False,
        )
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
        pilfer_script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")
        if not os.path.exists(pilfer_script):
            self.skipTest("Standalone pilfer.py not found")
        result = subprocess.run(
            [sys.executable, pilfer_script, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"pilfer {pilfer_version}", result.stdout)


if __name__ == "__main__":
    unittest.main()
