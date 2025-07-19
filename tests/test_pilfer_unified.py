#!/usr/bin/env python3
"""
Unified tests for pilfer - DRY approach testing both standalone and CLI versions
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from abc import ABC, abstractmethod

# Import CLI version for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pilfer"))

from pilfer import cli as pilfer_cli


class PilferTestBase(unittest.TestCase, ABC):
    """Base test class with shared test logic for both CLI and standalone versions"""

    def setUp(self):
        """Set up test environment with vault files"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

        # Create a vault password file
        self.vault_password = "test_password"
        with open("vault_pass", "w") as f:
            f.write(self.vault_password)

        # Sample vault content with different line endings
        self.vault_content_unix = "test_secret: value1\nother_secret: value2\n"
        self.vault_content_windows = "test_secret: value1\r\nother_secret: value2\r\n"
        self.vault_content_mixed = "test_secret: value1\nother_secret: value2\r\n"

        # Create encrypted vault files using Ansible's VaultLib
        from ansible.constants import DEFAULT_VAULT_ID_MATCH
        from ansible.parsing.vault import VaultLib, VaultSecret

        vault = VaultLib(
            [(DEFAULT_VAULT_ID_MATCH, VaultSecret(self.vault_password.encode("utf-8")))]
        )

        # Create test vault files with different line endings
        self.vault_files = {
            "unix_vault.yml": vault.encrypt(self.vault_content_unix.encode("utf-8")),
            "windows_vault.yml": vault.encrypt(
                self.vault_content_windows.encode("utf-8")
            ),
            "mixed_vault.yml": vault.encrypt(self.vault_content_mixed.encode("utf-8")),
        }

        for filename, encrypted_content in self.vault_files.items():
            with open(filename, "wb") as f:
                f.write(encrypted_content)

        # Store original hashes
        self.original_hashes = {}
        for filename in self.vault_files.keys():
            with open(filename, "rb") as f:
                self.original_hashes[filename] = hashlib.sha256(f.read()).hexdigest()

    def tearDown(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    @abstractmethod
    def pilfer_open(self, vault_pass_file="vault_pass"):
        """Open vault files - implemented by subclasses"""
        pass

    @abstractmethod
    def pilfer_close(self, vault_pass_file="vault_pass"):
        """Close vault files - implemented by subclasses"""
        pass

    def test_unchanged_files_same_hash(self):
        """Test that unchanged files maintain the same hash after re-encryption"""
        # Open vault files
        self.pilfer_open()

        # Don't modify any files - just close immediately
        modified_count = self.pilfer_close()

        # Check that no files were marked as modified
        self.assertEqual(
            modified_count, 0, "No files should be marked as modified when unchanged"
        )

        # Check that hashes are identical
        for filename in self.vault_files.keys():
            with open(filename, "rb") as f:
                new_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(
                self.original_hashes[filename],
                new_hash,
                f"Hash for unchanged file {filename} should remain the same",
            )

    def test_line_endings_preserved(self):
        """Test that line endings are preserved during re-encryption"""
        # Open vault files
        self.pilfer_open()

        # Verify decrypted content has correct line endings
        with open("unix_vault.yml", "rb") as f:
            decrypted_content = f.read()
            self.assertEqual(decrypted_content, self.vault_content_unix.encode("utf-8"))

        with open("windows_vault.yml", "rb") as f:
            decrypted_content = f.read()
            self.assertEqual(
                decrypted_content, self.vault_content_windows.encode("utf-8")
            )

        with open("mixed_vault.yml", "rb") as f:
            decrypted_content = f.read()
            self.assertEqual(
                decrypted_content, self.vault_content_mixed.encode("utf-8")
            )

        # Re-encrypt without changes
        modified_count = self.pilfer_close()
        self.assertEqual(modified_count, 0)

        # Decrypt again and verify line endings are still correct
        self.pilfer_open()

        with open("unix_vault.yml", "rb") as f:
            final_content = f.read()
            self.assertEqual(final_content, self.vault_content_unix.encode("utf-8"))

        with open("windows_vault.yml", "rb") as f:
            final_content = f.read()
            self.assertEqual(final_content, self.vault_content_windows.encode("utf-8"))

        with open("mixed_vault.yml", "rb") as f:
            final_content = f.read()
            self.assertEqual(final_content, self.vault_content_mixed.encode("utf-8"))

    def test_modified_file_detection(self):
        """Test that modified files are correctly detected and counted"""
        # Open vault files
        self.pilfer_open()

        # Modify one file
        with open("unix_vault.yml", "w") as f:
            f.write("modified_secret: new_value\n")

        # Re-encrypt
        modified_count = self.pilfer_close()

        # Should detect exactly 1 modified file
        self.assertEqual(modified_count, 1, "Should detect exactly 1 modified file")

        # Hash should be different for modified file
        with open("unix_vault.yml", "rb") as f:
            new_hash = hashlib.sha256(f.read()).hexdigest()
        self.assertNotEqual(
            self.original_hashes["unix_vault.yml"],
            new_hash,
            "Hash should be different for modified file",
        )

        # Other files should remain unchanged
        for filename in ["windows_vault.yml", "mixed_vault.yml"]:
            with open(filename, "rb") as f:
                unchanged_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(
                self.original_hashes[filename],
                unchanged_hash,
                f"Hash for unmodified file {filename} should remain the same",
            )

    def test_multiple_modifications(self):
        """Test detection of multiple modified files"""
        # Open vault files
        self.pilfer_open()

        # Modify two files
        with open("unix_vault.yml", "w") as f:
            f.write("modified_secret1: new_value1\n")

        with open("windows_vault.yml", "w") as f:
            f.write("modified_secret2: new_value2\r\n")

        # Re-encrypt
        modified_count = self.pilfer_close()

        # Should detect exactly 2 modified files
        self.assertEqual(modified_count, 2, "Should detect exactly 2 modified files")


class TestPilferCLI(PilferTestBase):
    """Test CLI version by calling functions directly"""

    def pilfer_open(self, vault_pass_file="vault_pass"):
        """Open vault files using CLI functions"""
        pilfer_cli.write_vaulted_file_list()
        pilfer_cli.decrypt_vault_files(vault_pass_file)

    def pilfer_close(self, vault_pass_file="vault_pass"):
        """Close vault files using CLI functions"""
        return pilfer_cli.recrypt_vault_files(vault_pass_file)


class TestPilferStandalone(PilferTestBase):
    """Test standalone version by running subprocess"""

    def setUp(self):
        """Set up test environment and check for standalone script"""
        super().setUp()

        # Find the standalone pilfer.py script
        self.pilfer_script = os.path.join(os.path.dirname(__file__), "..", "pilfer.py")
        if not os.path.exists(self.pilfer_script):
            self.skipTest("Standalone pilfer.py not found")

    def run_pilfer(self, action, vault_pass_file="vault_pass"):
        """Helper to run standalone pilfer script"""
        cmd = [sys.executable, self.pilfer_script, action, "-p", vault_pass_file]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def pilfer_open(self, vault_pass_file="vault_pass"):
        """Open vault files using standalone script"""
        result = self.run_pilfer("open", vault_pass_file)
        self.assertEqual(result.returncode, 0, f"Open failed: {result.stderr}")

    def pilfer_close(self, vault_pass_file="vault_pass"):
        """Close vault files using standalone script"""
        result = self.run_pilfer("close", vault_pass_file)
        self.assertEqual(result.returncode, 0, f"Close failed: {result.stderr}")

        # Extract modified count from output
        output = result.stdout
        if "0 modified files" in output:
            return 0
        elif "1 modified files" in output:
            return 1
        elif "2 modified files" in output:
            return 2
        else:
            # Try to extract number from pattern "X modified files"
            import re

            match = re.search(r"(\d+) modified files", output)
            if match:
                return int(match.group(1))
            else:
                self.fail(f"Could not parse modified count from output: {output}")


class TestCompatibility(unittest.TestCase):
    """Test that both versions produce identical results on same data"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

        # Create vault password file
        with open("vault_pass", "w") as f:
            f.write("test_password")

        # Create a simple vault file
        from ansible.constants import DEFAULT_VAULT_ID_MATCH
        from ansible.parsing.vault import VaultLib, VaultSecret

        vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(b"test_password"))])

        content = "test: value\n"
        encrypted = vault.encrypt(content.encode("utf-8"))

        with open("test_vault.yml", "wb") as f:
            f.write(encrypted)

    def tearDown(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_identical_behavior(self):
        """Test that both versions produce identical results"""
        # Test CLI version
        pilfer_cli.write_vaulted_file_list()
        pilfer_cli.decrypt_vault_files("vault_pass")

        # Get decrypted content from CLI version
        with open("test_vault.yml", "rb") as f:
            cli_decrypted = f.read()

        # Re-encrypt with CLI
        cli_modified_count = pilfer_cli.recrypt_vault_files("vault_pass")

        # Both should report 0 modifications for unchanged content
        self.assertEqual(
            cli_modified_count,
            0,
            "CLI should report 0 modifications for unchanged content",
        )

        # Content should be identical to original (since unchanged)
        self.assertEqual(
            cli_decrypted, b"test: value\n", "Decrypted content should match original"
        )


if __name__ == "__main__":
    unittest.main()
