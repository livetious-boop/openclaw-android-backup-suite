#!/usr/bin/env python3
"""
Unit tests for Android Backup Manager — encryption, integrity, and core logic.
Runs without ADB or Android device.
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

from backup_manager import SecurityManager


class TestSecurityManager(unittest.TestCase):
    """Test AES-256-GCM encryption/decryption pipeline."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_data = b"Hello, this is sensitive Android backup data!" * 100
        self.password = "StrongP@ssw0rd!2026"
        self.wrong_password = "WrongPassword123"

        self.plain_file = os.path.join(self.temp_dir, "test_plain.bin")
        self.enc_file = os.path.join(self.temp_dir, "test_encrypted.enc")
        self.dec_file = os.path.join(self.temp_dir, "test_decrypted.bin")

        with open(self.plain_file, 'wb') as f:
            f.write(self.test_data)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_encrypt_creates_file(self):
        result = SecurityManager.encrypt_file(self.plain_file, self.enc_file, self.password)
        self.assertTrue(os.path.exists(self.enc_file))
        self.assertGreater(result["encrypted_size"], 0)
        self.assertEqual(result["original_size"], len(self.test_data))
        self.assertIn("sha256", result)

    def test_encrypt_decrypt_roundtrip(self):
        SecurityManager.encrypt_file(self.plain_file, self.enc_file, self.password)
        success = SecurityManager.decrypt_file(self.enc_file, self.dec_file, self.password)
        self.assertTrue(success)

        with open(self.dec_file, 'rb') as f:
            decrypted = f.read()
        self.assertEqual(decrypted, self.test_data)

    def test_decrypt_wrong_password_fails(self):
        SecurityManager.encrypt_file(self.plain_file, self.enc_file, self.password)
        success = SecurityManager.decrypt_file(self.enc_file, self.dec_file, self.wrong_password)
        self.assertFalse(success)

    def test_encrypted_differs_from_plaintext(self):
        SecurityManager.encrypt_file(self.plain_file, self.enc_file, self.password)
        with open(self.enc_file, 'rb') as f:
            encrypted = f.read()
        self.assertNotEqual(encrypted, self.test_data)

    def test_different_encryptions_differ(self):
        enc1 = os.path.join(self.temp_dir, "enc1.enc")
        enc2 = os.path.join(self.temp_dir, "enc2.enc")
        SecurityManager.encrypt_file(self.plain_file, enc1, self.password)
        SecurityManager.encrypt_file(self.plain_file, enc2, self.password)
        with open(enc1, 'rb') as f:
            data1 = f.read()
        with open(enc2, 'rb') as f:
            data2 = f.read()
        # Salt and nonce are random, so encryptions should differ
        self.assertNotEqual(data1, data2)

    def test_integrity_hash_consistent(self):
        r1 = SecurityManager.encrypt_file(self.plain_file, self.enc_file, self.password)
        # Re-encrypt to different file
        enc2 = os.path.join(self.temp_dir, "enc2.enc")
        r2 = SecurityManager.encrypt_file(self.plain_file, enc2, self.password)
        # SHA-256 of plaintext should be identical
        self.assertEqual(r1["sha256"], r2["sha256"])

    def test_empty_file(self):
        empty_file = os.path.join(self.temp_dir, "empty.bin")
        enc_file = os.path.join(self.temp_dir, "empty.enc")
        dec_file = os.path.join(self.temp_dir, "empty_dec.bin")
        with open(empty_file, 'wb') as f:
            pass  # empty

        SecurityManager.encrypt_file(empty_file, enc_file, self.password)
        success = SecurityManager.decrypt_file(enc_file, dec_file, self.password)
        self.assertTrue(success)
        with open(dec_file, 'rb') as f:
            self.assertEqual(f.read(), b"")

    def test_large_data(self):
        large_file = os.path.join(self.temp_dir, "large.bin")
        enc_file = os.path.join(self.temp_dir, "large.enc")
        dec_file = os.path.join(self.temp_dir, "large_dec.bin")
        large_data = os.urandom(5 * 1024 * 1024)  # 5MB

        with open(large_file, 'wb') as f:
            f.write(large_data)

        SecurityManager.encrypt_file(large_file, enc_file, self.password)
        success = SecurityManager.decrypt_file(enc_file, dec_file, self.password)
        self.assertTrue(success)

        with open(dec_file, 'rb') as f:
            self.assertEqual(f.read(), large_data)


class TestKeyDerivation(unittest.TestCase):
    """Test PBKDF2 key derivation."""

    def test_same_password_same_salt_same_key(self):
        salt = os.urandom(16)
        k1 = SecurityManager.derive_key("test123", salt)
        k2 = SecurityManager.derive_key("test123", salt)
        self.assertEqual(k1, k2)

    def test_different_salt_different_key(self):
        k1 = SecurityManager.derive_key("test123", os.urandom(16))
        k2 = SecurityManager.derive_key("test123", os.urandom(16))
        self.assertNotEqual(k1, k2)

    def test_different_password_different_key(self):
        salt = os.urandom(16)
        k1 = SecurityManager.derive_key("password1", salt)
        k2 = SecurityManager.derive_key("password2", salt)
        self.assertNotEqual(k1, k2)

    def test_key_length_32_bytes(self):
        key = SecurityManager.derive_key("test", os.urandom(16))
        self.assertEqual(len(key), 32)  # AES-256


if __name__ == "__main__":
    unittest.main(verbosity=2)
