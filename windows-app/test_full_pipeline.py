#!/usr/bin/env python3
"""
Full pipeline integration test — simulates Windows backup + Android restore.
Mocks ADB and simulates Android-side decryption to verify cross-platform compatibility.
"""

import os
import sys
import json
import shutil
import socket
import struct
import tempfile
import threading
import unittest
import hashlib
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

from backup_manager import (
    ADBManager, BackupEngine, RestoreEngine, SecurityManager, BACKUP_VERSION
)


class MockADB:
    """Simulates ADB responses for a fake Android device."""

    def __init__(self, fake_device_dir: str):
        self.fake_dir = Path(fake_device_dir)
        self._setup_fake_device()

    def _setup_fake_device(self):
        """Create fake device filesystem."""
        # Fake APKs
        apk_dir = self.fake_dir / "apks"
        apk_dir.mkdir(parents=True, exist_ok=True)
        for pkg in ["com.example.app1", "com.example.app2", "com.example.gallery"]:
            apk = apk_dir / f"{pkg}.apk"
            apk.write_bytes(os.urandom(1024) + f"FAKE_APK:{pkg}".encode())

        # Fake storage
        for folder, files in {
            "DCIM/Camera": ["photo1.jpg", "photo2.jpg", "video1.mp4"],
            "Pictures": ["screenshot1.png", "meme.jpg"],
            "Download": ["document.pdf", "report.xlsx"],
            "Documents": ["notes.txt", "resume.docx"],
            "Music": ["song1.mp3"],
            "Movies": ["clip.mp4"],
        }.items():
            d = self.fake_dir / "sdcard" / folder
            d.mkdir(parents=True, exist_ok=True)
            for f in files:
                (d / f).write_bytes(os.urandom(512) + f"FAKE:{folder}/{f}".encode())

        # Fake contacts
        contacts = self.fake_dir / "data"
        contacts.mkdir(parents=True, exist_ok=True)
        (contacts / "contacts.txt").write_text(
            "Row: 0 display_name=John Doe, number=+1234567890\n"
            "Row: 1 display_name=Jane Smith, number=+0987654321\n"
        )
        (contacts / "sms.txt").write_text(
            "Row: 0 address=+1234567890, body=Hello!, date=1711900000000, type=1\n"
            "Row: 1 address=+0987654321, body=Meeting at 3pm, date=1711900060000, type=2\n"
        )


class SimulatedADBManager(ADBManager):
    """ADB manager that uses fake device filesystem instead of real ADB."""

    def __init__(self, fake_dir: str):
        super().__init__("fake_adb")
        self.fake_dir = Path(fake_dir)

    def is_connected(self) -> bool:
        return True

    def get_device_info(self) -> dict:
        return {
            "model": "Pixel 8 Pro (Simulated)",
            "brand": "Google",
            "android_version": "15",
            "sdk_version": "35",
            "serial": "SIM000001",
            "build_id": "AP3A.240905.015",
            "storage_raw": "Filesystem  Size  Used  Avail  Use%  Mounted on\n/dev/block  128G  64G   64G    50%   /data"
        }

    def list_packages(self, include_system=False) -> list:
        apk_dir = self.fake_dir / "apks"
        return [f.stem for f in apk_dir.glob("*.apk")]

    def get_apk_path(self, package: str) -> str:
        return str(self.fake_dir / "apks" / f"{package}.apk")

    def pull_file(self, remote: str, local: str) -> bool:
        src = Path(remote)
        if src.exists():
            shutil.copy2(str(src), local)
            return True
        return False

    def backup_app(self, package: str, output_path: str) -> bool:
        apk_path = self.get_apk_path(package)
        return self.pull_file(apk_path, output_path)

    def pull_storage(self, remote_dir: str, local_dir: str) -> bool:
        # Map /sdcard/X to fake_dir/sdcard/X
        dir_name = remote_dir.split("/")[-1]
        src = self.fake_dir / "sdcard" / dir_name
        if src.exists():
            dst = Path(local_dir) / dir_name
            shutil.copytree(str(src), str(dst), dirs_exist_ok=True)
            return True
        return False

    def backup_contacts(self, output_path: str) -> bool:
        src = self.fake_dir / "data" / "contacts.txt"
        if src.exists():
            shutil.copy2(str(src), output_path)
            return True
        return False

    def backup_sms(self, output_path: str) -> bool:
        src = self.fake_dir / "data" / "sms.txt"
        if src.exists():
            shutil.copy2(str(src), output_path)
            return True
        return False


class AndroidDecryptionSimulator:
    """
    Simulates the Android SecurityUtil.java decryption in Python.
    Verifies that Android app can decrypt files created by Windows app.
    """

    @staticmethod
    def decrypt(encrypted_path: str, output_path: str, password: str) -> bool:
        """
        Replicates SecurityUtil.java decryptFile():
        - Read 16-byte salt
        - Read 12-byte nonce
        - Read remaining ciphertext
        - PBKDF2-HMAC-SHA256 with 600K iterations
        - AES-256-GCM decrypt
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        with open(encrypted_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()

        # Same KDF as Java side
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = kdf.derive(password.encode('utf-8'))

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            return True
        except Exception as e:
            print(f"Android simulation decrypt failed: {e}")
            return False


class WiFiTransferSimulator:
    """Simulates Wi-Fi transfer between Windows app and Android app."""

    @staticmethod
    def simulate_transfer(encrypted_path: str, password: str) -> dict:
        """
        Simulates:
        1. Windows sends encrypted backup over TCP socket
        2. Android receives, decrypts, and extracts
        """
        results = {"send_ok": False, "receive_ok": False, "decrypt_ok": False, "files_restored": []}
        received_path = encrypted_path + ".received"
        decrypted_path = encrypted_path + ".decrypted.zip"

        server_ready = threading.Event()

        def android_server():
            """Simulates Android TransferService."""
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(('127.0.0.1', 0))
                port = srv.getsockname()[1]
                results["port"] = port
                srv.listen(1)
                server_ready.set()

                conn, addr = srv.accept()
                data = b""
                while True:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    data += chunk

                with open(received_path, 'wb') as f:
                    f.write(data)

                results["receive_ok"] = True
                results["bytes_received"] = len(data)

                # Decrypt
                ok = AndroidDecryptionSimulator.decrypt(received_path, decrypted_path, password)
                results["decrypt_ok"] = ok

                if ok and os.path.exists(decrypted_path):
                    # Extract zip and list files
                    extract_dir = decrypted_path + "_extracted"
                    with zipfile.ZipFile(decrypted_path, 'r') as zf:
                        zf.extractall(extract_dir)
                        results["files_restored"] = zf.namelist()

                    # Cleanup
                    shutil.rmtree(extract_dir, ignore_errors=True)

                conn.sendall(b"OK:RESTORED")
                conn.close()
                srv.close()
            except Exception as e:
                results["error"] = str(e)
                server_ready.set()

        # Start Android server
        server_thread = threading.Thread(target=android_server, daemon=True)
        server_thread.start()
        server_ready.wait(timeout=5)

        # Windows client sends file
        try:
            with open(encrypted_path, 'rb') as f:
                data = f.read()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', results.get("port", 0)))
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)

            response = sock.recv(1024)
            results["send_ok"] = True
            results["server_response"] = response.decode('utf-8', errors='replace')
            sock.close()
        except Exception as e:
            results["send_error"] = str(e)

        server_thread.join(timeout=30)

        # Cleanup
        for f in [received_path, decrypted_path]:
            if os.path.exists(f):
                os.remove(f)

        return results


# =============================================================================
# TEST SUITE
# =============================================================================

class TestFullBackupPipeline(unittest.TestCase):
    """End-to-end: simulate Windows backup → encrypt → transfer → Android decrypt → restore."""

    PASSWORD = "T3stP@ssw0rd!Secure"

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="backup_test_")
        self.fake_device_dir = os.path.join(self.temp_dir, "fake_device")
        self.backup_output_dir = os.path.join(self.temp_dir, "backup_output")

        # Setup fake device
        self.mock = MockADB(self.fake_device_dir)
        self.adb = SimulatedADBManager(self.fake_device_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_device_detection(self):
        """Simulated device is detected."""
        self.assertTrue(self.adb.is_connected())
        info = self.adb.get_device_info()
        self.assertEqual(info["brand"], "Google")
        self.assertEqual(info["model"], "Pixel 8 Pro (Simulated)")
        self.assertEqual(info["android_version"], "15")
        print(f"  ✅ Device: {info['brand']} {info['model']} Android {info['android_version']}")

    def test_02_package_listing(self):
        """Lists installed packages."""
        packages = self.adb.list_packages()
        self.assertEqual(len(packages), 3)
        self.assertIn("com.example.app1", packages)
        print(f"  ✅ Found {len(packages)} packages: {packages}")

    def test_03_full_backup_pipeline(self):
        """Full backup: device → backup dir → encrypted archive."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)

        progress_log = []
        engine.set_progress_callback(lambda s, d, p: progress_log.append((s, d, p)))

        success = engine.run_backup()
        self.assertTrue(success, "Backup should succeed")

        # Verify output files
        self.assertTrue(os.path.exists(os.path.join(self.backup_output_dir, "backup.enc")))
        self.assertTrue(os.path.exists(os.path.join(self.backup_output_dir, "manifest.json")))

        # Verify manifest
        with open(os.path.join(self.backup_output_dir, "manifest.json")) as f:
            manifest = json.load(f)

        self.assertEqual(manifest["version"], BACKUP_VERSION)
        self.assertEqual(manifest["device"]["brand"], "Google")
        self.assertGreater(manifest["contents"]["apps"]["count"], 0)
        self.assertIn("sha256", manifest["integrity"])

        # Verify progress reached 100%
        final_pct = max(p for _, _, p in progress_log)
        self.assertEqual(final_pct, 100)

        print(f"  ✅ Backup created: {manifest['contents']['apps']['count']} apps")
        print(f"  ✅ Storage dirs: {manifest['contents']['storage']}")
        print(f"  ✅ Data: {manifest['contents']['data']}")
        print(f"  ✅ Encrypted size: {manifest['integrity']['encrypted_size']} bytes")
        print(f"  ✅ SHA-256: {manifest['integrity']['sha256'][:16]}...")

    def test_04_backup_verification(self):
        """Verify backup integrity."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        engine.run_backup()

        restore = RestoreEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        result = restore.verify_backup()

        self.assertTrue(result["valid"])
        self.assertIn("manifest", result)
        print(f"  ✅ Backup verification passed")

    def test_05_windows_decrypt(self):
        """Windows-side decryption works."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        engine.run_backup()

        restore = RestoreEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        output_dir = os.path.join(self.temp_dir, "restored")
        os.makedirs(output_dir)

        success = restore.decrypt_backup(output_dir)
        self.assertTrue(success)

        zip_path = os.path.join(output_dir, "backup_raw.zip")
        self.assertTrue(os.path.exists(zip_path))

        # Verify zip contents
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            self.assertTrue(any("apks/" in n for n in names), "Should contain APKs")
            self.assertTrue(any("storage/" in n for n in names), "Should contain storage files")
            self.assertTrue(any("data/" in n for n in names), "Should contain data files")

        print(f"  ✅ Windows decryption successful, {len(names)} files in archive")

    def test_06_android_decrypt_simulation(self):
        """Android-side decryption (simulated Java SecurityUtil) works."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        engine.run_backup()

        encrypted_path = os.path.join(self.backup_output_dir, "backup.enc")
        android_output = os.path.join(self.temp_dir, "android_decrypted.zip")

        success = AndroidDecryptionSimulator.decrypt(encrypted_path, android_output, self.PASSWORD)
        self.assertTrue(success, "Android decryption should succeed")

        # Verify the decrypted zip is valid
        self.assertTrue(zipfile.is_zipfile(android_output))
        with zipfile.ZipFile(android_output) as zf:
            names = zf.namelist()
            self.assertGreater(len(names), 0)

        print(f"  ✅ Android decryption simulation successful, {len(names)} files recovered")

    def test_07_android_wrong_password_fails(self):
        """Android decryption with wrong password fails gracefully."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        engine.run_backup()

        encrypted_path = os.path.join(self.backup_output_dir, "backup.enc")
        android_output = os.path.join(self.temp_dir, "android_bad.zip")

        success = AndroidDecryptionSimulator.decrypt(encrypted_path, android_output, "WrongPassword123")
        self.assertFalse(success, "Wrong password should fail")
        print(f"  ✅ Wrong password correctly rejected by Android simulator")

    def test_08_wifi_transfer_simulation(self):
        """Simulate Wi-Fi transfer: Windows → Android over TCP socket."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        engine.run_backup()

        encrypted_path = os.path.join(self.backup_output_dir, "backup.enc")
        results = WiFiTransferSimulator.simulate_transfer(encrypted_path, self.PASSWORD)

        self.assertTrue(results["send_ok"], "Windows should send successfully")
        self.assertTrue(results["receive_ok"], "Android should receive successfully")
        self.assertTrue(results["decrypt_ok"], "Android should decrypt successfully")
        self.assertEqual(results["server_response"], "OK:RESTORED")
        self.assertGreater(len(results["files_restored"]), 0)

        print(f"  ✅ Wi-Fi transfer: sent {results['bytes_received']} bytes")
        print(f"  ✅ Server response: {results['server_response']}")
        print(f"  ✅ Files restored: {len(results['files_restored'])}")

    def test_09_backup_cancel(self):
        """Backup can be cancelled mid-operation."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)

        # Set cancel flag before run — should abort at first check
        engine._cancel_flag = True
        result = engine.run_backup()
        self.assertFalse(result, "Cancelled backup should return False")
        print(f"  ✅ Backup cancel works correctly")

    def test_10_cross_platform_integrity(self):
        """Full integrity check: Windows encrypt → Android decrypt → verify SHA-256."""
        engine = BackupEngine(self.backup_output_dir, self.PASSWORD, self.adb)
        engine.run_backup()

        # Read manifest for expected hash
        with open(os.path.join(self.backup_output_dir, "manifest.json")) as f:
            manifest = json.load(f)
        expected_hash = manifest["integrity"]["sha256"]

        # Android-side decrypt
        encrypted_path = os.path.join(self.backup_output_dir, "backup.enc")
        android_output = os.path.join(self.temp_dir, "integrity_check.zip")
        AndroidDecryptionSimulator.decrypt(encrypted_path, android_output, self.PASSWORD)

        # Verify SHA-256 matches
        with open(android_output, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(expected_hash, actual_hash, "SHA-256 must match across platforms")
        print(f"  ✅ Cross-platform integrity verified")
        print(f"     Windows SHA-256: {expected_hash[:32]}...")
        print(f"     Android SHA-256: {actual_hash[:32]}...")


if __name__ == "__main__":
    print("=" * 70)
    print("ANDROID BACKUP SUITE — FULL PIPELINE INTEGRATION TEST")
    print("Simulating Windows 11 + Android 15 environments")
    print("=" * 70)
    unittest.main(verbosity=2)
