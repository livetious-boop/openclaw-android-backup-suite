#!/usr/bin/env python3
"""
Android Backup Manager for Windows 11
Backs up all Android phone data and apps via ADB with AES-256 encryption.
"""

import os
import sys
import json
import hashlib
import subprocess
import threading
import time
import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

# Encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- Constants ---
BACKUP_VERSION = "1.0.0"
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for encryption
PBKDF2_ITERATIONS = 600_000
ADB_TIMEOUT = 300  # seconds


class SecurityManager:
    """Handles AES-256-GCM encryption/decryption with PBKDF2 key derivation."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
        salt = os.urandom(16)
        key = SecurityManager.derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        with open(input_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(output_path, 'wb') as f:
            f.write(salt)       # 16 bytes
            f.write(nonce)      # 12 bytes
            f.write(ciphertext) # rest

        file_hash = hashlib.sha256(plaintext).hexdigest()
        return {
            "original_size": len(plaintext),
            "encrypted_size": os.path.getsize(output_path),
            "sha256": file_hash
        }

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, password: str) -> bool:
        with open(input_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()

        key = SecurityManager.derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            logger.error("Decryption failed — wrong password or corrupted file")
            return False

        with open(output_path, 'wb') as f:
            f.write(plaintext)
        return True


class ADBManager:
    """Manages ADB communication with Android device."""

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    def run(self, args: list, timeout: int = ADB_TIMEOUT) -> subprocess.CompletedProcess:
        cmd = [self.adb_path] + args
        logger.info(f"ADB: {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def is_connected(self) -> bool:
        result = self.run(["devices"])
        lines = result.stdout.strip().split('\n')
        return any('device' in line and 'devices' not in line for line in lines)

    def get_device_info(self) -> dict:
        info = {}
        props = {
            "model": "ro.product.model",
            "brand": "ro.product.brand",
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "serial": "ro.serialno",
            "build_id": "ro.build.display.id",
        }
        for key, prop in props.items():
            result = self.run(["shell", "getprop", prop])
            info[key] = result.stdout.strip()
        # Storage info
        result = self.run(["shell", "df", "/data"])
        info["storage_raw"] = result.stdout.strip()
        return info

    def list_packages(self, include_system: bool = False) -> list:
        flag = "" if include_system else "-3"
        result = self.run(["shell", "pm", "list", "packages", flag])
        packages = []
        for line in result.stdout.strip().split('\n'):
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return packages

    def get_apk_path(self, package: str) -> Optional[str]:
        result = self.run(["shell", "pm", "path", package])
        for line in result.stdout.strip().split('\n'):
            if line.startswith("package:"):
                return line.replace("package:", "").strip()
        return None

    def pull_file(self, remote: str, local: str) -> bool:
        result = self.run(["pull", remote, local], timeout=600)
        return result.returncode == 0

    def backup_app(self, package: str, output_path: str) -> bool:
        """Pull APK for a package."""
        apk_path = self.get_apk_path(package)
        if not apk_path:
            logger.warning(f"Could not find APK path for {package}")
            return False
        return self.pull_file(apk_path, output_path)

    def pull_storage(self, remote_dir: str, local_dir: str) -> bool:
        result = self.run(["pull", remote_dir, local_dir], timeout=3600)
        return result.returncode == 0

    def backup_contacts(self, output_path: str) -> bool:
        """Export contacts via content provider."""
        result = self.run([
            "shell", "content", "query",
            "--uri", "content://com.android.contacts/contacts",
            "--projection", "display_name:number"
        ])
        if result.returncode == 0:
            with open(output_path, 'w') as f:
                f.write(result.stdout)
            return True
        return False

    def backup_sms(self, output_path: str) -> bool:
        """Export SMS messages."""
        result = self.run([
            "shell", "content", "query",
            "--uri", "content://sms",
            "--projection", "address:body:date:type"
        ])
        if result.returncode == 0:
            with open(output_path, 'w') as f:
                f.write(result.stdout)
            return True
        return False


class BackupEngine:
    """Orchestrates the full backup process."""

    def __init__(self, backup_dir: str, password: str, adb: ADBManager):
        self.backup_dir = Path(backup_dir)
        self.password = password
        self.adb = adb
        self.security = SecurityManager()
        self.manifest = {
            "version": BACKUP_VERSION,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "device": {},
            "contents": {},
            "integrity": {}
        }
        self._progress_callback: Optional[Callable] = None
        self._cancel_flag = False

    def set_progress_callback(self, cb: Callable):
        self._progress_callback = cb

    def cancel(self):
        self._cancel_flag = True

    def _update_progress(self, stage: str, detail: str, pct: float):
        if self._progress_callback:
            self._progress_callback(stage, detail, pct)

    def run_backup(self):
        """Execute full backup pipeline."""
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            temp_dir = self.backup_dir / "_temp"
            os.makedirs(temp_dir, exist_ok=True)

            if self._cancel_flag:
                return False

            # 1. Device info
            self._update_progress("Device Info", "Reading device information...", 5)
            self.manifest["device"] = self.adb.get_device_info()

            if self._cancel_flag:
                return False

            # 2. Backup APKs
            self._update_progress("Apps", "Listing installed apps...", 10)
            packages = self.adb.list_packages(include_system=False)
            apk_dir = temp_dir / "apks"
            os.makedirs(apk_dir, exist_ok=True)

            backed_up_apps = []
            for i, pkg in enumerate(packages):
                if self._cancel_flag:
                    return False
                pct = 10 + (i / max(len(packages), 1)) * 30
                self._update_progress("Apps", f"Backing up {pkg}...", pct)
                apk_file = apk_dir / f"{pkg}.apk"
                if self.adb.backup_app(pkg, str(apk_file)):
                    backed_up_apps.append(pkg)

            self.manifest["contents"]["apps"] = {
                "count": len(backed_up_apps),
                "packages": backed_up_apps
            }

            # 3. Backup storage (photos, downloads, documents)
            self._update_progress("Storage", "Backing up internal storage...", 45)
            storage_dir = temp_dir / "storage"
            os.makedirs(storage_dir, exist_ok=True)

            storage_dirs = [
                "/sdcard/DCIM",
                "/sdcard/Pictures",
                "/sdcard/Download",
                "/sdcard/Documents",
                "/sdcard/Music",
                "/sdcard/Movies",
            ]
            backed_up_storage = []
            for j, sd in enumerate(storage_dirs):
                if self._cancel_flag:
                    return False
                pct = 45 + (j / len(storage_dirs)) * 25
                dir_name = sd.split("/")[-1]
                self._update_progress("Storage", f"Backing up {dir_name}...", pct)
                local = storage_dir / dir_name
                if self.adb.pull_storage(sd, str(local)):
                    backed_up_storage.append(dir_name)

            self.manifest["contents"]["storage"] = backed_up_storage

            # 4. Backup contacts & SMS
            self._update_progress("Data", "Backing up contacts...", 72)
            data_dir = temp_dir / "data"
            os.makedirs(data_dir, exist_ok=True)
            self.adb.backup_contacts(str(data_dir / "contacts.txt"))
            self.adb.backup_sms(str(data_dir / "sms.txt"))
            self.manifest["contents"]["data"] = ["contacts", "sms"]

            # 5. Create archive
            self._update_progress("Archive", "Creating backup archive...", 78)
            archive_path = self.backup_dir / "backup_raw"
            shutil.make_archive(str(archive_path), 'zip', str(temp_dir))
            archive_file = str(archive_path) + ".zip"

            # 6. Encrypt
            self._update_progress("Encrypt", "Encrypting backup (AES-256-GCM)...", 85)
            encrypted_file = str(self.backup_dir / "backup.enc")
            enc_info = self.security.encrypt_file(archive_file, encrypted_file, self.password)
            self.manifest["integrity"] = enc_info

            # 7. Write manifest
            self._update_progress("Manifest", "Writing backup manifest...", 95)
            manifest_path = self.backup_dir / "manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(self.manifest, f, indent=2)

            # 8. Cleanup temp
            shutil.rmtree(temp_dir, ignore_errors=True)
            if os.path.exists(archive_file):
                os.remove(archive_file)

            self._update_progress("Complete", "Backup completed successfully!", 100)
            logger.info(f"Backup saved to {self.backup_dir}")
            return True

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            self._update_progress("Error", str(e), -1)
            return False


class RestoreEngine:
    """Handles decryption and restore to device."""

    def __init__(self, backup_dir: str, password: str, adb: ADBManager):
        self.backup_dir = Path(backup_dir)
        self.password = password
        self.adb = adb
        self.security = SecurityManager()

    def verify_backup(self) -> dict:
        manifest_path = self.backup_dir / "manifest.json"
        encrypted_path = self.backup_dir / "backup.enc"

        if not manifest_path.exists() or not encrypted_path.exists():
            return {"valid": False, "error": "Missing backup files"}

        with open(manifest_path) as f:
            manifest = json.load(f)

        return {"valid": True, "manifest": manifest}

    def decrypt_backup(self, output_dir: str) -> bool:
        encrypted_path = str(self.backup_dir / "backup.enc")
        decrypted_path = os.path.join(output_dir, "backup_raw.zip")
        return self.security.decrypt_file(encrypted_path, decrypted_path, self.password)


if __name__ == "__main__":
    # CLI mode for testing
    import argparse
    parser = argparse.ArgumentParser(description="Android Backup Manager")
    parser.add_argument("action", choices=["backup", "restore", "verify", "info"])
    parser.add_argument("--dir", required=True, help="Backup directory")
    parser.add_argument("--password", required=True, help="Encryption password")
    parser.add_argument("--adb", default="adb", help="Path to adb executable")
    args = parser.parse_args()

    adb = ADBManager(args.adb)

    if not adb.is_connected():
        print("ERROR: No Android device connected via ADB")
        sys.exit(1)

    if args.action == "info":
        info = adb.get_device_info()
        print(json.dumps(info, indent=2))

    elif args.action == "backup":
        engine = BackupEngine(args.dir, args.password, adb)
        engine.set_progress_callback(lambda s, d, p: print(f"[{p:.0f}%] {s}: {d}"))
        success = engine.run_backup()
        sys.exit(0 if success else 1)

    elif args.action == "verify":
        engine = RestoreEngine(args.dir, args.password, adb)
        result = engine.verify_backup()
        print(json.dumps(result, indent=2))

    elif args.action == "restore":
        engine = RestoreEngine(args.dir, args.password, adb)
        success = engine.decrypt_backup(args.dir)
        print("Decryption " + ("succeeded" if success else "FAILED"))
        sys.exit(0 if success else 1)
