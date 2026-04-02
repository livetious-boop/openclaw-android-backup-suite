# Android Backup Suite

Complete backup and restore solution for Android devices.

## Components

### 1. Windows Backup App (`windows-app/`)
- **Python GUI** for Windows 11 (tkinter)
- Backs up: APKs, photos, downloads, documents, music, movies, contacts, SMS
- **AES-256-GCM encryption** with PBKDF2 key derivation (600K iterations)
- Integrity verification via SHA-256 checksums
- Cancel/resume support

### 2. Android Data Transfer App (`android-app/`)
- Receives encrypted backup over local Wi-Fi
- Decrypts using same AES-256-GCM (cross-platform compatible)
- Restores files to original locations
- Installs APKs via PackageInstaller

## Security

| Feature | Detail |
|---------|--------|
| Encryption | AES-256-GCM |
| Key Derivation | PBKDF2-HMAC-SHA256, 600K iterations |
| Salt | 16 bytes, random per file |
| Nonce | 12 bytes, random per file |
| Integrity | SHA-256 hash in manifest |
| Network | Local Wi-Fi only, cleartext blocked for internet |
| Password | Minimum 8 characters enforced |

## Usage

### Backup (Windows)
```bash
pip install -r windows-app/requirements.txt
python windows-app/gui.py           # GUI mode
python windows-app/backup_manager.py backup --dir ./my-backup --password "MyStr0ngPw!"  # CLI
```

### Restore (Android)
1. Install the Data Transfer APK
2. Open app, enter same password used for backup
3. Tap "Start" to begin listening
4. On Windows, use "Send to Phone" (connects to phone's IP:port)

### Verify Backup
```bash
python windows-app/backup_manager.py verify --dir ./my-backup --password "MyStr0ngPw!"
```

## Testing
```bash
cd windows-app && python test_backup_manager.py -v
```

## Build APKs
Both apps include GitHub Actions CI. Push to GitHub and APKs build automatically.
