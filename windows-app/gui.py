#!/usr/bin/env python3
"""
Android Backup Manager — Windows 11 GUI
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

from backup_manager import ADBManager, BackupEngine, RestoreEngine, SecurityManager


class BackupApp:
    """Main GUI Application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Android Backup Manager v1.0")
        self.root.geometry("720x580")
        self.root.minsize(600, 500)
        self.root.resizable(True, True)

        self.adb = ADBManager()
        self.backup_thread = None
        self.engine = None

        self._build_ui()
        self._check_device()

    def _build_ui(self):
        # --- Header ---
        header = ttk.Frame(self.root, padding=10)
        header.pack(fill=tk.X)
        ttk.Label(header, text="🔒 Android Backup Manager", font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)

        # --- Device Info ---
        device_frame = ttk.LabelFrame(self.root, text="Device", padding=10)
        device_frame.pack(fill=tk.X, padx=10, pady=5)

        self.device_label = ttk.Label(device_frame, text="No device connected", font=("Segoe UI", 10))
        self.device_label.pack(side=tk.LEFT)

        self.refresh_btn = ttk.Button(device_frame, text="🔄 Refresh", command=self._check_device)
        self.refresh_btn.pack(side=tk.RIGHT)

        # --- Settings ---
        settings_frame = ttk.LabelFrame(self.root, text="Settings", padding=10)
        settings_frame.pack(fill=tk.X, padx=10, pady=5)

        # Backup directory
        dir_row = ttk.Frame(settings_frame)
        dir_row.pack(fill=tk.X, pady=3)
        ttk.Label(dir_row, text="Backup Location:", width=15).pack(side=tk.LEFT)
        self.dir_var = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "AndroidBackups"))
        ttk.Entry(dir_row, textvariable=self.dir_var, width=45).pack(side=tk.LEFT, padx=5)
        ttk.Button(dir_row, text="Browse", command=self._browse_dir).pack(side=tk.LEFT)

        # Password
        pw_row = ttk.Frame(settings_frame)
        pw_row.pack(fill=tk.X, pady=3)
        ttk.Label(pw_row, text="Password:", width=15).pack(side=tk.LEFT)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(pw_row, textvariable=self.pw_var, show="*", width=35)
        self.pw_entry.pack(side=tk.LEFT, padx=5)

        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pw_row, text="Show", variable=self.show_pw_var, command=self._toggle_pw).pack(side=tk.LEFT)

        # Confirm password
        pw2_row = ttk.Frame(settings_frame)
        pw2_row.pack(fill=tk.X, pady=3)
        ttk.Label(pw2_row, text="Confirm Password:", width=15).pack(side=tk.LEFT)
        self.pw2_var = tk.StringVar()
        ttk.Entry(pw2_row, textvariable=self.pw2_var, show="*", width=35).pack(side=tk.LEFT, padx=5)

        # Options
        opt_row = ttk.Frame(settings_frame)
        opt_row.pack(fill=tk.X, pady=3)
        self.include_system_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row, text="Include system apps", variable=self.include_system_var).pack(side=tk.LEFT)

        # --- Actions ---
        action_frame = ttk.Frame(self.root, padding=10)
        action_frame.pack(fill=tk.X, padx=10)

        self.backup_btn = ttk.Button(action_frame, text="▶ Start Backup", command=self._start_backup)
        self.backup_btn.pack(side=tk.LEFT, padx=5)

        self.restore_btn = ttk.Button(action_frame, text="⬇ Restore", command=self._start_restore)
        self.restore_btn.pack(side=tk.LEFT, padx=5)

        self.verify_btn = ttk.Button(action_frame, text="✓ Verify Backup", command=self._verify_backup)
        self.verify_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(action_frame, text="✕ Cancel", command=self._cancel, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        # --- Progress ---
        progress_frame = ttk.LabelFrame(self.root, text="Progress", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)

        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=400)
        self.progress_bar.pack(fill=tk.X, pady=3)

        self.status_label = ttk.Label(progress_frame, text="Ready", font=("Segoe UI", 9))
        self.status_label.pack(fill=tk.X)

        # --- Log ---
        log_frame = ttk.LabelFrame(self.root, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = tk.Text(log_frame, height=8, font=("Consolas", 9), state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _browse_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.dir_var.set(d)

    def _toggle_pw(self):
        self.pw_entry.configure(show="" if self.show_pw_var.get() else "*")

    def _check_device(self):
        self._log("Checking for connected device...")
        if self.adb.is_connected():
            info = self.adb.get_device_info()
            label = f"{info.get('brand', '?')} {info.get('model', '?')} — Android {info.get('android_version', '?')}"
            self.device_label.configure(text=f"✅ {label}")
            self._log(f"Device found: {label}")
        else:
            self.device_label.configure(text="❌ No device connected")
            self._log("No device found. Connect via USB and enable USB debugging.")

    def _validate_inputs(self) -> bool:
        if not self.adb.is_connected():
            messagebox.showerror("Error", "No Android device connected.")
            return False
        pw = self.pw_var.get()
        if len(pw) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return False
        if pw != self.pw2_var.get():
            messagebox.showerror("Error", "Passwords do not match.")
            return False
        if not self.dir_var.get():
            messagebox.showerror("Error", "Select a backup location.")
            return False
        return True

    def _set_running(self, running: bool):
        state = tk.DISABLED if running else tk.NORMAL
        self.backup_btn.configure(state=state)
        self.restore_btn.configure(state=state)
        self.verify_btn.configure(state=state)
        self.cancel_btn.configure(state=tk.NORMAL if running else tk.DISABLED)

    def _progress_callback(self, stage: str, detail: str, pct: float):
        self.root.after(0, self._update_ui, stage, detail, pct)

    def _update_ui(self, stage: str, detail: str, pct: float):
        if pct >= 0:
            self.progress_bar['value'] = pct
        self.status_label.configure(text=f"{stage}: {detail}")
        self._log(f"{stage}: {detail}")

    def _start_backup(self):
        if not self._validate_inputs():
            return

        backup_dir = os.path.join(
            self.dir_var.get(),
            f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        self._set_running(True)
        self._log(f"Starting backup to {backup_dir}")

        self.engine = BackupEngine(backup_dir, self.pw_var.get(), self.adb)
        self.engine.set_progress_callback(self._progress_callback)

        def run():
            success = self.engine.run_backup()
            self.root.after(0, self._backup_done, success)

        self.backup_thread = threading.Thread(target=run, daemon=True)
        self.backup_thread.start()

    def _backup_done(self, success: bool):
        self._set_running(False)
        if success:
            messagebox.showinfo("Complete", "Backup completed successfully!")
        else:
            messagebox.showerror("Failed", "Backup failed. Check the log for details.")

    def _start_restore(self):
        backup_dir = filedialog.askdirectory(title="Select backup folder to restore")
        if not backup_dir:
            return

        pw = self.pw_var.get()
        if len(pw) < 8:
            messagebox.showerror("Error", "Enter the backup password (min 8 chars).")
            return

        self._set_running(True)
        self._log(f"Starting restore from {backup_dir}")

        def run():
            engine = RestoreEngine(backup_dir, pw, self.adb)
            result = engine.verify_backup()
            if not result["valid"]:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Invalid backup: {result.get('error')}"))
                self.root.after(0, lambda: self._set_running(False))
                return

            output_dir = os.path.join(backup_dir, "_restored")
            os.makedirs(output_dir, exist_ok=True)
            success = engine.decrypt_backup(output_dir)

            self.root.after(0, self._restore_done, success, output_dir)

        threading.Thread(target=run, daemon=True).start()

    def _restore_done(self, success: bool, output_dir: str):
        self._set_running(False)
        if success:
            messagebox.showinfo("Complete", f"Backup decrypted to:\n{output_dir}\n\nUse ADB to push files back to device.")
        else:
            messagebox.showerror("Failed", "Restore failed. Wrong password or corrupted backup.")

    def _verify_backup(self):
        backup_dir = filedialog.askdirectory(title="Select backup folder to verify")
        if not backup_dir:
            return

        engine = RestoreEngine(backup_dir, "", self.adb)
        result = engine.verify_backup()
        if result["valid"]:
            manifest = result["manifest"]
            info = (
                f"Version: {manifest.get('version')}\n"
                f"Created: {manifest.get('created_at')}\n"
                f"Device: {manifest.get('device', {}).get('brand', '?')} {manifest.get('device', {}).get('model', '?')}\n"
                f"Apps: {manifest.get('contents', {}).get('apps', {}).get('count', 0)}\n"
                f"SHA-256: {manifest.get('integrity', {}).get('sha256', 'N/A')}"
            )
            messagebox.showinfo("Backup Valid", info)
        else:
            messagebox.showerror("Invalid", f"Invalid backup: {result.get('error')}")

    def _cancel(self):
        if self.engine:
            self.engine.cancel()
            self._log("Cancelling...")


def main():
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
