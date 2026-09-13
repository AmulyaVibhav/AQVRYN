"""
Settings view — app settings, security, backup/restore, import/export.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea,
    QPushButton, QCheckBox, QSpinBox, QComboBox, QLineEdit,
    QMessageBox, QFileDialog, QTabWidget, QFormLayout, QGroupBox,
)

from core.vault.vault_service import VaultService
from core.models.vault_models import AppSettings
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


class SettingsView(QWidget):
    vault_locked = pyqtSignal()

    def __init__(self, vault_service: VaultService, parent=None) -> None:
        super().__init__(parent)
        self._vault = vault_service
        self._setup_ui()

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        header = QLabel("Settings")
        header.setStyleSheet("font-size: 22px; font-weight: bold;")
        layout.addWidget(header)

        tabs = QTabWidget()

        tabs.addTab(self._build_security_tab(), "Security")
        tabs.addTab(self._build_generator_tab(), "Password Generator")
        tabs.addTab(self._build_backup_tab(), "Backup & Restore")
        tabs.addTab(self._build_import_export_tab(), "Import / Export")
        tabs.addTab(self._build_about_tab(), "About")

        layout.addWidget(tabs)
        layout.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ------------------------------------------------------------------
    # Security tab
    # ------------------------------------------------------------------

    def _build_security_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.setSpacing(12)
        form.setContentsMargins(16, 16, 16, 16)

        # Auto-lock
        self._autolock_spin = QSpinBox()
        self._autolock_spin.setRange(0, 3600)
        self._autolock_spin.setValue(300)
        self._autolock_spin.setSuffix(" seconds (0 = disabled)")
        form.addRow("Auto-lock Timeout", self._autolock_spin)

        # Clipboard timeout
        self._clipboard_spin = QSpinBox()
        self._clipboard_spin.setRange(0, 300)
        self._clipboard_spin.setValue(30)
        self._clipboard_spin.setSuffix(" seconds (0 = disabled)")
        form.addRow("Clipboard Clear Timeout", self._clipboard_spin)

        # Password history
        self._history_spin = QSpinBox()
        self._history_spin.setRange(0, 50)
        self._history_spin.setValue(10)
        self._history_spin.setSuffix(" passwords")
        form.addRow("Password History Size", self._history_spin)

        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self._save_security_settings)
        form.addRow("", save_btn)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #45475a;")
        form.addRow(sep)

        # Change master password
        form.addRow(QLabel("Change Master Password"))
        self._old_pw = QLineEdit()
        self._old_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._old_pw.setPlaceholderText("Current master password")
        form.addRow("Current", self._old_pw)

        self._new_pw = QLineEdit()
        self._new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._new_pw.setPlaceholderText("New master password")
        form.addRow("New", self._new_pw)

        self._new_pw_confirm = QLineEdit()
        self._new_pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._new_pw_confirm.setPlaceholderText("Confirm new password")
        form.addRow("Confirm", self._new_pw_confirm)

        change_btn = QPushButton("Change Master Password")
        change_btn.clicked.connect(self._change_master_password)
        form.addRow("", change_btn)

        return w

    # ------------------------------------------------------------------
    # Generator tab
    # ------------------------------------------------------------------

    def _build_generator_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.setSpacing(12)
        form.setContentsMargins(16, 16, 16, 16)

        self._gen_length = QSpinBox()
        self._gen_length.setRange(8, 128)
        self._gen_length.setValue(20)
        form.addRow("Default Length", self._gen_length)

        self._gen_upper = QCheckBox("Uppercase (A-Z)")
        self._gen_upper.setChecked(True)
        form.addRow("", self._gen_upper)

        self._gen_lower = QCheckBox("Lowercase (a-z)")
        self._gen_lower.setChecked(True)
        form.addRow("", self._gen_lower)

        self._gen_digits = QCheckBox("Digits (0-9)")
        self._gen_digits.setChecked(True)
        form.addRow("", self._gen_digits)

        self._gen_symbols = QCheckBox("Symbols (!@#$%...)")
        self._gen_symbols.setChecked(True)
        form.addRow("", self._gen_symbols)

        self._gen_ambiguous = QCheckBox("Exclude ambiguous characters (0O1lI)")
        self._gen_ambiguous.setChecked(True)
        form.addRow("", self._gen_ambiguous)

        save_btn = QPushButton("Save Generator Settings")
        save_btn.clicked.connect(self._save_generator_settings)
        form.addRow("", save_btn)

        # Live generator preview
        preview_btn = QPushButton("Generate Sample Password")
        preview_btn.clicked.connect(self._generate_preview)
        form.addRow("", preview_btn)

        self._gen_preview = QLabel("")
        self._gen_preview.setStyleSheet("font-family: monospace; font-size: 14px; color: #a6e3a1;")
        self._gen_preview.setWordWrap(True)
        form.addRow("Preview", self._gen_preview)

        return w

    # ------------------------------------------------------------------
    # Backup tab
    # ------------------------------------------------------------------

    def _build_backup_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(QLabel("Create an encrypted backup of your vault."))

        self._backup_pw = QLineEdit()
        self._backup_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._backup_pw.setPlaceholderText("Backup password (can differ from master password)")
        layout.addWidget(self._backup_pw)

        backup_btn = QPushButton("📦 Create Encrypted Backup")
        backup_btn.clicked.connect(self._create_backup)
        layout.addWidget(backup_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #45475a;")
        layout.addWidget(sep)

        layout.addWidget(QLabel("Restore vault from backup (requires backup password)."))

        warn = QLabel("⚠️ Restoring will overwrite your current vault. A rollback copy will be saved.")
        warn.setStyleSheet("color: #f9e2af;")
        warn.setWordWrap(True)
        layout.addWidget(warn)

        self._restore_pw = QLineEdit()
        self._restore_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._restore_pw.setPlaceholderText("Backup password")
        layout.addWidget(self._restore_pw)

        restore_btn = QPushButton("🔄 Restore from Backup…")
        restore_btn.setObjectName("secondary")
        restore_btn.clicked.connect(self._restore_backup)
        layout.addWidget(restore_btn)

        layout.addStretch()
        return w

    # ------------------------------------------------------------------
    # Import/Export tab
    # ------------------------------------------------------------------

    def _build_import_export_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        layout.addWidget(QLabel("Import passwords from another manager:"))

        import_csv_btn = QPushButton("📥 Import from CSV…")
        import_csv_btn.clicked.connect(lambda: self._import("csv"))
        layout.addWidget(import_csv_btn)

        import_json_btn = QPushButton("📥 Import from JSON…")
        import_json_btn.clicked.connect(lambda: self._import("json"))
        layout.addWidget(import_json_btn)

        import_bw_btn = QPushButton("📥 Import from Bitwarden JSON…")
        import_bw_btn.clicked.connect(lambda: self._import("bitwarden"))
        layout.addWidget(import_bw_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #45475a;")
        layout.addWidget(sep)

        warn = QLabel(
            "⚠️  EXPORT WARNING: Plaintext exports contain your actual passwords in readable form.\n"
            "Never store plaintext exports in unsecured locations."
        )
        warn.setStyleSheet("color: #f38ba8;")
        warn.setWordWrap(True)
        layout.addWidget(warn)

        export_csv_btn = QPushButton("📤 Export to CSV (Plaintext)…")
        export_csv_btn.setObjectName("secondary")
        export_csv_btn.clicked.connect(lambda: self._export("csv"))
        layout.addWidget(export_csv_btn)

        export_json_btn = QPushButton("📤 Export to JSON (Plaintext)…")
        export_json_btn.setObjectName("secondary")
        export_json_btn.clicked.connect(lambda: self._export("json"))
        layout.addWidget(export_json_btn)

        export_bw_btn = QPushButton("📤 Export to Bitwarden JSON…")
        export_bw_btn.setObjectName("secondary")
        export_bw_btn.clicked.connect(lambda: self._export("bitwarden"))
        layout.addWidget(export_bw_btn)

        layout.addStretch()
        return w

    # ------------------------------------------------------------------
    # About tab
    # ------------------------------------------------------------------

    def _build_about_tab(self) -> QWidget:
        from config.settings import APP_NAME, APP_VERSION
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        layout.addWidget(QLabel(f"🔐 {APP_NAME}"))
        layout.addWidget(QLabel(f"Version: {APP_VERSION}"))
        layout.addWidget(QLabel("Encryption: AES-256-GCM"))
        layout.addWidget(QLabel("KDF: Argon2id"))
        layout.addWidget(QLabel("Database: SQLite (encrypted fields)"))
        layout.addWidget(QLabel(""))

        lock_btn = QPushButton("🔒 Lock Vault Now")
        lock_btn.clicked.connect(self.vault_locked)
        layout.addWidget(lock_btn)
        layout.addStretch()
        return w

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _save_security_settings(self) -> None:
        try:
            settings = self._vault.get_settings()
            settings.auto_lock_seconds = self._autolock_spin.value()
            settings.clipboard_clear_seconds = self._clipboard_spin.value()
            settings.password_history_size = self._history_spin.value()
            self._vault.save_settings(settings)
            QMessageBox.information(self, "Settings", "Security settings saved.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _save_generator_settings(self) -> None:
        try:
            settings = self._vault.get_settings()
            settings.generator_length = self._gen_length.value()
            settings.generator_uppercase = self._gen_upper.isChecked()
            settings.generator_lowercase = self._gen_lower.isChecked()
            settings.generator_digits = self._gen_digits.isChecked()
            settings.generator_symbols = self._gen_symbols.isChecked()
            settings.generator_exclude_ambiguous = self._gen_ambiguous.isChecked()
            self._vault.save_settings(settings)
            QMessageBox.information(self, "Settings", "Generator settings saved.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _generate_preview(self) -> None:
        try:
            from core.generator.password_generator import GeneratorConfig, PasswordGenerator
            config = GeneratorConfig(
                length=self._gen_length.value(),
                use_uppercase=self._gen_upper.isChecked(),
                use_lowercase=self._gen_lower.isChecked(),
                use_digits=self._gen_digits.isChecked(),
                use_symbols=self._gen_symbols.isChecked(),
                exclude_ambiguous=self._gen_ambiguous.isChecked(),
            )
            pw = PasswordGenerator().generate(config)
            self._gen_preview.setText(pw)
        except Exception as exc:
            self._gen_preview.setText(f"Error: {exc}")

    def _change_master_password(self) -> None:
        old = self._old_pw.text()
        new = self._new_pw.text()
        confirm = self._new_pw_confirm.text()

        if not old or not new:
            QMessageBox.warning(self, "Validation", "All password fields are required.")
            return
        if new != confirm:
            QMessageBox.warning(self, "Validation", "New passwords do not match.")
            return

        reply = QMessageBox.question(
            self, "Confirm",
            "Are you sure you want to change your master password?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self._vault.change_master_password(old, new)
            self._old_pw.clear()
            self._new_pw.clear()
            self._new_pw_confirm.clear()
            QMessageBox.information(self, "Success", "Master password changed successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _create_backup(self) -> None:
        pw = self._backup_pw.text()
        if not pw:
            QMessageBox.warning(self, "Backup", "Please enter a backup password.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Backup", "", "SecureVault Backup (*.svbak)"
        )
        if not path:
            return

        try:
            from core.backup.backup_manager import BackupManager
            bm = BackupManager(self._vault._db)
            out = bm.create_backup(pw, Path(path))
            self._backup_pw.clear()
            QMessageBox.information(self, "Backup", f"Backup created:\n{out}")
        except Exception as exc:
            QMessageBox.critical(self, "Backup Error", str(exc))

    def _restore_backup(self) -> None:
        pw = self._restore_pw.text()
        if not pw:
            QMessageBox.warning(self, "Restore", "Please enter the backup password.")
            return

        path, _ = QFileDialog.getOpenFileName(
            self, "Select Backup File", "", "SecureVault Backup (*.svbak)"
        )
        if not path:
            return

        try:
            from core.backup.backup_manager import BackupManager
            bm = BackupManager(self._vault._db)
            preview = bm.restore_backup(Path(path), pw)

            confirm_msg = (
                f"Backup from: {preview.get('created_at', 'Unknown')}\n"
                f"Entries: {preview.get('entry_count', 0)}\n"
                f"Categories: {preview.get('category_count', 0)}\n\n"
                "This will OVERWRITE your current vault. Continue?"
            )
            reply = QMessageBox.question(
                self, "Confirm Restore", confirm_msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                bm.restore_apply(preview, overwrite_existing=True)
                self._restore_pw.clear()
                QMessageBox.information(
                    self, "Restored",
                    "Vault restored. You must re-unlock with the backup's master password.\n"
                    "The application will now lock."
                )
                self.vault_locked.emit()
        except Exception as exc:
            QMessageBox.critical(self, "Restore Error", str(exc))

    def _import(self, fmt: str) -> None:
        filter_map = {
            "csv": "CSV Files (*.csv)",
            "json": "JSON Files (*.json)",
            "bitwarden": "JSON Files (*.json)",
        }
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Import File", "", filter_map.get(fmt, "All Files (*)")
        )
        if not path:
            return

        QMessageBox.information(
            self, "Import",
            f"Importing from: {path}\n\n"
            "⚠️ Imported data will be immediately encrypted and stored securely.\n"
            "The import file contains plaintext — delete it securely after import."
        )

        try:
            from core.import_export.importer_exporter import VaultImporter
            importer = VaultImporter()
            if fmt == "csv":
                entries = importer.import_csv(Path(path))
            elif fmt == "json":
                entries = importer.import_json(Path(path))
            else:
                entries = importer.import_bitwarden_json(Path(path))

            imported = 0
            for entry in entries:
                try:
                    self._vault.add_entry(entry)
                    imported += 1
                except Exception:
                    pass

            from core.utilities.logging_utils import security_logger
            security_logger.import_performed(imported, fmt)
            QMessageBox.information(self, "Import Complete", f"Imported {imported} entries.")
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", str(exc))

    def _export(self, fmt: str) -> None:
        reply = QMessageBox.warning(
            self, "⚠️ Export Warning",
            "You are about to export your vault to PLAINTEXT.\n\n"
            "The exported file will contain ALL your passwords in readable form.\n"
            "Anyone with access to this file can read all your passwords.\n\n"
            "Are you absolutely sure you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ext_map = {"csv": "csv", "json": "json", "bitwarden": "json"}
        filter_map = {"csv": "CSV Files (*.csv)", "json": "JSON Files (*.json)", "bitwarden": "JSON Files (*.json)"}
        path, _ = QFileDialog.getSaveFileName(
            self, "Export To", f"vault_export.{ext_map.get(fmt, 'json')}",
            filter_map.get(fmt, "All Files (*)")
        )
        if not path:
            return

        try:
            from core.import_export.importer_exporter import VaultExporter
            entries = self._vault.list_entries()
            exporter = VaultExporter()
            if fmt == "csv":
                exporter.export_csv(entries, Path(path))
            elif fmt == "json":
                exporter.export_json(entries, Path(path))
            else:
                exporter.export_bitwarden_json(entries, Path(path))

            QMessageBox.information(
                self, "Export Complete",
                f"Exported {len(entries)} entries to:\n{path}\n\n"
                "⚠️ Delete this file securely when no longer needed!"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))
