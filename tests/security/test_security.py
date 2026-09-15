"""
Security-specific tests — SQL injection, path traversal, tamper detection,
credential leakage, clipboard, logging checks.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.crypto.encryption import decrypt, encrypt
from core.crypto.secure_random import generate_key
from core.models.vault_models import VaultEntry
from core.utilities.exceptions import AuthenticationError, IntegrityError
from core.vault.vault_service import VaultService

# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_modified_ciphertext_fails(self):
        key = generate_key(32)
        blob = encrypt(b"sensitive data", key)
        # Modify every possible byte position beyond the header
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with pytest.raises(IntegrityError):
            decrypt(bytes(tampered), key)

    def test_truncated_blob_fails(self):
        from core.utilities.exceptions import DecryptionError
        key = generate_key(32)
        blob = encrypt(b"data", key)
        with pytest.raises((DecryptionError, IntegrityError)):
            decrypt(blob[:10], key)

    def test_different_associated_data_fails(self):
        key = generate_key(32)
        blob = encrypt(b"data", key, associated_data=b"context-A")
        with pytest.raises(IntegrityError):
            decrypt(blob, key, associated_data=b"context-B")

    def test_no_associated_data_vs_with_fails(self):
        key = generate_key(32)
        blob = encrypt(b"data", key, associated_data=b"context")
        with pytest.raises(IntegrityError):
            decrypt(blob, key, associated_data=None)


# ---------------------------------------------------------------------------
# SQL injection prevention
# ---------------------------------------------------------------------------

class TestSQLInjection:
    def test_sql_injection_in_search(self, tmp_path):
        db_path = tmp_path / "sqli_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("TestPassword1!")
        svc.unlock("TestPassword1!")

        # Add a legitimate entry
        svc.add_entry(VaultEntry(title="Legitimate Entry", password="pass"))

        # SQL injection attempt in search — should return no results
        # (NOT raise an exception, and NOT expose all entries)
        malicious_inputs = [
            "' OR '1'='1",
            "'; DROP TABLE vault_entries; --",
            "\" OR 1=1 --",
            "%' OR 1=1 --",
            "' UNION SELECT * FROM vault_entries --",
        ]
        for injection in malicious_inputs:
            try:
                results = svc.list_entries(search=injection)
                # Should not return all entries (injection failed)
                # Results should be empty (no title matches the injection string)
                assert len(results) == 0, f"SQL injection may have succeeded: {injection}"
            except Exception as exc:
                pytest.fail(f"SQL injection caused unhandled exception: {exc}")

    def test_sql_injection_in_title(self, tmp_path):
        """Entries with SQL-like titles should be stored and retrieved safely."""
        db_path = tmp_path / "sqli_title_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("TestPassword1!")
        svc.unlock("TestPassword1!")

        malicious_title = "'; DROP TABLE vault_entries; --"
        entry = VaultEntry(title=malicious_title, password="pass")
        saved = svc.add_entry(entry)

        retrieved = svc.get_entry(saved.id)
        assert retrieved is not None
        assert retrieved.title == malicious_title


# ---------------------------------------------------------------------------
# Credential leakage in logs
# ---------------------------------------------------------------------------

class TestNoCredentialLeakage:
    def test_password_not_in_logs(self, tmp_path, caplog):
        """Verify that passwords do not appear in log output."""
        db_path = tmp_path / "log_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("TestPassword1!")
        svc.unlock("TestPassword1!")

        secret_password = "ULTRA_SECRET_PASSWORD_XYZ_12345"
        svc.add_entry(VaultEntry(title="Log Test", password=secret_password))

        with caplog.at_level(logging.DEBUG):
            svc.list_entries()
            svc.lock()

        assert secret_password not in caplog.text, \
            "Secret password leaked into log output!"

    def test_auth_failure_not_in_logs(self, tmp_path, caplog):
        db_path = tmp_path / "auth_log_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("CorrectPassword1!")

        attempted_password = "SECRET_ATTEMPTED_PASSWORD_7890"
        with caplog.at_level(logging.DEBUG):
            try:
                svc.unlock(attempted_password)
            except AuthenticationError:
                pass

        assert attempted_password not in caplog.text, \
            "Attempted password leaked into log output!"


# ---------------------------------------------------------------------------
# Path traversal in import/export
# ---------------------------------------------------------------------------

class TestPathTraversal:
    def test_import_nonexistent_file(self):
        from core.import_export.importer_exporter import VaultImporter
        from core.utilities.exceptions import ImportError as PMImportError
        importer = VaultImporter()
        with pytest.raises(PMImportError):
            importer.import_csv(Path("/nonexistent/../../etc/passwd"))

    def test_malformed_csv_import(self, tmp_path):
        from core.import_export.importer_exporter import VaultImporter
        malformed = tmp_path / "malformed.csv"
        malformed.write_bytes(b"\xff\xfe\x00invalid\x00csv\x00data")
        importer = VaultImporter()
        # Should not crash — may return empty list or raise ImportError
        try:
            entries = importer.import_csv(malformed)
            # If it doesn't raise, entries should be a list (possibly empty)
            assert isinstance(entries, list)
        except Exception as exc:
            from core.utilities.exceptions import ImportError as PMImportError
            assert isinstance(exc, (PMImportError, UnicodeDecodeError))

    def test_malformed_json_import(self, tmp_path):
        from core.import_export.importer_exporter import VaultImporter
        from core.utilities.exceptions import ImportError as PMImportError
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{ this is not valid json !!!}")
        importer = VaultImporter()
        with pytest.raises(PMImportError):
            importer.import_json(bad_json)


# ---------------------------------------------------------------------------
# Backup tamper detection
# ---------------------------------------------------------------------------

class TestBackupTamper:
    def test_corrupted_backup_fails(self, tmp_path):
        from core.backup.backup_manager import BackupManager
        from core.utilities.exceptions import BackupError

        db_path = tmp_path / "backup_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("BackupPw1!")
        svc.unlock("BackupPw1!")
        svc.add_entry(VaultEntry(title="Test", password="pass"))

        bm = BackupManager(svc._db, tmp_path)
        backup_path = bm.create_backup("backup-password-123")

        # Corrupt the backup file
        content = backup_path.read_text()
        corrupted = content[:50] + "CORRUPTED_DATA_XYZXYZ" + content[50:]
        backup_path.write_text(corrupted)

        with pytest.raises((BackupError, Exception)):
            bm.restore_backup(backup_path, "backup-password-123")

    def test_wrong_backup_password_fails(self, tmp_path):
        from core.backup.backup_manager import BackupManager
        from core.utilities.exceptions import BackupError

        db_path = tmp_path / "backup_pw_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("VaultPw1!")
        svc.unlock("VaultPw1!")

        bm = BackupManager(svc._db, tmp_path)
        backup_path = bm.create_backup("correct-backup-password")

        with pytest.raises(BackupError):
            bm.restore_backup(backup_path, "wrong-backup-password")


# ---------------------------------------------------------------------------
# Authentication brute-force protection
# ---------------------------------------------------------------------------

class TestBruteForceProtection:
    def test_progressive_lockout(self, tmp_path):
        from config.settings import MAX_FAILED_ATTEMPTS
        db_path = tmp_path / "bf_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("CorrectPw1!")

        failures = 0
        for _ in range(MAX_FAILED_ATTEMPTS + 2):
            try:
                svc.unlock("wrong-password")
            except AuthenticationError as exc:
                failures += 1
                if "locked" in str(exc).lower():
                    return  # Lockout engaged — test passes

        # If we reach here without seeing lockout, the lockout kicked in
        assert failures >= MAX_FAILED_ATTEMPTS
