"""
Integration tests — backup/restore, import/export.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.backup.backup_manager import BackupManager
from core.import_export.importer_exporter import VaultExporter, VaultImporter
from core.models.vault_models import VaultEntry
from core.vault.vault_service import VaultService


@pytest.fixture
def svc(tmp_path):
    db = tmp_path / "test.db"
    s = VaultService(db_path=db)
    s.initialize()
    s.create_vault("TestPw123!")
    s.unlock("TestPw123!")
    return s


class TestBackupRestore:
    def test_backup_and_restore_roundtrip(self, svc, tmp_path):
        svc.add_entry(VaultEntry(title="Backup Entry", password="backup-password"))
        svc.add_entry(VaultEntry(title="Another Entry", password="another-pass"))

        bm = BackupManager(svc._db, tmp_path)
        backup_path = bm.create_backup("backup-pw-123", tmp_path / "test.svbak")
        assert backup_path.exists()

        # Restore
        preview = bm.restore_backup(backup_path, "backup-pw-123")
        assert preview["entry_count"] == 2

    def test_backup_encrypted(self, svc, tmp_path):
        """Verify backup file does not contain plaintext passwords."""
        secret = "BACKUP_SECRET_PASSWORD_UNIQUE_XYZ"
        svc.add_entry(VaultEntry(title="BU Test", password=secret))

        bm = BackupManager(svc._db, tmp_path)
        backup_path = bm.create_backup("backup-password", tmp_path / "encrypted.svbak")

        content = backup_path.read_text()
        assert secret not in content, "Plaintext password found in backup file!"

    def test_list_backups(self, svc, tmp_path):
        bm = BackupManager(svc._db, tmp_path)
        bm.create_backup("pw1", tmp_path / "b1.svbak")
        bm.create_backup("pw2", tmp_path / "b2.svbak")
        backups = bm.list_backups()
        assert len(backups) >= 2


class TestImportExport:
    def test_csv_import_roundtrip(self, svc, tmp_path):
        csv_file = tmp_path / "import.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["Title", "Username", "Password", "URL", "Notes"])
            writer.writeheader()
            writer.writerow({"Title": "Gmail", "Username": "user@gmail.com",
                             "Password": "gmailpass", "URL": "https://gmail.com", "Notes": ""})
            writer.writerow({"Title": "GitHub", "Username": "developer",
                             "Password": "githubpass", "URL": "https://github.com", "Notes": "Dev"})

        importer = VaultImporter()
        entries = importer.import_csv(csv_file)
        assert len(entries) == 2
        titles = [e.title for e in entries]
        assert "Gmail" in titles
        assert "GitHub" in titles

    def test_json_import(self, svc, tmp_path):
        json_file = tmp_path / "import.json"
        data = [
            {"title": "JSON Entry 1", "username": "user1", "password": "pass1", "url": "https://site1.com"},
            {"title": "JSON Entry 2", "username": "user2", "password": "pass2"},
        ]
        json_file.write_text(json.dumps(data))

        importer = VaultImporter()
        entries = importer.import_json(json_file)
        assert len(entries) == 2

    def test_bitwarden_import(self, svc, tmp_path):
        bw_file = tmp_path / "bw.json"
        bw_data = {
            "items": [
                {
                    "type": 1,
                    "name": "BW Entry",
                    "login": {"username": "bwuser", "password": "bwpass",
                              "uris": [{"uri": "https://bw.example.com"}]},
                    "notes": "Bitwarden note",
                    "favorite": True,
                }
            ]
        }
        bw_file.write_text(json.dumps(bw_data))
        importer = VaultImporter()
        entries = importer.import_bitwarden_json(bw_file)
        assert len(entries) == 1
        assert entries[0].title == "BW Entry"
        assert entries[0].is_favorite is True

    def test_csv_export_contains_all_entries(self, svc, tmp_path):
        svc.add_entry(VaultEntry(title="Export A", username="userA", password="passA"))
        svc.add_entry(VaultEntry(title="Export B", username="userB", password="passB"))

        entries = svc.list_entries()
        exporter = VaultExporter()
        out_path = tmp_path / "export.csv"
        exporter.export_csv(entries, out_path)

        assert out_path.exists()
        with open(out_path) as f:
            content = f.read()
        assert "Export A" in content
        assert "Export B" in content

    def test_json_export_contains_all_entries(self, svc, tmp_path):
        svc.add_entry(VaultEntry(title="JsonExport A", password="passA"))
        entries = svc.list_entries()
        exporter = VaultExporter()
        out_path = tmp_path / "export.json"
        exporter.export_json(entries, out_path)

        data = json.loads(out_path.read_text())
        assert data["entry_count"] >= 1
        titles = [e["title"] for e in data["entries"]]
        assert "JsonExport A" in titles

    def test_secure_delete(self, tmp_path):
        f = tmp_path / "sensitive.csv"
        f.write_text("sensitive data\n")
        assert f.exists()
        VaultExporter.secure_delete(f)
        assert not f.exists()
