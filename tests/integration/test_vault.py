"""
Integration tests — vault CRUD, auth, search, history.
Uses an in-memory SQLite database.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models.vault_models import Category, VaultEntry
from core.utilities.exceptions import (
    AuthenticationError,
    VaultAlreadyExistsError,
    VaultLockedError,
)
from core.vault.vault_service import VaultService


@pytest.fixture
def vault_service(tmp_path):
    """Create a fresh VaultService backed by a temp database."""
    db_path = tmp_path / "test_vault.db"
    svc = VaultService(db_path=db_path)
    svc.initialize()
    return svc


@pytest.fixture
def unlocked_vault(vault_service):
    """Create and unlock a test vault."""
    vault_service.create_vault("TestMasterPassword123!")
    vault_service.unlock("TestMasterPassword123!")
    return vault_service


class TestVaultCreation:
    def test_create_vault(self, vault_service):
        meta = vault_service.create_vault("StrongPassword1!")
        assert meta is not None
        assert meta.vault_id

    def test_vault_exists_after_creation(self, vault_service):
        vault_service.create_vault("StrongPassword1!")
        assert vault_service.vault_exists()

    def test_duplicate_create_raises(self, vault_service):
        vault_service.create_vault("Password1!")
        with pytest.raises(VaultAlreadyExistsError):
            vault_service.create_vault("Password2!")

    def test_weak_password_raises(self, vault_service):
        from core.utilities.exceptions import ValidationError
        with pytest.raises(ValidationError):
            vault_service.create_vault("short")


class TestAuthentication:
    def test_correct_password_unlocks(self, vault_service):
        vault_service.create_vault("CorrectPassword1!")
        vault_service.unlock("CorrectPassword1!")
        assert not vault_service.is_locked

    def test_wrong_password_raises(self, vault_service):
        vault_service.create_vault("CorrectPassword1!")
        with pytest.raises(AuthenticationError):
            vault_service.unlock("WrongPassword!")

    def test_lock_relocks_vault(self, unlocked_vault):
        unlocked_vault.lock()
        assert unlocked_vault.is_locked

    def test_operations_require_unlock(self, vault_service):
        vault_service.create_vault("Password1!")
        # Vault is locked after creation (create_vault unlocks internally through KeyManager)
        vault_service.lock()
        with pytest.raises(VaultLockedError):
            vault_service.list_entries()

    def test_lockout_after_max_attempts(self, vault_service):
        from config.settings import MAX_FAILED_ATTEMPTS
        vault_service.create_vault("CorrectPassword1!")
        for _ in range(MAX_FAILED_ATTEMPTS):
            try:
                vault_service.unlock("WrongPassword!")
            except AuthenticationError:
                pass
        # Next attempt should be locked out
        with pytest.raises(AuthenticationError) as exc_info:
            vault_service.unlock("WrongPassword!")
        assert "locked" in str(exc_info.value).lower() or "attempt" in str(exc_info.value).lower()


class TestVaultCRUD:
    def test_add_entry(self, unlocked_vault):
        entry = VaultEntry(title="Test Gmail", username="user@gmail.com", password="secret123")
        saved = unlocked_vault.add_entry(entry)
        assert saved.id
        assert saved.title == "Test Gmail"

    def test_new_entry_form_stays_blank_until_user_types_title(self, unlocked_vault):
        from desktop.views.vault_view import EntryDetailPanel
        from core.security.clipboard_manager import ClipboardManager

        panel = EntryDetailPanel(unlocked_vault, ClipboardManager())
        panel.new_entry()

        assert panel._field_title.text() == ""
        assert panel._is_new is True
        assert panel._save_btn.isVisible() is True

    def test_get_entry(self, unlocked_vault):
        entry = VaultEntry(title="Test Entry", username="user", password="pass")
        saved = unlocked_vault.add_entry(entry)
        retrieved = unlocked_vault.get_entry(saved.id)
        assert retrieved is not None
        assert retrieved.title == "Test Entry"
        assert retrieved.username == "user"
        assert retrieved.password == "pass"

    def test_update_entry(self, unlocked_vault):
        entry = VaultEntry(title="Original Title", password="oldpassword")
        saved = unlocked_vault.add_entry(entry)

        saved.title = "Updated Title"
        saved.password = "newpassword"
        updated = unlocked_vault.update_entry(saved)
        assert updated.title == "Updated Title"

        retrieved = unlocked_vault.get_entry(saved.id)
        assert retrieved.title == "Updated Title"
        assert retrieved.password == "newpassword"

    def test_delete_entry(self, unlocked_vault):
        entry = VaultEntry(title="To Delete", password="pass")
        saved = unlocked_vault.add_entry(entry)
        unlocked_vault.delete_entry(saved.id)
        assert unlocked_vault.get_entry(saved.id) is None

    def test_list_entries_returns_all(self, unlocked_vault):
        for i in range(5):
            unlocked_vault.add_entry(VaultEntry(title=f"Entry {i}", password="pass"))
        entries = unlocked_vault.list_entries()
        assert len(entries) >= 5

    def test_search_by_title(self, unlocked_vault):
        unlocked_vault.add_entry(VaultEntry(title="GitHub Account", password="p"))
        unlocked_vault.add_entry(VaultEntry(title="Google Account", password="p"))
        unlocked_vault.add_entry(VaultEntry(title="Amazon Shopping", password="p"))

        results = unlocked_vault.list_entries(search="github")
        assert len(results) == 1
        assert results[0].title == "GitHub Account"

    def test_filter_by_favorite(self, unlocked_vault):
        unlocked_vault.add_entry(VaultEntry(title="Fav", password="p", is_favorite=True))
        unlocked_vault.add_entry(VaultEntry(title="Not Fav", password="p", is_favorite=False))

        favorites = unlocked_vault.list_entries(favorites_only=True)
        assert all(e.is_favorite for e in favorites)
        assert any(e.title == "Fav" for e in favorites)

    def test_password_is_encrypted_at_rest(self, tmp_path):
        """Verify that the database does not contain plaintext passwords."""
        import sqlite3
        db_path = tmp_path / "security_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("TestMasterPw123!")
        svc.unlock("TestMasterPw123!")

        secret_password = "MY_SUPER_SECRET_PASSWORD_XYZ"
        svc.add_entry(VaultEntry(title="Test", password=secret_password))
        svc.lock()

        # Read raw database and verify plaintext password is NOT present
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT * FROM vault_entries")
        rows = cursor.fetchall()
        conn.close()

        all_data = str(rows)
        assert secret_password not in all_data, \
            "Plaintext password found in database — encryption failed!"

    def test_wrong_key_cannot_decrypt(self, tmp_path):
        """Verify that a different key cannot decrypt vault data."""
        db_path = tmp_path / "key_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("CorrectPassword1!")
        svc.unlock("CorrectPassword1!")
        svc.add_entry(VaultEntry(title="Secret Entry", password="TopSecret!"))
        svc.lock()

        with pytest.raises(AuthenticationError):
            svc.unlock("WrongPassword!")


class TestPasswordHistory:
    def test_history_recorded_on_password_change(self, unlocked_vault):
        entry = VaultEntry(title="Track Me", password="initial-password")
        saved = unlocked_vault.add_entry(entry)

        saved.password = "second-password"
        unlocked_vault.update_entry(saved)

        history = unlocked_vault.get_password_history(saved.id)
        assert len(history) >= 1
        assert history[0].password == "initial-password"

    def test_history_is_encrypted(self, tmp_path):
        """Verify password history is not stored in plaintext."""
        import sqlite3
        db_path = tmp_path / "hist_test.db"
        svc = VaultService(db_path=db_path)
        svc.initialize()
        svc.create_vault("HistPw123!")
        svc.unlock("HistPw123!")

        old_pw = "OLD_HISTORY_PASSWORD_SECRET"
        entry = VaultEntry(title="History Test", password=old_pw)
        saved = svc.add_entry(entry)
        saved.password = "new-password"
        svc.update_entry(saved)
        svc.lock()

        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT * FROM password_history")
        rows = cursor.fetchall()
        conn.close()

        all_data = str(rows)
        assert old_pw not in all_data, "Plaintext password found in history!"


class TestCategories:
    def test_default_categories_exist(self, unlocked_vault):
        cats = unlocked_vault.get_categories()
        cat_names = [c.name for c in cats]
        assert "Personal" in cat_names
        assert "Work" in cat_names

    def test_create_category(self, unlocked_vault):
        cat = Category(name="Custom Category")
        saved = unlocked_vault.create_category(cat)
        assert saved.id

        cats = unlocked_vault.get_categories()
        assert any(c.name == "Custom Category" for c in cats)

    def test_delete_category(self, unlocked_vault):
        cat = unlocked_vault.create_category(Category(name="Temp Cat"))
        unlocked_vault.delete_category(cat.id)
        cats = unlocked_vault.get_categories()
        assert not any(c.id == cat.id for c in cats)


class TestSecurityAudit:
    def test_detects_reused_passwords(self, unlocked_vault):
        for title in ["Site A", "Site B", "Site C"]:
            unlocked_vault.add_entry(VaultEntry(title=title, password="same-password-123"))

        result = unlocked_vault.run_security_audit()
        assert len(result.reused_passwords) >= 1
        assert sum(len(g) for g in result.reused_passwords) >= 3

    def test_detects_weak_passwords(self, unlocked_vault):
        unlocked_vault.add_entry(VaultEntry(title="Weak Site", password="123"))
        result = unlocked_vault.run_security_audit()
        assert len(result.weak_passwords) >= 1

    def test_score_decreases_with_issues(self, unlocked_vault):
        for i in range(5):
            unlocked_vault.add_entry(VaultEntry(title=f"Site {i}", password="weakpw"))
        result = unlocked_vault.run_security_audit()
        assert result.security_score < 100
