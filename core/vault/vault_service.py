"""
Vault service — high-level vault operations.

Orchestrates: KeyManager, DatabaseManager, VaultRepository, AuthManager.
This is the primary entry point for all vault operations.
"""
from __future__ import annotations

import json
from pathlib import Path

from config.settings import (
    VAULT_DB_PATH,
)
from core.authentication.auth_manager import AuthManager
from core.crypto.key_manager import KeyManager, VaultKeyMaterial
from core.database.database_manager import DatabaseManager
from core.database.db_models import DbAppSettings, DbVaultMetadata
from core.models.vault_models import (
    AppSettings,
    Category,
    SecurityAuditResult,
    VaultEntry,
    VaultMetadata,
)
from core.utilities.exceptions import (
    AuthenticationError,
    ValidationError,
    VaultAlreadyExistsError,
    VaultLockedError,
    VaultNotFoundError,
)
from core.utilities.logging_utils import get_logger, security_logger
from core.vault.vault_repository import VaultRepository

logger = get_logger(__name__)


class VaultService:
    """
    Main service for all vault operations.

    Usage:
        svc = VaultService()
        svc.create_vault("my-strong-password!")
        svc.unlock("my-strong-password!")
        entry = svc.add_entry(VaultEntry(title="Gmail", username="me@gmail.com", ...))
        svc.lock()
    """

    def __init__(
        self,
        db_path: Path = VAULT_DB_PATH,
    ) -> None:
        self._db_path = db_path
        self._db = DatabaseManager(db_path)
        self._km = KeyManager()
        self._repo = VaultRepository(self._km)
        self._auth = AuthManager()
        self._settings: AppSettings = AppSettings()
        self._initialized = False

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Initialize the database (create tables, run migrations)."""
        self._db.initialize()
        self._load_settings()
        self._initialized = True

    # ------------------------------------------------------------------
    # Vault creation
    # ------------------------------------------------------------------

    def create_vault(self, master_password: str) -> VaultMetadata:
        """
        Create a new vault with the given master password.

        Raises:
            VaultAlreadyExistsError: If a vault already exists.
            ValidationError: If master password is too weak.
        """
        self._ensure_initialized()

        with self._db.session() as session:
            existing = session.query(DbVaultMetadata).first()
            if existing is not None:
                raise VaultAlreadyExistsError(
                    "A vault already exists. Delete or restore instead of creating a new one."
                )

        if len(master_password) < 8:
            raise ValidationError("Master password must be at least 8 characters.")

        # Generate key material
        key_material = self._km.create_new_vault(master_password)

        metadata = VaultMetadata()
        with self._db.session() as session:
            session.add(DbVaultMetadata(
                id=1,
                vault_id=metadata.vault_id,
                format_version=metadata.format_version,
                app_version=metadata.app_version,
                created_at=metadata.created_at,
                modified_at=metadata.modified_at,
                entry_count=0,
                key_material_json=json.dumps(key_material.to_dict()),
            ))
            session.commit()

        logger.info("Vault created successfully.")
        return metadata

    # ------------------------------------------------------------------
    # Unlock / Lock
    # ------------------------------------------------------------------

    def unlock(self, master_password: str) -> None:
        """
        Unlock the vault.

        Raises:
            AuthenticationError: Wrong password or account locked out.
            VaultNotFoundError: No vault exists.
        """
        self._ensure_initialized()

        # Check lockout
        self._auth.check_lockout()

        key_material = self._load_key_material()

        try:
            self._km.unlock(master_password, key_material)
        except Exception:
            self._auth.record_failed_attempt()
            raise AuthenticationError("Incorrect master password.")

        self._auth.reset_attempts()
        self._load_settings()
        security_logger.vault_unlocked()
        logger.info("Vault unlocked.")

    def lock(self, reason: str = "manual") -> None:
        """Lock the vault and clear sensitive memory."""
        self._km.lock()
        security_logger.vault_locked(reason)

    @property
    def is_locked(self) -> bool:
        return self._km.is_locked

    # ------------------------------------------------------------------
    # Entry operations
    # ------------------------------------------------------------------

    def add_entry(self, entry: VaultEntry) -> VaultEntry:
        self._require_unlocked()
        with self._db.session() as session:
            result = self._repo.create_entry(session, entry)
            session.commit()
            self._update_entry_count(session)
        return result

    def get_entry(self, entry_id: str) -> VaultEntry | None:
        self._require_unlocked()
        with self._db.session() as session:
            return self._repo.get_entry(session, entry_id)

    def update_entry(self, entry: VaultEntry) -> VaultEntry:
        self._require_unlocked()
        max_hist = self._settings.password_history_size
        with self._db.session() as session:
            result = self._repo.update_entry(session, entry, max_history=max_hist)
            session.commit()
        return result

    def delete_entry(self, entry_id: str) -> None:
        self._require_unlocked()
        with self._db.session() as session:
            self._repo.delete_entry(session, entry_id)
            session.commit()
            self._update_entry_count(session)

    def list_entries(
        self,
        *,
        search: str = "",
        category_id: str | None = None,
        tag: str | None = None,
        favorites_only: bool = False,
        item_type: str | None = None,
        sort_by: str = "title",
        descending: bool = False,
    ) -> list[VaultEntry]:
        self._require_unlocked()
        with self._db.session() as session:
            return self._repo.list_entries(
                session,
                search=search,
                category_id=category_id,
                tag=tag,
                favorites_only=favorites_only,
                item_type=item_type,
                sort_by=sort_by,
                descending=descending,
            )

    def get_password_history(self, entry_id: str):  # type: ignore[return]
        self._require_unlocked()
        with self._db.session() as session:
            return self._repo.get_password_history(session, entry_id)

    # ------------------------------------------------------------------
    # Categories
    # ------------------------------------------------------------------

    def get_categories(self) -> list[Category]:
        self._require_unlocked()
        with self._db.session() as session:
            return self._repo.get_categories(session)

    def create_category(self, category: Category) -> Category:
        self._require_unlocked()
        with self._db.session() as session:
            result = self._repo.create_category(session, category)
            session.commit()
        return result

    def update_category(self, category: Category) -> Category:
        self._require_unlocked()
        with self._db.session() as session:
            result = self._repo.update_category(session, category)
            session.commit()
        return result

    def delete_category(self, category_id: str) -> None:
        self._require_unlocked()
        with self._db.session() as session:
            self._repo.delete_category(session, category_id)
            session.commit()

    # ------------------------------------------------------------------
    # Master password change
    # ------------------------------------------------------------------

    def change_master_password(
        self, current_password: str, new_password: str
    ) -> None:
        self._require_unlocked()
        # Re-authenticate before allowing password change
        key_material = self._load_key_material()
        try:
            test_km = KeyManager()
            test_km.unlock(current_password, key_material)
            test_km.lock()
        except Exception:
            raise AuthenticationError("Current master password is incorrect.")

        if len(new_password) < 8:
            raise ValidationError("New master password must be at least 8 characters.")

        new_key_material = self._km.change_master_password(new_password)
        self._save_key_material(new_key_material)
        security_logger.master_password_changed()
        logger.info("Master password changed successfully.")

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def get_settings(self) -> AppSettings:
        return self._settings

    def save_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        with self._db.session() as session:
            row = session.query(DbAppSettings).first()
            if row is None:
                session.add(DbAppSettings(id=1, settings_json=settings.model_dump_json()))
            else:
                row.settings_json = settings.model_dump_json()
            session.commit()

    # ------------------------------------------------------------------
    # Security audit
    # ------------------------------------------------------------------

    def run_security_audit(self) -> SecurityAuditResult:
        """Analyze vault entries for security weaknesses."""
        from core.security.audit import SecurityAuditor
        self._require_unlocked()
        entries = self.list_entries()
        auditor = SecurityAuditor()
        return auditor.audit(entries)

    # ------------------------------------------------------------------
    # Vault info
    # ------------------------------------------------------------------

    def get_vault_metadata(self) -> VaultMetadata | None:
        self._ensure_initialized()
        with self._db.session() as session:
            row = session.query(DbVaultMetadata).first()
            if row is None:
                return None
            return VaultMetadata(
                vault_id=row.vault_id,
                format_version=row.format_version,
                app_version=row.app_version,
                created_at=row.created_at,
                modified_at=row.modified_at,
                entry_count=row.entry_count,
            )

    def vault_exists(self) -> bool:
        self._ensure_initialized()
        with self._db.session() as session:
            return session.query(DbVaultMetadata).first() is not None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()

    def _require_unlocked(self) -> None:
        self._ensure_initialized()
        if self._km.is_locked:
            raise VaultLockedError("Vault is locked. Please unlock first.")

    def _load_key_material(self) -> VaultKeyMaterial:
        with self._db.session() as session:
            row = session.query(DbVaultMetadata).first()
            if row is None:
                raise VaultNotFoundError("No vault found. Create a vault first.")
            km_dict = json.loads(row.key_material_json)
            return VaultKeyMaterial.from_dict(km_dict)

    def _save_key_material(self, key_material: VaultKeyMaterial) -> None:
        with self._db.session() as session:
            row = session.query(DbVaultMetadata).first()
            if row is None:
                raise VaultNotFoundError("Vault metadata not found.")
            row.key_material_json = json.dumps(key_material.to_dict())
            session.commit()

    def _load_settings(self) -> None:
        try:
            with self._db.session() as session:
                row = session.query(DbAppSettings).first()
                if row and row.settings_json:
                    self._settings = AppSettings.model_validate_json(row.settings_json)
        except Exception:
            self._settings = AppSettings()

    def _update_entry_count(self, session) -> None:  # type: ignore[type-arg]
        from sqlalchemy import func

        from core.database.db_models import DbVaultEntry
        count = session.query(func.count(DbVaultEntry.id)).scalar() or 0
        row = session.query(DbVaultMetadata).first()
        if row:
            row.entry_count = count
