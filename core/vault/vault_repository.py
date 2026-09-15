"""
Vault repository — encrypted CRUD operations on vault entries.

All sensitive fields are encrypted before writing to the database and
decrypted only when explicitly requested (vault must be unlocked).

Provides:
- create_entry
- get_entry
- update_entry
- delete_entry
- list_entries (with filtering, sorting, search)
- get_categories
- password history management
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from core.crypto.encryption import decrypt_text, encrypt_text
from core.crypto.key_manager import KeyManager
from core.database.db_models import (
    DbCategory,
    DbPasswordHistory,
    DbVaultEntry,
)
from core.models.vault_models import (
    Category,
    CustomField,
    PasswordHistoryEntry,
    VaultEntry,
)
from core.utilities.exceptions import ValidationError
from core.utilities.logging_utils import get_logger, security_logger

logger = get_logger(__name__)


class VaultRepository:
    """
    Data-access layer for vault entries.
    All encryption/decryption is performed here using the KeyManager's DEK.
    """

    def __init__(self, key_manager: KeyManager) -> None:
        self._km = key_manager

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dek(self) -> bytes:
        return self._km.get_dek()   # Raises VaultLockedError if locked

    def _enc(self, plaintext: str, entry_id: str, field: str) -> bytes:
        """Encrypt a string field with entry-specific associated data."""
        aad = f"{entry_id}:{field}".encode()
        return encrypt_text(plaintext, self._dek(), aad)

    def _dec(self, blob: bytes | None, entry_id: str, field: str) -> str:
        """Decrypt a bytes blob; returns empty string if blob is None."""
        if not blob:
            return ""
        aad = f"{entry_id}:{field}".encode()
        return decrypt_text(blob, self._dek(), aad)

    # ------------------------------------------------------------------
    # Entry creation
    # ------------------------------------------------------------------

    def create_entry(self, session: Session, entry: VaultEntry) -> VaultEntry:
        """
        Persist a new vault entry with all sensitive fields encrypted.
        """
        dek = self._dek()

        db_entry = DbVaultEntry(
            id=entry.id,
            item_type=entry.item_type.value,
            title=entry.title,
            url=entry.url or None,
            is_favorite=entry.is_favorite,
            category_id=entry.category_id,
            tags=json.dumps(entry.tags),
            created_at=entry.created_at,
            modified_at=entry.modified_at,
            last_used_at=entry.last_used_at,
            card_holder=entry.card_holder or None,
            card_expiry=entry.card_expiry or None,
            wifi_ssid=entry.wifi_ssid or None,
            wifi_security=entry.wifi_security or None,
            identity_first_name=entry.identity_first_name or None,
            identity_last_name=entry.identity_last_name or None,
            identity_email=entry.identity_email or None,
            identity_phone=entry.identity_phone or None,
            identity_address=entry.identity_address or None,
        )

        eid = entry.id
        if entry.username:
            db_entry.username_enc = self._enc(entry.username, eid, "username")
        if entry.password:
            db_entry.password_enc = self._enc(entry.password, eid, "password")
        if entry.notes:
            db_entry.notes_enc = self._enc(entry.notes, eid, "notes")
        if entry.totp_secret:
            db_entry.totp_secret_enc = self._enc(entry.totp_secret, eid, "totp_secret")
        if entry.card_number:
            db_entry.card_number_enc = self._enc(entry.card_number, eid, "card_number")
        if entry.card_cvv:
            db_entry.card_cvv_enc = self._enc(entry.card_cvv, eid, "card_cvv")
        if entry.wifi_password:
            db_entry.wifi_password_enc = self._enc(entry.wifi_password, eid, "wifi_password")
        if entry.custom_fields:
            cf_json = json.dumps([cf.model_dump() for cf in entry.custom_fields])
            db_entry.custom_fields_enc = self._enc(cf_json, eid, "custom_fields")

        session.add(db_entry)

        # Save initial password history
        for hist in entry.password_history:
            self._add_history_row(session, entry.id, hist.password, hist.changed_at)

        session.flush()
        security_logger.entry_created(entry.id)
        logger.debug("Entry created: %s", entry.id)
        return entry

    # ------------------------------------------------------------------
    # Entry retrieval
    # ------------------------------------------------------------------

    def get_entry(self, session: Session, entry_id: str) -> VaultEntry | None:
        """
        Retrieve and decrypt a single vault entry.
        Returns None if not found.
        """
        db_entry = session.get(DbVaultEntry, entry_id)
        if db_entry is None:
            return None
        return self._db_to_model(db_entry)

    def list_entries(
        self,
        session: Session,
        *,
        search: str = "",
        category_id: str | None = None,
        tag: str | None = None,
        favorites_only: bool = False,
        item_type: str | None = None,
        sort_by: str = "title",
        descending: bool = False,
    ) -> list[VaultEntry]:
        """
        List and decrypt vault entries with optional filtering.

        Note: search is performed on title and URL (non-sensitive fields).
        After loading, caller may further filter on decrypted fields if needed.
        """
        query = session.query(DbVaultEntry)

        if search:
            pattern = f"%{search}%"
            query = query.filter(
                DbVaultEntry.title.ilike(pattern)
            )
        if category_id:
            query = query.filter(DbVaultEntry.category_id == category_id)
        if favorites_only:
            query = query.filter(DbVaultEntry.is_favorite == True)  # noqa: E712
        if item_type:
            query = query.filter(DbVaultEntry.item_type == item_type)
        if tag:
            query = query.filter(DbVaultEntry.tags.contains(f'"{tag}"'))

        # Sorting
        sort_col_map = {
            "title": DbVaultEntry.title,
            "modified_at": DbVaultEntry.modified_at,
            "created_at": DbVaultEntry.created_at,
            "last_used_at": DbVaultEntry.last_used_at,
        }
        sort_col = sort_col_map.get(sort_by, DbVaultEntry.title)
        if descending:
            query = query.order_by(sort_col.desc())
        else:
            query = query.order_by(sort_col.asc())

        db_entries = query.all()
        return [self._db_to_model(e) for e in db_entries]

    # ------------------------------------------------------------------
    # Entry update
    # ------------------------------------------------------------------

    def update_entry(
        self, session: Session, entry: VaultEntry, max_history: int = 10
    ) -> VaultEntry:
        """
        Update an existing vault entry.
        Preserves password history if password changed.
        """
        db_entry = session.get(DbVaultEntry, entry.id)
        if db_entry is None:
            raise ValidationError(f"Entry {entry.id} not found.")

        # Check if password changed — if so, archive old one
        old_password = self._dec(db_entry.password_enc, entry.id, "password")
        if old_password and old_password != entry.password:
            self._add_history_row(session, entry.id, old_password, datetime.now(UTC))
            # Trim history
            self._trim_history(session, entry.id, max_history)

        # Update non-sensitive fields
        db_entry.title = entry.title
        db_entry.url = entry.url or None
        db_entry.is_favorite = entry.is_favorite
        db_entry.category_id = entry.category_id
        db_entry.tags = json.dumps(entry.tags)
        db_entry.modified_at = datetime.now(UTC)
        db_entry.last_used_at = entry.last_used_at
        db_entry.card_holder = entry.card_holder or None
        db_entry.card_expiry = entry.card_expiry or None
        db_entry.wifi_ssid = entry.wifi_ssid or None
        db_entry.wifi_security = entry.wifi_security or None
        db_entry.identity_first_name = entry.identity_first_name or None
        db_entry.identity_last_name = entry.identity_last_name or None
        db_entry.identity_email = entry.identity_email or None
        db_entry.identity_phone = entry.identity_phone or None
        db_entry.identity_address = entry.identity_address or None

        eid = entry.id
        db_entry.username_enc = self._enc(entry.username, eid, "username") if entry.username else None
        db_entry.password_enc = self._enc(entry.password, eid, "password") if entry.password else None
        db_entry.notes_enc = self._enc(entry.notes, eid, "notes") if entry.notes else None
        db_entry.totp_secret_enc = self._enc(entry.totp_secret, eid, "totp_secret") if entry.totp_secret else None
        db_entry.card_number_enc = self._enc(entry.card_number, eid, "card_number") if entry.card_number else None
        db_entry.card_cvv_enc = self._enc(entry.card_cvv, eid, "card_cvv") if entry.card_cvv else None
        db_entry.wifi_password_enc = self._enc(entry.wifi_password, eid, "wifi_password") if entry.wifi_password else None

        if entry.custom_fields:
            cf_json = json.dumps([cf.model_dump() for cf in entry.custom_fields])
            db_entry.custom_fields_enc = self._enc(cf_json, eid, "custom_fields")
        else:
            db_entry.custom_fields_enc = None

        session.flush()
        security_logger.entry_updated(entry.id)
        return entry

    # ------------------------------------------------------------------
    # Entry deletion
    # ------------------------------------------------------------------

    def delete_entry(self, session: Session, entry_id: str) -> None:
        """Delete a vault entry and its history (cascade)."""
        db_entry = session.get(DbVaultEntry, entry_id)
        if db_entry is None:
            raise ValidationError(f"Entry {entry_id} not found.")
        session.delete(db_entry)
        session.flush()
        security_logger.entry_deleted(entry_id)

    # ------------------------------------------------------------------
    # Password history
    # ------------------------------------------------------------------

    def get_password_history(
        self, session: Session, entry_id: str
    ) -> list[PasswordHistoryEntry]:
        """Return decrypted password history for an entry."""
        rows = (
            session.query(DbPasswordHistory)
            .filter(DbPasswordHistory.entry_id == entry_id)
            .order_by(DbPasswordHistory.changed_at.desc())
            .all()
        )
        result = []
        for row in rows:
            try:
                pw = self._dec(row.password_enc, entry_id, "history_password")
                result.append(PasswordHistoryEntry(password=pw, changed_at=row.changed_at))
            except Exception:
                # Skip corrupted history entries
                pass
        return result

    def _add_history_row(
        self, session: Session, entry_id: str, password: str, changed_at: datetime
    ) -> None:
        if not password:
            return
        pw_enc = self._enc(password, entry_id, "history_password")
        session.add(DbPasswordHistory(
            entry_id=entry_id,
            password_enc=pw_enc,
            changed_at=changed_at,
        ))

    def _trim_history(
        self, session: Session, entry_id: str, max_history: int
    ) -> None:
        rows = (
            session.query(DbPasswordHistory)
            .filter(DbPasswordHistory.entry_id == entry_id)
            .order_by(DbPasswordHistory.changed_at.desc())
            .all()
        )
        to_delete = rows[max_history:]
        for row in to_delete:
            session.delete(row)

    # ------------------------------------------------------------------
    # Categories
    # ------------------------------------------------------------------

    def get_categories(self, session: Session) -> list[Category]:
        rows = session.query(DbCategory).order_by(DbCategory.name).all()
        return [
            Category(id=r.id, name=r.name, icon=r.icon, color=r.color)
            for r in rows
        ]

    def create_category(self, session: Session, category: Category) -> Category:
        session.add(DbCategory(
            id=category.id,
            name=category.name,
            icon=category.icon,
            color=category.color,
        ))
        session.flush()
        return category

    def update_category(self, session: Session, category: Category) -> Category:
        db_cat = session.get(DbCategory, category.id)
        if db_cat is None:
            raise ValidationError(f"Category {category.id} not found.")
        db_cat.name = category.name
        db_cat.icon = category.icon
        db_cat.color = category.color
        session.flush()
        return category

    def delete_category(self, session: Session, category_id: str) -> None:
        db_cat = session.get(DbCategory, category_id)
        if db_cat is None:
            raise ValidationError(f"Category {category_id} not found.")
        session.delete(db_cat)
        session.flush()

    # ------------------------------------------------------------------
    # Model conversion
    # ------------------------------------------------------------------

    def _db_to_model(self, db: DbVaultEntry) -> VaultEntry:
        """Convert a DB row to a decrypted VaultEntry model."""
        eid = db.id

        # Decrypt custom fields
        custom_fields: list[CustomField] = []
        if db.custom_fields_enc:
            try:
                cf_list = json.loads(self._dec(db.custom_fields_enc, eid, "custom_fields"))
                custom_fields = [CustomField(**cf) for cf in cf_list]
            except Exception:
                pass

        from core.models.vault_models import ItemType
        return VaultEntry(
            id=eid,
            item_type=ItemType(db.item_type),
            title=db.title,
            username=self._dec(db.username_enc, eid, "username"),
            password=self._dec(db.password_enc, eid, "password"),
            url=db.url or "",
            notes=self._dec(db.notes_enc, eid, "notes"),
            totp_secret=self._dec(db.totp_secret_enc, eid, "totp_secret"),
            category_id=db.category_id,
            tags=json.loads(db.tags) if db.tags else [],
            is_favorite=db.is_favorite,
            created_at=db.created_at,
            modified_at=db.modified_at,
            last_used_at=db.last_used_at,
            custom_fields=custom_fields,
            card_number=self._dec(db.card_number_enc, eid, "card_number"),
            card_holder=db.card_holder or "",
            card_expiry=db.card_expiry or "",
            card_cvv=self._dec(db.card_cvv_enc, eid, "card_cvv"),
            wifi_ssid=db.wifi_ssid or "",
            wifi_password=self._dec(db.wifi_password_enc, eid, "wifi_password"),
            wifi_security=db.wifi_security or "",
            identity_first_name=db.identity_first_name or "",
            identity_last_name=db.identity_last_name or "",
            identity_email=db.identity_email or "",
            identity_phone=db.identity_phone or "",
            identity_address=db.identity_address or "",
        )
