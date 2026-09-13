"""
SQLAlchemy ORM models for the vault database.

Schema:
  - vault_metadata   — one row, stores vault header + key material
  - categories       — entry categories
  - vault_entries    — all vault items; sensitive fields stored as encrypted blobs
  - password_history — encrypted previous passwords per entry
  - app_settings     — user settings (non-sensitive)
  - security_log     — audit log (no secrets)

All sensitive columns (password_enc, username_enc, etc.) are BLOB fields
holding AES-256-GCM encrypted data produced by core.crypto.encryption.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    event,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Vault metadata & key material
# ---------------------------------------------------------------------------

class DbVaultMetadata(Base):
    __tablename__ = "vault_metadata"

    id = Column(Integer, primary_key=True, default=1)
    vault_id = Column(String(36), nullable=False, unique=True)
    format_version = Column(Integer, nullable=False, default=1)
    app_version = Column(String(20), nullable=False, default="1.0.0")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    modified_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    entry_count = Column(Integer, nullable=False, default=0)

    # Serialized VaultKeyMaterial JSON (kdf_params + wrapped_dek) — not secret itself
    key_material_json = Column(Text, nullable=False)


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

class DbCategory(Base):
    __tablename__ = "categories"

    id = Column(String(36), primary_key=True)
    name = Column(String(100), nullable=False)
    icon = Column(String(50), nullable=False, default="folder")
    color = Column(String(10), nullable=False, default="#5865F2")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    entries = relationship("DbVaultEntry", back_populates="category", lazy="select")


# ---------------------------------------------------------------------------
# Vault entries
# ---------------------------------------------------------------------------

class DbVaultEntry(Base):
    __tablename__ = "vault_entries"

    id = Column(String(36), primary_key=True)
    item_type = Column(String(30), nullable=False, default="login")
    title = Column(String(255), nullable=False)   # NOT encrypted — used for display/search

    # Encrypted sensitive fields (AES-256-GCM blobs)
    username_enc = Column(LargeBinary, nullable=True)
    password_enc = Column(LargeBinary, nullable=True)
    notes_enc = Column(LargeBinary, nullable=True)
    totp_secret_enc = Column(LargeBinary, nullable=True)
    card_number_enc = Column(LargeBinary, nullable=True)
    card_cvv_enc = Column(LargeBinary, nullable=True)
    wifi_password_enc = Column(LargeBinary, nullable=True)

    # Non-sensitive metadata (stored plaintext for search/display)
    url = Column(String(2048), nullable=True)         # Encrypted separately if needed
    card_holder = Column(String(255), nullable=True)
    card_expiry = Column(String(10), nullable=True)
    wifi_ssid = Column(String(255), nullable=True)
    wifi_security = Column(String(50), nullable=True)
    identity_first_name = Column(String(100), nullable=True)
    identity_last_name = Column(String(100), nullable=True)
    identity_email = Column(String(255), nullable=True)
    identity_phone = Column(String(50), nullable=True)
    identity_address = Column(String(500), nullable=True)

    # Organization
    category_id = Column(String(36), ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)
    tags = Column(Text, nullable=True)           # JSON list of strings
    is_favorite = Column(Boolean, nullable=False, default=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    modified_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    # Encrypted JSON blob for custom fields
    custom_fields_enc = Column(LargeBinary, nullable=True)

    # Relationships
    category = relationship("DbCategory", back_populates="entries")
    password_history = relationship(
        "DbPasswordHistory", back_populates="entry",
        cascade="all, delete-orphan", order_by="DbPasswordHistory.changed_at.desc()"
    )


# Indexes for common queries
Index("idx_vault_entries_category", DbVaultEntry.category_id)
Index("idx_vault_entries_favorite", DbVaultEntry.is_favorite)
Index("idx_vault_entries_type", DbVaultEntry.item_type)
Index("idx_vault_entries_modified", DbVaultEntry.modified_at)


# ---------------------------------------------------------------------------
# Password history
# ---------------------------------------------------------------------------

class DbPasswordHistory(Base):
    __tablename__ = "password_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_id = Column(String(36), ForeignKey("vault_entries.id", ondelete="CASCADE"), nullable=False)
    password_enc = Column(LargeBinary, nullable=False)   # Encrypted previous password
    changed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    entry = relationship("DbVaultEntry", back_populates="password_history")


Index("idx_password_history_entry", DbPasswordHistory.entry_id)


# ---------------------------------------------------------------------------
# App settings
# ---------------------------------------------------------------------------

class DbAppSettings(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, default=1)
    settings_json = Column(Text, nullable=False, default="{}")


# ---------------------------------------------------------------------------
# Security audit log
# ---------------------------------------------------------------------------

class DbSecurityLog(Base):
    __tablename__ = "security_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)       # Safe details only, no secrets
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


Index("idx_security_log_timestamp", DbSecurityLog.timestamp)


# ---------------------------------------------------------------------------
# Schema version tracking (for migrations)
# ---------------------------------------------------------------------------

class DbSchemaVersion(Base):
    __tablename__ = "schema_version"

    version = Column(Integer, primary_key=True)
    applied_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    description = Column(String(255), nullable=True)
