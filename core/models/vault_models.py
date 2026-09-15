"""
Pydantic data models for vault entries and related objects.

All sensitive fields (password, username, notes, etc.) are stored as bytes
in the database (encrypted blobs). These models represent the decrypted,
in-memory representation of vault items while the vault is unlocked.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ItemType(str, Enum):
    LOGIN = "login"
    SECURE_NOTE = "secure_note"
    CREDIT_CARD = "credit_card"
    IDENTITY = "identity"
    WIFI = "wifi"
    API_CREDENTIAL = "api_credential"
    CUSTOM = "custom"


class PasswordStrength(str, Enum):
    VERY_WEAK = "very_weak"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


# ---------------------------------------------------------------------------
# Custom field
# ---------------------------------------------------------------------------

class CustomField(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    value: str = Field(default="")
    is_secret: bool = Field(default=False)


# ---------------------------------------------------------------------------
# Password history entry
# ---------------------------------------------------------------------------

class PasswordHistoryEntry(BaseModel):
    password: str
    changed_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Core vault entry — Login
# ---------------------------------------------------------------------------

class VaultEntry(BaseModel):
    """
    Complete in-memory representation of a vault entry.

    Sensitive fields (password, username, notes, totp_secret, custom_fields)
    are encrypted before database storage and decrypted on access.
    """

    id: str = Field(default_factory=_new_id)
    item_type: ItemType = Field(default=ItemType.LOGIN)
    title: str = Field(..., min_length=1, max_length=255)
    username: str = Field(default="")
    password: str = Field(default="")
    url: str = Field(default="")
    notes: str = Field(default="")
    totp_secret: str = Field(default="")
    category_id: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    is_favorite: bool = Field(default=False)
    created_at: datetime = Field(default_factory=_utcnow)
    modified_at: datetime = Field(default_factory=_utcnow)
    last_used_at: datetime | None = Field(default=None)
    password_history: list[PasswordHistoryEntry] = Field(default_factory=list)
    custom_fields: list[CustomField] = Field(default_factory=list)

    # Credit card fields (only populated for ItemType.CREDIT_CARD)
    card_number: str = Field(default="")
    card_holder: str = Field(default="")
    card_expiry: str = Field(default="")
    card_cvv: str = Field(default="")

    # Identity fields
    identity_first_name: str = Field(default="")
    identity_last_name: str = Field(default="")
    identity_email: str = Field(default="")
    identity_phone: str = Field(default="")
    identity_address: str = Field(default="")

    # Wi-Fi fields
    wifi_ssid: str = Field(default="")
    wifi_password: str = Field(default="")
    wifi_security: str = Field(default="")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Allow empty or valid-looking URLs."""
        if v and not (v.startswith("http://") or v.startswith("https://")
                      or v.startswith("ssh://") or v.startswith("ftp://")
                      or "://" not in v):
            # Accept any scheme; just strip leading/trailing whitespace
            pass
        return v.strip()

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        return [t.strip().lower() for t in v if t.strip()]

    def touch(self) -> None:
        """Update modified timestamp."""
        self.modified_at = _utcnow()

    def record_password_change(
        self, old_password: str, max_history: int = 10
    ) -> None:
        """Save current password to history before overwriting."""
        if old_password:
            self.password_history.insert(
                0, PasswordHistoryEntry(password=old_password)
            )
            # Trim to max history size
            self.password_history = self.password_history[:max_history]

    @property
    def sensitive_fields(self) -> dict[str, str]:
        """Return dict of all fields that must be encrypted."""
        return {
            "password": self.password,
            "username": self.username,
            "notes": self.notes,
            "totp_secret": self.totp_secret,
            "card_number": self.card_number,
            "card_cvv": self.card_cvv,
            "wifi_password": self.wifi_password,
        }


# ---------------------------------------------------------------------------
# Category
# ---------------------------------------------------------------------------

class Category(BaseModel):
    id: str = Field(default_factory=_new_id)
    name: str = Field(..., min_length=1, max_length=100)
    icon: str = Field(default="folder")
    color: str = Field(default="#5865F2")
    created_at: datetime = Field(default_factory=_utcnow)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return v.strip()


# Default categories
DEFAULT_CATEGORIES: list[dict[str, str]] = [
    {"name": "Personal",    "icon": "person",   "color": "#5865F2"},
    {"name": "Work",        "icon": "briefcase","color": "#ED4245"},
    {"name": "Banking",     "icon": "bank",     "color": "#57F287"},
    {"name": "Social",      "icon": "share",    "color": "#FEE75C"},
    {"name": "Shopping",    "icon": "cart",     "color": "#EB459E"},
    {"name": "Education",   "icon": "book",     "color": "#3BA55D"},
    {"name": "Development", "icon": "code",     "color": "#FAA61A"},
    {"name": "Other",       "icon": "other",    "color": "#99AAB5"},
]


# ---------------------------------------------------------------------------
# Vault metadata (stored unencrypted in header)
# ---------------------------------------------------------------------------

class VaultMetadata(BaseModel):
    vault_id: str = Field(default_factory=_new_id)
    format_version: int = Field(default=1)
    app_version: str = Field(default="1.0.0")
    created_at: datetime = Field(default_factory=_utcnow)
    modified_at: datetime = Field(default_factory=_utcnow)
    entry_count: int = Field(default=0)

    def touch(self) -> None:
        self.modified_at = _utcnow()


# ---------------------------------------------------------------------------
# Security audit result
# ---------------------------------------------------------------------------

class SecurityAuditResult(BaseModel):
    total_entries: int = 0
    weak_passwords: list[str] = Field(default_factory=list)         # entry IDs
    reused_passwords: list[list[str]] = Field(default_factory=list)  # groups of IDs
    old_passwords: list[str] = Field(default_factory=list)           # entry IDs
    missing_usernames: list[str] = Field(default_factory=list)
    missing_urls: list[str] = Field(default_factory=list)
    duplicate_entries: list[list[str]] = Field(default_factory=list)
    security_score: int = 100   # 0-100

    def compute_score(self) -> None:
        """Compute a simple security score based on findings."""
        deductions = 0
        if self.total_entries > 0:
            deductions += (len(self.weak_passwords) / self.total_entries) * 40
            reused_count = sum(len(g) for g in self.reused_passwords)
            deductions += (reused_count / self.total_entries) * 30
            deductions += (len(self.old_passwords) / self.total_entries) * 20
            deductions += (len(self.missing_usernames) / self.total_entries) * 5
            deductions += (len(self.missing_urls) / self.total_entries) * 5
        self.security_score = max(0, int(100 - deductions))


# ---------------------------------------------------------------------------
# Application settings (persisted, non-sensitive)
# ---------------------------------------------------------------------------

class AppSettings(BaseModel):
    theme: str = Field(default="dark")
    auto_lock_seconds: int = Field(default=300)
    clipboard_clear_seconds: int = Field(default=30)
    password_history_size: int = Field(default=10)
    generator_length: int = Field(default=20)
    generator_uppercase: bool = Field(default=True)
    generator_lowercase: bool = Field(default=True)
    generator_digits: bool = Field(default=True)
    generator_symbols: bool = Field(default=True)
    generator_exclude_ambiguous: bool = Field(default=True)
    biometric_enabled: bool = Field(default=False)
    breach_check_enabled: bool = Field(default=True)
    locale: str = Field(default="en")
