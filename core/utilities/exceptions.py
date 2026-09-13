"""
Custom exception hierarchy for the password manager.

User-facing messages are kept generic (no secrets).
Developer details may be attached as `detail` attributes.
"""
from __future__ import annotations


class PasswordManagerError(Exception):
    """Base class for all application errors."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail


class AuthenticationError(PasswordManagerError):
    """Raised when authentication fails (wrong master password, lockout)."""


class VaultLockedError(PasswordManagerError):
    """Raised when an operation is attempted on a locked vault."""


class DecryptionError(PasswordManagerError):
    """Raised when decryption fails (wrong key or corrupted data)."""


class IntegrityError(PasswordManagerError):
    """Raised when encrypted data fails authentication / integrity check."""


class InvalidVaultError(PasswordManagerError):
    """Raised when vault file is invalid or unsupported version."""


class VaultAlreadyExistsError(PasswordManagerError):
    """Raised when trying to create a vault that already exists."""


class VaultNotFoundError(PasswordManagerError):
    """Raised when vault is not found at expected path."""


class ImportError(PasswordManagerError):  # noqa: A001
    """Raised when import fails."""


class ExportError(PasswordManagerError):
    """Raised when export fails."""


class BackupError(PasswordManagerError):
    """Raised when backup or restore fails."""


class ValidationError(PasswordManagerError):
    """Raised when input validation fails."""


class MigrationError(PasswordManagerError):
    """Raised when database migration fails."""


class TOTPError(PasswordManagerError):
    """Raised when TOTP operation fails."""


class KeyDerivationError(PasswordManagerError):
    """Raised when key derivation fails."""
