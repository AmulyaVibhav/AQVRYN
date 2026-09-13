"""
Application configuration.

All cryptographic constants and application settings are centralized here.
Never scatter cryptographic values throughout the code.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Cryptographic constants
# ---------------------------------------------------------------------------

# Argon2id parameters — OWASP recommended minimums (2024)
# Memory cost: 64 MiB (minimum), raise for stronger security
ARGON2_MEMORY_COST: Final[int] = int(os.environ.get("ARGON2_MEMORY_COST", "65536"))   # KiB
ARGON2_TIME_COST: Final[int] = int(os.environ.get("ARGON2_TIME_COST", "3"))
ARGON2_PARALLELISM: Final[int] = int(os.environ.get("ARGON2_PARALLELISM", "4"))
ARGON2_HASH_LENGTH: Final[int] = 32  # 256-bit derived key

# Salt / nonce lengths in bytes
SALT_LENGTH: Final[int] = 32       # 256-bit salt for Argon2id
NONCE_LENGTH: Final[int] = 12      # 96-bit nonce for AES-256-GCM (NIST recommended)
AES_KEY_LENGTH: Final[int] = 32    # 256-bit AES key
KEK_LENGTH: Final[int] = 32        # Key Encryption Key length (256-bit)
DEK_LENGTH: Final[int] = 32        # Data Encryption Key length (256-bit)

# Vault format version
VAULT_FORMAT_VERSION: Final[int] = 1

# ---------------------------------------------------------------------------
# Authentication / lockout
# ---------------------------------------------------------------------------

MAX_FAILED_ATTEMPTS: Final[int] = int(os.environ.get("MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_DURATION_SECONDS: Final[int] = int(os.environ.get("LOCKOUT_DURATION_SECONDS", "30"))

# Auto-lock timeout in seconds (default 5 minutes, 0 = disabled)
DEFAULT_AUTO_LOCK_SECONDS: Final[int] = int(os.environ.get("DEFAULT_AUTO_LOCK_SECONDS", "300"))

# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

DEFAULT_CLIPBOARD_CLEAR_SECONDS: Final[int] = int(
    os.environ.get("DEFAULT_CLIPBOARD_CLEAR_SECONDS", "30")
)

# ---------------------------------------------------------------------------
# Password history
# ---------------------------------------------------------------------------

DEFAULT_PASSWORD_HISTORY_SIZE: Final[int] = int(
    os.environ.get("DEFAULT_PASSWORD_HISTORY_SIZE", "10")
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

APP_NAME: Final[str] = "SecureVault"
APP_VERSION: Final[str] = "1.0.0"

# Default data directory (platform-aware)
def _default_data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME
    home = Path.home()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))
        return Path(appdata) / APP_NAME
    return home / ".local" / "share" / APP_NAME


DATA_DIR: Path = Path(os.environ.get("PM_DATA_DIR", str(_default_data_dir())))
VAULT_DB_PATH: Path = DATA_DIR / "vault.db"
BACKUP_DIR: Path = DATA_DIR / "backups"
LOG_DIR: Path = DATA_DIR / "logs"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LEVEL: str = os.environ.get("PM_LOG_LEVEL", "INFO")
LOG_RETENTION_DAYS: int = int(os.environ.get("PM_LOG_RETENTION_DAYS", "30"))

# Disallow insecure parameter combinations
def validate_crypto_config() -> None:
    """Raise if crypto params are below safe minimums."""
    if ARGON2_MEMORY_COST < 47104:
        raise ValueError("ARGON2_MEMORY_COST must be >= 47104 KiB (46 MiB) per OWASP")
    if ARGON2_TIME_COST < 1:
        raise ValueError("ARGON2_TIME_COST must be >= 1")
    if ARGON2_PARALLELISM < 1:
        raise ValueError("ARGON2_PARALLELISM must be >= 1")
    if AES_KEY_LENGTH not in (16, 24, 32):
        raise ValueError("AES_KEY_LENGTH must be 16, 24, or 32 bytes")
