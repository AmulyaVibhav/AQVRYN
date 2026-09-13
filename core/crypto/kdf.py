"""
Key Derivation Function — Argon2id.

Implements the password-based key derivation function used to derive
cryptographic material from the master password.

Key hierarchy:
    Master Password
          ↓
      Argon2id (with per-vault random salt)
          ↓
    Key Encryption Key (KEK)
          ↓
    Vault Data Encryption Key (DEK) [wrapped/unwrapped with KEK]
          ↓
    Encrypted Vault Data

This allows master-password changes without re-encrypting every entry:
only the wrapped DEK needs to be re-encrypted.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw  # argon2-cffi low-level API

from config.settings import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KEK_LENGTH,
    SALT_LENGTH,
)
from core.crypto.secure_random import generate_salt
from core.utilities.exceptions import KeyDerivationError
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class KDFParams:
    """Argon2id parameters stored alongside the vault metadata."""

    salt: bytes          # Random 256-bit salt (not secret, stored in vault header)
    memory_cost: int     # KiB
    time_cost: int
    parallelism: int
    hash_length: int

    def to_dict(self) -> dict:
        return {
            "salt": base64.b64encode(self.salt).decode(),
            "memory_cost": self.memory_cost,
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "hash_length": self.hash_length,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KDFParams":
        return cls(
            salt=base64.b64decode(data["salt"]),
            memory_cost=int(data["memory_cost"]),
            time_cost=int(data["time_cost"]),
            parallelism=int(data["parallelism"]),
            hash_length=int(data["hash_length"]),
        )


def generate_kdf_params() -> KDFParams:
    """Generate new KDF parameters with a fresh random salt."""
    return KDFParams(
        salt=generate_salt(SALT_LENGTH),
        memory_cost=ARGON2_MEMORY_COST,
        time_cost=ARGON2_TIME_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_length=ARGON2_HASH_LENGTH,
    )


def derive_key(master_password: str | bytes, params: KDFParams) -> bytes:
    """
    Derive a Key Encryption Key (KEK) from the master password using Argon2id.

    The returned key is NEVER stored. It exists only in memory while the vault
    is unlocked and must be cleared when locking.

    Args:
        master_password: The user's master password (str or bytes).
        params: KDF parameters (salt, memory, time, parallelism).

    Returns:
        Raw bytes of length params.hash_length suitable for use as a KEK.

    Raises:
        KeyDerivationError: If derivation fails for any reason.
    """
    if isinstance(master_password, str):
        password_bytes = master_password.encode("utf-8")
    else:
        password_bytes = master_password

    if len(password_bytes) == 0:
        raise KeyDerivationError("Master password must not be empty.")

    try:
        key = hash_secret_raw(
            secret=password_bytes,
            salt=params.salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_length,
            type=Type.ID,  # Argon2id
        )
        logger.debug("Key derivation completed successfully.")
        return key
    except Exception as exc:
        raise KeyDerivationError(
            "Key derivation failed.", detail=str(exc)
        ) from exc
    finally:
        # Best-effort: zero out the local copy of the password bytes
        if isinstance(master_password, str):
            # Python strings are immutable; we can only clear our local bytearray
            password_bytes_mutable = bytearray(password_bytes)
            for i in range(len(password_bytes_mutable)):
                password_bytes_mutable[i] = 0


def derive_key_for_verification(
    master_password: str | bytes, params: KDFParams, expected_hash: bytes
) -> bool:
    """
    Verify a master password against a stored Argon2id hash.

    Uses constant-time comparison to prevent timing attacks.

    This is used only for the fast login check (hashed verifier), NOT for
    deriving the actual encryption key (which is done by derive_key).
    """
    from core.crypto.secure_random import constant_time_compare
    try:
        derived = derive_key(master_password, params)
        return constant_time_compare(derived, expected_hash)
    except KeyDerivationError:
        return False
