"""
Key management — implements the two-level key hierarchy.

Level 1: Master Password → Argon2id → Key Encryption Key (KEK)
Level 2: KEK wraps/unwraps the Vault Data Encryption Key (DEK)

The DEK is the key actually used to encrypt vault entries.
The KEK is derived from the master password at unlock time and lives
only in memory while the vault is open.

Changing the master password requires only:
  1. Deriving the new KEK from the new password.
  2. Re-wrapping the DEK with the new KEK.
  3. Updating the vault header.
  (Does NOT require re-encrypting every vault entry.)
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field

from config.settings import DEK_LENGTH, KEK_LENGTH
from core.crypto.encryption import decrypt, encrypt
from core.crypto.kdf import KDFParams, derive_key, generate_kdf_params
from core.crypto.secure_random import generate_key
from core.utilities.exceptions import DecryptionError, IntegrityError, KeyDerivationError
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class VaultKeyMaterial:
    """
    Persistent key material stored in the vault header.

    Contains:
    - KDF parameters (salt, Argon2 settings) — not secret
    - Wrapped DEK — encrypted blob that can only be unwrapped with the correct KEK

    NEVER stores the KEK or the unwrapped DEK.
    """

    kdf_params: KDFParams
    wrapped_dek: bytes   # AES-GCM encrypted DEK (encrypted with KEK)

    def to_dict(self) -> dict:
        return {
            "kdf_params": self.kdf_params.to_dict(),
            "wrapped_dek": base64.b64encode(self.wrapped_dek).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultKeyMaterial":
        return cls(
            kdf_params=KDFParams.from_dict(data["kdf_params"]),
            wrapped_dek=base64.b64decode(data["wrapped_dek"]),
        )


class KeyManager:
    """
    Manages the in-memory key hierarchy for an open vault session.

    Lifecycle:
      1. create_new_vault(master_password)  — generates fresh DEK + KDF params
      2. unlock(master_password, key_material)  — derives KEK, unwraps DEK
      3. get_dek()  — returns DEK for encryption/decryption operations
      4. lock()  — zeros and removes in-memory keys
    """

    def __init__(self) -> None:
        self._dek: bytes | None = None   # Data Encryption Key (in memory only)
        self._kek: bytes | None = None   # Key Encryption Key (in memory only)
        self._locked = True

    # ------------------------------------------------------------------
    # Vault creation
    # ------------------------------------------------------------------

    def create_new_vault(self, master_password: str) -> VaultKeyMaterial:
        """
        Create a brand-new vault:
          1. Generate KDF params with random salt.
          2. Derive KEK from master password.
          3. Generate random DEK.
          4. Wrap DEK with KEK.
          5. Store KEK and DEK in memory (vault is now unlocked).

        Returns VaultKeyMaterial for storage in the vault header.
        """
        kdf_params = generate_kdf_params()
        kek = derive_key(master_password, kdf_params)

        dek = generate_key(DEK_LENGTH)
        wrapped_dek = self._wrap_dek(dek, kek)

        self._kek = kek
        self._dek = dek
        self._locked = False

        logger.info("New vault created with fresh key material.")
        return VaultKeyMaterial(kdf_params=kdf_params, wrapped_dek=wrapped_dek)

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------

    def unlock(self, master_password: str, key_material: VaultKeyMaterial) -> None:
        """
        Unlock the vault by deriving the KEK and unwrapping the DEK.

        Raises:
            KeyDerivationError: If Argon2 derivation fails.
            IntegrityError / DecryptionError: If the master password is wrong
                or the key material is corrupted (authentication tag mismatch).
        """
        kek = derive_key(master_password, key_material.kdf_params)
        try:
            dek = self._unwrap_dek(key_material.wrapped_dek, kek)
        except (IntegrityError, DecryptionError):
            # Clear derived KEK before raising
            kek_arr = bytearray(kek)
            for i in range(len(kek_arr)):
                kek_arr[i] = 0
            raise

        self._kek = kek
        self._dek = dek
        self._locked = False
        logger.info("Vault unlocked.")

    # ------------------------------------------------------------------
    # Lock
    # ------------------------------------------------------------------

    def lock(self) -> None:
        """
        Zero out and discard in-memory key material.

        Python cannot guarantee that the garbage collector will immediately
        reclaim the memory, but we make a best-effort zeroing of bytearrays.
        String/bytes objects are immutable in Python and cannot be zeroed —
        this is a documented platform limitation.
        """
        if self._dek is not None:
            ba = bytearray(self._dek)
            for i in range(len(ba)):
                ba[i] = 0
            self._dek = None

        if self._kek is not None:
            ba = bytearray(self._kek)
            for i in range(len(ba)):
                ba[i] = 0
            self._kek = None

        self._locked = True
        logger.info("Vault locked. Key material cleared from memory.")

    # ------------------------------------------------------------------
    # Key access
    # ------------------------------------------------------------------

    @property
    def is_locked(self) -> bool:
        return self._locked

    def get_dek(self) -> bytes:
        """
        Return the Data Encryption Key.

        Raises:
            VaultLockedError: If the vault is locked.
        """
        from core.utilities.exceptions import VaultLockedError
        if self._locked or self._dek is None:
            raise VaultLockedError("Vault is locked. Unlock with master password first.")
        return self._dek

    # ------------------------------------------------------------------
    # Master password change
    # ------------------------------------------------------------------

    def change_master_password(
        self, new_master_password: str
    ) -> VaultKeyMaterial:
        """
        Re-wrap the existing DEK with a new KEK derived from the new password.

        The vault does NOT need to be re-encrypted — only the wrapped DEK changes.

        Raises:
            VaultLockedError: If the vault is not currently unlocked.
        """
        from core.utilities.exceptions import VaultLockedError
        if self._locked or self._dek is None:
            raise VaultLockedError("Vault must be unlocked to change master password.")

        new_kdf_params = generate_kdf_params()
        new_kek = derive_key(new_master_password, new_kdf_params)
        new_wrapped_dek = self._wrap_dek(self._dek, new_kek)

        # Replace KEK in memory
        if self._kek is not None:
            ba = bytearray(self._kek)
            for i in range(len(ba)):
                ba[i] = 0
        self._kek = new_kek

        logger.info("Master password changed. New key material generated.")
        return VaultKeyMaterial(kdf_params=new_kdf_params, wrapped_dek=new_wrapped_dek)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _wrap_dek(dek: bytes, kek: bytes) -> bytes:
        """Encrypt the DEK with the KEK using AES-256-GCM."""
        return encrypt(dek, kek, associated_data=b"wrapped_dek_v1")

    @staticmethod
    def _unwrap_dek(wrapped_dek: bytes, kek: bytes) -> bytes:
        """Decrypt the wrapped DEK using the KEK."""
        return decrypt(wrapped_dek, kek, associated_data=b"wrapped_dek_v1")
