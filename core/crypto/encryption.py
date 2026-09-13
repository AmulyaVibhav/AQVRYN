"""
AES-256-GCM authenticated encryption.

Every encrypted record includes:
  - 12-byte random nonce (per-message)
  - ciphertext
  - 16-byte GCM authentication tag (included in cryptography library output)
  - format version byte

Format of an encrypted blob (binary):
  [version: 1 byte][nonce: 12 bytes][ciphertext+tag: variable]

The GCM tag is appended to the ciphertext by the `cryptography` library
(last 16 bytes of the ciphertext blob returned by finalize_with_tag).

Guarantees:
  - Confidentiality: AES-256 in GCM mode
  - Integrity: GCM authentication tag
  - Tamper detection: any bit flip in ciphertext or tag raises InvalidTag

Never reuse nonces with the same key. Each call generates a fresh random nonce.
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config.settings import AES_KEY_LENGTH, NONCE_LENGTH, VAULT_FORMAT_VERSION
from core.crypto.secure_random import generate_nonce
from core.utilities.exceptions import DecryptionError, IntegrityError
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)

# Blob layout constants
_VERSION_BYTES = 1
_NONCE_BYTES = NONCE_LENGTH
_HEADER_SIZE = _VERSION_BYTES + _NONCE_BYTES
_GCM_TAG_SIZE = 16


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        plaintext: The data to encrypt.
        key: 32-byte AES-256 key.
        associated_data: Optional authenticated-but-not-encrypted data
                         (e.g. record ID, version).

    Returns:
        Encrypted blob: [version(1)][nonce(12)][ciphertext+tag(variable)]

    Raises:
        ValueError: If key length is invalid.
    """
    if len(key) != AES_KEY_LENGTH:
        raise ValueError(f"Key must be exactly {AES_KEY_LENGTH} bytes, got {len(key)}.")

    nonce = generate_nonce(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    version_byte = struct.pack("B", VAULT_FORMAT_VERSION)
    blob = version_byte + nonce + ciphertext_with_tag
    return blob


def decrypt(blob: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted blob.

    Args:
        blob: Encrypted blob produced by `encrypt()`.
        key: 32-byte AES-256 key.
        associated_data: Must match what was passed during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        IntegrityError: If the authentication tag is invalid (tamper detected).
        DecryptionError: If the blob is malformed or decryption fails.
    """
    if len(key) != AES_KEY_LENGTH:
        raise ValueError(f"Key must be exactly {AES_KEY_LENGTH} bytes, got {len(key)}.")

    if len(blob) < _HEADER_SIZE + _GCM_TAG_SIZE:
        raise DecryptionError("Encrypted blob is too short to be valid.")

    version = struct.unpack("B", blob[:_VERSION_BYTES])[0]
    if version != VAULT_FORMAT_VERSION:
        raise DecryptionError(
            f"Unsupported vault format version {version}. "
            f"Expected {VAULT_FORMAT_VERSION}."
        )

    nonce = blob[_VERSION_BYTES:_HEADER_SIZE]
    ciphertext_with_tag = blob[_HEADER_SIZE:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except InvalidTag as exc:
        # Authentication tag mismatch — data was tampered with or wrong key
        raise IntegrityError(
            "Authentication failed: vault data may have been tampered with."
        ) from exc
    except Exception as exc:
        raise DecryptionError(
            "Decryption failed.", detail=str(exc)
        ) from exc


def encrypt_text(plaintext: str, key: bytes, associated_data: bytes | None = None) -> bytes:
    """Convenience wrapper: encrypt a UTF-8 string."""
    return encrypt(plaintext.encode("utf-8"), key, associated_data)


def decrypt_text(blob: bytes, key: bytes, associated_data: bytes | None = None) -> str:
    """Convenience wrapper: decrypt to a UTF-8 string."""
    return decrypt(blob, key, associated_data).decode("utf-8")
