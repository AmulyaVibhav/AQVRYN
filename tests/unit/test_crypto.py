"""
Unit tests for cryptographic functions.
Tests: key derivation, encryption, decryption, tamper detection, key hierarchy.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent.parent))

from core.crypto.encryption import decrypt, decrypt_text, encrypt, encrypt_text
from core.crypto.kdf import KDFParams, derive_key, generate_kdf_params
from core.crypto.key_manager import KeyManager, VaultKeyMaterial
from core.crypto.secure_random import (
    constant_time_compare,
    generate_key,
    generate_nonce,
    generate_salt,
    secure_bytes,
    secure_shuffle,
)
from core.utilities.exceptions import (
    DecryptionError,
    IntegrityError,
    KeyDerivationError,
    VaultLockedError,
)

# ---------------------------------------------------------------------------
# Secure random
# ---------------------------------------------------------------------------

class TestSecureRandom:
    def test_secure_bytes_length(self):
        for length in [16, 32, 64]:
            data = secure_bytes(length)
            assert len(data) == length

    def test_secure_bytes_uniqueness(self):
        """Each call must produce different bytes."""
        a = secure_bytes(32)
        b = secure_bytes(32)
        assert a != b

    def test_secure_bytes_invalid_length(self):
        with pytest.raises(ValueError):
            secure_bytes(0)
        with pytest.raises(ValueError):
            secure_bytes(-1)

    def test_generate_salt(self):
        salt = generate_salt(32)
        assert len(salt) == 32

    def test_generate_nonce(self):
        nonce = generate_nonce(12)
        assert len(nonce) == 12

    def test_generate_key(self):
        key = generate_key(32)
        assert len(key) == 32

    def test_constant_time_compare_equal(self):
        assert constant_time_compare(b"secret", b"secret") is True

    def test_constant_time_compare_unequal(self):
        assert constant_time_compare(b"secret", b"wrong") is False

    def test_constant_time_compare_strings(self):
        assert constant_time_compare("hello", "hello") is True
        assert constant_time_compare("hello", "world") is False

    def test_secure_shuffle_preserves_elements(self):
        lst = list(range(100))
        shuffled = secure_shuffle(lst[:])
        assert sorted(shuffled) == sorted(lst)

    def test_secure_shuffle_randomizes(self):
        lst = list(range(100))
        results = [tuple(secure_shuffle(lst[:])) for _ in range(5)]
        # At least one shuffle must differ from original
        assert any(r != tuple(lst) for r in results)


# ---------------------------------------------------------------------------
# Key derivation (Argon2id)
# ---------------------------------------------------------------------------

class TestKeyDerivation:
    def test_derive_key_produces_correct_length(self):
        params = generate_kdf_params()
        key = derive_key("test-master-password", params)
        assert len(key) == 32

    def test_same_password_same_params_reproducible(self):
        params = generate_kdf_params()
        key1 = derive_key("password123", params)
        key2 = derive_key("password123", params)
        assert key1 == key2

    def test_different_passwords_different_keys(self):
        params = generate_kdf_params()
        key1 = derive_key("password1", params)
        key2 = derive_key("password2", params)
        assert key1 != key2

    def test_different_salts_different_keys(self):
        params1 = generate_kdf_params()
        params2 = generate_kdf_params()
        key1 = derive_key("same-password", params1)
        key2 = derive_key("same-password", params2)
        # Salts differ, so keys must differ
        assert key1 != key2

    def test_empty_password_raises(self):
        params = generate_kdf_params()
        with pytest.raises(KeyDerivationError):
            derive_key("", params)

    def test_kdf_params_serialization(self):
        params = generate_kdf_params()
        d = params.to_dict()
        restored = KDFParams.from_dict(d)
        assert restored.salt == params.salt
        assert restored.memory_cost == params.memory_cost
        assert restored.time_cost == params.time_cost


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption
# ---------------------------------------------------------------------------

class TestEncryption:
    def _key(self) -> bytes:
        return generate_key(32)

    def test_encrypt_decrypt_roundtrip(self):
        key = self._key()
        plaintext = b"Hello, World! This is a secret message."
        blob = encrypt(plaintext, key)
        result = decrypt(blob, key)
        assert result == plaintext

    def test_encrypt_text_roundtrip(self):
        key = self._key()
        text = "My secret password: CorrectHorseBatteryStaple"
        blob = encrypt_text(text, key)
        result = decrypt_text(blob, key)
        assert result == text

    def test_wrong_key_raises_integrity_error(self):
        key1 = self._key()
        key2 = self._key()
        blob = encrypt(b"secret data", key1)
        with pytest.raises(IntegrityError):
            decrypt(blob, key2)

    def test_tampered_ciphertext_raises_integrity_error(self):
        key = self._key()
        blob = encrypt(b"secret data", key)
        # Flip a byte in the ciphertext (after the 13-byte header)
        tampered = bytearray(blob)
        tampered[20] ^= 0xFF
        with pytest.raises(IntegrityError):
            decrypt(bytes(tampered), key)

    def test_tampered_nonce_raises_error(self):
        key = self._key()
        blob = encrypt(b"secret data", key)
        tampered = bytearray(blob)
        tampered[2] ^= 0xAA  # Flip nonce byte
        with pytest.raises((IntegrityError, DecryptionError)):
            decrypt(bytes(tampered), key)

    def test_associated_data_mismatch_raises_error(self):
        key = self._key()
        blob = encrypt(b"secret", key, associated_data=b"record:123")
        with pytest.raises(IntegrityError):
            decrypt(blob, key, associated_data=b"record:456")

    def test_nonces_are_unique(self):
        key = self._key()
        blobs = [encrypt(b"same plaintext", key) for _ in range(100)]
        nonces = [b[1:13] for b in blobs]  # Extract nonces
        assert len(set(nonces)) == 100, "Nonces must be unique"

    def test_encrypts_empty_plaintext(self):
        key = self._key()
        blob = encrypt(b"", key)
        assert decrypt(blob, key) == b""

    def test_invalid_key_length_raises(self):
        with pytest.raises(ValueError):
            encrypt(b"data", b"short_key")

    def test_short_blob_raises(self):
        key = self._key()
        with pytest.raises(DecryptionError):
            decrypt(b"tooshort", key)

    def test_unicode_plaintext(self):
        key = self._key()
        text = "Password: 🔐 Ünïcödé Pàssw0rd! ñoño"
        blob = encrypt_text(text, key)
        assert decrypt_text(blob, key) == text


# ---------------------------------------------------------------------------
# Key manager (key hierarchy)
# ---------------------------------------------------------------------------

class TestKeyManager:
    def test_create_new_vault_returns_key_material(self):
        km = KeyManager()
        material = km.create_new_vault("strong-master-password")
        assert isinstance(material, VaultKeyMaterial)
        assert material.kdf_params is not None
        assert material.wrapped_dek

    def test_vault_unlocked_after_creation(self):
        km = KeyManager()
        km.create_new_vault("password123!")
        assert not km.is_locked

    def test_unlock_correct_password(self):
        km = KeyManager()
        material = km.create_new_vault("correct-password")
        km.lock()
        assert km.is_locked
        km.unlock("correct-password", material)
        assert not km.is_locked

    def test_unlock_wrong_password_raises(self):
        km = KeyManager()
        material = km.create_new_vault("correct-password")
        km.lock()
        with pytest.raises((IntegrityError, DecryptionError)):
            km.unlock("wrong-password", material)

    def test_lock_clears_keys(self):
        km = KeyManager()
        km.create_new_vault("password!")
        km.lock()
        assert km.is_locked
        with pytest.raises(VaultLockedError):
            km.get_dek()

    def test_dek_consistent_after_unlock(self):
        km = KeyManager()
        material = km.create_new_vault("password!")
        dek1 = km.get_dek()
        km.lock()
        km.unlock("password!", material)
        dek2 = km.get_dek()
        assert dek1 == dek2

    def test_change_master_password(self):
        km = KeyManager()
        material = km.create_new_vault("old-password")
        dek_before = km.get_dek()

        new_material = km.change_master_password("new-password")

        # Old password should fail
        km.lock()
        with pytest.raises((IntegrityError, DecryptionError)):
            km.unlock("old-password", new_material)

        # New password should work
        km2 = KeyManager()
        km2.unlock("new-password", new_material)
        dek_after = km2.get_dek()
        assert dek_before == dek_after  # DEK unchanged

    def test_vault_key_material_serialization(self):
        km = KeyManager()
        material = km.create_new_vault("password!")
        d = material.to_dict()
        restored = VaultKeyMaterial.from_dict(d)
        assert restored.wrapped_dek == material.wrapped_dek
