"""
Cryptographically secure random number generation.

All security-sensitive random values must be obtained through this module.
Uses Python's `secrets` module (backed by OS CSPRNG: getrandom / CryptGenRandom).

Never use:
  - random.random()
  - random.randint()
  - time-based seeds
  - predictable sequences
"""
from __future__ import annotations

import secrets
import string


def secure_bytes(length: int) -> bytes:
    """Return `length` cryptographically random bytes from OS CSPRNG."""
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    return secrets.token_bytes(length)


def secure_hex(length: int) -> str:
    """Return a hex-encoded string of `length` random bytes."""
    return secrets.token_hex(length)


def secure_urlsafe(length: int) -> str:
    """Return a URL-safe base64 string from `length` random bytes."""
    return secrets.token_urlsafe(length)


def secure_int(low: int, high: int) -> int:
    """Return a secure random integer in [low, high] inclusive."""
    if low > high:
        raise ValueError(f"low ({low}) must be <= high ({high})")
    return secrets.randbelow(high - low + 1) + low


def secure_choice(population: str | list) -> str:  # type: ignore[type-arg]
    """Return a random element from a non-empty sequence."""
    if not population:
        raise ValueError("population must not be empty")
    return secrets.choice(population)  # type: ignore[arg-type]


def secure_shuffle(lst: list) -> list:  # type: ignore[type-arg]
    """Return a new list with items in secure random order (Fisher-Yates)."""
    lst = list(lst)
    for i in range(len(lst) - 1, 0, -1):
        j = secure_int(0, i)
        lst[i], lst[j] = lst[j], lst[i]
    return lst


def generate_salt(length: int = 32) -> bytes:
    """Generate a cryptographically secure random salt."""
    return secure_bytes(length)


def generate_nonce(length: int = 12) -> bytes:
    """Generate a cryptographically secure random nonce for AES-GCM."""
    return secure_bytes(length)


def generate_key(length: int = 32) -> bytes:
    """Generate a cryptographically secure random symmetric key."""
    return secure_bytes(length)


def generate_recovery_code(words: int = 12) -> str:
    """Generate a recovery code as space-separated random words from a secure wordlist."""
    # Use hex groups as a simple, unambiguous recovery code format
    groups = [secrets.token_hex(4).upper() for _ in range(words)]
    return "-".join(groups)


def generate_secure_token(length: int = 32) -> str:
    """Generate a URL-safe token of at least `length` bytes of randomness."""
    return secrets.token_urlsafe(length)


# Constant-time comparison — use hmac.compare_digest for sensitive values
import hmac  # noqa: E402


def constant_time_compare(a: bytes | str, b: bytes | str) -> bool:
    """Compare two values in constant time to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)
