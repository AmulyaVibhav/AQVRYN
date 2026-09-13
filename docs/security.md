# Security Architecture

## Overview

SecureVault uses industry-standard cryptographic primitives throughout. This document describes every security decision.

## Cryptographic Algorithms

### Key Derivation: Argon2id

Argon2id is the winner of the Password Hashing Competition (PHC) and is the recommended algorithm for password-based key derivation (OWASP 2024).

Parameters (defaults, configurable via environment):
- `ARGON2_MEMORY_COST`: 65536 KiB (64 MiB) — resistance to GPU attacks
- `ARGON2_TIME_COST`: 3 iterations
- `ARGON2_PARALLELISM`: 4 threads
- `ARGON2_HASH_LENGTH`: 32 bytes (256-bit KEK)

The salt is 256-bit random (from OS CSPRNG) and is **not secret** — it is stored in the vault header.

### Symmetric Encryption: AES-256-GCM

AES-256-GCM provides:
- **Confidentiality**: 256-bit AES in Galois/Counter Mode
- **Integrity and Authenticity**: GHASH authentication tag (128-bit)
- **Tamper detection**: any modification to ciphertext causes decryption failure

Each encryption call:
1. Generates a fresh 96-bit random nonce from OS CSPRNG
2. Encrypts with AES-256-GCM
3. Appends the 16-byte authentication tag to the ciphertext
4. Returns: `[version(1 byte)][nonce(12 bytes)][ciphertext+tag(N bytes)]`

**Nonces are never reused** — each encryption generates a fresh random nonce.

## Key Hierarchy

```
User's Master Password
        │
        ▼ Argon2id (memory=64MiB, time=3, para=4)
Key Encryption Key (KEK) ─── 256-bit, RAM ONLY while unlocked
        │
        ▼ AES-256-GCM wrapping with AAD="wrapped_dek_v1"
Wrapped DEK ─────────────── stored in vault_metadata table (encrypted blob)
        │
        ▼ (unwrapped at unlock time)
Data Encryption Key (DEK) ── 256-bit random, RAM ONLY while unlocked
        │
        ▼ AES-256-GCM per field with per-field AAD="entry_id:field_name"
Encrypted Vault Fields ───── stored as BLOB columns in vault_entries
```

### Benefits of two-level hierarchy

When the user changes their master password:
- A new KEK is derived from the new password
- The DEK is **re-wrapped** with the new KEK
- **No re-encryption of vault entries is required**
- Only the wrapped DEK in the header changes

## Database Security

SQLite stores sensitive fields as encrypted BLOB columns:
- `username_enc`
- `password_enc`
- `notes_enc`
- `totp_secret_enc`
- `card_number_enc`
- `card_cvv_enc`
- `wifi_password_enc`
- `custom_fields_enc`
- `password_enc` (history)

Non-sensitive metadata (title, URL, timestamps) is stored in plaintext to enable search and display without decrypting the entire vault.

**The title is not encrypted by design** — this is a deliberate trade-off for usability.  
If full title encryption is required, re-encrypt titles with the DEK and build an in-memory search index when unlocked.

## Authentication Security

- Master password is **never stored** — only the Argon2id-derived KEK is used
- Failed authentication attempts are tracked with progressive lockout
- Default: 5 failures → 30-second lockout (doubles each cycle)
- All comparisons use `hmac.compare_digest` (constant-time)

## Memory Security

Python does not provide guaranteed memory clearing (strings are immutable, GC is non-deterministic). Best-effort mitigations:
- Keys are stored as `bytes` objects (not `str`)
- On `lock()`, bytearrays are zeroed before releasing references
- Keys are held only in the `KeyManager` instance — never passed unnecessarily
- All secrets are cleared on `closeEvent` in the UI

**Limitation**: Python's garbage collector and OS memory management cannot guarantee secrets are never accessible via memory dumps on a compromised machine.

## Threat Model Summary

| Threat | Protection |
|--------|-----------|
| Database theft | All sensitive fields encrypted with AES-256-GCM |
| Offline brute force | Argon2id with high memory cost |
| Tampered vault | GCM authentication tag detects any modification |
| Wrong master password | IntegrityError from GCM tag failure |
| Clipboard hijacking | Auto-clear after configurable timeout |
| Log credential leak | Scrub filter on all log handlers |
| SQL injection | Parameterized queries (SQLAlchemy ORM) |
| Weak master password | Minimum length + strength guidance |

## What SecureVault Cannot Protect Against

- **Compromised OS**: Root access can dump process memory
- **Keyloggers**: The master password can be captured at input time
- **Evil maid attacks**: Physical access to an unlocked device
- **Insecure OS clipboard**: Other apps can read clipboard before auto-clear
- **SSD secure deletion**: Wear leveling may retain deleted data
- **Backup theft without password**: Encrypted backups resist this; plaintext exports do not
