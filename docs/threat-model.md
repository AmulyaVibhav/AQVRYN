# Threat Model

## Scope

This document describes the threats SecureVault is designed to protect against, and those it explicitly does not protect against.

## Assets Being Protected

1. Master password (never stored)
2. Vault encryption keys (KEK, DEK — RAM-only while unlocked)
3. Vault entries (passwords, usernames, notes, TOTP secrets)
4. Password history
5. Backup files

## Trust Boundaries

```
User ──► SecureVault Application ──► SQLite Database (encrypted fields)
                │
                ▼
           Backup Files (encrypted)
                │
                ▼
         (Optional) Import/Export files (plaintext — user responsibility)
```

## Threat Matrix

### T1: Database Theft
**Scenario**: Attacker obtains the SQLite database file.

**Protection**: All sensitive fields encrypted with AES-256-GCM using a key that requires the master password to derive. Without the master password, the database is useless.

**Residual Risk**: The attacker can perform offline brute-force against the Argon2id-protected key. High memory cost (64 MiB) significantly impedes GPU-based attacks.

---

### T2: Offline Brute-Force Attack
**Scenario**: Attacker has the database and attempts to brute-force the master password.

**Protection**: Argon2id with memory_cost=64MiB, time=3, parallelism=4. A modern GPU cluster would require significant time/cost per guess.

**Recommendation**: Use a strong, unique master password (>16 characters, mixed types). A weak master password (e.g., "password123") can be cracked regardless of KDF strength.

---

### T3: Tampered Vault
**Scenario**: Attacker modifies the database file.

**Protection**: AES-256-GCM authentication tag. Any modification — even a single bit — causes `InvalidTag` and the application reports `IntegrityError`.

---

### T4: Backup Theft
**Scenario**: Attacker steals a backup file.

**Protection**: Backup files are encrypted with AES-256-GCM using a key derived from a backup password. Without the backup password, the file is unusable.

---

### T5: Clipboard Hijacking
**Scenario**: A malicious application monitors the clipboard.

**Protection**: Auto-clear clipboard after configurable timeout (default 30 seconds). **Limitation**: This is a mitigation only — any app with clipboard access can read during the window.

---

### T6: Shoulder Surfing
**Protection**: Passwords hidden by default, show/hide toggle. Consider screen privacy filters for sensitive environments.

---

### T7: Phishing / Autofill Abuse
**Protection**: Manual credential entry. The current version does not implement automatic fill — users must explicitly copy/paste. Future autofill must use exact domain matching.

---

### T8: Weak Master Password
**Protection**: Minimum length enforcement (8 chars). Recommend passphrase-based passwords.

**Note**: No policy can force a user to choose a strong password. Security awareness is essential.

---

### T9: Memory Exposure
**Scenario**: Memory dump or swap file contains decrypted vault data.

**Protection**: Keys zeroed on lock (best-effort). Vault locked on app close.

**Limitation**: Python garbage collector provides no guarantees. Swapping to disk may contain decrypted data on heavily loaded systems.

---

### T10: Malicious Import Files
**Protection**: All import paths use Python's built-in CSV/JSON parsers; no binary deserialization. SQL injection prevented via SQLAlchemy ORM parameterized queries.

---

### T11: Logging Credential Leak
**Protection**: Custom `ScrubFilter` applied to all log handlers. Regex patterns redact any value following `password=`, `secret=`, `token=`, `key=` patterns. Tested explicitly in security test suite.

---

## Non-Goals (Out of Scope)

| Threat | Reason Out of Scope |
|--------|---------------------|
| Compromised OS (root access) | Cannot protect against privileged OS access |
| Hardware keyloggers | Pre-application capture; no software mitigation |
| Biometric spoofing | Platform-dependent; biometric is advisory |
| Server-side attacks | No server component in current version |
| Cryptographic algorithm breaks | AES-256-GCM and Argon2id are considered secure; library updates required if broken |
| Side-channel attacks on encryption | Requires hardware-level protections |
