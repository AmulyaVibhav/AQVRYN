# SecureVault — Secure Password Manager

A production-quality, open-source password manager built in Python with a focus on cryptographic security, correctness, and usability.

## Features

- **AES-256-GCM** authenticated encryption for all sensitive vault data
- **Argon2id** key derivation (OWASP-recommended parameters)
- **Two-level key hierarchy** (KEK + DEK) — master password changes don't require re-encrypting the vault
- **SQLite database** with fully encrypted sensitive fields
- **TOTP / 2FA** support (RFC 6238 compliant)
- **Password generator** with strength analysis (zxcvbn)
- **Security audit** — weak, reused, old password detection
- **Breach checking** (k-anonymity via HIBP — never sends plaintext)
- **Encrypted backups** with integrity verification
- **Import/Export** — CSV, JSON, Bitwarden-compatible formats
- **Auto-lock** with configurable inactivity timeout
- **Clipboard auto-clear** after configurable timeout
- **Password history** (configurable retention)
- **Cross-platform desktop** UI (PyQt6 — Windows, Linux, macOS)
- **Android architecture** documented (buildozer/Kivy-based)
- **Zero-knowledge design** — server never sees plaintext

## Quick Start

### 1. Install dependencies

```bash
cd password_manager
python -m venv .venv

# Windows:
.venv\Scripts\activate

# Linux/macOS:
source .venv/bin/activate

pip install -e ".[dev]"
```

### 2. Run the desktop application

```bash
python main.py
```

### 3. Run tests

```bash
pytest tests/ -v
```

### 4. Run linter / type-checker

```bash
ruff check .
mypy .
```

## Security Architecture

```
Master Password
      │
      ▼
  Argon2id (memory=64MiB, time=3, parallelism=4, salt=256-bit)
      │
      ▼
Key Encryption Key (KEK) ──► kept in memory only while vault is unlocked
      │
      ▼ (AES-256-GCM wrapping)
Data Encryption Key (DEK) ──► stored as encrypted blob in vault header
      │
      ▼ (AES-256-GCM per field)
Encrypted Vault Data ──────► stored in SQLite database
```

See [docs/security.md](docs/security.md) and [docs/cryptography.md](docs/cryptography.md) for full details.

## Project Structure

```
password_manager/
├── config/               Configuration and crypto constants
├── core/
│   ├── authentication/   Brute-force protection, lockout
│   ├── backup/           Encrypted backup/restore
│   ├── crypto/           AES-GCM, Argon2id, key manager, secure random
│   ├── database/         SQLAlchemy ORM, migrations, integrity checks
│   ├── generator/        Cryptographically secure password generator
│   ├── import_export/    CSV, JSON, Bitwarden import/export
│   ├── models/           Pydantic data models
│   ├── security/         Audit, auto-lock, clipboard manager
│   ├── totp/             RFC 6238 TOTP support
│   ├── utilities/        Exceptions, logging
│   └── vault/            Vault service, repository
├── desktop/              PyQt6 desktop application
│   ├── application/      App entry point, dark theme
│   ├── views/            Login, dashboard, vault, settings
│   └── widgets/          Password field, strength indicator
├── android/              Android build documentation
├── tests/
│   ├── unit/             Crypto, generator, TOTP tests
│   ├── integration/      Vault CRUD, backup, import/export
│   └── security/         SQL injection, tamper detection, log leakage
├── docs/                 Comprehensive documentation
├── scripts/              Build and packaging scripts
├── main.py               Desktop entry point
└── pyproject.toml        Dependencies and build config
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| UI | PyQt6 |
| Database | SQLite via SQLAlchemy 2.x |
| Encryption | AES-256-GCM (`cryptography` library) |
| KDF | Argon2id (`argon2-cffi`) |
| TOTP | `pyotp` |
| Strength analysis | `zxcvbn` |
| Validation | Pydantic v2 |
| Testing | pytest + pytest-cov |
| Linting | ruff |
| Type checking | mypy |

## License

MIT License. See [LICENSE](LICENSE).
