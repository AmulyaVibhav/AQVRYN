# Database Schema

## Overview

SecureVault uses SQLite with SQLAlchemy ORM. All queries are parameterized — no raw string concatenation with user input.

## Tables

### `vault_metadata`
Stores vault header information and encrypted key material.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Always 1 (single row) |
| vault_id | TEXT | UUID identifying this vault |
| format_version | INTEGER | Vault format version (currently 1) |
| app_version | TEXT | App version that created the vault |
| created_at | DATETIME | Vault creation timestamp (UTC) |
| modified_at | DATETIME | Last modification timestamp (UTC) |
| entry_count | INTEGER | Cached count of entries |
| key_material_json | TEXT | JSON with KDF params + wrapped DEK |

`key_material_json` structure:
```json
{
  "kdf_params": {
    "salt": "<base64>",
    "memory_cost": 65536,
    "time_cost": 3,
    "parallelism": 4,
    "hash_length": 32
  },
  "wrapped_dek": "<base64 of AES-256-GCM encrypted DEK>"
}
```

### `categories`
User-defined entry categories.

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID |
| name | TEXT | Category name |
| icon | TEXT | Icon identifier |
| color | TEXT | Hex color code |
| created_at | DATETIME | UTC |

### `vault_entries`
All vault items. Sensitive fields stored as encrypted BLOBs.

| Column | Type | Encrypted? | Description |
|--------|------|-----------|-------------|
| id | TEXT PK | No | UUID |
| item_type | TEXT | No | login/secure_note/credit_card/etc |
| title | TEXT | No | Entry title (searchable) |
| username_enc | BLOB | **Yes** | AES-256-GCM encrypted username |
| password_enc | BLOB | **Yes** | AES-256-GCM encrypted password |
| notes_enc | BLOB | **Yes** | AES-256-GCM encrypted notes |
| totp_secret_enc | BLOB | **Yes** | AES-256-GCM encrypted TOTP secret |
| card_number_enc | BLOB | **Yes** | AES-256-GCM encrypted card number |
| card_cvv_enc | BLOB | **Yes** | AES-256-GCM encrypted CVV |
| wifi_password_enc | BLOB | **Yes** | AES-256-GCM encrypted Wi-Fi password |
| custom_fields_enc | BLOB | **Yes** | AES-256-GCM encrypted JSON custom fields |
| url | TEXT | No | Website URL |
| card_holder | TEXT | No | Cardholder name |
| card_expiry | TEXT | No | Card expiry |
| wifi_ssid | TEXT | No | Wi-Fi SSID |
| category_id | TEXT FK | No | Foreign key to categories |
| tags | TEXT | No | JSON array of tags |
| is_favorite | BOOLEAN | No | Favorite flag |
| created_at | DATETIME | No | UTC |
| modified_at | DATETIME | No | UTC |
| last_used_at | DATETIME | No | UTC |

### `password_history`
Previous passwords for vault entries.

| Column | Type | Encrypted? | Description |
|--------|------|-----------|-------------|
| id | INTEGER PK | No | Auto-increment |
| entry_id | TEXT FK | No | Foreign key to vault_entries (CASCADE DELETE) |
| password_enc | BLOB | **Yes** | AES-256-GCM encrypted previous password |
| changed_at | DATETIME | No | UTC timestamp of change |

### `app_settings`
User preferences (non-sensitive).

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Always 1 |
| settings_json | TEXT | JSON-serialized AppSettings |

### `security_log`
Audit trail of security events. **Never contains secrets.**

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| event | TEXT | Event type (VAULT_UNLOCKED, AUTH_FAILED, etc.) |
| details | TEXT | Safe details — no credentials |
| timestamp | DATETIME | UTC |

### `schema_version`
Tracks applied migrations.

| Column | Type | Description |
|--------|------|-------------|
| version | INTEGER PK | Schema version number |
| applied_at | DATETIME | UTC |
| description | TEXT | Migration description |

## Encryption Scheme Per Field

Each encrypted blob uses a unique encryption context:
- **Associated data (AAD)**: `f"{entry_id}:{field_name}"` — binds ciphertext to specific field + entry
- This prevents cross-entry ciphertext transplantation attacks

## Indexes

- `idx_vault_entries_category` — fast category filtering
- `idx_vault_entries_favorite` — fast favorites query
- `idx_vault_entries_type` — fast item type filtering
- `idx_vault_entries_modified` — fast recent entries query
- `idx_password_history_entry` — fast history lookup
- `idx_security_log_timestamp` — fast log pruning

## Migrations

Schema changes use `DbSchemaVersion` tracking. Each migration version is defined as a method in `DatabaseManager._apply_migration()`. The migration framework ensures:
- Migrations are applied exactly once
- Failed migrations are rolled back
- Version tracking is transactional
