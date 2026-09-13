"""
Backup and restore — encrypted vault backup.

Backup format (JSON, encrypted with AES-256-GCM):
{
    "format": "securevault_backup",
    "version": 1,
    "app_version": "1.0.0",
    "created_at": "...",
    "vault_id": "...",
    "key_material": { ... },   // VaultKeyMaterial
    "categories": [ ... ],
    "entries": [ ... ],        // Encrypted vault entry blobs
    "checksum": "sha256:..."
}

The backup file is:
1. Serialized to JSON
2. Encrypted with a password-derived key (for password-protected backups)
   OR encrypted with the vault DEK (for vault-internal backups)
3. Written to disk

Security: The encrypted backup cannot be read without either the master password
or the backup password if one was set separately.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from config.settings import BACKUP_DIR
from core.crypto.encryption import decrypt, encrypt
from core.crypto.kdf import generate_kdf_params, derive_key
from core.crypto.key_manager import VaultKeyMaterial
from core.database.database_manager import DatabaseManager
from core.database.db_models import DbCategory, DbPasswordHistory, DbVaultEntry, DbVaultMetadata
from core.models.vault_models import AppSettings
from core.utilities.exceptions import BackupError, IntegrityError
from core.utilities.logging_utils import get_logger, security_logger

logger = get_logger(__name__)

BACKUP_FORMAT = "securevault_backup"
BACKUP_FORMAT_VERSION = 1


class BackupManager:
    """
    Creates and restores encrypted vault backups.
    """

    def __init__(self, db_manager: DatabaseManager, backup_dir: Path = BACKUP_DIR) -> None:
        self._db = db_manager
        self._backup_dir = backup_dir

    # ------------------------------------------------------------------
    # Create backup
    # ------------------------------------------------------------------

    def create_backup(
        self,
        backup_password: str,
        backup_path: Path | None = None,
    ) -> Path:
        """
        Create an encrypted backup of the entire vault.

        Args:
            backup_password: Password to encrypt the backup (can differ from master password).
            backup_path: Optional explicit output path. Defaults to backup directory.

        Returns:
            Path to the created backup file.
        """
        self._backup_dir.mkdir(parents=True, exist_ok=True)

        if backup_path is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = self._backup_dir / f"securevault_backup_{ts}.svbak"

        # Collect all data from DB
        payload = self._collect_payload()

        # Serialize to JSON
        payload_json = json.dumps(payload, default=str).encode("utf-8")

        # Add checksum
        checksum = hashlib.sha256(payload_json).hexdigest()

        outer = {
            "format": BACKUP_FORMAT,
            "version": BACKUP_FORMAT_VERSION,
            "checksum": f"sha256:{checksum}",
            "encrypted_payload": None,  # Will be replaced
        }

        # Derive backup key from backup_password
        kdf_params = generate_kdf_params()
        backup_key = derive_key(backup_password, kdf_params)

        # Encrypt the payload
        encrypted_payload = encrypt(payload_json, backup_key, associated_data=b"backup_payload_v1")

        outer["kdf_params"] = kdf_params.to_dict()
        outer["encrypted_payload"] = encrypted_payload.hex()

        # Write atomically via temp file
        tmp_path = backup_path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(outer, f, indent=2)
            tmp_path.replace(backup_path)
        except Exception as exc:
            if tmp_path.exists():
                tmp_path.unlink()
            raise BackupError("Failed to write backup file.", detail=str(exc)) from exc

        security_logger.backup_created(str(backup_path))
        logger.info("Backup created at %s", backup_path)
        return backup_path

    def _collect_payload(self) -> dict:
        """Collect all vault data for backup."""
        with self._db.session() as session:
            meta = session.query(DbVaultMetadata).first()
            categories = session.query(DbCategory).all()
            entries = session.query(DbVaultEntry).all()

            return {
                "metadata": {
                    "vault_id": meta.vault_id if meta else "",
                    "format_version": meta.format_version if meta else 1,
                    "app_version": meta.app_version if meta else "1.0.0",
                    "key_material_json": meta.key_material_json if meta else "{}",
                    "created_at": str(meta.created_at) if meta else "",
                    "modified_at": str(meta.modified_at) if meta else "",
                },
                "categories": [
                    {"id": c.id, "name": c.name, "icon": c.icon, "color": c.color}
                    for c in categories
                ],
                "entries": [
                    {
                        "id": e.id,
                        "item_type": e.item_type,
                        "title": e.title,
                        "url": e.url,
                        "is_favorite": e.is_favorite,
                        "category_id": e.category_id,
                        "tags": e.tags,
                        "created_at": str(e.created_at),
                        "modified_at": str(e.modified_at),
                        "last_used_at": str(e.last_used_at) if e.last_used_at else None,
                        "username_enc": e.username_enc.hex() if e.username_enc else None,
                        "password_enc": e.password_enc.hex() if e.password_enc else None,
                        "notes_enc": e.notes_enc.hex() if e.notes_enc else None,
                        "totp_secret_enc": e.totp_secret_enc.hex() if e.totp_secret_enc else None,
                        "card_number_enc": e.card_number_enc.hex() if e.card_number_enc else None,
                        "card_cvv_enc": e.card_cvv_enc.hex() if e.card_cvv_enc else None,
                        "card_holder": e.card_holder,
                        "card_expiry": e.card_expiry,
                        "wifi_password_enc": e.wifi_password_enc.hex() if e.wifi_password_enc else None,
                        "wifi_ssid": e.wifi_ssid,
                        "wifi_security": e.wifi_security,
                        "custom_fields_enc": e.custom_fields_enc.hex() if e.custom_fields_enc else None,
                        "identity_first_name": e.identity_first_name,
                        "identity_last_name": e.identity_last_name,
                        "identity_email": e.identity_email,
                        "identity_phone": e.identity_phone,
                        "identity_address": e.identity_address,
                    }
                    for e in entries
                ],
            }

    # ------------------------------------------------------------------
    # Restore backup
    # ------------------------------------------------------------------

    def restore_backup(
        self,
        backup_path: Path,
        backup_password: str,
        overwrite_existing: bool = False,
    ) -> dict:
        """
        Restore a vault from an encrypted backup.

        Steps:
        1. Load and parse backup file.
        2. Verify integrity (checksum).
        3. Decrypt payload.
        4. Validate structure and version.
        5. Show metadata (caller should confirm before calling restore_apply).

        Returns:
            Metadata dict for preview before applying.
        """
        outer = self._load_and_validate_backup_file(backup_path)
        payload = self._decrypt_backup_payload(outer, backup_password)
        meta = payload.get("metadata", {})
        return {
            "vault_id": meta.get("vault_id", ""),
            "app_version": meta.get("app_version", ""),
            "created_at": meta.get("created_at", ""),
            "entry_count": len(payload.get("entries", [])),
            "category_count": len(payload.get("categories", [])),
            "_payload": payload,   # Internal: passed to restore_apply
        }

    def restore_apply(
        self,
        preview: dict,
        overwrite_existing: bool = False,
    ) -> None:
        """
        Apply a backup restore (after user confirmation).

        Creates a backup of the current vault before overwriting.
        """
        payload = preview.get("_payload")
        if not payload:
            raise BackupError("Invalid preview object.")

        # Safety: create rollback backup of current vault
        with self._db.session() as session:
            has_existing = session.query(DbVaultMetadata).first() is not None

        if has_existing and not overwrite_existing:
            raise BackupError(
                "A vault already exists. Pass overwrite_existing=True after user confirmation."
            )

        if has_existing:
            rollback_path = self._backup_dir / "pre_restore_rollback.svbak.raw"
            self._backup_dir.mkdir(parents=True, exist_ok=True)
            # Raw copy of the DB file
            try:
                import shutil
                db_path = self._db._db_path
                shutil.copy2(db_path, rollback_path)
                logger.info("Rollback backup created at %s", rollback_path)
            except Exception as exc:
                logger.warning("Could not create rollback backup: %s", exc)

        self._apply_payload(payload)
        security_logger.restore_performed(str(preview.get("vault_id", "unknown")))
        logger.info("Backup restored successfully.")

    def _apply_payload(self, payload: dict) -> None:
        """Write backup payload into the database."""
        from datetime import datetime, timezone

        def _parse_dt(s):
            if not s or s == "None":
                return None
            try:
                return datetime.fromisoformat(s)
            except Exception:
                return datetime.now(timezone.utc)

        with self._db.session() as session:
            # Clear existing data
            session.query(DbPasswordHistory).delete()
            session.query(DbVaultEntry).delete()
            session.query(DbCategory).delete()
            session.query(DbVaultMetadata).delete()
            session.commit()

            # Restore metadata
            meta = payload.get("metadata", {})
            session.add(DbVaultMetadata(
                id=1,
                vault_id=meta.get("vault_id", ""),
                format_version=int(meta.get("format_version", 1)),
                app_version=meta.get("app_version", "1.0.0"),
                created_at=_parse_dt(meta.get("created_at")) or datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
                entry_count=len(payload.get("entries", [])),
                key_material_json=meta.get("key_material_json", "{}"),
            ))

            # Restore categories
            for cat in payload.get("categories", []):
                session.add(DbCategory(
                    id=cat["id"], name=cat["name"],
                    icon=cat.get("icon", "folder"), color=cat.get("color", "#5865F2"),
                ))

            # Restore entries
            for e in payload.get("entries", []):
                db_e = DbVaultEntry(
                    id=e["id"],
                    item_type=e.get("item_type", "login"),
                    title=e.get("title", ""),
                    url=e.get("url"),
                    is_favorite=e.get("is_favorite", False),
                    category_id=e.get("category_id"),
                    tags=e.get("tags"),
                    created_at=_parse_dt(e.get("created_at")) or datetime.now(timezone.utc),
                    modified_at=_parse_dt(e.get("modified_at")) or datetime.now(timezone.utc),
                    last_used_at=_parse_dt(e.get("last_used_at")),
                    card_holder=e.get("card_holder"),
                    card_expiry=e.get("card_expiry"),
                    wifi_ssid=e.get("wifi_ssid"),
                    wifi_security=e.get("wifi_security"),
                    identity_first_name=e.get("identity_first_name"),
                    identity_last_name=e.get("identity_last_name"),
                    identity_email=e.get("identity_email"),
                    identity_phone=e.get("identity_phone"),
                    identity_address=e.get("identity_address"),
                )
                for field in ["username_enc", "password_enc", "notes_enc", "totp_secret_enc",
                              "card_number_enc", "card_cvv_enc", "wifi_password_enc", "custom_fields_enc"]:
                    hex_val = e.get(field)
                    if hex_val:
                        setattr(db_e, field, bytes.fromhex(hex_val))
                session.add(db_e)

            session.commit()

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _load_and_validate_backup_file(self, path: Path) -> dict:
        if not path.exists():
            raise BackupError(f"Backup file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                outer = json.load(f)
        except json.JSONDecodeError as exc:
            raise BackupError("Backup file is not valid JSON.", detail=str(exc)) from exc

        if outer.get("format") != BACKUP_FORMAT:
            raise BackupError("File is not a SecureVault backup.")
        if outer.get("version", 0) > BACKUP_FORMAT_VERSION:
            raise BackupError(f"Backup version {outer.get('version')} is not supported.")
        return outer

    def _decrypt_backup_payload(self, outer: dict, backup_password: str) -> dict:
        from core.crypto.kdf import KDFParams

        kdf_params = KDFParams.from_dict(outer["kdf_params"])
        backup_key = derive_key(backup_password, kdf_params)

        encrypted_hex = outer.get("encrypted_payload", "")
        if not encrypted_hex:
            raise BackupError("Backup file contains no encrypted payload.")

        try:
            encrypted = bytes.fromhex(encrypted_hex)
            payload_bytes = decrypt(encrypted, backup_key, associated_data=b"backup_payload_v1")
        except (IntegrityError, ValueError) as exc:
            raise BackupError(
                "Could not decrypt backup. Wrong password or corrupted file."
            ) from exc

        # Verify checksum
        actual_checksum = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
        expected_checksum = outer.get("checksum", "")
        if expected_checksum and actual_checksum != expected_checksum:
            raise BackupError("Backup integrity check failed. File may be corrupted.")

        return json.loads(payload_bytes.decode("utf-8"))

    def list_backups(self) -> list[Path]:
        """List available backup files, newest first."""
        if not self._backup_dir.exists():
            return []
        backups = sorted(
            self._backup_dir.glob("*.svbak"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return backups
