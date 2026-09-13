"""
Import/Export module — CSV, JSON, Bitwarden-compatible formats.

Security requirements:
- Never write plaintext temporary files
- Warn about plaintext exports
- Validate all input before importing
- Encrypt imported data immediately
- Support preview before final import
"""
from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.models.vault_models import CustomField, ItemType, VaultEntry
from core.utilities.exceptions import ExportError
from core.utilities.exceptions import ImportError as PMImportError
from core.utilities.logging_utils import get_logger, security_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

class VaultImporter:
    """
    Import vault entries from external formats.
    All imported entries are returned as VaultEntry objects (decrypted),
    then immediately passed to VaultService.add_entry() for encryption.
    """

    def import_csv(self, file_path: Path, column_map: dict | None = None) -> list[VaultEntry]:
        """
        Import from CSV file.

        Default column mapping:
            Title, Username, Password, URL, Notes

        Args:
            file_path: Path to the CSV file.
            column_map: Optional dict mapping CSV column names to VaultEntry fields.

        Returns:
            List of VaultEntry objects (not yet persisted).

        Raises:
            PMImportError: On invalid or unreadable file.
        """
        if not file_path.exists():
            raise PMImportError(f"File not found: {file_path}")

        default_map = {
            "title": "title",
            "username": "username",
            "password": "password",
            "url": "url",
            "notes": "notes",
        }
        cmap = {k.lower(): v for k, v in (column_map or default_map).items()}

        entries: list[VaultEntry] = []
        try:
            with open(file_path, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    try:
                        # Normalize column names
                        norm_row = {k.lower().strip(): v for k, v in row.items()}
                        entry = VaultEntry(
                            title=norm_row.get(cmap.get("title", "title"), f"Imported {i+1}") or f"Imported {i+1}",
                            username=norm_row.get(cmap.get("username", "username"), ""),
                            password=norm_row.get(cmap.get("password", "password"), ""),
                            url=norm_row.get(cmap.get("url", "url"), ""),
                            notes=norm_row.get(cmap.get("notes", "notes"), ""),
                        )
                        entries.append(entry)
                    except Exception as exc:
                        logger.warning("Skipped row %d during CSV import: %s", i + 1, exc)
        except Exception as exc:
            raise PMImportError(f"Failed to read CSV file: {exc}") from exc

        logger.info("CSV import: %d entries loaded.", len(entries))
        return entries

    def import_json(self, file_path: Path) -> list[VaultEntry]:
        """
        Import from a JSON file.

        Supports SecureVault JSON format and a generic flat format.
        """
        if not file_path.exists():
            raise PMImportError(f"File not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise PMImportError(f"Invalid JSON file: {exc}") from exc

        entries: list[VaultEntry] = []

        # Handle array of objects
        items = data if isinstance(data, list) else data.get("items", data.get("entries", []))
        if not isinstance(items, list):
            raise PMImportError("JSON import: expected array of entry objects.")

        for i, item in enumerate(items):
            try:
                entry = VaultEntry(
                    title=str(item.get("title", item.get("name", f"Imported {i+1}"))),
                    username=str(item.get("username", item.get("login", {}).get("username", "") if isinstance(item.get("login"), dict) else "")),
                    password=str(item.get("password", item.get("login", {}).get("password", "") if isinstance(item.get("login"), dict) else "")),
                    url=str(item.get("url", item.get("login", {}).get("uris", [{}])[0].get("uri", "") if isinstance(item.get("login"), dict) and item.get("login", {}).get("uris") else "")),
                    notes=str(item.get("notes", "")),
                    is_favorite=bool(item.get("favorite", item.get("is_favorite", False))),
                )
                entries.append(entry)
            except Exception as exc:
                logger.warning("Skipped item %d during JSON import: %s", i + 1, exc)

        logger.info("JSON import: %d entries loaded.", len(entries))
        return entries

    def import_bitwarden_json(self, file_path: Path) -> list[VaultEntry]:
        """
        Import from Bitwarden-compatible JSON export.

        Bitwarden format:
        {
            "items": [
                {
                    "type": 1,
                    "name": "...",
                    "login": {"username": "...", "password": "...", "uris": [{"uri": "..."}]},
                    "notes": "...",
                    "favorite": false
                }
            ]
        }
        """
        if not file_path.exists():
            raise PMImportError(f"File not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise PMImportError(f"Invalid Bitwarden JSON file: {exc}") from exc

        items = data.get("items", [])
        entries: list[VaultEntry] = []

        bw_type_map = {1: ItemType.LOGIN, 2: ItemType.SECURE_NOTE, 3: ItemType.CREDIT_CARD, 4: ItemType.IDENTITY}

        for i, item in enumerate(items):
            try:
                item_type = bw_type_map.get(item.get("type", 1), ItemType.LOGIN)
                login = item.get("login") or {}
                uris = login.get("uris") or []
                url = uris[0].get("uri", "") if uris else ""

                custom_fields: list[CustomField] = []
                for field in (item.get("fields") or []):
                    cf = CustomField(
                        name=field.get("name", ""),
                        value=field.get("value", ""),
                        is_secret=field.get("type", 0) == 1,
                    )
                    custom_fields.append(cf)

                entry = VaultEntry(
                    item_type=item_type,
                    title=item.get("name", f"Imported {i+1}"),
                    username=login.get("username", ""),
                    password=login.get("password", ""),
                    url=url,
                    notes=item.get("notes", "") or "",
                    is_favorite=item.get("favorite", False),
                    totp_secret=login.get("totp", "") or "",
                    custom_fields=custom_fields,
                )
                entries.append(entry)
            except Exception as exc:
                logger.warning("Skipped Bitwarden item %d: %s", i + 1, exc)

        logger.info("Bitwarden import: %d entries loaded.", len(entries))
        return entries


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class VaultExporter:
    """
    Export vault entries to various formats.

    WARNING: CSV/JSON plaintext exports contain sensitive data!
    Always show a warning and require explicit user confirmation before calling
    plaintext export methods.
    """

    def export_csv(
        self, entries: list[VaultEntry], output_path: Path
    ) -> Path:
        """
        Export entries to CSV (PLAINTEXT — sensitive data).

        Caller MUST ensure explicit user confirmation before calling this.
        """
        try:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["Title", "Username", "Password", "URL", "Notes", "Favorite", "Tags"],
                )
                writer.writeheader()
                for entry in entries:
                    writer.writerow({
                        "Title": entry.title,
                        "Username": entry.username,
                        "Password": entry.password,
                        "URL": entry.url,
                        "Notes": entry.notes,
                        "Favorite": "yes" if entry.is_favorite else "no",
                        "Tags": ",".join(entry.tags),
                    })
        except Exception as exc:
            raise ExportError(f"CSV export failed: {exc}") from exc

        security_logger.export_performed(len(entries), "csv")
        logger.info("CSV export: %d entries exported to %s.", len(entries), output_path)
        return output_path

    def export_json(
        self, entries: list[VaultEntry], output_path: Path
    ) -> Path:
        """
        Export entries to JSON (PLAINTEXT — sensitive data).

        Caller MUST ensure explicit user confirmation before calling this.
        """
        try:
            export_data = {
                "format": "securevault_export",
                "version": 1,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": len(entries),
                "entries": [
                    {
                        "title": e.title,
                        "username": e.username,
                        "password": e.password,
                        "url": e.url,
                        "notes": e.notes,
                        "favorite": e.is_favorite,
                        "tags": e.tags,
                        "totp_secret": e.totp_secret,
                    }
                    for e in entries
                ],
            }
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)
        except Exception as exc:
            raise ExportError(f"JSON export failed: {exc}") from exc

        security_logger.export_performed(len(entries), "json")
        logger.info("JSON export: %d entries exported to %s.", len(entries), output_path)
        return output_path

    def export_bitwarden_json(
        self, entries: list[VaultEntry], output_path: Path
    ) -> Path:
        """
        Export in Bitwarden-compatible JSON format (PLAINTEXT).

        Caller MUST ensure explicit user confirmation before calling this.
        """
        bw_items = []
        for entry in entries:
            bw_item = {
                "type": 1,
                "name": entry.title,
                "notes": entry.notes,
                "favorite": entry.is_favorite,
                "login": {
                    "username": entry.username,
                    "password": entry.password,
                    "uris": [{"uri": entry.url, "match": None}] if entry.url else [],
                    "totp": entry.totp_secret or None,
                },
                "fields": [
                    {"name": cf.name, "value": cf.value, "type": 1 if cf.is_secret else 0}
                    for cf in entry.custom_fields
                ],
            }
            bw_items.append(bw_item)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump({"encrypted": False, "items": bw_items}, f, indent=2)
        except Exception as exc:
            raise ExportError(f"Bitwarden export failed: {exc}") from exc

        security_logger.export_performed(len(entries), "bitwarden_json")
        logger.info("Bitwarden export: %d entries.", len(entries))
        return output_path

    @staticmethod
    def secure_delete(path: Path) -> None:
        """
        Best-effort secure deletion of a plaintext export file.

        LIMITATION: Secure deletion cannot be guaranteed on SSDs (wear leveling),
        network filesystems, or systems with filesystem journaling.
        This overwrites the file with zeros before deletion as a mitigation.
        """
        try:
            if path.exists():
                size = path.stat().st_size
                with open(path, "wb") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
                path.unlink()
                logger.info("Securely deleted: %s", path)
        except Exception as exc:
            logger.warning("Secure delete failed for %s: %s. File may still exist.", path, exc)
