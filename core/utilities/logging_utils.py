"""
Structured security logging — never logs secrets.

Safe to log: events, timestamps, IDs, error types.
Never log: passwords, keys, tokens, secrets, master password.
"""
from __future__ import annotations

import logging
import logging.handlers
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Secret scrubber — last-resort defence against accidental secret logging
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(password\s*[=:]\s*)[^\s,;]+', re.IGNORECASE),
    re.compile(r'(master_pass\w*\s*[=:]\s*)[^\s,;]+', re.IGNORECASE),
    re.compile(r'(secret\s*[=:]\s*)[^\s,;]+', re.IGNORECASE),
    re.compile(r'(token\s*[=:]\s*)[^\s,;]+', re.IGNORECASE),
    re.compile(r'(key\s*[=:]\s*)[0-9a-fA-F]{16,}', re.IGNORECASE),
]


def _scrub(message: str) -> str:
    for pattern in _SECRET_PATTERNS:
        message = pattern.sub(r'\1[REDACTED]', message)
    return message


class _ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _scrub(str(record.msg))
        record.args = None  # prevent format-string injection of secrets
        return True


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

def get_logger(name: str) -> logging.Logger:
    """Return a logger that never emits secret values."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addFilter(_ScrubFilter())
    return logger


def configure_logging(log_dir: Path, level: str = "INFO") -> None:
    """Configure root logging: console + rotating file handler."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"securevault_{datetime.now(timezone.utc).strftime('%Y%m%d')}.log"

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.addFilter(_ScrubFilter())
    root.addHandler(ch)

    # Rotating file handler — 5 MB × 10 files
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    fh.addFilter(_ScrubFilter())
    root.addHandler(fh)


# ---------------------------------------------------------------------------
# Security event logger — structured audit trail
# ---------------------------------------------------------------------------

class SecurityEventLogger:
    """Logs security-relevant events with structured fields, no secrets."""

    def __init__(self) -> None:
        self._log = get_logger("security.audit")

    def _emit(self, event: str, **fields: Any) -> None:
        safe_fields = {k: v for k, v in fields.items() if "pass" not in k.lower()
                       and "key" not in k.lower() and "secret" not in k.lower()
                       and "token" not in k.lower()}
        parts = " | ".join(f"{k}={v}" for k, v in safe_fields.items())
        self._log.info("[%s] %s", event, parts)

    def vault_unlocked(self) -> None:
        self._emit("VAULT_UNLOCKED", ts=_ts())

    def vault_locked(self, reason: str = "manual") -> None:
        self._emit("VAULT_LOCKED", reason=reason, ts=_ts())

    def auth_failed(self, attempts: int) -> None:
        self._emit("AUTH_FAILED", attempts=attempts, ts=_ts())

    def auth_locked_out(self, duration_s: int) -> None:
        self._emit("AUTH_LOCKED_OUT", duration_s=duration_s, ts=_ts())

    def entry_created(self, entry_id: str) -> None:
        self._emit("ENTRY_CREATED", entry_id=entry_id, ts=_ts())

    def entry_updated(self, entry_id: str) -> None:
        self._emit("ENTRY_UPDATED", entry_id=entry_id, ts=_ts())

    def entry_deleted(self, entry_id: str) -> None:
        self._emit("ENTRY_DELETED", entry_id=entry_id, ts=_ts())

    def backup_created(self, path: str) -> None:
        self._emit("BACKUP_CREATED", path=path, ts=_ts())

    def restore_performed(self, path: str) -> None:
        self._emit("RESTORE_PERFORMED", path=path, ts=_ts())

    def import_performed(self, count: int, source: str) -> None:
        self._emit("IMPORT_PERFORMED", count=count, source=source, ts=_ts())

    def export_performed(self, count: int, fmt: str) -> None:
        self._emit("EXPORT_PERFORMED", count=count, format=fmt, ts=_ts())

    def master_password_changed(self) -> None:
        self._emit("MASTER_PASSWORD_CHANGED", ts=_ts())


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# Module-level singleton
security_logger = SecurityEventLogger()
