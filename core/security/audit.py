"""
Security auditor — analyzes vault entries for security weaknesses.

Checks:
- Weak passwords (zxcvbn score < 2)
- Reused passwords (same password across multiple entries)
- Old passwords (not changed in >180 days)
- Missing usernames
- Missing URLs
- Duplicate entries (same title + username)

Does NOT send passwords to any external service.
Breach checking uses k-anonymity (HIBP API) if enabled.
"""
from __future__ import annotations

import hashlib
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

from core.models.vault_models import SecurityAuditResult, VaultEntry
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)

OLD_PASSWORD_DAYS = 180  # Passwords older than this are flagged


class SecurityAuditor:
    """
    Performs a comprehensive security audit of vault entries.
    All analysis is performed locally; no plaintext leaves the device.
    """

    def audit(self, entries: list[VaultEntry]) -> SecurityAuditResult:
        """Run all security checks and return a consolidated result."""
        result = SecurityAuditResult(total_entries=len(entries))

        if not entries:
            result.security_score = 100
            return result

        self._check_weak_passwords(entries, result)
        self._check_reused_passwords(entries, result)
        self._check_old_passwords(entries, result)
        self._check_missing_fields(entries, result)
        self._check_duplicates(entries, result)
        result.compute_score()

        logger.info(
            "Security audit complete: score=%d, weak=%d, reused=%d, old=%d",
            result.security_score,
            len(result.weak_passwords),
            len(result.reused_passwords),
            len(result.old_passwords),
        )
        return result

    def _check_weak_passwords(
        self, entries: list[VaultEntry], result: SecurityAuditResult
    ) -> None:
        from core.generator.password_generator import estimate_strength
        from core.models.vault_models import PasswordStrength

        for entry in entries:
            if not entry.password:
                continue
            try:
                strength = estimate_strength(entry.password)
                if strength.score < 2:  # very_weak or weak
                    result.weak_passwords.append(entry.id)
            except Exception:
                pass

    def _check_reused_passwords(
        self, entries: list[VaultEntry], result: SecurityAuditResult
    ) -> None:
        """
        Group entries that share the same password.
        Comparison uses SHA-256 hashes of passwords to avoid holding
        multiple plaintext copies in memory longer than necessary.
        """
        pw_hash_map: dict[str, list[str]] = {}
        for entry in entries:
            if not entry.password:
                continue
            # Use SHA-256 for grouping — note: this is for LOCAL comparison only,
            # not for storage. The plaintext is decrypted from the vault already.
            pw_hash = hashlib.sha256(entry.password.encode()).hexdigest()
            pw_hash_map.setdefault(pw_hash, []).append(entry.id)

        for ids in pw_hash_map.values():
            if len(ids) > 1:
                result.reused_passwords.append(ids)

    def _check_old_passwords(
        self, entries: list[VaultEntry], result: SecurityAuditResult
    ) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=OLD_PASSWORD_DAYS)
        for entry in entries:
            if not entry.password:
                continue
            ts = entry.modified_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                result.old_passwords.append(entry.id)

    def _check_missing_fields(
        self, entries: list[VaultEntry], result: SecurityAuditResult
    ) -> None:
        for entry in entries:
            if not entry.username:
                result.missing_usernames.append(entry.id)
            if not entry.url:
                result.missing_urls.append(entry.id)

    def _check_duplicates(
        self, entries: list[VaultEntry], result: SecurityAuditResult
    ) -> None:
        """Flag entries with identical title + username combinations."""
        seen: dict[str, list[str]] = {}
        for entry in entries:
            key = f"{entry.title.lower()}|{entry.username.lower()}"
            seen.setdefault(key, []).append(entry.id)
        for ids in seen.values():
            if len(ids) > 1:
                result.duplicate_entries.append(ids)


# ---------------------------------------------------------------------------
# k-Anonymity breach check (Have I Been Pwned)
# ---------------------------------------------------------------------------

def check_password_breach(password: str) -> int:
    """
    Check if a password appears in known breaches using k-anonymity.

    Sends only the first 5 hex characters of SHA-1 hash to HIBP.
    The full hash never leaves the device.

    Returns: Number of times found in breaches (0 = not found or API unavailable).
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SecureVault-PasswordManager/1.0", "Add-Padding": "true"},
        )
        with urllib.request.urlopen(req, timeout=5) as response:  # noqa: S310
            body = response.read().decode("utf-8")

        for line in body.splitlines():
            if ":" in line:
                hash_suffix, count = line.split(":", 1)
                if hash_suffix.upper() == suffix:
                    return int(count)
        return 0
    except Exception as exc:
        logger.debug("Breach check unavailable: %s", exc)
        return 0
