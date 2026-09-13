"""
TOTP (Time-based One-Time Password) — RFC 6238 compliant.

Uses pyotp for TOTP generation and validation.
TOTP secrets are stored encrypted in the vault.

Features:
- Generate current OTP
- Countdown to next code
- Verify OTP
- Parse otpauth:// URIs
"""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass

import pyotp

from core.utilities.exceptions import TOTPError
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class TOTPInfo:
    """Current TOTP state."""
    code: str               # Current 6-digit (or configured) OTP
    seconds_remaining: int  # Seconds until next code
    period: int             # TOTP period (default 30)
    digits: int             # Code length (default 6)


@dataclass
class TOTPConfig:
    """TOTP configuration parameters."""
    secret: str
    issuer: str = ""
    account_name: str = ""
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


def get_totp_code(secret: str, digits: int = 6, period: int = 30) -> TOTPInfo:
    """
    Generate the current TOTP code for a given secret.

    Args:
        secret: Base32-encoded TOTP secret (stored encrypted in vault).
        digits: OTP length (typically 6).
        period: TOTP period in seconds (typically 30).

    Returns:
        TOTPInfo with current code and remaining seconds.

    Raises:
        TOTPError: If the secret is invalid.
    """
    try:
        totp = pyotp.TOTP(secret, digits=digits, interval=period)
        code = totp.now()
        # Calculate seconds remaining in the current period
        now = time.time()
        seconds_remaining = period - int(now % period)
        return TOTPInfo(
            code=code,
            seconds_remaining=seconds_remaining,
            period=period,
            digits=digits,
        )
    except Exception as exc:
        raise TOTPError("Failed to generate TOTP code. Check the secret.", detail=str(exc)) from exc


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code against the secret.

    Args:
        secret: Base32 TOTP secret.
        code: The code to verify.
        window: Number of periods before/after to check (for clock skew).

    Returns:
        True if valid, False otherwise.
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=window)
    except Exception:
        return False


def parse_otpauth_uri(uri: str) -> TOTPConfig:
    """
    Parse an otpauth:// URI (e.g., from a QR code).

    Format: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER&digits=6&period=30

    Raises:
        TOTPError: If the URI is invalid.
    """
    try:
        if not uri.startswith("otpauth://totp/"):
            raise TOTPError("Only TOTP (otpauth://totp/) URIs are supported.")

        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)

        secret = params.get("secret", [""])[0]
        if not secret:
            raise TOTPError("TOTP URI missing 'secret' parameter.")

        issuer = params.get("issuer", [""])[0]
        digits = int(params.get("digits", ["6"])[0])
        period = int(params.get("period", ["30"])[0])
        algorithm = params.get("algorithm", ["SHA1"])[0].upper()

        # Parse label (path component)
        label = urllib.parse.unquote(parsed.path.lstrip("/"))
        account_name = label
        if ":" in label:
            _, account_name = label.split(":", 1)

        return TOTPConfig(
            secret=secret.upper().replace(" ", ""),
            issuer=issuer,
            account_name=account_name,
            digits=digits,
            period=period,
            algorithm=algorithm,
        )
    except TOTPError:
        raise
    except Exception as exc:
        raise TOTPError("Failed to parse OTP URI.", detail=str(exc)) from exc


def generate_totp_secret() -> str:
    """Generate a new random base32 TOTP secret."""
    return pyotp.random_base32()


def build_otpauth_uri(config: TOTPConfig) -> str:
    """Build an otpauth:// URI from a TOTPConfig."""
    label = urllib.parse.quote(f"{config.issuer}:{config.account_name}" if config.issuer else config.account_name)
    params = urllib.parse.urlencode({
        "secret": config.secret,
        "issuer": config.issuer,
        "digits": config.digits,
        "period": config.period,
        "algorithm": config.algorithm,
    })
    return f"otpauth://totp/{label}?{params}"
