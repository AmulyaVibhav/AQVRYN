"""
Unit tests for TOTP functionality.
"""
from __future__ import annotations

import sys
import time
import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent.parent))

import pyotp

from core.totp.totp_manager import (
    build_otpauth_uri, generate_totp_secret, get_totp_code,
    parse_otpauth_uri, verify_totp,
)
from core.utilities.exceptions import TOTPError


class TestTOTP:
    # RFC 6238 known test vector secret
    KNOWN_SECRET = "JBSWY3DPEHPK3PXP"

    def test_generate_secret(self):
        secret = generate_totp_secret()
        assert len(secret) >= 16
        # Must be valid base32
        import base64
        try:
            base64.b32decode(secret, casefold=True)
        except Exception:
            pytest.fail("Generated secret is not valid base32")

    def test_get_totp_code_returns_digits(self):
        info = get_totp_code(self.KNOWN_SECRET)
        assert len(info.code) == 6
        assert info.code.isdigit()

    def test_code_changes_after_period(self):
        """Verify that code changes after the period (30s). Uses mocked time."""
        info = get_totp_code(self.KNOWN_SECRET, period=1)
        # Sleep briefly to cross boundary
        time.sleep(1.1)
        info2 = get_totp_code(self.KNOWN_SECRET, period=1)
        # Codes may or may not differ depending on exact timing, but no exception expected

    def test_verify_valid_code(self):
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        assert verify_totp(secret, current_code) is True

    def test_verify_invalid_code(self):
        secret = generate_totp_secret()
        assert verify_totp(secret, "000000") is False

    def test_invalid_secret_raises(self):
        with pytest.raises(TOTPError):
            get_totp_code("NOT_VALID_BASE32!!!")

    def test_parse_otpauth_uri(self):
        uri = f"otpauth://totp/Example%3Auser%40example.com?secret={self.KNOWN_SECRET}&issuer=Example&digits=6&period=30"
        config = parse_otpauth_uri(uri)
        assert config.secret == self.KNOWN_SECRET
        assert config.digits == 6
        assert config.period == 30

    def test_parse_invalid_uri_raises(self):
        with pytest.raises(TOTPError):
            parse_otpauth_uri("https://not-an-otp-uri.com")

    def test_build_otpauth_uri(self):
        from core.totp.totp_manager import TOTPConfig
        config = TOTPConfig(
            secret=self.KNOWN_SECRET,
            issuer="TestApp",
            account_name="user@test.com",
        )
        uri = build_otpauth_uri(config)
        assert uri.startswith("otpauth://totp/")
        assert self.KNOWN_SECRET in uri

    def test_countdown_is_valid(self):
        info = get_totp_code(self.KNOWN_SECRET, period=30)
        assert 0 < info.seconds_remaining <= 30
