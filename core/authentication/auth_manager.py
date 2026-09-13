"""
Authentication manager — tracks failed attempts, enforces lockout, manages session state.
"""
from __future__ import annotations

import time
from threading import Lock

from config.settings import LOCKOUT_DURATION_SECONDS, MAX_FAILED_ATTEMPTS
from core.utilities.exceptions import AuthenticationError
from core.utilities.logging_utils import get_logger, security_logger

logger = get_logger(__name__)


class AuthManager:
    """
    Tracks authentication state:
    - Failed attempt counter
    - Progressive delay / lockout
    - Thread-safe via a lock
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._failed_attempts = 0
        self._lockout_until: float = 0.0

    def check_lockout(self) -> None:
        """
        Raise AuthenticationError if the account is currently locked out.
        """
        with self._lock:
            if time.monotonic() < self._lockout_until:
                remaining = int(self._lockout_until - time.monotonic())
                raise AuthenticationError(
                    f"Account locked. Try again in {remaining} seconds."
                )

    def record_failed_attempt(self) -> None:
        """
        Record a failed authentication attempt.
        After MAX_FAILED_ATTEMPTS, applies a lockout.
        """
        with self._lock:
            self._failed_attempts += 1
            security_logger.auth_failed(self._failed_attempts)

            if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
                # Progressive lockout: double the duration after each cycle
                cycles = self._failed_attempts // MAX_FAILED_ATTEMPTS
                duration = LOCKOUT_DURATION_SECONDS * (2 ** (cycles - 1))
                self._lockout_until = time.monotonic() + duration
                security_logger.auth_locked_out(duration)
                logger.warning(
                    "Too many failed attempts (%d). Locked for %d seconds.",
                    self._failed_attempts, duration,
                )

    def reset_attempts(self) -> None:
        """Reset failed attempt counter on successful authentication."""
        with self._lock:
            self._failed_attempts = 0
            self._lockout_until = 0.0

    @property
    def failed_attempts(self) -> int:
        with self._lock:
            return self._failed_attempts

    @property
    def is_locked_out(self) -> bool:
        with self._lock:
            return time.monotonic() < self._lockout_until

    @property
    def lockout_remaining(self) -> int:
        """Seconds remaining in lockout, or 0 if not locked out."""
        with self._lock:
            remaining = self._lockout_until - time.monotonic()
            return max(0, int(remaining))
