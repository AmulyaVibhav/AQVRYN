"""
Auto-lock manager — configurable vault locking after inactivity.

Runs a background thread that fires a lock callback after the configured
inactivity timeout. The timer resets on every user activity event.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable

from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


class AutoLockManager:
    """
    Manages automatic vault locking on inactivity.

    Usage:
        mgr = AutoLockManager(timeout_seconds=300, lock_callback=vault.lock)
        mgr.start()
        mgr.activity()  # call on any user interaction
        mgr.stop()
    """

    def __init__(
        self,
        timeout_seconds: int,
        lock_callback: Callable[[], None],
    ) -> None:
        self._timeout = timeout_seconds
        self._lock_callback = lock_callback
        self._last_activity = time.monotonic()
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the auto-lock background thread."""
        if self._timeout <= 0:
            logger.info("Auto-lock disabled (timeout=0).")
            return
        self._running = True
        self._stop_event.clear()
        self._last_activity = time.monotonic()
        self._thread = threading.Thread(
            target=self._monitor, name="AutoLockMonitor", daemon=True
        )
        self._thread.start()
        logger.info("Auto-lock started (timeout=%ds).", self._timeout)

    def stop(self) -> None:
        """Stop the auto-lock monitor."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info("Auto-lock stopped.")

    def activity(self) -> None:
        """Reset the inactivity timer (call on any user interaction)."""
        self._last_activity = time.monotonic()

    def update_timeout(self, timeout_seconds: int) -> None:
        """Update the inactivity timeout without restarting."""
        self._timeout = timeout_seconds
        if timeout_seconds <= 0:
            self.stop()

    def _monitor(self) -> None:
        while not self._stop_event.wait(timeout=5):  # Check every 5 seconds
            if self._timeout <= 0:
                continue
            elapsed = time.monotonic() - self._last_activity
            if elapsed >= self._timeout:
                logger.info("Auto-lock triggered after %ds inactivity.", int(elapsed))
                try:
                    self._lock_callback()
                except Exception as exc:
                    logger.error("Auto-lock callback failed: %s", exc)
                # Wait for activity restart or stop
                self._stop_event.wait(timeout=self._timeout)
