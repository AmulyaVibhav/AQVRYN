"""
Clipboard manager — secure clipboard operations with auto-clear.

Features:
- Copy to clipboard
- Configurable timeout (auto-clear)
- Clear clipboard
- Cross-platform via pyperclip

Never stores passwords in logs.
"""
from __future__ import annotations

import threading

import pyperclip

from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


class ClipboardManager:
    """
    Manages secure clipboard operations.

    The clipboard is automatically cleared after the configured timeout
    to reduce the risk of clipboard hijacking by other applications.

    LIMITATION: Clipboard security cannot be guaranteed on all platforms.
    Other applications may read the clipboard before it is cleared.
    This manager provides a best-effort mitigation only.
    """

    def __init__(self, clear_after_seconds: int = 30) -> None:
        self._clear_after = clear_after_seconds
        self._timer: threading.Timer | None = None
        self._copied_value: str | None = None   # Not logged, not persisted

    def copy(self, value: str, clear_after: int | None = None) -> None:
        """
        Copy a value to the system clipboard and schedule auto-clear.

        Args:
            value: The value to copy (e.g., password). Never logged.
            clear_after: Override the default clear timeout (seconds).
                         Pass 0 to disable auto-clear.
        """
        timeout = clear_after if clear_after is not None else self._clear_after

        # Cancel existing timer
        self._cancel_timer()

        try:
            pyperclip.copy(value)
            self._copied_value = value
            logger.debug("Value copied to clipboard.")
        except Exception as exc:
            logger.warning("Clipboard copy failed: %s", exc)
            return

        if timeout > 0:
            self._timer = threading.Timer(timeout, self._clear)
            self._timer.daemon = True
            self._timer.start()
            logger.debug("Clipboard will be cleared in %ds.", timeout)

    def clear(self) -> None:
        """Immediately clear the clipboard."""
        self._cancel_timer()
        self._clear()

    def _clear(self) -> None:
        try:
            pyperclip.copy("")
            self._copied_value = None
            logger.debug("Clipboard cleared.")
        except Exception as exc:
            logger.debug("Clipboard clear failed: %s", exc)

    def _cancel_timer(self) -> None:
        if self._timer and self._timer.is_alive():
            self._timer.cancel()
            self._timer = None

    def update_timeout(self, seconds: int) -> None:
        """Update the default clear timeout."""
        self._clear_after = seconds
