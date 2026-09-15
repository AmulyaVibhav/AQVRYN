"""
Desktop application entry point and main window controller.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow, QStackedWidget

# Add project root to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import APP_NAME, APP_VERSION, LOG_DIR, LOG_LEVEL
from core.security.auto_lock import AutoLockManager
from core.security.clipboard_manager import ClipboardManager
from core.utilities.logging_utils import configure_logging, get_logger
from core.vault.vault_service import VaultService
from desktop.views.login_view import LoginView
from desktop.views.main_view import MainView

logger = get_logger(__name__)


class PasswordManagerApp(QMainWindow):
    """Main application window — manages the view stack."""

    def __init__(self, vault_service: VaultService) -> None:
        super().__init__()
        self._vault = vault_service
        self._clipboard = ClipboardManager()
        self._auto_lock = AutoLockManager(
            timeout_seconds=vault_service.get_settings().auto_lock_seconds,
            lock_callback=self._on_auto_lock,
        )

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(900, 650)

        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)

        self._login_view = LoginView(vault_service, self)
        self._main_view = MainView(vault_service, self._clipboard, self)

        self._stack.addWidget(self._login_view)
        self._stack.addWidget(self._main_view)

        # Connect signals
        self._login_view.login_successful.connect(self._on_login_success)
        self._main_view.lock_requested.connect(self._on_lock_requested)

        # Show correct initial view
        if vault_service.vault_exists():
            self._stack.setCurrentWidget(self._login_view)
        else:
            self._stack.setCurrentWidget(self._login_view)

        self._auto_lock.start()

    def _on_login_success(self) -> None:
        """Called when the user successfully unlocks or creates the vault."""
        self._main_view.refresh()
        self._stack.setCurrentWidget(self._main_view)
        settings = self._vault.get_settings()
        self._auto_lock.update_timeout(settings.auto_lock_seconds)
        self._clipboard.update_timeout(settings.clipboard_clear_seconds)

    def _on_lock_requested(self) -> None:
        self._vault.lock()
        self._clipboard.clear()
        self._stack.setCurrentWidget(self._login_view)
        self._login_view.reset()

    def _on_auto_lock(self) -> None:
        """Called by auto-lock timer."""
        if not self._vault.is_locked:
            logger.info("Auto-lock triggered.")
            self._vault.lock("auto_lock")
            self._clipboard.clear()
            # Switch to login view on main thread
            QTimer.singleShot(0, self._switch_to_login)

    def _switch_to_login(self) -> None:
        self._stack.setCurrentWidget(self._login_view)
        self._login_view.reset()
        self._login_view.show_message("Vault locked due to inactivity.", error=False)

    def mousePressEvent(self, event) -> None:
        self._auto_lock.activity()
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:
        self._auto_lock.activity()
        super().keyPressEvent(event)

    def closeEvent(self, event) -> None:
        self._auto_lock.stop()
        self._clipboard.clear()
        self._vault.lock("application_close")
        super().closeEvent(event)


def main() -> None:
    """Desktop application entry point."""
    configure_logging(LOG_DIR, LOG_LEVEL)
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    # Apply dark theme stylesheet
    app.setStyleSheet(_DARK_THEME)

    vault_service = VaultService()
    vault_service.initialize()

    window = PasswordManagerApp(vault_service)
    window.show()

    sys.exit(app.exec())


# ---------------------------------------------------------------------------
# Dark theme stylesheet
# ---------------------------------------------------------------------------

_DARK_THEME = """
QMainWindow, QDialog, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 13px;
}
QPushButton {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
    min-height: 32px;
}
QPushButton:hover { background-color: #b4befe; }
QPushButton:pressed { background-color: #74c7ec; }
QPushButton:disabled { background-color: #45475a; color: #6c7086; }
QPushButton#danger {
    background-color: #f38ba8;
    color: #1e1e2e;
}
QPushButton#secondary {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
}
QPushButton#secondary:hover { background-color: #45475a; }
QLineEdit {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 8px 12px;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
}
QLineEdit:focus { border-color: #89b4fa; }
QListWidget {
    background-color: #181825;
    border: none;
    border-radius: 6px;
}
QListWidget::item {
    padding: 10px 14px;
    border-radius: 4px;
    margin: 2px 4px;
}
QListWidget::item:selected {
    background-color: #313244;
    color: #cdd6f4;
}
QListWidget::item:hover { background-color: #2a2a3d; }
QLabel { color: #cdd6f4; }
QLabel#title { font-size: 18px; font-weight: bold; color: #89b4fa; }
QLabel#subtitle { font-size: 13px; color: #6c7086; }
QLabel#error { color: #f38ba8; }
QLabel#success { color: #a6e3a1; }
QTextEdit {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 8px;
    color: #cdd6f4;
}
QComboBox {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 6px 10px;
    color: #cdd6f4;
    min-height: 28px;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background-color: #313244; color: #cdd6f4; }
QScrollBar:vertical {
    background-color: #1e1e2e;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background-color: #45475a;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background-color: #6c7086; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator {
    width: 18px; height: 18px;
    border-radius: 4px;
    border: 1px solid #45475a;
    background-color: #313244;
}
QCheckBox::indicator:checked {
    background-color: #89b4fa;
    border-color: #89b4fa;
}
QSpinBox {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 6px 10px;
    color: #cdd6f4;
}
QTabWidget::pane { border: 1px solid #45475a; border-radius: 6px; }
QTabBar::tab {
    background-color: #313244;
    color: #6c7086;
    padding: 8px 20px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTabBar::tab:selected { background-color: #1e1e2e; color: #cdd6f4; }
QSplitter::handle { background-color: #45475a; width: 1px; }
QProgressBar {
    background-color: #313244;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}
QProgressBar::chunk { background-color: #89b4fa; border-radius: 4px; }
"""
