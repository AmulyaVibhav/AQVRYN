"""
Main vault view — sidebar navigation + content stack.
"""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.security.clipboard_manager import ClipboardManager
from core.utilities.logging_utils import get_logger
from core.vault.vault_service import VaultService
from desktop.views.dashboard_view import DashboardView
from desktop.views.settings_view import SettingsView
from desktop.views.vault_view import VaultView

logger = get_logger(__name__)


class MainView(QWidget):
    """
    Main application view with sidebar + content area.
    """

    lock_requested = pyqtSignal()

    def __init__(
        self,
        vault_service: VaultService,
        clipboard: ClipboardManager,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._vault = vault_service
        self._clipboard = clipboard
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar
        sidebar = self._build_sidebar()
        layout.addWidget(sidebar)

        # Content stack
        self._content_stack = QStackedWidget()
        self._dashboard = DashboardView(self._vault, self)
        self._vault_view = VaultView(self._vault, self._clipboard, self)
        self._settings_view = SettingsView(self._vault, self)

        self._content_stack.addWidget(self._dashboard)
        self._content_stack.addWidget(self._vault_view)
        self._content_stack.addWidget(self._settings_view)

        layout.addWidget(self._content_stack)

        self._settings_view.vault_locked.connect(self.lock_requested)

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #181825;
                border-right: 1px solid #313244;
            }
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 20, 12, 20)
        layout.setSpacing(4)

        # App name
        app_label = QLabel("🔐 SecureVault")
        app_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #89b4fa; padding: 8px 4px;")
        layout.addWidget(app_label)
        layout.addSpacing(16)

        # Nav buttons
        self._nav_btns = []
        nav_items = [
            ("🏠  Dashboard", 0),
            ("🔑  Vault",     1),
            ("⚙️  Settings",  2),
        ]
        for label, idx in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("navBtn")
            btn.setStyleSheet("""
                QPushButton#navBtn {
                    background-color: transparent;
                    color: #cdd6f4;
                    text-align: left;
                    padding: 10px 12px;
                    border-radius: 8px;
                    font-size: 13px;
                }
                QPushButton#navBtn:hover { background-color: #313244; }
                QPushButton#navBtn:checked {
                    background-color: #313244;
                    color: #89b4fa;
                    font-weight: bold;
                }
            """)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=idx: self._switch_tab(i))
            layout.addWidget(btn)
            self._nav_btns.append(btn)

        layout.addStretch()

        # Lock button
        lock_btn = QPushButton("🔒  Lock Vault")
        lock_btn.setObjectName("danger")
        lock_btn.clicked.connect(self.lock_requested)
        layout.addWidget(lock_btn)

        self._nav_btns[0].setChecked(True)
        return sidebar

    def _switch_tab(self, index: int) -> None:
        self._content_stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_btns):
            btn.setChecked(i == index)

    def refresh(self) -> None:
        """Refresh all views when vault is unlocked."""
        self._dashboard.refresh()
        self._vault_view.refresh()
        self._switch_tab(0)
