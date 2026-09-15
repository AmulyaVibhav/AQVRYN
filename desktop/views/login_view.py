"""
Login view — master password entry, vault creation.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.utilities.exceptions import AuthenticationError, ValidationError
from core.utilities.logging_utils import get_logger
from core.vault.vault_service import VaultService

logger = get_logger(__name__)


class LoginView(QWidget):
    """
    Login/Create vault screen.

    Signals:
        login_successful: Emitted after successful authentication.
    """

    login_successful = pyqtSignal()

    def __init__(self, vault_service: VaultService, parent=None) -> None:
        super().__init__(parent)
        self._vault = vault_service
        self._setup_ui()

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Card frame
        card = QFrame()
        card.setObjectName("loginCard")
        card.setFixedWidth(400)
        card.setStyleSheet("""
            QFrame#loginCard {
                background-color: #181825;
                border-radius: 16px;
                padding: 40px;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        # Logo / title
        title = QLabel("🔐 SecureVault")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #89b4fa; margin-bottom: 8px;")
        layout.addWidget(title)

        subtitle = QLabel("Your secure password manager")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        layout.addSpacing(16)

        # Password label
        self._pw_label = QLabel("Master Password")
        self._pw_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self._pw_label)

        # Password input row
        pw_row = QHBoxLayout()
        self._pw_input = QLineEdit()
        self._pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_input.setPlaceholderText("Enter master password…")
        self._pw_input.returnPressed.connect(self._on_unlock_clicked)
        pw_row.addWidget(self._pw_input)

        self._show_pw_btn = QPushButton("👁")
        self._show_pw_btn.setObjectName("secondary")
        self._show_pw_btn.setFixedWidth(40)
        self._show_pw_btn.setCheckable(True)
        self._show_pw_btn.clicked.connect(self._toggle_password_visibility)
        pw_row.addWidget(self._show_pw_btn)
        layout.addLayout(pw_row)

        # Confirm password (for vault creation)
        self._confirm_label = QLabel("Confirm Password")
        self._confirm_label.setStyleSheet("font-weight: bold;")
        self._confirm_label.setVisible(False)
        layout.addWidget(self._confirm_label)

        self._confirm_input = QLineEdit()
        self._confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_input.setPlaceholderText("Confirm master password…")
        self._confirm_input.setVisible(False)
        layout.addWidget(self._confirm_input)

        layout.addSpacing(8)

        # Primary button
        self._primary_btn = QPushButton("Unlock Vault")
        self._primary_btn.clicked.connect(self._on_unlock_clicked)
        layout.addWidget(self._primary_btn)

        # Message label
        self._message = QLabel("")
        self._message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message.setWordWrap(True)
        self._message.setVisible(False)
        layout.addWidget(self._message)

        outer.addWidget(card)

        # Determine initial state
        self._is_create_mode = not self._vault.vault_exists()
        self._apply_mode()

    def _apply_mode(self) -> None:
        if self._is_create_mode:
            self._pw_label.setText("Create Master Password")
            self._pw_input.setPlaceholderText("Create a strong master password…")
            self._confirm_label.setVisible(True)
            self._confirm_input.setVisible(True)
            self._primary_btn.setText("Create Vault")
        else:
            self._pw_label.setText("Master Password")
            self._pw_input.setPlaceholderText("Enter master password…")
            self._confirm_label.setVisible(False)
            self._confirm_input.setVisible(False)
            self._primary_btn.setText("Unlock Vault")

    def _toggle_password_visibility(self) -> None:
        if self._show_pw_btn.isChecked():
            self._pw_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._confirm_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self._pw_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

    def _on_unlock_clicked(self) -> None:
        master_pw = self._pw_input.text()
        if not master_pw:
            self.show_message("Please enter your master password.", error=True)
            return

        self._primary_btn.setEnabled(False)
        self._message.setVisible(False)

        try:
            if self._is_create_mode:
                confirm = self._confirm_input.text()
                if master_pw != confirm:
                    self.show_message("Passwords do not match.", error=True)
                    return
                self._vault.create_vault(master_pw)
                self._vault.unlock(master_pw)
            else:
                self._vault.unlock(master_pw)

            # Clear password field immediately
            self._pw_input.clear()
            self._confirm_input.clear()
            self.login_successful.emit()

        except AuthenticationError as exc:
            self.show_message(str(exc), error=True)
        except ValidationError as exc:
            self.show_message(str(exc), error=True)
        except Exception as exc:
            logger.error("Login error: %s", exc)
            self.show_message("An error occurred. Please try again.", error=True)
        finally:
            self._primary_btn.setEnabled(True)

    def show_message(self, text: str, error: bool = True) -> None:
        self._message.setText(text)
        self._message.setObjectName("error" if error else "success")
        color = "#f38ba8" if error else "#a6e3a1"
        self._message.setStyleSheet(f"color: {color};")
        self._message.setVisible(True)

    def reset(self) -> None:
        """Reset the login form (called on lock)."""
        self._pw_input.clear()
        self._confirm_input.clear()
        self._message.setVisible(False)
        self._show_pw_btn.setChecked(False)
        self._pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._is_create_mode = not self._vault.vault_exists()
        self._apply_mode()
        self._pw_input.setFocus()
