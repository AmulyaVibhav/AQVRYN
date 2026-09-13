"""
PasswordField widget — password input with show/hide, copy, generate.
"""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QPushButton, QDialog,
    QVBoxLayout, QLabel, QSlider, QCheckBox, QDialogButtonBox,
)

from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


class PasswordField(QWidget):
    """
    Custom password field with:
    - Show/hide toggle
    - Copy button
    - Generate button (opens generator dialog)
    """

    copy_requested = pyqtSignal(str)    # Emits the password (to clipboard manager)
    password_changed = pyqtSignal(str)  # Emits on every change (for strength indicator)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._editable = True
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._pw_input = QLineEdit()
        self._pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_input.textChanged.connect(self.password_changed)
        layout.addWidget(self._pw_input)

        self._show_btn = QPushButton("👁")
        self._show_btn.setObjectName("secondary")
        self._show_btn.setFixedSize(36, 36)
        self._show_btn.setCheckable(True)
        self._show_btn.clicked.connect(self._toggle_visibility)
        self._show_btn.setToolTip("Show/hide password")
        layout.addWidget(self._show_btn)

        self._copy_btn = QPushButton("📋")
        self._copy_btn.setObjectName("secondary")
        self._copy_btn.setFixedSize(36, 36)
        self._copy_btn.setToolTip("Copy password")
        self._copy_btn.clicked.connect(lambda: self.copy_requested.emit(self._pw_input.text()))
        layout.addWidget(self._copy_btn)

        self._gen_btn = QPushButton("🔄")
        self._gen_btn.setObjectName("secondary")
        self._gen_btn.setFixedSize(36, 36)
        self._gen_btn.setToolTip("Generate password")
        self._gen_btn.clicked.connect(self._open_generator)
        layout.addWidget(self._gen_btn)

    def _toggle_visibility(self) -> None:
        if self._show_btn.isChecked():
            self._pw_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self._pw_input.setEchoMode(QLineEdit.EchoMode.Password)

    def _open_generator(self) -> None:
        dlg = PasswordGeneratorDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            pw = dlg.generated_password
            if pw:
                self._pw_input.setText(pw)
                self.password_changed.emit(pw)

    def set_password(self, password: str) -> None:
        self._pw_input.setText(password)

    def get_password(self) -> str:
        return self._pw_input.text()

    def set_editable(self, editable: bool) -> None:
        self._editable = editable
        self._pw_input.setReadOnly(not editable)
        self._gen_btn.setVisible(editable)


class PasswordGeneratorDialog(QDialog):
    """Dialog for generating and previewing a new password."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.generated_password = ""
        self.setWindowTitle("Generate Password")
        self.setMinimumWidth(420)
        self._setup_ui()
        self._generate()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(QLabel("Configure Password:"))

        # Length
        from PyQt6.QtWidgets import QFormLayout, QSpinBox
        form = QFormLayout()

        self._length_spin = QSpinBox()
        self._length_spin.setRange(8, 128)
        self._length_spin.setValue(20)
        self._length_spin.valueChanged.connect(self._generate)
        form.addRow("Length", self._length_spin)

        self._upper = QCheckBox("Uppercase (A-Z)")
        self._upper.setChecked(True)
        self._upper.toggled.connect(self._generate)
        form.addRow("", self._upper)

        self._lower = QCheckBox("Lowercase (a-z)")
        self._lower.setChecked(True)
        self._lower.toggled.connect(self._generate)
        form.addRow("", self._lower)

        self._digits = QCheckBox("Digits (0-9)")
        self._digits.setChecked(True)
        self._digits.toggled.connect(self._generate)
        form.addRow("", self._digits)

        self._symbols = QCheckBox("Symbols (!@#$%...)")
        self._symbols.setChecked(True)
        self._symbols.toggled.connect(self._generate)
        form.addRow("", self._symbols)

        self._ambiguous = QCheckBox("Exclude ambiguous (0O1lI)")
        self._ambiguous.setChecked(True)
        self._ambiguous.toggled.connect(self._generate)
        form.addRow("", self._ambiguous)

        layout.addLayout(form)

        # Preview
        self._preview = QLabel("")
        self._preview.setStyleSheet(
            "font-family: monospace; font-size: 16px; "
            "color: #a6e3a1; background-color: #181825; "
            "padding: 12px; border-radius: 6px;"
        )
        self._preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._preview.setWordWrap(True)
        layout.addWidget(self._preview)

        # Strength
        self._strength_label = QLabel("")
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._strength_label)

        # Buttons
        regen = QPushButton("🔄 Regenerate")
        regen.clicked.connect(self._generate)
        layout.addWidget(regen)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _generate(self) -> None:
        try:
            from core.generator.password_generator import GeneratorConfig, PasswordGenerator, estimate_strength
            config = GeneratorConfig(
                length=self._length_spin.value(),
                use_uppercase=self._upper.isChecked(),
                use_lowercase=self._lower.isChecked(),
                use_digits=self._digits.isChecked(),
                use_symbols=self._symbols.isChecked(),
                exclude_ambiguous=self._ambiguous.isChecked(),
            )
            pw = PasswordGenerator().generate(config)
            self.generated_password = pw
            self._preview.setText(pw)

            strength = estimate_strength(pw)
            colors = {
                "very_weak": "#f38ba8", "weak": "#fab387",
                "moderate": "#f9e2af", "strong": "#a6e3a1", "very_strong": "#89b4fa",
            }
            color = colors.get(strength.strength.value, "#cdd6f4")
            self._strength_label.setText(
                f"Strength: <b style='color:{color}'>{strength.strength.value.replace('_', ' ').title()}</b>"
                f" — Crack time: {strength.crack_time_display}"
            )
            self._strength_label.setTextFormat(Qt.TextFormat.RichText)
        except Exception as exc:
            self._preview.setText(f"Error: {exc}")

    def _accept(self) -> None:
        self.accept()
