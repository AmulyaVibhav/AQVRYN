"""
Password strength indicator widget.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QWidget


class StrengthIndicator(QWidget):
    """Displays password strength as a colored progress bar with label."""

    _COLOR_MAP = {
        "very_weak":  ("#f38ba8", 10),
        "weak":       ("#fab387", 30),
        "moderate":   ("#f9e2af", 55),
        "strong":     ("#a6e3a1", 80),
        "very_strong":("#89b4fa", 100),
    }

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setMaximumHeight(8)
        self._bar.setTextVisible(False)
        layout.addWidget(self._bar)

        self._label = QLabel("—")
        self._label.setFixedWidth(80)
        self._label.setStyleSheet("font-size: 11px; color: #6c7086;")
        layout.addWidget(self._label)

    def update_strength(self, password: str) -> None:
        if not password:
            self._bar.setValue(0)
            self._label.setText("—")
            self._bar.setStyleSheet("")
            return

        try:
            from core.generator.password_generator import estimate_strength
            result = estimate_strength(password)
            strength_key = result.strength.value
            color, pct = self._COLOR_MAP.get(strength_key, ("#6c7086", 0))
            self._bar.setValue(pct)
            self._bar.setStyleSheet(
                f"QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}"
            )
            self._label.setText(strength_key.replace("_", " ").title())
            self._label.setStyleSheet(f"font-size: 11px; color: {color};")
        except Exception:
            pass
