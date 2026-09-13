"""
Dashboard view — security score, stats, recently modified entries.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QGridLayout, QPushButton,
)

from core.vault.vault_service import VaultService
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)


class StatCard(QFrame):
    def __init__(self, title: str, value: str, color: str = "#89b4fa", parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #181825;
                border-radius: 12px;
                border-left: 4px solid {color};
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)

        val_label = QLabel(value)
        val_label.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
        layout.addWidget(val_label)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 12px; color: #6c7086;")
        layout.addWidget(title_label)

    def update_value(self, value: str) -> None:
        # First child is the value label
        self.layout().itemAt(0).widget().setText(value)


class DashboardView(QWidget):
    """Security dashboard — shows vault health at a glance."""

    def __init__(self, vault_service: VaultService, parent=None) -> None:
        super().__init__(parent)
        self._vault = vault_service
        self._setup_ui()

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Header
        header = QLabel("Security Dashboard")
        header.setStyleSheet("font-size: 22px; font-weight: bold; color: #cdd6f4;")
        layout.addWidget(header)

        # Security score
        self._score_section = self._build_score_section()
        layout.addWidget(self._score_section)

        # Stats row
        self._stats_row = QHBoxLayout()
        self._stat_total = StatCard("Total Entries", "0", "#89b4fa")
        self._stat_weak = StatCard("Weak Passwords", "0", "#f38ba8")
        self._stat_reused = StatCard("Reused Passwords", "0", "#fab387")
        self._stat_old = StatCard("Old Passwords", "0", "#f9e2af")
        self._stat_favorites = StatCard("Favorites", "0", "#a6e3a1")

        for card in [self._stat_total, self._stat_weak, self._stat_reused,
                     self._stat_old, self._stat_favorites]:
            self._stats_row.addWidget(card)

        stats_widget = QWidget()
        stats_widget.setLayout(self._stats_row)
        layout.addWidget(stats_widget)

        # Audit button
        audit_btn = QPushButton("🔍  Run Security Audit")
        audit_btn.clicked.connect(self._run_audit)
        audit_btn.setFixedWidth(200)
        layout.addWidget(audit_btn)

        # Recent entries
        recent_header = QLabel("Recently Modified")
        recent_header.setStyleSheet("font-size: 16px; font-weight: bold; color: #cdd6f4;")
        layout.addWidget(recent_header)

        self._recent_frame = QFrame()
        self._recent_frame.setStyleSheet("background-color: #181825; border-radius: 12px;")
        self._recent_layout = QVBoxLayout(self._recent_frame)
        self._recent_layout.setContentsMargins(16, 12, 16, 12)
        layout.addWidget(self._recent_frame)

        layout.addStretch()
        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _build_score_section(self) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet("background-color: #181825; border-radius: 12px;")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(24, 20, 24, 20)

        self._score_value = QLabel("—")
        self._score_value.setStyleSheet("font-size: 48px; font-weight: bold; color: #89b4fa;")
        layout.addWidget(self._score_value)

        info = QVBoxLayout()
        info.addWidget(QLabel("Security Score"))
        self._score_desc = QLabel("Run an audit to calculate your security score.")
        self._score_desc.setStyleSheet("color: #6c7086; font-size: 12px;")
        self._score_desc.setWordWrap(True)
        info.addWidget(self._score_desc)
        info.addStretch()
        layout.addLayout(info)
        layout.addStretch()
        return frame

    def _run_audit(self) -> None:
        try:
            result = self._vault.run_security_audit()
            self._score_value.setText(str(result.security_score))
            self._score_value.setStyleSheet(
                f"font-size: 48px; font-weight: bold; color: {self._score_color(result.security_score)};"
            )
            desc_parts = []
            if result.weak_passwords:
                desc_parts.append(f"{len(result.weak_passwords)} weak password(s)")
            if result.reused_passwords:
                desc_parts.append(f"{sum(len(g) for g in result.reused_passwords)} reused")
            if result.old_passwords:
                desc_parts.append(f"{len(result.old_passwords)} outdated")
            self._score_desc.setText(
                ", ".join(desc_parts) if desc_parts else "Excellent! No issues found."
            )
            self._stat_weak.update_value(str(len(result.weak_passwords)))
            self._stat_reused.update_value(str(sum(len(g) for g in result.reused_passwords)))
            self._stat_old.update_value(str(len(result.old_passwords)))
        except Exception as exc:
            logger.error("Audit error: %s", exc)

    def _score_color(self, score: int) -> str:
        if score >= 80:
            return "#a6e3a1"
        if score >= 60:
            return "#f9e2af"
        if score >= 40:
            return "#fab387"
        return "#f38ba8"

    def refresh(self) -> None:
        """Reload dashboard data."""
        try:
            meta = self._vault.get_vault_metadata()
            if meta:
                self._stat_total.update_value(str(meta.entry_count))

            entries = self._vault.list_entries()
            favorites = sum(1 for e in entries if e.is_favorite)
            self._stat_favorites.update_value(str(favorites))

            # Recent entries (last 5 modified)
            recent = sorted(entries, key=lambda e: e.modified_at, reverse=True)[:5]
            self._populate_recent(recent)
        except Exception as exc:
            logger.error("Dashboard refresh error: %s", exc)

    def _populate_recent(self, entries) -> None:
        # Clear existing
        while self._recent_layout.count():
            item = self._recent_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not entries:
            lbl = QLabel("No entries yet.")
            lbl.setStyleSheet("color: #6c7086;")
            self._recent_layout.addWidget(lbl)
            return

        for entry in entries:
            row = QHBoxLayout()
            title = QLabel(entry.title)
            title.setStyleSheet("font-weight: bold;")
            row.addWidget(title)
            ts = entry.modified_at.strftime("%Y-%m-%d %H:%M") if entry.modified_at else ""
            ts_label = QLabel(ts)
            ts_label.setStyleSheet("color: #6c7086; font-size: 11px;")
            row.addStretch()
            row.addWidget(ts_label)
            wrapper = QWidget()
            wrapper.setLayout(row)
            self._recent_layout.addWidget(wrapper)
