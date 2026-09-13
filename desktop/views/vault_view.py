"""
Vault view — entry list, search, filter, entry editor.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QListWidget, QListWidgetItem,
    QLineEdit, QPushButton, QLabel, QFrame, QScrollArea, QComboBox,
    QTextEdit, QCheckBox, QMessageBox, QDialog, QFormLayout,
    QDialogButtonBox, QSplitter, QTabWidget,
)

from core.models.vault_models import ItemType, VaultEntry
from core.vault.vault_service import VaultService
from core.security.clipboard_manager import ClipboardManager
from core.utilities.logging_utils import get_logger
from desktop.widgets.password_field import PasswordField
from desktop.widgets.strength_indicator import StrengthIndicator

logger = get_logger(__name__)


class VaultView(QWidget):
    """Main vault browser — list + detail panel."""

    def __init__(
        self,
        vault_service: VaultService,
        clipboard: ClipboardManager,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._vault = vault_service
        self._clipboard = clipboard
        self._entries: list[VaultEntry] = []
        self._selected_entry: VaultEntry | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel — list
        left = QWidget()
        left.setMinimumWidth(280)
        left.setMaximumWidth(380)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(16, 16, 8, 16)
        left_layout.setSpacing(8)

        # Search
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("🔍 Search entries…")
        self._search_input.textChanged.connect(self._on_search_changed)
        left_layout.addWidget(self._search_input)

        # Filter row
        filter_row = QHBoxLayout()
        self._cat_filter = QComboBox()
        self._cat_filter.addItem("All Categories", None)
        self._cat_filter.currentIndexChanged.connect(self._apply_filters)
        filter_row.addWidget(self._cat_filter)

        fav_btn = QPushButton("★")
        fav_btn.setObjectName("secondary")
        fav_btn.setFixedWidth(36)
        fav_btn.setCheckable(True)
        fav_btn.setToolTip("Show favorites only")
        fav_btn.clicked.connect(self._apply_filters)
        self._fav_btn = fav_btn
        filter_row.addWidget(fav_btn)
        left_layout.addLayout(filter_row)

        # Entry list
        self._entry_list = QListWidget()
        self._entry_list.currentItemChanged.connect(self._on_item_selected)
        left_layout.addWidget(self._entry_list)

        # Add entry button
        add_btn = QPushButton("+ Add Entry")
        add_btn.clicked.connect(self._on_add_entry)
        left_layout.addWidget(add_btn)

        splitter.addWidget(left)

        # Right panel — detail / editor
        self._detail_panel = EntryDetailPanel(self._vault, self._clipboard, self)
        self._detail_panel.entry_saved.connect(self._on_entry_saved)
        self._detail_panel.entry_deleted.connect(self._on_entry_deleted)
        splitter.addWidget(self._detail_panel)

        splitter.setSizes([300, 600])
        layout.addWidget(splitter)

    def refresh(self) -> None:
        """Reload entries and categories."""
        try:
            self._entries = self._vault.list_entries(sort_by="title")
            self._populate_categories()
            self._populate_list(self._entries)
        except Exception as exc:
            logger.error("VaultView refresh error: %s", exc)

    def _populate_categories(self) -> None:
        self._cat_filter.blockSignals(True)
        self._cat_filter.clear()
        self._cat_filter.addItem("All Categories", None)
        try:
            for cat in self._vault.get_categories():
                self._cat_filter.addItem(cat.name, cat.id)
        except Exception:
            pass
        self._cat_filter.blockSignals(False)

    def _populate_list(self, entries: list[VaultEntry]) -> None:
        self._entry_list.clear()
        for entry in entries:
            item = QListWidgetItem()
            item.setText(
                f"{'★ ' if entry.is_favorite else ''}{entry.title}\n"
                f"{entry.username or entry.url or ''}"
            )
            item.setData(Qt.ItemDataRole.UserRole, entry.id)
            self._entry_list.addItem(item)

    def _on_search_changed(self, text: str) -> None:
        QTimer.singleShot(200, self._apply_filters)  # debounce

    def _apply_filters(self) -> None:
        search = self._search_input.text().strip()
        cat_id = self._cat_filter.currentData()
        favs_only = self._fav_btn.isChecked()
        try:
            filtered = self._vault.list_entries(
                search=search,
                category_id=cat_id,
                favorites_only=favs_only,
                sort_by="title",
            )
            self._populate_list(filtered)
        except Exception as exc:
            logger.error("Filter error: %s", exc)

    def _on_item_selected(self, current, _previous) -> None:
        if current is None:
            return
        entry_id = current.data(Qt.ItemDataRole.UserRole)
        try:
            entry = self._vault.get_entry(entry_id)
            if entry:
                self._detail_panel.load_entry(entry)
        except Exception as exc:
            logger.error("Entry load error: %s", exc)

    def _on_add_entry(self) -> None:
        self._detail_panel.new_entry()

    def _on_entry_saved(self, entry: VaultEntry) -> None:
        self.refresh()
        # Re-select the saved entry
        for i in range(self._entry_list.count()):
            item = self._entry_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == entry.id:
                self._entry_list.setCurrentItem(item)
                break

    def _on_entry_deleted(self, entry_id: str) -> None:
        self.refresh()
        self._detail_panel.clear()


class EntryDetailPanel(QWidget):
    """Entry viewer/editor panel."""

    entry_saved = pyqtSignal(VaultEntry)
    entry_deleted = pyqtSignal(str)

    def __init__(
        self,
        vault_service: VaultService,
        clipboard: ClipboardManager,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._vault = vault_service
        self._clipboard = clipboard
        self._current_entry: VaultEntry | None = None
        self._is_new = False
        self._setup_ui()
        self.clear()

    def _setup_ui(self) -> None:
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(16, 16, 24, 16)
        self._outer.setSpacing(12)

        # Header row
        header_row = QHBoxLayout()
        self._title_label = QLabel("Select an entry")
        self._title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_row.addWidget(self._title_label)
        header_row.addStretch()

        self._edit_btn = QPushButton("✏️ Edit")
        self._edit_btn.setObjectName("secondary")
        self._edit_btn.clicked.connect(self._enter_edit_mode)
        self._edit_btn.setVisible(False)
        header_row.addWidget(self._edit_btn)

        self._delete_btn = QPushButton("🗑 Delete")
        self._delete_btn.setObjectName("danger")
        self._delete_btn.clicked.connect(self._delete_entry)
        self._delete_btn.setVisible(False)
        header_row.addWidget(self._delete_btn)

        self._outer.addLayout(header_row)

        # Tabs
        self._tabs = QTabWidget()
        self._outer.addWidget(self._tabs)

        # Details tab
        self._details_widget = self._build_details_tab()
        self._tabs.addTab(self._details_widget, "Details")

        # History tab
        self._history_widget = self._build_history_tab()
        self._tabs.addTab(self._history_widget, "History")

        # TOTP tab
        self._totp_widget = self._build_totp_tab()
        self._tabs.addTab(self._totp_widget, "TOTP")

        # Action buttons (save/cancel — shown only in edit mode)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._save_btn = QPushButton("💾 Save")
        self._save_btn.clicked.connect(self._save_entry)
        self._save_btn.setVisible(False)
        btn_row.addWidget(self._save_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("secondary")
        self._cancel_btn.clicked.connect(self._cancel_edit)
        self._cancel_btn.setVisible(False)
        btn_row.addWidget(self._cancel_btn)
        self._outer.addLayout(btn_row)

    def _build_details_tab(self) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        form = QFormLayout(container)
        form.setSpacing(12)
        form.setContentsMargins(8, 8, 8, 8)

        self._field_title = QLineEdit()
        form.addRow("Title *", self._field_title)

        self._field_username = QLineEdit()
        copy_user_btn = QPushButton("Copy")
        copy_user_btn.setObjectName("secondary")
        copy_user_btn.setFixedWidth(60)
        copy_user_btn.clicked.connect(lambda: self._clipboard.copy(self._field_username.text()))
        user_row = QHBoxLayout()
        user_row.addWidget(self._field_username)
        user_row.addWidget(copy_user_btn)
        form.addRow("Username", user_row)

        self._field_password = PasswordField()
        self._field_password.copy_requested.connect(
            lambda pw: self._clipboard.copy(pw)
        )
        form.addRow("Password", self._field_password)

        self._strength_indicator = StrengthIndicator()
        self._field_password.password_changed.connect(self._strength_indicator.update_strength)
        form.addRow("Strength", self._strength_indicator)

        self._field_url = QLineEdit()
        self._field_url.setPlaceholderText("https://example.com")
        form.addRow("URL", self._field_url)

        self._field_notes = QTextEdit()
        self._field_notes.setMaximumHeight(100)
        form.addRow("Notes", self._field_notes)

        self._field_favorite = QCheckBox("Mark as favorite")
        form.addRow("", self._field_favorite)

        self._field_category = QComboBox()
        form.addRow("Category", self._field_category)

        scroll.setWidget(container)
        return scroll

    def _build_history_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)
        self._history_list = QListWidget()
        layout.addWidget(QLabel("Previous passwords (newest first):"))
        layout.addWidget(self._history_list)
        return w

    def _build_totp_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        layout.addWidget(QLabel("TOTP Secret (stored encrypted):"))
        self._field_totp = QLineEdit()
        self._field_totp.setPlaceholderText("Base32 TOTP secret or otpauth:// URI")
        self._field_totp.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._field_totp)

        show_totp = QPushButton("Show/Hide Secret")
        show_totp.setObjectName("secondary")
        show_totp.setCheckable(True)
        show_totp.clicked.connect(lambda c: self._field_totp.setEchoMode(
            QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password
        ))
        layout.addWidget(show_totp)

        self._totp_code_label = QLabel("")
        self._totp_code_label.setStyleSheet("font-size: 32px; font-weight: bold; color: #89b4fa; letter-spacing: 4px;")
        self._totp_code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._totp_code_label)

        self._totp_countdown = QLabel("")
        self._totp_countdown.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._totp_countdown.setStyleSheet("color: #6c7086;")
        layout.addWidget(self._totp_countdown)

        gen_btn = QPushButton("Generate OTP")
        gen_btn.clicked.connect(self._generate_totp)
        layout.addWidget(gen_btn)

        copy_otp = QPushButton("Copy OTP")
        copy_otp.setObjectName("secondary")
        copy_otp.clicked.connect(self._copy_totp)
        layout.addWidget(copy_otp)

        layout.addStretch()

        # Timer for countdown
        self._totp_timer = QTimer()
        self._totp_timer.timeout.connect(self._update_totp_display)
        self._totp_timer.start(1000)

        return w

    def _generate_totp(self) -> None:
        self._update_totp_display()

    def _update_totp_display(self) -> None:
        secret = self._field_totp.text().strip()
        if not secret:
            return
        try:
            from core.totp.totp_manager import get_totp_code
            info = get_totp_code(secret)
            self._totp_code_label.setText(info.code)
            self._totp_countdown.setText(f"Expires in {info.seconds_remaining}s")
        except Exception:
            self._totp_code_label.setText("Invalid secret")
            self._totp_countdown.setText("")

    def _copy_totp(self) -> None:
        code = self._totp_code_label.text()
        if code and code != "Invalid secret":
            self._clipboard.copy(code, clear_after=30)

    def load_entry(self, entry: VaultEntry) -> None:
        """Display an existing entry."""
        self._current_entry = entry
        self._is_new = False
        self._populate_fields(entry)
        self._set_read_only(True)
        self._title_label.setText(entry.title)
        self._edit_btn.setVisible(True)
        self._delete_btn.setVisible(True)
        self._save_btn.setVisible(False)
        self._cancel_btn.setVisible(False)

        # Load history
        self._load_history(entry.id)

    def new_entry(self) -> None:
        """Open a blank form for a new entry."""
        self._current_entry = None
        self._is_new = True
        self._populate_fields(VaultEntry(title=""))
        self._set_read_only(False)
        self._title_label.setText("New Entry")
        self._edit_btn.setVisible(False)
        self._delete_btn.setVisible(False)
        self._save_btn.setVisible(True)
        self._cancel_btn.setVisible(True)
        self._field_title.setFocus()

    def clear(self) -> None:
        """Clear the detail panel."""
        self._current_entry = None
        self._is_new = False
        self._title_label.setText("Select an entry or add a new one")
        self._edit_btn.setVisible(False)
        self._delete_btn.setVisible(False)
        self._save_btn.setVisible(False)
        self._cancel_btn.setVisible(False)

    def _populate_fields(self, entry: VaultEntry) -> None:
        self._field_title.setText(entry.title)
        self._field_username.setText(entry.username)
        self._field_password.set_password(entry.password)
        self._field_url.setText(entry.url)
        self._field_notes.setPlainText(entry.notes)
        self._field_favorite.setChecked(entry.is_favorite)
        self._field_totp.setText(entry.totp_secret)

        # Populate categories
        self._field_category.clear()
        self._field_category.addItem("(None)", None)
        try:
            for cat in self._vault.get_categories():
                self._field_category.addItem(cat.name, cat.id)
                if cat.id == entry.category_id:
                    self._field_category.setCurrentText(cat.name)
        except Exception:
            pass

    def _load_history(self, entry_id: str) -> None:
        self._history_list.clear()
        try:
            history = self._vault.get_password_history(entry_id)
            for h in history:
                ts = h.changed_at.strftime("%Y-%m-%d %H:%M") if h.changed_at else ""
                self._history_list.addItem(f"[{ts}] {'*' * min(len(h.password), 12)}")
        except Exception:
            pass

    def _set_read_only(self, read_only: bool) -> None:
        for field in [self._field_title, self._field_username,
                      self._field_url]:
            field.setReadOnly(read_only)
        self._field_notes.setReadOnly(read_only)
        self._field_favorite.setEnabled(not read_only)
        self._field_category.setEnabled(not read_only)
        self._field_password.set_editable(not read_only)
        self._field_totp.setReadOnly(read_only)

    def _enter_edit_mode(self) -> None:
        self._set_read_only(False)
        self._edit_btn.setVisible(False)
        self._save_btn.setVisible(True)
        self._cancel_btn.setVisible(True)

    def _cancel_edit(self) -> None:
        if self._is_new:
            self.clear()
        elif self._current_entry:
            self.load_entry(self._current_entry)
        else:
            self.clear()

    def _save_entry(self) -> None:
        title = self._field_title.text().strip()
        if not title:
            QMessageBox.warning(self, "Validation", "Title is required.")
            return

        try:
            entry_data = dict(
                title=title,
                username=self._field_username.text(),
                password=self._field_password.get_password(),
                url=self._field_url.text().strip(),
                notes=self._field_notes.toPlainText(),
                is_favorite=self._field_favorite.isChecked(),
                category_id=self._field_category.currentData(),
                totp_secret=self._field_totp.text().strip(),
            )

            if self._is_new:
                entry = VaultEntry(**entry_data)
                saved = self._vault.add_entry(entry)
            else:
                assert self._current_entry is not None
                for k, v in entry_data.items():
                    setattr(self._current_entry, k, v)
                saved = self._vault.update_entry(self._current_entry)

            self.entry_saved.emit(saved)
            self.load_entry(saved)

        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Could not save entry: {exc}")

    def _delete_entry(self) -> None:
        if self._current_entry is None:
            return
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete '{self._current_entry.title}'?\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                entry_id = self._current_entry.id
                self._vault.delete_entry(entry_id)
                self.entry_deleted.emit(entry_id)
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Could not delete entry: {exc}")
