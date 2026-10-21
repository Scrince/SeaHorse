from __future__ import annotations

import json
import secrets
from dataclasses import replace
from pathlib import Path

from PyQt6.QtCore import QEvent, QObject, Qt, QSize, QTimer
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from crypto.vault import (
    InvalidPasswordError,
    SecretItem,
    SecretsVault,
    VaultError,
    parse_import_payload,
)
from gpg_backend.manager import GpgError, GpgKeyInfo, GpgManager
from ssh_backend.manager import SshError, SshKeyInfo, SshManager
from utils.clipboard import ClipboardManager
from utils.themes import theme_stylesheet
from version import APP_DISPLAY_NAME, APP_VERSION


def password_strength(password: str) -> tuple[int, str]:
    if not password:
        return 0, "Empty"
    score = 0
    length = len(password)
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    if classes >= 3:
        score += 1
    if classes >= 4 and length >= 12:
        score = min(4, score + 1)
    score = min(4, score)
    labels = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong"}
    return score, labels[score]


class SecretEditor(QDialog):
    def __init__(self, item: SecretItem | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Password" if item else "New Password")
        self.setMinimumWidth(480)
        self.item = item
        layout = QFormLayout(self)
        layout.setSpacing(10)
        self.title = QLineEdit(item.title if item else "")
        self.username = QLineEdit(item.username if item else "")
        self.password = QLineEdit(item.password if item else "")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.textChanged.connect(self._update_strength)
        self.url = QLineEdit(item.url if item else "")
        self.folder = QLineEdit(item.folder if item else "")
        self.folder.setPlaceholderText("e.g. Work, Personal")
        self.tags = QLineEdit(", ".join(item.tags) if item and item.tags else "")
        self.tags.setPlaceholderText("comma-separated, e.g. bank, shared")
        self.notes = QPlainTextEdit(item.notes if item else "")
        self.notes.setMinimumHeight(100)
        self.strength_label = QLabel("Strength: —")
        self.strength_label.setObjectName("Muted")
        layout.addRow("Description", self.title)
        layout.addRow("Username", self.username)
        pass_row = QHBoxLayout()
        pass_row.addWidget(self.password)
        gen = QPushButton("Generate")
        gen.clicked.connect(self._generate)
        pass_row.addWidget(gen)
        show = QPushButton("Show")
        show.setCheckable(True)
        show.toggled.connect(
            lambda on: self.password.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
            )
        )
        pass_row.addWidget(show)
        layout.addRow("Password", pass_row)
        layout.addRow("", self.strength_label)
        layout.addRow("Key / URL", self.url)
        layout.addRow("Folder", self.folder)
        layout.addRow("Tags", self.tags)
        layout.addRow("Notes", self.notes)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        self._update_strength(self.password.text())

    def _update_strength(self, text: str = "") -> None:
        pwd = text if text is not None else self.password.text()
        _score, label = password_strength(pwd)
        self.strength_label.setText(f"Strength: {label}")

    def _generate(self) -> None:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+"
        self.password.setText("".join(secrets.choice(alphabet) for _ in range(20)))
        self.password.setEchoMode(QLineEdit.EchoMode.Normal)

    def result_item(self) -> SecretItem:
        if self.item:
            base = replace(self.item, tags=list(self.item.tags))
        else:
            base = SecretItem(id=secrets.token_hex(8), title="")
        base.title = self.title.text().strip() or "Untitled"
        base.username = self.username.text()
        base.password = self.password.text()
        base.url = self.url.text()
        base.folder = self.folder.text().strip()
        raw_tags = self.tags.text().strip()
        base.tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
        base.notes = self.notes.toPlainText()
        return base


class GenerateGpgDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New PGP Key")
        form = QFormLayout(self)
        form.setSpacing(10)
        self.name = QLineEdit()
        self.email = QLineEdit()
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_type = QComboBox()
        self.key_type.addItems(["ed25519", "rsa4096"])
        self.expire = QComboBox()
        self.expire.addItem("Never expires", "0")
        self.expire.addItem("1 year", "1y")
        self.expire.addItem("2 years", "2y")
        form.addRow("Full name", self.name)
        form.addRow("Email address", self.email)
        form.addRow("Passphrase", self.passphrase)
        form.addRow("Key type", self.key_type)
        form.addRow("Expiration", self.expire)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Create")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)


class GenerateSshDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Secure Shell Key")
        form = QFormLayout(self)
        form.setSpacing(10)
        self.name = QLineEdit("id_ed25519")
        self.comment = QLineEdit()
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_type = QComboBox()
        self.key_type.addItems(["ed25519", "rsa", "ecdsa"])
        form.addRow("Description", self.name)
        form.addRow("Comment", self.comment)
        form.addRow("Passphrase", self.passphrase)
        form.addRow("Encryption type", self.key_type)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Create")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)


class UnlockDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 16)
        title = QLabel("Enter password to unlock your keyring")
        title.setObjectName("ViewTitle")
        title.setStyleSheet("font-size: 16px;")
        layout.addWidget(title)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password")
        layout.addWidget(self.password)
        row = QHBoxLayout()
        ok = QPushButton("Unlock")
        ok.setObjectName("PrimaryButton")
        ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        row.addStretch(1)
        row.addWidget(cancel)
        row.addWidget(ok)
        layout.addLayout(row)
        self.password.returnPressed.connect(self.accept)

    def accept(self) -> None:
        if not self.password.text():
            QMessageBox.warning(self, "Password required", "Master password is required.")
            return
        super().accept()


class ActivityFilter(QObject):
    def __init__(self, on_activity, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._on_activity = on_activity

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        et = event.type()
        if et in (
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseMove,
            QEvent.Type.Wheel,
            QEvent.Type.TouchBegin,
        ):
            self._on_activity()
        return False


class MainWindow(QMainWindow):
    CAT_PASSWORDS = 0
    CAT_GPG = 1
    CAT_SSH = 2

    def __init__(
        self,
        vault: SecretsVault,
        gpg: GpgManager,
        ssh: SshManager,
        theme_name: str = "light",
        clipboard: ClipboardManager | None = None,
        auto_lock_minutes: int = 10,
        on_settings_changed=None,
    ) -> None:
        super().__init__()
        self.vault = vault
        self.gpg = gpg
        self.ssh = ssh
        self.theme_name = theme_name
        self._auto_lock_minutes = max(0, int(auto_lock_minutes))
        self._on_settings_changed = on_settings_changed
        app = QGuiApplication.instance()
        if clipboard is not None:
            self.clipboard = clipboard
        elif app is not None:
            self.clipboard = ClipboardManager(app)
        else:
            raise RuntimeError("ClipboardManager requires a running QGuiApplication")
        self._gpg_keys: list[GpgKeyInfo] = []
        self._ssh_keys: list[SshKeyInfo] = []
        self._folder_filter = ""
        self.setWindowTitle(f"{APP_DISPLAY_NAME}")
        self.resize(1080, 700)
        self.setMinimumSize(860, 560)
        self._build_chrome()
        self._setup_auto_lock()
        self.refresh_all()

    def _setup_auto_lock(self) -> None:
        self._idle_timer = QTimer(self)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.timeout.connect(self._on_auto_lock)
        self._activity_filter = ActivityFilter(self._reset_idle_timer, self)
        app = QGuiApplication.instance()
        if app is not None:
            app.installEventFilter(self._activity_filter)
        self._reset_idle_timer()

    def _reset_idle_timer(self) -> None:
        if not hasattr(self, "_idle_timer"):
            return
        self._idle_timer.stop()
        if self._auto_lock_minutes > 0 and self.vault.unlocked:
            self._idle_timer.start(self._auto_lock_minutes * 60 * 1000)

    def _on_auto_lock(self) -> None:
        if not self.vault.unlocked:
            return
        self._lock_vault_silent()
        self.statusBar().showMessage("Vault locked due to inactivity", 5000)
        self._prompt_unlock()

    def _close_open_dialogs(self) -> None:
        for widget in list(self.findChildren(QDialog)):
            try:
                if widget.isVisible():
                    widget.reject()
            except Exception:
                pass

    def _lock_vault_silent(self) -> None:
        self._close_open_dialogs()
        try:
            self.clipboard.flush()
        except Exception:
            pass
        self.vault.lock()
        self._idle_timer.stop()
        self.refresh_secrets()
        self.pass_detail.setPlainText("")

    def _prompt_unlock(self) -> bool:
        while True:
            dialog = UnlockDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                self.refresh_secrets()
                return False
            try:
                self.vault.unlock(dialog.password.text())
                self.refresh_secrets()
                self.apply_filter(self.search.text())
                self._reset_idle_timer()
                self.statusBar().showMessage("Vault unlocked", 2500)
                return True
            except InvalidPasswordError:
                QMessageBox.warning(self, "Unlock failed", "Incorrect master password.")
            except VaultError as exc:
                QMessageBox.warning(self, "Vault error", str(exc))
                return False

    def _build_chrome(self) -> None:
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QWidget()
        header.setObjectName("HeaderBar")
        header_l = QHBoxLayout(header)
        header_l.setContentsMargins(12, 8, 12, 8)
        header_l.setSpacing(10)

        title = QLabel(APP_DISPLAY_NAME)
        title.setObjectName("AppTitle")
        header_l.addWidget(title)
        header_l.addStretch(1)

        self.search = QLineEdit()
        self.search.setObjectName("SearchField")
        self.search.setPlaceholderText("Search")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.apply_filter)
        header_l.addWidget(self.search)

        self.add_btn = QToolButton()
        self.add_btn.setObjectName("HeaderPrimary")
        self.add_btn.setText("+")
        self.add_btn.setToolTip("Add")
        self.add_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.add_btn.setFixedSize(QSize(40, 34))
        add_menu = QMenu(self)
        add_menu.addAction("Password", self.add_secret)
        add_menu.addAction("PGP Key", self.generate_gpg)
        add_menu.addAction("Secure Shell Key", self.generate_ssh)
        add_menu.addSeparator()
        add_menu.addAction("Import PGP Key…", self.import_gpg)
        add_menu.addAction("Import SSH Key…", self.import_ssh)
        self.add_btn.setMenu(add_menu)
        header_l.addWidget(self.add_btn)

        menu_btn = QToolButton()
        menu_btn.setObjectName("HeaderButton")
        menu_btn.setText("☰")
        menu_btn.setToolTip("Menu")
        menu_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu_btn.setFixedSize(QSize(40, 34))
        overflow = QMenu(self)
        overflow.addAction("Refresh", self.refresh_all)
        overflow.addSeparator()
        overflow.addAction("Lock passwords…", self.lock_vault)
        overflow.addAction("Unlock passwords…", self.unlock_vault_ui)
        overflow.addAction("Change master password…", self.change_master_password)
        overflow.addSeparator()
        overflow.addAction("Export passwords (JSON)…", self.export_passwords_json)
        overflow.addAction("Export passwords redacted (JSON)…", self.export_passwords_json_redacted)
        overflow.addAction("Import passwords (JSON)…", self.import_passwords_json)
        overflow.addSeparator()
        lock_menu = overflow.addMenu("Auto-lock timeout")
        for minutes, label in (
            (0, "Disabled"),
            (1, "1 minute"),
            (5, "5 minutes"),
            (10, "10 minutes"),
            (15, "15 minutes"),
            (30, "30 minutes"),
            (60, "1 hour"),
        ):
            act = lock_menu.addAction(label)
            act.setCheckable(True)
            act.setChecked(minutes == self._auto_lock_minutes)
            act.triggered.connect(lambda _checked=False, m=minutes: self.set_auto_lock_minutes(m))
        self._lock_menu = lock_menu
        overflow.addSeparator()
        style_menu = overflow.addMenu("Appearance")
        style_menu.addAction("Light (GNOME Adwaita)", lambda: self.set_theme("light"))
        style_menu.addAction("Dark (GNOME Adwaita)", lambda: self.set_theme("dark"))
        overflow.addSeparator()
        overflow.addAction("About Passwords and Keys", self.show_about)
        overflow.addAction("Quit", self.close)
        menu_btn.setMenu(overflow)
        header_l.addWidget(menu_btn)
        outer.addWidget(header)

        body = QSplitter(Qt.Orientation.Horizontal)
        body.setHandleWidth(1)
        body.setChildrenCollapsible(False)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(220)
        self.sidebar.setIconSize(QSize(20, 20))
        for label in ("Passwords", "OpenPGP Keys", "Secure Shell Keys"):
            item = QListWidgetItem(f"  {label}")
            item.setSizeHint(QSize(0, 40))
            self.sidebar.addItem(item)
        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self._on_category_changed)
        body.addWidget(self.sidebar)

        content = QFrame()
        content.setObjectName("ContentPane")
        content_l = QVBoxLayout(content)
        content_l.setContentsMargins(18, 14, 18, 14)
        content_l.setSpacing(10)

        title_row = QHBoxLayout()
        self.view_title = QLabel("Passwords")
        self.view_title.setObjectName("ViewTitle")
        title_row.addWidget(self.view_title)
        title_row.addStretch(1)
        self.folder_combo = QComboBox()
        self.folder_combo.setMinimumWidth(160)
        self.folder_combo.setToolTip("Filter by folder")
        self.folder_combo.currentIndexChanged.connect(self._on_folder_filter_changed)
        self.folder_label = QLabel("Folder:")
        title_row.addWidget(self.folder_label)
        title_row.addWidget(self.folder_combo)
        content_l.addLayout(title_row)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._make_list_page("passwords"))
        self.stack.addWidget(self._make_list_page("gpg"))
        self.stack.addWidget(self._make_list_page("ssh"))
        content_l.addWidget(self.stack, 1)

        self.action_row = QHBoxLayout()
        self.action_row.setSpacing(8)
        content_l.addLayout(self.action_row)
        self._rebuild_actions(self.CAT_PASSWORDS)

        body.addWidget(content)
        body.setStretchFactor(0, 0)
        body.setStretchFactor(1, 1)
        outer.addWidget(body, 1)

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(self._status_summary())

        file_menu = self.menuBar().addMenu("_File")
        file_menu.menuAction().setVisible(False)

    def set_auto_lock_minutes(self, minutes: int) -> None:
        self._auto_lock_minutes = max(0, int(minutes))
        labels = {
            0: "Disabled",
            1: "1 minute",
            5: "5 minutes",
            10: "10 minutes",
            15: "15 minutes",
            30: "30 minutes",
            60: "1 hour",
        }
        wanted = labels.get(self._auto_lock_minutes, "")
        for act in self._lock_menu.actions():
            act.setChecked(act.text() == wanted)
        self._reset_idle_timer()
        if self._on_settings_changed:
            try:
                self._on_settings_changed({"auto_lock_minutes": self._auto_lock_minutes})
            except Exception:
                pass
        if self._auto_lock_minutes == 0:
            self.statusBar().showMessage("Auto-lock disabled", 2500)
        else:
            self.statusBar().showMessage(f"Auto-lock: {self._auto_lock_minutes} min", 2500)

    def _make_list_page(self, kind: str) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        left = QVBoxLayout()
        lst = QListWidget()
        lst.setObjectName("ItemList")
        lst.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        lst.setUniformItemSizes(True)
        lst.itemSelectionChanged.connect(lambda k=kind: self._on_item_selected(k))
        lst.itemDoubleClicked.connect(lambda *_a, k=kind: self._on_item_activated(k))
        left.addWidget(lst)
        empty = QLabel()
        empty.setObjectName("EmptyHint")
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.setWordWrap(True)
        left.addWidget(empty)
        layout.addLayout(left, 3)

        detail = QFrame()
        detail.setObjectName("DetailPane")
        detail_l = QVBoxLayout(detail)
        detail_l.setContentsMargins(14, 14, 14, 14)
        detail_title = QLabel("Details")
        detail_title.setObjectName("ViewTitle")
        detail_title.setStyleSheet("font-size: 15px;")
        detail_body = QPlainTextEdit()
        detail_body.setReadOnly(True)
        detail_body.setPlaceholderText("Select an item to see details.")
        detail_l.addWidget(detail_title)
        detail_l.addWidget(detail_body, 1)
        layout.addWidget(detail, 2)

        if kind == "passwords":
            self.pass_list, self.pass_empty, self.pass_detail = lst, empty, detail_body
        elif kind == "gpg":
            self.gpg_list, self.gpg_empty, self.gpg_detail = lst, empty, detail_body
            self.gpg_text_in = QPlainTextEdit()
            self.gpg_text_in.setPlaceholderText("Text to encrypt, decrypt, or sign…")
            self.gpg_text_in.setMaximumHeight(90)
            detail_l.addWidget(self.gpg_text_in)
            tools = QHBoxLayout()
            b1 = QPushButton("Encrypt")
            b1.clicked.connect(self.encrypt_gpg_text)
            b2 = QPushButton("Decrypt")
            b2.clicked.connect(self.decrypt_gpg_text)
            b3 = QPushButton("Sign")
            b3.clicked.connect(self.sign_gpg_text)
            for b in (b1, b2, b3):
                tools.addWidget(b)
            tools.addStretch(1)
            detail_l.addLayout(tools)
        else:
            self.ssh_list, self.ssh_empty, self.ssh_detail = lst, empty, detail_body

        return page

    def _clear_action_row(self) -> None:
        while self.action_row.count():
            item = self.action_row.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _rebuild_actions(self, category: int) -> None:
        self._clear_action_row()
        if category == self.CAT_PASSWORDS:
            buttons = [
                ("Add Password", "PrimaryButton", self.add_secret),
                ("Properties", "", self.edit_secret),
                ("Copy Password", "", lambda: self.copy_secret_field("password")),
                ("Copy Username", "", lambda: self.copy_secret_field("username")),
                ("Delete", "DangerButton", self.delete_secret),
            ]
        elif category == self.CAT_GPG:
            buttons = [
                ("New PGP Key", "PrimaryButton", self.generate_gpg),
                ("Import…", "", self.import_gpg),
                ("Export Public…", "", lambda: self.export_gpg(False)),
                ("Export Secret…", "", lambda: self.export_gpg(True)),
                ("Delete", "DangerButton", self.delete_gpg),
            ]
        else:
            buttons = [
                ("New SSH Key", "PrimaryButton", self.generate_ssh),
                ("Import…", "", self.import_ssh),
                ("Copy Public Key", "", self.copy_ssh_public),
                ("Export Public…", "", self.export_ssh_public),
                ("Delete", "DangerButton", self.delete_ssh),
            ]
        for text, obj, slot in buttons:
            btn = QPushButton(text)
            if obj:
                btn.setObjectName(obj)
            btn.clicked.connect(slot)
            self.action_row.addWidget(btn)
        self.action_row.addStretch(1)

    def _on_category_changed(self, row: int) -> None:
        titles = ("Passwords", "OpenPGP Keys", "Secure Shell Keys")
        self.view_title.setText(titles[row] if 0 <= row < len(titles) else "Keys")
        self.stack.setCurrentIndex(row)
        self._rebuild_actions(row)
        show_folder = row == self.CAT_PASSWORDS
        self.folder_combo.setVisible(show_folder)
        self.folder_label.setVisible(show_folder)
        self.apply_filter(self.search.text())

    def set_theme(self, name: str) -> None:
        from PyQt6.QtWidgets import QApplication

        self.theme_name = name
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme_stylesheet(name))

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Passwords and Keys",
            f"<h3>{APP_DISPLAY_NAME}</h3>"
            f"<p>Version {APP_VERSION}</p>"
            "<p>A portable Windows application inspired by GNOME "
            "<b>Seahorse</b> on Ubuntu.</p>"
            "<p>Layout and colors follow the GNOME Adwaita style. "
            "This is not the original GNOME/GTK codebase.</p>",
        )

    def _status_summary(self) -> str:
        gpg = "GnuPG ready" if self.gpg.available else "GnuPG not installed"
        ssh = "OpenSSH ready" if self.ssh.available else "OpenSSH not installed"
        lock = (
            f"auto-lock {self._auto_lock_minutes}m"
            if self._auto_lock_minutes > 0
            else "auto-lock off"
        )
        return f"{gpg}  ·  {ssh}  ·  {lock}  ·  Portable data"

    def refresh_all(self) -> None:
        self.refresh_secrets()
        self.refresh_gpg()
        self.refresh_ssh()
        self.apply_filter(self.search.text())
        self.statusBar().showMessage(self._status_summary())

    def _rebuild_folder_combo(self) -> None:
        current = self._folder_filter
        self.folder_combo.blockSignals(True)
        self.folder_combo.clear()
        self.folder_combo.addItem("All folders", "")
        folders: set[str] = set()
        if self.vault.unlocked:
            for item in self.vault.items:
                if item.folder.strip():
                    folders.add(item.folder.strip())
        for name in sorted(folders, key=str.lower):
            self.folder_combo.addItem(name, name)
        idx = 0
        for i in range(self.folder_combo.count()):
            if self.folder_combo.itemData(i) == current:
                idx = i
                break
        self.folder_combo.setCurrentIndex(idx)
        self._folder_filter = self.folder_combo.currentData() or ""
        self.folder_combo.blockSignals(False)

    def _on_folder_filter_changed(self, _index: int = 0) -> None:
        self._folder_filter = self.folder_combo.currentData() or ""
        self.apply_filter(self.search.text())

    def _secret_matches_query(self, secret: SecretItem, q: str) -> bool:
        if not q:
            return True
        haystacks = [
            secret.title,
            secret.username,
            secret.url,
            secret.notes,
            secret.folder,
            " ".join(secret.tags),
        ]
        return any(q in (h or "").lower() for h in haystacks)

    def apply_filter(self, text: str) -> None:
        q = (text or "").strip().lower()

        for i in range(self.pass_list.count()):
            row = self.pass_list.item(i)
            item_id = row.data(Qt.ItemDataRole.UserRole)
            secret = next((s for s in self.vault.items if s.id == item_id), None)
            if secret is None:
                row.setHidden(True)
                continue
            folder_ok = (
                not self._folder_filter
                or (secret.folder or "").strip() == self._folder_filter
            )
            search_ok = self._secret_matches_query(secret, q)
            row.setHidden(not (folder_ok and search_ok))

        for lst in (self.gpg_list, self.ssh_list):
            for i in range(lst.count()):
                item = lst.item(i)
                item.setHidden(bool(q) and q not in item.text().lower())

    def _item_line(self, primary: str, secondary: str = "") -> str:
        if secondary:
            return f"{primary}\n{secondary}"
        return primary

    def _format_list_secondary(self, item: SecretItem) -> str:
        parts: list[str] = []
        if item.folder:
            parts.append(f"[{item.folder}]")
        if item.username:
            parts.append(item.username)
        elif item.url:
            parts.append(item.url)
        else:
            parts.append("Password")
        if item.tags:
            parts.append("· " + ", ".join(item.tags[:4]))
        return "  ".join(parts)

    def refresh_secrets(self) -> None:
        self.pass_list.clear()
        if not self.vault.unlocked:
            self.pass_empty.setText("Password vault is locked.\nUse menu → Unlock passwords…")
            self.pass_empty.show()
            self._rebuild_folder_combo()
            return
        if not self.vault.items:
            self.pass_empty.setText("No passwords yet.\nClick + to store a password.")
            self.pass_empty.show()
        else:
            self.pass_empty.hide()
        for item in self.vault.items:
            secondary = self._format_list_secondary(item)
            row = QListWidgetItem(self._item_line(item.title, secondary))
            row.setData(Qt.ItemDataRole.UserRole, item.id)
            row.setSizeHint(QSize(0, 52))
            font = QFont()
            font.setPointSize(11)
            font.setBold(True)
            row.setFont(font)
            self.pass_list.addItem(row)
        self._rebuild_folder_combo()
        self.apply_filter(self.search.text())

    def refresh_gpg(self) -> None:
        self.gpg_list.clear()
        self._gpg_keys = []
        if not self.gpg.available:
            self.gpg_empty.setText("GnuPG was not found.\nInstall Gpg4win to manage OpenPGP keys.")
            self.gpg_empty.show()
            return
        try:
            public_keys = self.gpg.list_keys(secret=False)
            secret_keys = self.gpg.list_keys(secret=True)
        except GpgError as exc:
            self.gpg_empty.setText(str(exc))
            self.gpg_empty.show()
            return
        secret_ids: set[str] = set()
        for key in secret_keys:
            if key.fingerprint:
                secret_ids.add(key.fingerprint)
            if key.key_id:
                secret_ids.add(key.key_id)
        merged: dict[str, GpgKeyInfo] = {}
        for key in public_keys + secret_keys:
            ident = key.fingerprint or key.key_id
            if not ident:
                continue
            existing = merged.get(ident)
            if existing is None:
                key.is_secret = (key.fingerprint in secret_ids) or (key.key_id in secret_ids)
                merged[ident] = key
            elif key.is_secret:
                existing.is_secret = True
        self._gpg_keys = list(merged.values())
        if not self._gpg_keys:
            self.gpg_empty.setText("No PGP keys.\nCreate a key or import one.")
            self.gpg_empty.show()
        else:
            self.gpg_empty.hide()
        for key in self._gpg_keys:
            uid = key.uids[0] if key.uids else "(no user ID)"
            tail = (key.key_id or key.fingerprint or "")[-8:]
            secondary = f"OpenPGP key  ·  {tail}"
            row = QListWidgetItem(self._item_line(uid, secondary))
            row.setData(Qt.ItemDataRole.UserRole, key.fingerprint or key.key_id)
            row.setSizeHint(QSize(0, 52))
            self.gpg_list.addItem(row)
        self.apply_filter(self.search.text())

    def refresh_ssh(self) -> None:
        self.ssh_list.clear()
        self._ssh_keys = []
        if not self.ssh.available:
            self.ssh_empty.setText("ssh-keygen was not found.\nInstall OpenSSH Client.")
            self.ssh_empty.show()
            return
        try:
            self._ssh_keys = self.ssh.list_keys()
        except SshError as exc:
            self.ssh_empty.setText(str(exc))
            self.ssh_empty.show()
            return
        if not self._ssh_keys:
            self.ssh_empty.setText("No Secure Shell keys.\nCreate a key or import one.")
            self.ssh_empty.show()
        else:
            self.ssh_empty.hide()
        for key in self._ssh_keys:
            secondary = f"SSH Key  ·  {key.key_type}  ·  {key.fingerprint}"
            row = QListWidgetItem(self._item_line(key.name, secondary))
            row.setData(Qt.ItemDataRole.UserRole, key.name)
            row.setSizeHint(QSize(0, 52))
            self.ssh_list.addItem(row)
        self.apply_filter(self.search.text())

    def _selected_secret(self) -> SecretItem | None:
        item = self.pass_list.currentItem()
        if not item:
            return None
        item_id = item.data(Qt.ItemDataRole.UserRole)
        for secret in self.vault.items:
            if secret.id == item_id:
                return secret
        return None

    def _selected_gpg_fpr(self) -> str | None:
        item = self.gpg_list.currentItem()
        if not item:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _selected_ssh(self) -> SshKeyInfo | None:
        item = self.ssh_list.currentItem()
        if not item:
            return None
        name = item.data(Qt.ItemDataRole.UserRole)
        for key in self._ssh_keys:
            if key.name == name:
                return key
        return None

    def _on_item_selected(self, kind: str) -> None:
        if kind == "passwords":
            secret = self._selected_secret()
            if not secret:
                self.pass_detail.setPlainText("")
                return
            tags = ", ".join(secret.tags) if secret.tags else "—"
            folder = secret.folder or "—"
            self.pass_detail.setPlainText(
                f"Description: {secret.title}\n"
                f"Username: {secret.username}\n"
                f"Password: {'•' * min(12, max(4, len(secret.password)))}\n"
                f"URL / key: {secret.url}\n"
                f"Folder: {folder}\n"
                f"Tags: {tags}\n"
                f"Modified: {secret.modified}\n\n"
                f"{secret.notes}"
            )
        elif kind == "gpg":
            fpr = self._selected_gpg_fpr()
            key = next((k for k in self._gpg_keys if (k.fingerprint or k.key_id) == fpr), None)
            if not key:
                self.gpg_detail.setPlainText("")
                return
            self.gpg_detail.setPlainText(
                f"User IDs:\n  " + "\n  ".join(key.uids or ["(none)"]) + "\n\n"
                f"Key ID: {key.key_id}\n"
                f"Fingerprint: {key.fingerprint}\n"
                f"Created: {key.created}\n"
                f"Expires: {key.expires}\n"
                f"Capabilities: {key.capabilities or '—'}\n"
                f"Secret key: {'yes' if key.is_secret else 'no'}"
            )
        else:
            key = self._selected_ssh()
            if not key:
                self.ssh_detail.setPlainText("")
                return
            try:
                pub = self.ssh.read_public(key)
            except SshError:
                pub = "(public key unavailable)"
            self.ssh_detail.setPlainText(
                f"Name: {key.name}\n"
                f"Type: {key.key_type}\n"
                f"Bits: {key.bits}\n"
                f"Fingerprint: {key.fingerprint}\n"
                f"Comment: {key.comment}\n"
                f"Private key: {'yes' if key.has_private else 'no'}\n\n"
                f"Public key:\n{pub}"
            )

    def _on_item_activated(self, kind: str) -> None:
        if kind == "passwords":
            self.edit_secret()
        elif kind == "ssh":
            self.copy_ssh_public()

    def _ensure_unlocked(self) -> bool:
        if self.vault.unlocked:
            return True
        return self._prompt_unlock()

    def add_secret(self) -> None:
        self.sidebar.setCurrentRow(self.CAT_PASSWORDS)
        if not self._ensure_unlocked():
            return
        dialog = SecretEditor(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.vault.add_item(dialog.result_item())
            self.refresh_secrets()
            self.apply_filter(self.search.text())
            self._reset_idle_timer()
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def edit_secret(self) -> None:
        if not self._ensure_unlocked():
            return
        item = self._selected_secret()
        if not item:
            return
        dialog = SecretEditor(item, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.vault.update_item(dialog.result_item())
            self.refresh_secrets()
            self.apply_filter(self.search.text())
            self._reset_idle_timer()
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def delete_secret(self) -> None:
        if not self._ensure_unlocked():
            return
        item = self._selected_secret()
        if not item:
            return
        if QMessageBox.question(self, "Delete", f'Delete "{item.title}"?') != QMessageBox.StandardButton.Yes:
            return
        try:
            self.vault.delete_item(item.id)
            self.refresh_secrets()
            self._reset_idle_timer()
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def copy_secret_field(self, field: str) -> None:
        if not self._ensure_unlocked():
            return
        item = self._selected_secret()
        if not item:
            return
        text = getattr(item, field, "") or ""
        if not text:
            self.statusBar().showMessage(f"No {field} to copy", 2500)
            return
        self.clipboard.copy(text, clear_after_seconds=30)
        self.statusBar().showMessage(f"Copied {field} (clears in 30s)", 2500)
        self._reset_idle_timer()

    def export_passwords_json(self) -> None:
        self._export_passwords(redacted=False)

    def export_passwords_json_redacted(self) -> None:
        self._export_passwords(redacted=True)

    def _export_passwords(self, redacted: bool) -> None:
        if not self._ensure_unlocked():
            return
        if not redacted:
            reply = QMessageBox.warning(
                self,
                "Export passwords",
                "This file will contain passwords in cleartext.\n"
                "Treat it as highly sensitive.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export passwords",
            "seahorse-passwords-redacted.json" if redacted else "seahorse-passwords.json",
            "JSON files (*.json)",
        )
        if not path:
            return
        items = []
        for item in self.vault.items:
            d = item.to_dict()
            if redacted:
                d["password"] = ""
                d["_redacted"] = True
            items.append(d)
        document = {
            "format": "seahorse-secrets",
            "version": 1,
            "redacted": redacted,
            "items": items,
        }
        try:
            Path(path).write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
            self.statusBar().showMessage(f"Exported {len(items)} item(s) to {path}", 4000)
        except OSError as exc:
            QMessageBox.warning(self, "Export", f"Could not write file:\n{exc}")

    def import_passwords_json(self) -> None:
        if not self._ensure_unlocked():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import passwords", "", "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            rows = parse_import_payload(raw)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.warning(self, "Import", f"Could not read JSON:\n{exc}")
            return
        except VaultError as exc:
            QMessageBox.warning(self, "Import", str(exc))
            return
        existing_ids = {x.id for x in self.vault.items}
        added = 0
        updated = 0
        try:
            for row in rows:
                item = SecretItem.from_dict(row)
                if item.id in existing_ids:
                    self.vault.update_item(item, persist=False)
                    updated += 1
                else:
                    if not item.id:
                        item.id = secrets.token_hex(8)
                    self.vault.add_item(item, persist=False)
                    existing_ids.add(item.id)
                    added += 1
            if added or updated:
                self.vault.save()
            self.refresh_secrets()
            self.apply_filter(self.search.text())
            self._reset_idle_timer()
            QMessageBox.information(
                self,
                "Import",
                f"Import complete.\nAdded: {added}\nUpdated: {updated}",
            )
        except VaultError as exc:
            QMessageBox.warning(self, "Import", str(exc))

    def generate_gpg(self) -> None:
        self.sidebar.setCurrentRow(self.CAT_GPG)
        try:
            dialog = GenerateGpgDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            key_type = "ed25519" if dialog.key_type.currentText() == "ed25519" else "rsa"
            expire = dialog.expire.currentData()
            expire_s = "0" if expire is None else str(expire)
            fpr = self.gpg.generate_key(
                dialog.name.text(),
                dialog.email.text(),
                dialog.passphrase.text(),
                key_type=key_type,
                expire=expire_s,
            )
            QMessageBox.information(self, "PGP Key", f"Created key:\n{fpr}")
            self.refresh_gpg()
            self.apply_filter(self.search.text())
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))
        except Exception as exc:
            QMessageBox.critical(self, "OpenPGP", f"Unexpected error:\n{exc}")

    def import_gpg(self) -> None:
        self.sidebar.setCurrentRow(self.CAT_GPG)
        path, _ = QFileDialog.getOpenFileName(
            self, "Import OpenPGP key", "", "Key files (*.asc *.gpg *.key);;All files (*)"
        )
        if not path:
            return
        try:
            msg = self.gpg.import_key(path)
            QMessageBox.information(self, "Import", msg)
            self.refresh_gpg()
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))

    def export_gpg(self, secret: bool = False) -> None:
        fpr = self._selected_gpg_fpr()
        if not fpr:
            QMessageBox.information(self, "Export", "Select a key first.")
            return
        if secret:
            key = next((k for k in self._gpg_keys if (k.fingerprint or k.key_id) == fpr), None)
            if key is not None and not key.is_secret:
                QMessageBox.warning(self, "Export", "This key has no secret part to export.")
                return
        try:
            text = self.gpg.export_secret(fpr) if secret else self.gpg.export_public(fpr)
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export key",
            f"{fpr[-16:]}.{'sec' if secret else 'pub'}.asc",
            "ASCII armored (*.asc)",
        )
        if path:
            try:
                Path(path).write_text(text, encoding="utf-8")
                self.statusBar().showMessage(f"Exported {path}", 4000)
            except OSError as exc:
                QMessageBox.warning(self, "Export", f"Could not write file:\n{exc}")

    def delete_gpg(self) -> None:
        fpr = self._selected_gpg_fpr()
        if not fpr:
            return
        if QMessageBox.question(self, "Delete", f"Delete key {fpr}?") != QMessageBox.StandardButton.Yes:
            return
        key = next((k for k in self._gpg_keys if (k.fingerprint or k.key_id) == fpr), None)
        try:
            self.gpg.delete_key(fpr, secret=bool(key and key.is_secret))
            self.refresh_gpg()
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))

    def encrypt_gpg_text(self) -> None:
        fpr = self._selected_gpg_fpr()
        if not fpr:
            QMessageBox.information(self, "Encrypt", "Select a recipient key first.")
            return
        try:
            out = self.gpg.encrypt_text([fpr], self.gpg_text_in.toPlainText())
            self.gpg_detail.setPlainText(out)
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))

    def decrypt_gpg_text(self) -> None:
        try:
            out = self.gpg.decrypt_text(self.gpg_text_in.toPlainText())
            self.gpg_detail.setPlainText(out)
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))

    def sign_gpg_text(self) -> None:
        try:
            out = self.gpg.sign_text(self.gpg_text_in.toPlainText())
            self.gpg_detail.setPlainText(out)
        except GpgError as exc:
            QMessageBox.warning(self, "OpenPGP", str(exc))

    def generate_ssh(self) -> None:
        self.sidebar.setCurrentRow(self.CAT_SSH)
        try:
            dialog = GenerateSshDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            info = self.ssh.generate_key(
                name=dialog.name.text().strip() or "id_ed25519",
                key_type=dialog.key_type.currentText(),
                comment=dialog.comment.text(),
                passphrase=dialog.passphrase.text(),
            )
            QMessageBox.information(self, "SSH Key", f"Created {info.name}\n{info.fingerprint}")
            self.refresh_ssh()
            self.apply_filter(self.search.text())
        except SshError as exc:
            QMessageBox.warning(self, "SSH", str(exc))
        except Exception as exc:
            QMessageBox.critical(self, "SSH", f"Unexpected error:\n{exc}")

    def import_ssh(self) -> None:
        self.sidebar.setCurrentRow(self.CAT_SSH)
        path, _ = QFileDialog.getOpenFileName(self, "Import key", "", "All files (*)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            QMessageBox.warning(self, "SSH", f"Could not read file:\n{exc}")
            return
        name, ok = QInputDialog.getText(
            self, "Key name", "Store as:", text=Path(path).name.replace(".pub", "")
        )
        if not ok or not name:
            return
        try:
            if "PRIVATE KEY" in text:
                self.ssh.import_key_pair(private_text=text, name=name)
            else:
                self.ssh.import_key_pair(public_text=text, name=name)
            self.refresh_ssh()
        except SshError as exc:
            QMessageBox.warning(self, "SSH", str(exc))

    def copy_ssh_public(self) -> None:
        key = self._selected_ssh()
        if not key:
            return
        try:
            self.clipboard.copy(self.ssh.read_public(key).strip(), clear_after_seconds=0)
            self.statusBar().showMessage("Public key copied", 2500)
        except SshError as exc:
            QMessageBox.warning(self, "SSH", str(exc))

    def export_ssh_public(self) -> None:
        key = self._selected_ssh()
        if not key:
            return
        try:
            text = self.ssh.read_public(key)
        except SshError as exc:
            QMessageBox.warning(self, "SSH", str(exc))
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export public key", f"{key.name}.pub")
        if path:
            try:
                Path(path).write_text(text, encoding="utf-8")
            except OSError as exc:
                QMessageBox.warning(self, "Export", f"Could not write file:\n{exc}")

    def delete_ssh(self) -> None:
        key = self._selected_ssh()
        if not key:
            return
        if QMessageBox.question(self, "Delete", f"Delete {key.name}?") != QMessageBox.StandardButton.Yes:
            return
        try:
            self.ssh.delete_key(key)
            self.refresh_ssh()
        except SshError as exc:
            QMessageBox.warning(self, "SSH", str(exc))

    def lock_vault(self) -> None:
        if not self.vault.unlocked:
            QMessageBox.information(self, "Locked", "Password vault is already locked.")
            return
        self._lock_vault_silent()
        QMessageBox.information(
            self,
            "Locked",
            "Password vault is locked.\nUse Unlock passwords… to unlock again.",
        )

    def unlock_vault_ui(self) -> None:
        if self.vault.unlocked:
            QMessageBox.information(self, "Unlocked", "Password vault is already unlocked.")
            return
        self._prompt_unlock()

    def closeEvent(self, event) -> None:
        try:
            self.clipboard.flush()
        except Exception:
            pass
        try:
            self._idle_timer.stop()
        except Exception:
            pass
        app = QGuiApplication.instance()
        if app is not None and hasattr(self, "_activity_filter"):
            try:
                app.removeEventFilter(self._activity_filter)
            except Exception:
                pass
        super().closeEvent(event)

    def change_master_password(self) -> None:
        if not self._ensure_unlocked():
            return
        old, ok = QInputDialog.getText(
            self, "Current password", "Current master password:", QLineEdit.EchoMode.Password
        )
        if not ok:
            return
        new, ok = QInputDialog.getText(
            self, "New password", "New master password:", QLineEdit.EchoMode.Password
        )
        if not ok or not new:
            return
        confirm, ok = QInputDialog.getText(
            self, "Confirm", "Confirm new password:", QLineEdit.EchoMode.Password
        )
        if not ok:
            return
        if new != confirm:
            QMessageBox.warning(self, "Mismatch", "New passwords do not match.")
            return
        try:
            self.vault.change_password(old, new)
            self._reset_idle_timer()
            QMessageBox.information(self, "Done", "Master password updated.")
        except InvalidPasswordError:
            QMessageBox.warning(self, "Error", "Current password is incorrect.")
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))
