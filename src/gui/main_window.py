from __future__ import annotations

import secrets
from pathlib import Path

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QFont, QGuiApplication
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

from crypto.vault import InvalidPasswordError, SecretItem, SecretsVault, VaultError
from gpg_backend.manager import GpgError, GpgKeyInfo, GpgManager
from ssh_backend.manager import SshError, SshKeyInfo, SshManager
from utils.clipboard import ClipboardManager
from utils.themes import theme_stylesheet
from version import APP_DISPLAY_NAME, APP_VERSION


class SecretEditor(QDialog):
    def __init__(self, item: SecretItem | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Password" if item else "New Password")
        self.setMinimumWidth(440)
        self.item = item
        layout = QFormLayout(self)
        layout.setSpacing(10)
        self.title = QLineEdit(item.title if item else "")
        self.username = QLineEdit(item.username if item else "")
        self.password = QLineEdit(item.password if item else "")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.url = QLineEdit(item.url if item else "")
        self.notes = QPlainTextEdit(item.notes if item else "")
        self.notes.setMinimumHeight(100)
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
        layout.addRow("Key / URL", self.url)
        layout.addRow("Notes", self.notes)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _generate(self) -> None:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+"
        self.password.setText("".join(secrets.choice(alphabet) for _ in range(20)))
        self.password.setEchoMode(QLineEdit.EchoMode.Normal)

    def result_item(self) -> SecretItem:
        base = self.item or SecretItem(id=secrets.token_hex(8), title="")
        base.title = self.title.text().strip() or "Untitled"
        base.username = self.username.text()
        base.password = self.password.text()
        base.url = self.url.text()
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
    ) -> None:
        super().__init__()
        self.vault = vault
        self.gpg = gpg
        self.ssh = ssh
        self.theme_name = theme_name
        app = QGuiApplication.instance()
        if clipboard is not None:
            self.clipboard = clipboard
        elif app is not None:
            self.clipboard = ClipboardManager(app)
        else:
            raise RuntimeError("ClipboardManager requires a running QGuiApplication")
        self._gpg_keys: list[GpgKeyInfo] = []
        self._ssh_keys: list[SshKeyInfo] = []
        self.setWindowTitle(f"{APP_DISPLAY_NAME}")
        self.resize(1080, 700)
        self.setMinimumSize(860, 560)
        self._build_chrome()
        self.refresh_all()

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
        overflow.addAction("Change master password…", self.change_master_password)
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

        self.view_title = QLabel("Passwords")
        self.view_title.setObjectName("ViewTitle")
        content_l.addWidget(self.view_title)

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
        return f"{gpg}  ·  {ssh}  ·  Portable data"

    def refresh_all(self) -> None:
        self.refresh_secrets()
        self.refresh_gpg()
        self.refresh_ssh()
        self.apply_filter(self.search.text())
        self.statusBar().showMessage(self._status_summary())

    def apply_filter(self, text: str) -> None:
        q = (text or "").strip().lower()
        for lst in (self.pass_list, self.gpg_list, self.ssh_list):
            for i in range(lst.count()):
                item = lst.item(i)
                item.setHidden(bool(q) and q not in item.text().lower())

    def _item_line(self, primary: str, secondary: str = "") -> str:
        if secondary:
            return f"{primary}\n{secondary}"
        return primary

    def refresh_secrets(self) -> None:
        self.pass_list.clear()
        if not self.vault.unlocked:
            self.pass_empty.setText("Password vault is locked.")
            self.pass_empty.show()
            return
        if not self.vault.items:
            self.pass_empty.setText("No passwords yet.\nClick + to store a password.")
            self.pass_empty.show()
        else:
            self.pass_empty.hide()
        for item in self.vault.items:
            secondary = item.username or item.url or "Password"
            row = QListWidgetItem(self._item_line(item.title, secondary))
            row.setData(Qt.ItemDataRole.UserRole, item.id)
            row.setSizeHint(QSize(0, 52))
            font = QFont()
            font.setPointSize(11)
            font.setBold(True)
            row.setFont(font)
            self.pass_list.addItem(row)

    def refresh_gpg(self) -> None:
        self.gpg_list.clear()
        self._gpg_keys = []
        if not self.gpg.available:
            self.gpg_empty.setText("GnuPG was not found.\nInstall Gpg4win to manage OpenPGP keys.")
            self.gpg_empty.show()
            return
        try:
            keys = self.gpg.list_keys(secret=True)
            if not keys:
                keys = self.gpg.list_keys(secret=False)
            self._gpg_keys = keys
        except GpgError as exc:
            self.gpg_empty.setText(str(exc))
            self.gpg_empty.show()
            return
        if not self._gpg_keys:
            self.gpg_empty.setText("No PGP keys.\nCreate a key or import one.")
            self.gpg_empty.show()
        else:
            self.gpg_empty.hide()
        for key in self._gpg_keys:
            uid = key.uids[0] if key.uids else "(no user ID)"
            secondary = f"OpenPGP key  ·  {key.key_id[-8:] if key.key_id else key.fingerprint[-8:]}"
            row = QListWidgetItem(self._item_line(uid, secondary))
            row.setData(Qt.ItemDataRole.UserRole, key.fingerprint or key.key_id)
            row.setSizeHint(QSize(0, 52))
            self.gpg_list.addItem(row)

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
            self.pass_detail.setPlainText(
                f"Description: {secret.title}\n"
                f"Username: {secret.username}\n"
                f"Password: {'•' * min(12, max(4, len(secret.password)))}\n"
                f"URL / key: {secret.url}\n"
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

    def add_secret(self) -> None:
        self.sidebar.setCurrentRow(self.CAT_PASSWORDS)
        dialog = SecretEditor(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.vault.add_item(dialog.result_item())
            self.refresh_secrets()
            self.apply_filter(self.search.text())
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def edit_secret(self) -> None:
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
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def delete_secret(self) -> None:
        item = self._selected_secret()
        if not item:
            return
        if QMessageBox.question(self, "Delete", f'Delete "{item.title}"?') != QMessageBox.StandardButton.Yes:
            return
        try:
            self.vault.delete_item(item.id)
            self.refresh_secrets()
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def copy_secret_field(self, field: str) -> None:
        item = self._selected_secret()
        if not item:
            return
        text = getattr(item, field, "") or ""
        if not text:
            self.statusBar().showMessage(f"No {field} to copy", 2500)
            return
        # Auto-clear secrets from the clipboard after 30s (and on lock/exit).
        self.clipboard.copy(text, clear_after_seconds=30)
        self.statusBar().showMessage(f"Copied {field} (clears in 30s)", 2500)

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
            Path(path).write_text(text, encoding="utf-8")
            self.statusBar().showMessage(f"Exported {path}", 4000)

    def delete_gpg(self) -> None:
        fpr = self._selected_gpg_fpr()
        if not fpr:
            return
        if QMessageBox.question(self, "Delete", f"Delete key {fpr}?") != QMessageBox.StandardButton.Yes:
            return
        try:
            self.gpg.delete_key(fpr, secret=True)
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
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
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
            # Public keys are not secrets; leave on clipboard (no auto-clear).
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
            Path(path).write_text(text, encoding="utf-8")

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
        self.clipboard.flush()
        self.vault.lock()
        self.refresh_secrets()
        QMessageBox.information(
            self,
            "Locked",
            "Password vault is locked.\nRestart Passwords and Keys to unlock.",
        )

    def closeEvent(self, event) -> None:  # type: ignore[override]
        try:
            self.clipboard.flush()
        except Exception:
            pass
        super().closeEvent(event)

    def change_master_password(self) -> None:
        if not self.vault.unlocked:
            QMessageBox.information(self, "Locked", "Unlock the vault first.")
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
        if not ok or new != confirm:
            QMessageBox.warning(self, "Mismatch", "New passwords do not match.")
            return
        try:
            self.vault.change_password(old, new)
            QMessageBox.information(self, "Done", "Master password updated.")
        except InvalidPasswordError:
            QMessageBox.warning(self, "Error", "Current password is incorrect.")
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))
