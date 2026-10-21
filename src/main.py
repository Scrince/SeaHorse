from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _install_exception_hook() -> None:
    def _hook(exc_type, exc, tb) -> None:
        details = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            QMessageBox.critical(
                None,
                "Passwords and Keys — unexpected error",
                f"{exc_type.__name__}: {exc}\n\n{details[-2500:]}",
            )
        except Exception:
            sys.__excepthook__(exc_type, exc, tb)
            return
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook


from crypto.vault import InvalidPasswordError, SecretsVault, VaultError
from gpg_backend.manager import GpgManager
from gui.main_window import MainWindow
from ssh_backend.manager import SshManager
from utils.clipboard import ClipboardManager
from utils.paths import (
    DataDirError,
    portable_gnupg_home,
    portable_ssh_dir,
    settings_path,
    vault_path,
)
from utils.themes import theme_stylesheet
from version import APP_DISPLAY_NAME, APP_NAME, APP_VERSION

DEFAULT_AUTO_LOCK_MINUTES = 10


class UnlockDialog(QDialog):
    def __init__(self, creating: bool) -> None:
        super().__init__()
        self.creating = creating
        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 16)
        title = QLabel("Create a new keyring password" if creating else "Enter password to unlock your keyring")
        title.setObjectName("ViewTitle")
        title.setStyleSheet("font-size: 16px;")
        layout.addWidget(title)
        hint = QLabel(
            "Passwords are stored in a local encrypted keyring. "
            "OpenPGP and SSH keys are managed separately, like in GNOME Seahorse."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password")
        layout.addWidget(self.password)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm.setPlaceholderText("Confirm password")
        self.confirm.setVisible(creating)
        layout.addWidget(self.confirm)
        row = QHBoxLayout()
        ok = QPushButton("Create" if creating else "Unlock")
        ok.setObjectName("PrimaryButton")
        ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        row.addStretch(1)
        row.addWidget(cancel)
        row.addWidget(ok)
        layout.addLayout(row)
        self.password.returnPressed.connect(self.accept)
        self.confirm.returnPressed.connect(self.accept)

    def accept(self) -> None:
        if not self.password.text():
            QMessageBox.warning(self, "Password required", "Master password is required.")
            return
        if self.creating and self.password.text() != self.confirm.text():
            QMessageBox.warning(self, "Mismatch", "Password confirmation does not match.")
            return
        super().accept()


def load_settings() -> dict[str, Any]:
    path = settings_path()
    defaults: dict[str, Any] = {
        "theme": "light",
        "auto_lock_minutes": DEFAULT_AUTO_LOCK_MINUTES,
    }
    if not path.exists():
        return dict(defaults)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return dict(defaults)
    except (OSError, json.JSONDecodeError, TypeError):
        return dict(defaults)
    theme = str(data.get("theme", "light"))
    if theme not in ("dark", "light"):
        theme = "light"
    try:
        auto_lock = int(data.get("auto_lock_minutes", DEFAULT_AUTO_LOCK_MINUTES))
    except (TypeError, ValueError):
        auto_lock = DEFAULT_AUTO_LOCK_MINUTES
    auto_lock = max(0, min(auto_lock, 24 * 60))
    return {"theme": theme, "auto_lock_minutes": auto_lock}


def save_settings(updates: dict[str, Any]) -> None:
    path = settings_path()
    data: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError, TypeError):
            data = {}
    data.update(updates)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_theme_name() -> str:
    return str(load_settings().get("theme", "light"))


def save_theme_name(name: str) -> None:
    save_settings({"theme": name})


class SeaHorseApp:
    def __init__(self) -> None:
        try:
            QApplication.setHighDpiScaleFactorRoundingPolicy(
                Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
            )
        except Exception:
            pass
        self.qt = QApplication(sys.argv)
        self.qt.setApplicationName(APP_NAME)
        self.qt.setApplicationDisplayName(APP_DISPLAY_NAME)
        self.qt.setApplicationVersion(APP_VERSION)
        self.qt.setOrganizationName("SeaHorse")
        try:
            self.settings = load_settings()
            self.theme_name = str(self.settings.get("theme", "light"))
            self.qt.setStyleSheet(theme_stylesheet(self.theme_name))
            self.vault = SecretsVault(vault_path())
            self.gpg = GpgManager(portable_gnupg_home())
            self.ssh = SshManager(portable_ssh_dir())
        except DataDirError as exc:
            QMessageBox.critical(None, APP_DISPLAY_NAME, str(exc))
            raise SystemExit(1) from exc
        self.window: MainWindow | None = None

    def _persist_settings(self, updates: dict[str, Any]) -> None:
        try:
            save_settings(updates)
            self.settings.update(updates)
        except OSError:
            pass

    def run(self) -> int:
        if not self.unlock_vault():
            return 0
        self.clipboard = ClipboardManager(self.qt)
        auto_lock = int(self.settings.get("auto_lock_minutes", DEFAULT_AUTO_LOCK_MINUTES))
        self.window = MainWindow(
            self.vault,
            self.gpg,
            self.ssh,
            self.theme_name,
            clipboard=self.clipboard,
            auto_lock_minutes=auto_lock,
            on_settings_changed=self._persist_settings,
        )
        original_set_theme = self.window.set_theme

        def set_theme_and_persist(name: str) -> None:
            original_set_theme(name)
            self.qt.setStyleSheet(theme_stylesheet(name))
            self._persist_settings({"theme": name})

        self.window.set_theme = set_theme_and_persist
        self.window.show()
        missing = []
        if not self.gpg.available:
            missing.append("• GnuPG / Gpg4win — needed for OpenPGP keys")
        if not self.ssh.available:
            missing.append("• OpenSSH Client (ssh-keygen) — needed for SSH keys")
        if missing:
            QMessageBox.information(
                self.window,
                "Optional components",
                "Passwords work offline. For full features, install:\n\n"
                + "\n".join(missing)
                + "\n\nKeep the whole SeaHorse folder together (SeaHorse.exe + _internal).",
            )
        return self.qt.exec()

    def unlock_vault(self) -> bool:
        creating = not self.vault.exists()
        while True:
            dialog = UnlockDialog(creating)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return False
            password = dialog.password.text()
            try:
                if creating:
                    self.vault.create(password)
                else:
                    self.vault.unlock(password)
                return True
            except InvalidPasswordError:
                QMessageBox.warning(None, "Unlock failed", "Incorrect master password.")
            except VaultError as exc:
                QMessageBox.warning(None, "Vault error", str(exc))


def main() -> int:
    _install_exception_hook()
    return SeaHorseApp().run()


if __name__ == "__main__":
    raise SystemExit(main())
