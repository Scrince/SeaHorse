from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QGuiApplication


class ClipboardManager:
    def __init__(self, app: QGuiApplication) -> None:
        self._app = app
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear)
        self._pending_text: str | None = None

    def copy(self, text: str, clear_after_seconds: int = 30) -> None:
        self._app.clipboard().setText(text)
        self._pending_text = text
        self._timer.stop()
        if clear_after_seconds > 0:
            self._timer.start(clear_after_seconds * 1000)
        else:
            self._pending_text = None

    def clear(self) -> None:
        if self._pending_text is not None and self._app.clipboard().text() == self._pending_text:
            self._app.clipboard().clear()
        self._timer.stop()
        self._pending_text = None

    def flush(self) -> None:
        self.clear()
