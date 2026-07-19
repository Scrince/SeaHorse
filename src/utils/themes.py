from __future__ import annotations


def theme_stylesheet(name: str) -> str:
    if name == "dark":
        return ADWAITA_DARK
    return ADWAITA_LIGHT


ADWAITA_LIGHT = """
* {
  font-family: "Segoe UI", "Cantarell", "Ubuntu", sans-serif;
  font-size: 14px;
}
QMainWindow, QDialog, QWidget#Root {
  background: #fafafa;
  color: #241f31;
}
QWidget#HeaderBar {
  background: #ffffff;
  border-bottom: 1px solid #deddda;
  min-height: 46px;
}
QLabel#AppTitle {
  font-size: 15px;
  font-weight: 700;
  color: #241f31;
  padding-left: 4px;
}
QLabel#ViewTitle {
  font-size: 20px;
  font-weight: 800;
  color: #241f31;
  padding: 4px 0 8px 0;
}
QLabel#Muted, QLabel#EmptyHint {
  color: #77767b;
}
QLabel#EmptyHint {
  font-size: 15px;
  padding: 24px;
}
QLineEdit#SearchField {
  background: #f6f5f4;
  border: 1px solid #c0bfbc;
  border-radius: 9px;
  padding: 7px 12px;
  min-width: 220px;
  selection-background-color: #3584e4;
}
QLineEdit#SearchField:focus {
  border: 2px solid #3584e4;
  background: #ffffff;
}
QListWidget#Sidebar {
  background: #f6f5f4;
  border: none;
  border-right: 1px solid #deddda;
  outline: none;
  padding: 8px 6px;
  font-size: 14px;
}
QListWidget#Sidebar::item {
  padding: 10px 12px;
  margin: 2px 4px;
  border-radius: 8px;
  color: #3d3846;
}
QListWidget#Sidebar::item:selected {
  background: #3584e4;
  color: #ffffff;
  font-weight: 600;
}
QListWidget#Sidebar::item:hover:!selected {
  background: #eae9e7;
}
QListWidget#ItemList {
  background: #ffffff;
  border: 1px solid #deddda;
  border-radius: 12px;
  outline: none;
  padding: 4px;
}
QListWidget#ItemList::item {
  padding: 12px 14px;
  border-radius: 8px;
  margin: 1px 2px;
  border-bottom: 1px solid #f0efed;
}
QListWidget#ItemList::item:selected {
  background: #cce0f5;
  color: #241f31;
  border-bottom: 1px solid #cce0f5;
}
QListWidget#ItemList::item:hover:!selected {
  background: #f6f5f4;
}
QPushButton {
  background: #ffffff;
  color: #241f31;
  border: 1px solid #c0bfbc;
  border-radius: 9px;
  padding: 7px 14px;
  min-height: 18px;
}
QPushButton:hover {
  background: #f6f5f4;
}
QPushButton:pressed {
  background: #eae9e7;
}
QPushButton#PrimaryButton, QPushButton#HeaderPrimary, QToolButton#HeaderPrimary {
  background: #3584e4;
  color: #ffffff;
  border: 1px solid #1c71d8;
  font-weight: 600;
}
QPushButton#PrimaryButton:hover, QPushButton#HeaderPrimary:hover, QToolButton#HeaderPrimary:hover {
  background: #1c71d8;
}
QToolButton#HeaderPrimary {
  border-radius: 9px;
  font-size: 18px;
  padding: 4px 10px;
}
QPushButton#FlatButton, QPushButton#HeaderButton, QToolButton#HeaderButton {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 9px;
  padding: 7px 12px;
  font-size: 16px;
  min-width: 28px;
  color: #241f31;
}
QPushButton#FlatButton:hover, QPushButton#HeaderButton:hover, QToolButton#HeaderButton:hover {
  background: #eae9e7;
  border: 1px solid #deddda;
}
QPushButton#DangerButton {
  background: #e01b24;
  color: #ffffff;
  border: 1px solid #c01c28;
}
QPushButton#DangerButton:hover {
  background: #c01c28;
}
QFrame#ContentPane {
  background: #fafafa;
  border: none;
}
QFrame#DetailPane {
  background: #ffffff;
  border: 1px solid #deddda;
  border-radius: 12px;
}
QPlainTextEdit, QTextEdit, QLineEdit, QComboBox {
  background: #ffffff;
  color: #241f31;
  border: 1px solid #c0bfbc;
  border-radius: 8px;
  padding: 7px 10px;
  selection-background-color: #3584e4;
  selection-color: #ffffff;
}
QPlainTextEdit:focus, QTextEdit:focus, QLineEdit:focus, QComboBox:focus {
  border: 2px solid #3584e4;
}
QComboBox::drop-down { border: none; width: 24px; }
QStatusBar {
  background: #f6f5f4;
  color: #5e5c64;
  border-top: 1px solid #deddda;
}
QMenuBar {
  background: #ffffff;
  color: #241f31;
  border-bottom: 1px solid #deddda;
  spacing: 4px;
  padding: 2px 6px;
}
QMenuBar::item {
  background: transparent;
  padding: 6px 10px;
  border-radius: 6px;
}
QMenuBar::item:selected { background: #eae9e7; }
QMenu {
  background: #ffffff;
  color: #241f31;
  border: 1px solid #c0bfbc;
  border-radius: 10px;
  padding: 6px;
}
QMenu::item {
  padding: 8px 28px 8px 12px;
  border-radius: 6px;
}
QMenu::item:selected {
  background: #3584e4;
  color: #ffffff;
}
QMenu::separator {
  height: 1px;
  background: #deddda;
  margin: 4px 8px;
}
QDialog {
  background: #fafafa;
}
QDialogButtonBox QPushButton {
  min-width: 80px;
}
QGroupBox {
  border: 1px solid #deddda;
  border-radius: 10px;
  margin-top: 12px;
  padding-top: 14px;
  background: #ffffff;
}
QGroupBox::title {
  subcontrol-origin: margin;
  left: 12px;
  padding: 0 6px;
  color: #5e5c64;
  font-weight: 600;
}
QScrollBar:vertical {
  background: transparent;
  width: 12px;
  margin: 4px;
}
QScrollBar::handle:vertical {
  background: #c0bfbc;
  border-radius: 6px;
  min-height: 30px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QMessageBox { background: #fafafa; }
QToolTip {
  background: #3d3846;
  color: #ffffff;
  border: none;
  padding: 6px 8px;
  border-radius: 6px;
}
"""

ADWAITA_DARK = """
* {
  font-family: "Segoe UI", "Cantarell", "Ubuntu", sans-serif;
  font-size: 14px;
}
QMainWindow, QDialog, QWidget#Root {
  background: #242424;
  color: #ffffff;
}
QWidget#HeaderBar {
  background: #303030;
  border-bottom: 1px solid #3d3846;
  min-height: 46px;
}
QLabel#AppTitle {
  font-size: 15px;
  font-weight: 700;
  color: #ffffff;
  padding-left: 4px;
}
QLabel#ViewTitle {
  font-size: 20px;
  font-weight: 800;
  color: #ffffff;
  padding: 4px 0 8px 0;
}
QLabel#Muted, QLabel#EmptyHint { color: #9a9996; }
QLabel#EmptyHint { font-size: 15px; padding: 24px; }
QLineEdit#SearchField {
  background: #1e1e1e;
  border: 1px solid #5e5c64;
  border-radius: 9px;
  padding: 7px 12px;
  min-width: 220px;
  color: #ffffff;
  selection-background-color: #3584e4;
}
QLineEdit#SearchField:focus {
  border: 2px solid #3584e4;
  background: #1e1e1e;
}
QListWidget#Sidebar {
  background: #303030;
  border: none;
  border-right: 1px solid #3d3846;
  outline: none;
  padding: 8px 6px;
}
QListWidget#Sidebar::item {
  padding: 10px 12px;
  margin: 2px 4px;
  border-radius: 8px;
  color: #deddda;
}
QListWidget#Sidebar::item:selected {
  background: #3584e4;
  color: #ffffff;
  font-weight: 600;
}
QListWidget#Sidebar::item:hover:!selected { background: #3d3846; }
QListWidget#ItemList {
  background: #1e1e1e;
  border: 1px solid #3d3846;
  border-radius: 12px;
  outline: none;
  padding: 4px;
  color: #ffffff;
}
QListWidget#ItemList::item {
  padding: 12px 14px;
  border-radius: 8px;
  margin: 1px 2px;
  border-bottom: 1px solid #2a2a2a;
}
QListWidget#ItemList::item:selected {
  background: #1c71d8;
  color: #ffffff;
}
QListWidget#ItemList::item:hover:!selected { background: #303030; }
QPushButton {
  background: #3d3846;
  color: #ffffff;
  border: 1px solid #5e5c64;
  border-radius: 9px;
  padding: 7px 14px;
}
QPushButton:hover { background: #5e5c64; }
QPushButton#PrimaryButton, QPushButton#HeaderPrimary, QToolButton#HeaderPrimary {
  background: #3584e4;
  color: #ffffff;
  border: 1px solid #1c71d8;
  font-weight: 600;
}
QPushButton#PrimaryButton:hover, QPushButton#HeaderPrimary:hover, QToolButton#HeaderPrimary:hover {
  background: #1c71d8;
}
QToolButton#HeaderPrimary { border-radius: 9px; font-size: 18px; padding: 4px 10px; }
QPushButton#FlatButton, QPushButton#HeaderButton, QToolButton#HeaderButton {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 9px;
  padding: 7px 12px;
  font-size: 16px;
  color: #ffffff;
}
QPushButton#FlatButton:hover, QPushButton#HeaderButton:hover, QToolButton#HeaderButton:hover {
  background: #3d3846;
  border: 1px solid #5e5c64;
}
QPushButton#DangerButton {
  background: #c01c28;
  color: #ffffff;
  border: 1px solid #a51d2d;
}
QFrame#ContentPane { background: #242424; border: none; }
QFrame#DetailPane {
  background: #1e1e1e;
  border: 1px solid #3d3846;
  border-radius: 12px;
}
QPlainTextEdit, QTextEdit, QLineEdit, QComboBox {
  background: #1e1e1e;
  color: #ffffff;
  border: 1px solid #5e5c64;
  border-radius: 8px;
  padding: 7px 10px;
  selection-background-color: #3584e4;
}
QPlainTextEdit:focus, QTextEdit:focus, QLineEdit:focus, QComboBox:focus {
  border: 2px solid #3584e4;
}
QStatusBar {
  background: #303030;
  color: #9a9996;
  border-top: 1px solid #3d3846;
}
QMenuBar {
  background: #303030;
  color: #ffffff;
  border-bottom: 1px solid #3d3846;
}
QMenuBar::item { padding: 6px 10px; border-radius: 6px; }
QMenuBar::item:selected { background: #3d3846; }
QMenu {
  background: #303030;
  color: #ffffff;
  border: 1px solid #5e5c64;
  border-radius: 10px;
  padding: 6px;
}
QMenu::item { padding: 8px 28px 8px 12px; border-radius: 6px; }
QMenu::item:selected { background: #3584e4; color: #ffffff; }
QMenu::separator { height: 1px; background: #5e5c64; margin: 4px 8px; }
QDialog { background: #242424; }
QGroupBox {
  border: 1px solid #3d3846;
  border-radius: 10px;
  margin-top: 12px;
  padding-top: 14px;
  background: #1e1e1e;
}
QGroupBox::title { left: 12px; padding: 0 6px; color: #9a9996; font-weight: 600; }
QScrollBar:vertical { background: transparent; width: 12px; margin: 4px; }
QScrollBar::handle:vertical { background: #5e5c64; border-radius: 6px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QMessageBox { background: #242424; }
"""
