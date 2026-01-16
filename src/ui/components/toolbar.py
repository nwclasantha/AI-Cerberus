"""
Main toolbar component.

Provides quick access to common actions and file operations.
"""

from __future__ import annotations

from typing import Optional
from PyQt6.QtWidgets import (
    QToolBar, QWidget, QLineEdit, QToolButton, QMenu,
    QFileDialog, QSizePolicy, QHBoxLayout, QLabel,
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QAction, QIcon, QKeySequence

from ..theme import get_theme_manager


class SearchBar(QLineEdit):
    """Enhanced search bar with clear button."""

    search_submitted = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self.setPlaceholderText("Search samples, hashes, strings...")
        self.setMinimumWidth(300)
        self.setMaximumWidth(400)

        # Style
        theme = get_theme_manager()
        p = theme.get_palette()
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: {p.bg_tertiary};
                border: 1px solid {p.border_primary};
                border-radius: 20px;
                padding: 8px 16px;
                color: {p.text_primary};
            }}
            QLineEdit:focus {{
                border-color: {p.accent_primary};
            }}
        """)

        # Connect signals
        self.returnPressed.connect(self._on_submit)

    def _on_submit(self) -> None:
        """Handle search submission."""
        query = self.text().strip()
        if query:
            self.search_submitted.emit(query)


class MainToolbar(QToolBar):
    """
    Main application toolbar.

    Provides:
    - File operations (open, save, export)
    - Search functionality
    - Quick actions
    - View toggles
    """

    # Signals
    file_open_requested = pyqtSignal()
    folder_open_requested = pyqtSignal()
    file_save_requested = pyqtSignal()
    export_requested = pyqtSignal()
    search_submitted = pyqtSignal(str)
    refresh_requested = pyqtSignal()
    settings_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize toolbar."""
        super().__init__("Main Toolbar", parent)

        self.setMovable(False)
        self.setIconSize(QSize(20, 20))
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)

        self._setup_ui()
        self._setup_style()

    def _setup_ui(self) -> None:
        """Set up toolbar UI."""
        # File operations
        self._add_file_actions()

        self.addSeparator()

        # Analysis actions
        self._add_analysis_actions()

        self.addSeparator()

        # Spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.addWidget(spacer)

        # Search bar
        self._search_bar = SearchBar()
        self._search_bar.search_submitted.connect(self.search_submitted.emit)
        self.addWidget(self._search_bar)

        # Spacer
        spacer2 = QWidget()
        spacer2.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.addWidget(spacer2)

        # View actions
        self._add_view_actions()

        self.addSeparator()

        # Settings
        self._add_settings_actions()

    def _add_file_actions(self) -> None:
        """Add file operation actions."""
        # Open file
        open_action = QAction("Open File", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.setToolTip("Open file for analysis (Ctrl+O)")
        open_action.triggered.connect(self.file_open_requested.emit)
        self.addAction(open_action)

        # Open folder
        open_folder_action = QAction("Open Folder", self)
        open_folder_action.setToolTip("Open folder for batch analysis")
        open_folder_action.triggered.connect(self.folder_open_requested.emit)
        self.addAction(open_folder_action)

        # Save report
        save_action = QAction("Save Report", self)
        save_action.setShortcut(QKeySequence.StandardKey.Save)
        save_action.setToolTip("Save analysis report (Ctrl+S)")
        save_action.triggered.connect(self.file_save_requested.emit)
        self.addAction(save_action)

        # Export menu
        export_btn = QToolButton()
        export_btn.setText("Export")
        export_btn.setToolTip("Export analysis results")
        export_btn.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)

        export_menu = QMenu(export_btn)
        export_menu.addAction("Export as JSON")
        export_menu.addAction("Export as PDF")
        export_menu.addAction("Export as CSV")
        export_menu.addAction("Export as STIX")
        export_btn.setMenu(export_menu)
        export_btn.clicked.connect(self.export_requested.emit)

        self.addWidget(export_btn)

    def _add_analysis_actions(self) -> None:
        """Add analysis action buttons."""
        # Start analysis
        analyze_action = QAction("Analyze", self)
        analyze_action.setToolTip("Start analysis (F5)")
        analyze_action.setShortcut(QKeySequence("F5"))
        self.addAction(analyze_action)

        # Stop analysis
        stop_action = QAction("Stop", self)
        stop_action.setToolTip("Stop current analysis")
        self.addAction(stop_action)

        # Refresh
        refresh_action = QAction("Refresh", self)
        refresh_action.setShortcut(QKeySequence.StandardKey.Refresh)
        refresh_action.setToolTip("Refresh current view (F5)")
        refresh_action.triggered.connect(self.refresh_requested.emit)
        self.addAction(refresh_action)

    def _add_view_actions(self) -> None:
        """Add view toggle actions."""
        # Theme toggle
        theme_btn = QToolButton()
        theme_btn.setText("Theme")
        theme_btn.setToolTip("Toggle light/dark theme")
        theme_btn.clicked.connect(self._toggle_theme)
        self.addWidget(theme_btn)

        # Fullscreen toggle
        fullscreen_action = QAction("Fullscreen", self)
        fullscreen_action.setShortcut(QKeySequence("F11"))
        fullscreen_action.setToolTip("Toggle fullscreen (F11)")
        self.addAction(fullscreen_action)

    def _add_settings_actions(self) -> None:
        """Add settings actions."""
        settings_action = QAction("Settings", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.setToolTip("Open settings (Ctrl+,)")
        settings_action.triggered.connect(self.settings_requested.emit)
        self.addAction(settings_action)

    def _setup_style(self) -> None:
        """Configure toolbar appearance."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self.setStyleSheet(f"""
            QToolBar {{
                background-color: {p.bg_secondary};
                border: none;
                border-bottom: 1px solid {p.border_primary};
                spacing: 8px;
                padding: 8px 16px;
            }}
            QToolButton {{
                background-color: transparent;
                border: none;
                border-radius: 6px;
                padding: 8px 12px;
                color: {p.text_secondary};
                font-weight: 500;
            }}
            QToolButton:hover {{
                background-color: {p.bg_hover};
                color: {p.text_primary};
            }}
            QToolButton:pressed {{
                background-color: {p.bg_tertiary};
            }}
        """)

    def _toggle_theme(self) -> None:
        """Toggle application theme."""
        theme = get_theme_manager()
        theme.toggle_theme()
        self._setup_style()

    def set_search_text(self, text: str) -> None:
        """Set search bar text."""
        self._search_bar.setText(text)

    def get_search_text(self) -> str:
        """Get search bar text."""
        return self._search_bar.text()

    def clear_search(self) -> None:
        """Clear search bar."""
        self._search_bar.clear()
