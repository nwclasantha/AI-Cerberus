"""
Theme manager for the Malware Analysis Platform.

Handles theme switching, persistence, and dynamic updates.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor, QFont

from .colors import Colors, ColorPalette
from .dark_theme import DarkTheme
from ...utils.config import get_config
from ...utils.logger import get_logger

logger = get_logger("theme_manager")


class ThemeManager:
    """
    Manages application theming and appearance.

    Features:
    - Multiple theme support (dark, darker, light)
    - Runtime theme switching
    - Persistent theme preferences
    - Custom font management

    Thread-safe singleton implementation.
    """

    _instance: Optional[ThemeManager] = None
    _lock: threading.Lock = threading.Lock()

    THEMES: Dict[str, ColorPalette] = {
        "dark": Colors.DARK,
        "darker": Colors.DARKER,
        "light": Colors.LIGHT,
    }

    def __new__(cls) -> ThemeManager:
        """Thread-safe singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        """Initialize theme manager."""
        if self._initialized:
            return

        self._config = get_config()
        self._current_theme = self._config.get("ui.theme", "dark")
        self._palette = self.THEMES.get(self._current_theme, Colors.DARK)
        self._app: Optional[QApplication] = None

        self._initialized = True
        logger.info(f"Theme manager initialized with theme: {self._current_theme}")

    def initialize(self, app: QApplication) -> None:
        """
        Initialize theming for the application.

        Args:
            app: QApplication instance
        """
        self._app = app
        self.apply_theme(self._current_theme)
        self._setup_fonts()

    def apply_theme(self, theme_name: str) -> None:
        """
        Apply a theme to the application.

        Args:
            theme_name: Name of theme to apply
        """
        if theme_name not in self.THEMES:
            logger.warning(f"Unknown theme: {theme_name}, falling back to dark")
            theme_name = "dark"

        self._current_theme = theme_name
        self._palette = self.THEMES[theme_name]

        if self._app is None:
            return

        # Generate and apply stylesheet
        theme = DarkTheme(self._palette)
        stylesheet = theme.generate_stylesheet()
        self._app.setStyleSheet(stylesheet)

        # Apply palette for native widgets
        self._apply_palette()

        logger.info(f"Applied theme: {theme_name}")

    def _apply_palette(self) -> None:
        """Apply Qt palette for native widget styling."""
        if self._app is None:
            return

        palette = QPalette()
        p = self._palette

        # Window colors
        palette.setColor(QPalette.ColorRole.Window, QColor(p.bg_primary))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(p.text_primary))

        # Base colors (for inputs)
        palette.setColor(QPalette.ColorRole.Base, QColor(p.bg_input))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(p.bg_secondary))

        # Text colors
        palette.setColor(QPalette.ColorRole.Text, QColor(p.text_primary))
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(p.text_muted))

        # Button colors
        palette.setColor(QPalette.ColorRole.Button, QColor(p.bg_tertiary))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(p.text_primary))

        # Highlight colors
        palette.setColor(QPalette.ColorRole.Highlight, QColor(p.accent_primary))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))

        # Link colors
        palette.setColor(QPalette.ColorRole.Link, QColor(p.accent_primary))
        palette.setColor(QPalette.ColorRole.LinkVisited, QColor(p.accent_purple))

        # Disabled colors
        palette.setColor(
            QPalette.ColorGroup.Disabled,
            QPalette.ColorRole.WindowText,
            QColor(p.text_disabled),
        )
        palette.setColor(
            QPalette.ColorGroup.Disabled,
            QPalette.ColorRole.Text,
            QColor(p.text_disabled),
        )
        palette.setColor(
            QPalette.ColorGroup.Disabled,
            QPalette.ColorRole.ButtonText,
            QColor(p.text_disabled),
        )

        self._app.setPalette(palette)

    def _setup_fonts(self) -> None:
        """Configure application fonts."""
        if self._app is None:
            return

        # Set default font
        font_family = self._config.get("ui.font_family", "Segoe UI")
        font_size = self._config.get("ui.font_size", 13)

        font = QFont(font_family, font_size)
        self._app.setFont(font)

    def get_current_theme(self) -> str:
        """Get current theme name."""
        return self._current_theme

    def get_palette(self) -> ColorPalette:
        """Get current color palette."""
        return self._palette

    def get_color(self, color_name: str) -> str:
        """
        Get a specific color from the current palette.

        Args:
            color_name: Name of color attribute

        Returns:
            Color hex string
        """
        return getattr(self._palette, color_name, "#ffffff")

    def get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        return Colors.get_severity_color(severity, self._palette)

    def get_threat_color(self, score: float) -> str:
        """Get color for threat score."""
        return Colors.get_threat_color(score, self._palette)

    def toggle_theme(self) -> str:
        """Toggle between dark and light themes."""
        if self._current_theme == "dark":
            self.apply_theme("light")
        else:
            self.apply_theme("dark")
        return self._current_theme

    def get_monospace_font(self, size: int = 12) -> QFont:
        """
        Get monospace font for code views.

        Args:
            size: Font size

        Returns:
            QFont configured for monospace
        """
        font_family = self._config.get(
            "ui.code_font",
            "JetBrains Mono, Consolas, Courier New, monospace",
        )
        font = QFont(font_family.split(",")[0].strip(), size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        return font

    def create_syntax_highlighter_colors(self) -> dict:
        """
        Get syntax highlighting colors for code views.

        Returns:
            Dict of syntax element to QColor
        """
        p = self._palette
        return {
            "keyword": QColor(p.syntax_keyword),
            "string": QColor(p.syntax_string),
            "number": QColor(p.syntax_number),
            "comment": QColor(p.syntax_comment),
            "function": QColor(p.syntax_function),
            "type": QColor(p.syntax_type),
            "constant": QColor(p.syntax_constant),
            "operator": QColor(p.syntax_operator),
            "address": QColor(p.accent_cyan),
            "bytes": QColor(p.text_muted),
            "mnemonic": QColor(p.accent_primary),
            "register": QColor(p.accent_purple),
        }


# Global theme manager instance
_theme_manager: Optional[ThemeManager] = None


def get_theme_manager() -> ThemeManager:
    """Get global theme manager instance."""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager
