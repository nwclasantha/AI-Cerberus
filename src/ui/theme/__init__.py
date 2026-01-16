"""Theme system for the Malware Analysis Platform."""

from .colors import Colors, ColorPalette
from .dark_theme import DarkTheme
from .theme_manager import ThemeManager, get_theme_manager

__all__ = [
    "Colors",
    "ColorPalette",
    "DarkTheme",
    "ThemeManager",
    "get_theme_manager",
]
