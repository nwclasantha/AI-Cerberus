"""
Color definitions for the Malware Analysis Platform.

Provides a modern dark theme inspired by Ghidra/IDA Pro style interfaces.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class ColorPalette:
    """Color palette definition."""

    # Background colors
    bg_primary: str
    bg_secondary: str
    bg_tertiary: str
    bg_hover: str
    bg_selected: str
    bg_input: str

    # Text colors
    text_primary: str
    text_secondary: str
    text_muted: str
    text_disabled: str

    # Accent colors
    accent_primary: str
    accent_secondary: str
    accent_success: str
    accent_warning: str
    accent_danger: str
    accent_info: str
    accent_purple: str
    accent_cyan: str

    # Border colors
    border_primary: str
    border_secondary: str
    border_accent: str

    # Syntax highlighting
    syntax_keyword: str
    syntax_string: str
    syntax_number: str
    syntax_comment: str
    syntax_function: str
    syntax_type: str
    syntax_constant: str
    syntax_operator: str

    # Severity colors
    severity_critical: str
    severity_high: str
    severity_medium: str
    severity_low: str
    severity_info: str


class Colors:
    """
    Color constants and palettes for the application.

    Provides a GitHub-dark inspired color scheme with
    additional colors for malware analysis visualization.
    """

    # Modern Dark Theme (GitHub Dark / Ghidra style)
    DARK = ColorPalette(
        # Backgrounds
        bg_primary="#0d1117",
        bg_secondary="#161b22",
        bg_tertiary="#21262d",
        bg_hover="#30363d",
        bg_selected="#388bfd26",
        bg_input="#0d1117",

        # Text
        text_primary="#f0f6fc",
        text_secondary="#8b949e",
        text_muted="#6e7681",
        text_disabled="#484f58",

        # Accents
        accent_primary="#58a6ff",
        accent_secondary="#1f6feb",
        accent_success="#3fb950",
        accent_warning="#d29922",
        accent_danger="#f85149",
        accent_info="#58a6ff",
        accent_purple="#bc8cff",
        accent_cyan="#39c5cf",

        # Borders
        border_primary="#30363d",
        border_secondary="#21262d",
        border_accent="#58a6ff",

        # Syntax highlighting
        syntax_keyword="#ff7b72",
        syntax_string="#a5d6ff",
        syntax_number="#79c0ff",
        syntax_comment="#8b949e",
        syntax_function="#d2a8ff",
        syntax_type="#ffa657",
        syntax_constant="#79c0ff",
        syntax_operator="#ff7b72",

        # Severity
        severity_critical="#f85149",
        severity_high="#ff7b72",
        severity_medium="#d29922",
        severity_low="#58a6ff",
        severity_info="#8b949e",
    )

    # Alternative darker theme
    DARKER = ColorPalette(
        bg_primary="#010409",
        bg_secondary="#0d1117",
        bg_tertiary="#161b22",
        bg_hover="#21262d",
        bg_selected="#388bfd26",
        bg_input="#010409",

        text_primary="#e6edf3",
        text_secondary="#7d8590",
        text_muted="#636c76",
        text_disabled="#3d444d",

        accent_primary="#2f81f7",
        accent_secondary="#1f6feb",
        accent_success="#2ea043",
        accent_warning="#bf8700",
        accent_danger="#da3633",
        accent_info="#2f81f7",
        accent_purple="#a371f7",
        accent_cyan="#3fb5c4",

        border_primary="#21262d",
        border_secondary="#161b22",
        border_accent="#2f81f7",

        syntax_keyword="#ff7b72",
        syntax_string="#a5d6ff",
        syntax_number="#79c0ff",
        syntax_comment="#7d8590",
        syntax_function="#d2a8ff",
        syntax_type="#ffa657",
        syntax_constant="#79c0ff",
        syntax_operator="#ff7b72",

        severity_critical="#da3633",
        severity_high="#ff7b72",
        severity_medium="#bf8700",
        severity_low="#2f81f7",
        severity_info="#7d8590",
    )

    # Light theme for accessibility
    LIGHT = ColorPalette(
        bg_primary="#ffffff",
        bg_secondary="#f6f8fa",
        bg_tertiary="#eaecef",
        bg_hover="#d0d7de",
        bg_selected="#0550ae14",
        bg_input="#ffffff",

        text_primary="#1f2328",
        text_secondary="#656d76",
        text_muted="#8b949e",
        text_disabled="#afb8c1",

        accent_primary="#0969da",
        accent_secondary="#0550ae",
        accent_success="#1a7f37",
        accent_warning="#9a6700",
        accent_danger="#cf222e",
        accent_info="#0969da",
        accent_purple="#8250df",
        accent_cyan="#0891b2",

        border_primary="#d0d7de",
        border_secondary="#e6e8eb",
        border_accent="#0969da",

        syntax_keyword="#cf222e",
        syntax_string="#0a3069",
        syntax_number="#0550ae",
        syntax_comment="#656d76",
        syntax_function="#8250df",
        syntax_type="#953800",
        syntax_constant="#0550ae",
        syntax_operator="#cf222e",

        severity_critical="#cf222e",
        severity_high="#cf222e",
        severity_medium="#9a6700",
        severity_low="#0969da",
        severity_info="#656d76",
    )

    @classmethod
    def get_palette(cls, theme: str = "dark") -> ColorPalette:
        """Get color palette by theme name."""
        themes = {
            "dark": cls.DARK,
            "darker": cls.DARKER,
            "light": cls.LIGHT,
        }
        return themes.get(theme.lower(), cls.DARK)

    @classmethod
    def get_severity_color(cls, severity: str, palette: ColorPalette = None) -> str:
        """Get color for severity level."""
        if palette is None:
            palette = cls.DARK

        severity_map = {
            "critical": palette.severity_critical,
            "high": palette.severity_high,
            "medium": palette.severity_medium,
            "low": palette.severity_low,
            "info": palette.severity_info,
        }
        return severity_map.get(severity.lower(), palette.severity_info)

    @classmethod
    def get_threat_color(cls, score: float, palette: ColorPalette = None) -> str:
        """Get color based on threat score (0-100)."""
        if palette is None:
            palette = cls.DARK

        if score >= 80:
            return palette.severity_critical
        elif score >= 60:
            return palette.severity_high
        elif score >= 40:
            return palette.severity_medium
        elif score >= 20:
            return palette.severity_low
        else:
            return palette.accent_success
