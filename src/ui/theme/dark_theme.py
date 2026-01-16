"""
Dark theme stylesheet for PyQt6.

Provides a comprehensive dark theme inspired by modern IDEs
and analysis tools like Ghidra and IDA Pro.
"""

from __future__ import annotations

from .colors import Colors, ColorPalette


class DarkTheme:
    """
    Dark theme generator for PyQt6 applications.

    Creates QSS stylesheets for a modern, professional dark interface.
    """

    def __init__(self, palette: ColorPalette = None):
        """
        Initialize theme with color palette.

        Args:
            palette: Color palette to use (default: Colors.DARK)
        """
        self.palette = palette or Colors.DARK

    def generate_stylesheet(self) -> str:
        """Generate complete QSS stylesheet."""
        p = self.palette

        return f"""
/* ========================================
   Global Styles
   ======================================== */

QWidget {{
    background-color: {p.bg_primary};
    color: {p.text_primary};
    font-family: "Segoe UI", "SF Pro Display", -apple-system, sans-serif;
    font-size: 13px;
}}

QWidget:disabled {{
    color: {p.text_disabled};
}}

/* ========================================
   Main Window
   ======================================== */

QMainWindow {{
    background-color: {p.bg_primary};
}}

QMainWindow::separator {{
    background-color: {p.border_primary};
    width: 1px;
    height: 1px;
}}

/* ========================================
   Menu Bar
   ======================================== */

QMenuBar {{
    background-color: {p.bg_secondary};
    border-bottom: 1px solid {p.border_primary};
    padding: 4px 8px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background-color: {p.bg_hover};
}}

QMenuBar::item:pressed {{
    background-color: {p.bg_tertiary};
}}

QMenu {{
    background-color: {p.bg_secondary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 4px;
}}

QMenu::item {{
    padding: 8px 32px 8px 16px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: {p.bg_hover};
}}

QMenu::separator {{
    height: 1px;
    background-color: {p.border_primary};
    margin: 4px 8px;
}}

QMenu::icon {{
    margin-left: 8px;
}}

/* ========================================
   Tool Bar
   ======================================== */

QToolBar {{
    background-color: {p.bg_secondary};
    border: none;
    border-bottom: 1px solid {p.border_primary};
    spacing: 4px;
    padding: 4px 8px;
}}

QToolBar::separator {{
    background-color: {p.border_primary};
    width: 1px;
    margin: 4px 8px;
}}

QToolButton {{
    background-color: transparent;
    border: none;
    border-radius: 4px;
    padding: 6px 10px;
    color: {p.text_secondary};
}}

QToolButton:hover {{
    background-color: {p.bg_hover};
    color: {p.text_primary};
}}

QToolButton:pressed {{
    background-color: {p.bg_tertiary};
}}

QToolButton:checked {{
    background-color: {p.bg_selected};
    color: {p.accent_primary};
}}

/* ========================================
   Status Bar
   ======================================== */

QStatusBar {{
    background-color: {p.bg_secondary};
    border-top: 1px solid {p.border_primary};
    color: {p.text_secondary};
    padding: 4px 8px;
}}

QStatusBar::item {{
    border: none;
}}

QStatusBar QLabel {{
    color: {p.text_secondary};
    padding: 0 8px;
}}

/* ========================================
   Tab Widget
   ======================================== */

QTabWidget::pane {{
    background-color: {p.bg_primary};
    border: none;
    border-top: 1px solid {p.border_primary};
}}

QTabBar {{
    background-color: {p.bg_secondary};
}}

QTabBar::tab {{
    background-color: transparent;
    color: {p.text_secondary};
    border: none;
    padding: 10px 20px;
    min-width: 100px;
}}

QTabBar::tab:hover {{
    color: {p.text_primary};
    background-color: {p.bg_hover};
}}

QTabBar::tab:selected {{
    color: {p.text_primary};
    background-color: {p.bg_primary};
    border-bottom: 2px solid {p.accent_primary};
}}

QTabBar::close-button {{
    /* Icon removed - using default Qt close button */
    subcontrol-position: right;
}}

QTabBar::close-button:hover {{
    background-color: {p.bg_hover};
    border-radius: 4px;
}}

/* ========================================
   Scroll Bars
   ======================================== */

QScrollBar:vertical {{
    background-color: {p.bg_primary};
    width: 12px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {p.bg_hover};
    border-radius: 6px;
    min-height: 30px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {p.text_muted};
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar:horizontal {{
    background-color: {p.bg_primary};
    height: 12px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {p.bg_hover};
    border-radius: 6px;
    min-width: 30px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {p.text_muted};
}}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ========================================
   Buttons
   ======================================== */

QPushButton {{
    background-color: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    min-width: 80px;
}}

QPushButton:hover {{
    background-color: {p.bg_hover};
    border-color: {p.border_accent};
}}

QPushButton:pressed {{
    background-color: {p.bg_secondary};
}}

QPushButton:disabled {{
    background-color: {p.bg_secondary};
    color: {p.text_disabled};
    border-color: {p.border_secondary};
}}

QPushButton[primary="true"] {{
    background-color: {p.accent_primary};
    color: #ffffff;
    border: none;
}}

QPushButton[primary="true"]:hover {{
    background-color: {p.accent_secondary};
}}

QPushButton[danger="true"] {{
    background-color: {p.accent_danger};
    color: #ffffff;
    border: none;
}}

/* ========================================
   Input Fields
   ======================================== */

QLineEdit {{
    background-color: {p.bg_input};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 8px 12px;
    selection-background-color: {p.accent_primary};
}}

QLineEdit:focus {{
    border-color: {p.accent_primary};
    border-width: 2px;
}}

QLineEdit:disabled {{
    background-color: {p.bg_secondary};
    color: {p.text_disabled};
}}

QTextEdit, QPlainTextEdit {{
    background-color: {p.bg_input};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 8px;
    selection-background-color: {p.accent_primary};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {p.accent_primary};
}}

/* ========================================
   Combo Box
   ======================================== */

QComboBox {{
    background-color: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 8px 12px;
    min-width: 120px;
}}

QComboBox:hover {{
    border-color: {p.border_accent};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    /* Icon removed - using default */
    width: 12px;
    height: 12px;
}}

QComboBox QAbstractItemView {{
    background-color: {p.bg_secondary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    selection-background-color: {p.bg_hover};
    padding: 4px;
}}

/* ========================================
   Spin Box
   ======================================== */

QSpinBox, QDoubleSpinBox {{
    background-color: {p.bg_input};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 6px 8px;
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    background-color: transparent;
    border: none;
    width: 16px;
}}

QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background-color: transparent;
    border: none;
    width: 16px;
}}

/* ========================================
   Check Box & Radio Button
   ======================================== */

QCheckBox {{
    spacing: 8px;
    color: {p.text_primary};
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {p.border_primary};
    border-radius: 4px;
    background-color: {p.bg_input};
}}

QCheckBox::indicator:hover {{
    border-color: {p.accent_primary};
}}

QCheckBox::indicator:checked {{
    background-color: {p.accent_primary};
    border-color: {p.accent_primary};
    /* Icon removed - using background color to indicate checked state */
}}

QRadioButton {{
    spacing: 8px;
    color: {p.text_primary};
}}

QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {p.border_primary};
    border-radius: 10px;
    background-color: {p.bg_input};
}}

QRadioButton::indicator:hover {{
    border-color: {p.accent_primary};
}}

QRadioButton::indicator:checked {{
    background-color: {p.accent_primary};
    border-color: {p.accent_primary};
}}

/* ========================================
   Slider
   ======================================== */

QSlider::groove:horizontal {{
    background-color: {p.bg_tertiary};
    height: 6px;
    border-radius: 3px;
}}

QSlider::handle:horizontal {{
    background-color: {p.accent_primary};
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}}

QSlider::handle:horizontal:hover {{
    background-color: {p.accent_secondary};
}}

/* ========================================
   Progress Bar
   ======================================== */

QProgressBar {{
    background-color: {p.bg_tertiary};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {p.accent_primary};
    border-radius: 4px;
}}

/* ========================================
   Tables & Trees
   ======================================== */

QTableView, QTreeView, QListView {{
    background-color: {p.bg_primary};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    gridline-color: {p.border_secondary};
    selection-background-color: {p.bg_selected};
}}

QTableView::item, QTreeView::item, QListView::item {{
    padding: 8px;
    border-bottom: 1px solid {p.border_secondary};
}}

QTableView::item:hover, QTreeView::item:hover, QListView::item:hover {{
    background-color: {p.bg_hover};
}}

QTableView::item:selected, QTreeView::item:selected, QListView::item:selected {{
    background-color: {p.bg_selected};
    color: {p.text_primary};
}}

QHeaderView::section {{
    background-color: {p.bg_secondary};
    color: {p.text_secondary};
    border: none;
    border-bottom: 1px solid {p.border_primary};
    border-right: 1px solid {p.border_secondary};
    padding: 10px 12px;
    font-weight: 600;
}}

QHeaderView::section:hover {{
    background-color: {p.bg_hover};
    color: {p.text_primary};
}}

/* ========================================
   Splitter
   ======================================== */

QSplitter::handle {{
    background-color: {p.border_primary};
}}

QSplitter::handle:horizontal {{
    width: 1px;
}}

QSplitter::handle:vertical {{
    height: 1px;
}}

QSplitter::handle:hover {{
    background-color: {p.accent_primary};
}}

/* ========================================
   Group Box
   ======================================== */

QGroupBox {{
    background-color: {p.bg_secondary};
    border: 1px solid {p.border_primary};
    border-radius: 8px;
    margin-top: 16px;
    padding: 16px;
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 8px;
    color: {p.text_primary};
}}

/* ========================================
   Dock Widget
   ======================================== */

QDockWidget {{
    color: {p.text_primary};
    /* Icons removed - using defaults */
}}

QDockWidget::title {{
    background-color: {p.bg_secondary};
    border-bottom: 1px solid {p.border_primary};
    padding: 8px 12px;
    font-weight: 600;
}}

QDockWidget::close-button, QDockWidget::float-button {{
    background-color: transparent;
    border: none;
    padding: 4px;
}}

QDockWidget::close-button:hover, QDockWidget::float-button:hover {{
    background-color: {p.bg_hover};
    border-radius: 4px;
}}

/* ========================================
   Tool Tips
   ======================================== */

QToolTip {{
    background-color: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border_primary};
    border-radius: 6px;
    padding: 8px 12px;
}}

/* ========================================
   Dialog
   ======================================== */

QDialog {{
    background-color: {p.bg_primary};
}}

QDialogButtonBox {{
    button-layout: 2;
}}

/* ========================================
   Frame
   ======================================== */

QFrame[frameShape="4"] {{
    background-color: {p.border_primary};
    max-height: 1px;
}}

QFrame[frameShape="5"] {{
    background-color: {p.border_primary};
    max-width: 1px;
}}

/* ========================================
   Custom Classes
   ======================================== */

/* Sidebar */
QFrame#sidebar {{
    background-color: {p.bg_secondary};
    border-right: 1px solid {p.border_primary};
}}

/* Cards */
QFrame[card="true"] {{
    background-color: {p.bg_secondary};
    border: 1px solid {p.border_primary};
    border-radius: 8px;
    padding: 16px;
}}

/* Hex View */
QPlainTextEdit#hexView {{
    font-family: "JetBrains Mono", "Consolas", "Courier New", monospace;
    font-size: 12px;
    line-height: 1.5;
}}

/* Disassembly View */
QPlainTextEdit#disasmView {{
    font-family: "JetBrains Mono", "Consolas", "Courier New", monospace;
    font-size: 12px;
    line-height: 1.6;
}}

/* Severity Labels */
QLabel[severity="critical"] {{
    color: {p.severity_critical};
    font-weight: 600;
}}

QLabel[severity="high"] {{
    color: {p.severity_high};
    font-weight: 600;
}}

QLabel[severity="medium"] {{
    color: {p.severity_medium};
}}

QLabel[severity="low"] {{
    color: {p.severity_low};
}}

/* Threat Score */
QLabel#threatScore {{
    font-size: 48px;
    font-weight: 700;
}}

/* Section Headers */
QLabel[header="true"] {{
    font-size: 16px;
    font-weight: 600;
    color: {p.text_primary};
    padding-bottom: 8px;
    border-bottom: 1px solid {p.border_primary};
}}
"""

    def get_font_stylesheet(self) -> str:
        """Get font-specific stylesheet."""
        return """
/* Monospace Font for Code Views */
.monospace {
    font-family: "JetBrains Mono", "Fira Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
}

/* Headers */
.h1 { font-size: 24px; font-weight: 700; }
.h2 { font-size: 20px; font-weight: 600; }
.h3 { font-size: 16px; font-weight: 600; }
.h4 { font-size: 14px; font-weight: 600; }

/* Text styles */
.text-muted { color: #6e7681; }
.text-primary { color: #58a6ff; }
.text-success { color: #3fb950; }
.text-warning { color: #d29922; }
.text-danger { color: #f85149; }
"""
