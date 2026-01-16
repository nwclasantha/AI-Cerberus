"""
Navigation sidebar component.

Provides a modern, collapsible sidebar for application navigation.
"""

from typing import Callable, Dict, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFrame, QSpacerItem, QSizePolicy, QToolTip,
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor

from ..theme import get_theme_manager


class SidebarButton(QPushButton):
    """
    Custom sidebar navigation button.

    Features:
    - Icon + text display
    - Active state highlighting
    - Tooltip on hover
    - Collapsible text
    """

    def __init__(
        self,
        text: str,
        icon_name: str = "",
        parent: Optional[QWidget] = None,
    ):
        """
        Initialize sidebar button.

        Args:
            text: Button text
            icon_name: Icon identifier
            parent: Parent widget
        """
        super().__init__(parent)

        self._text = text
        self._icon_name = icon_name
        self._is_active = False
        self._expanded = True

        self.setText(text)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(text)

        self._setup_style()

    def _setup_style(self) -> None:
        """Configure button appearance."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {p.text_secondary};
                border: none;
                border-radius: 8px;
                padding: 12px 16px;
                text-align: left;
                font-size: 13px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {p.bg_hover};
                color: {p.text_primary};
            }}
            QPushButton:checked {{
                background-color: {p.bg_selected};
                color: {p.accent_primary};
            }}
        """)

    def set_expanded(self, expanded: bool) -> None:
        """Set whether button shows text."""
        self._expanded = expanded
        if expanded:
            self.setText(self._text)
            self.setMinimumWidth(180)
        else:
            self.setText("")
            self.setMinimumWidth(48)
            self.setMaximumWidth(48)

    def set_active(self, active: bool) -> None:
        """Set active state."""
        self._is_active = active
        self.setChecked(active)


class Sidebar(QFrame):
    """
    Application navigation sidebar.

    Features:
    - Collapsible design
    - Icon navigation
    - Section dividers
    - Settings and info at bottom
    """

    # Signals
    navigation_changed = pyqtSignal(str)  # Emits navigation key

    # Navigation items
    MAIN_ITEMS = [
        ("dashboard", "Dashboard", "home"),
        ("analysis", "Analysis", "file-search"),
        ("samples", "Samples", "folder"),
        ("yara", "YARA Rules", "shield"),
        ("ml", "ML Classification", "cpu"),
        ("virustotal", "VirusTotal", "globe"),
        ("sandbox", "Sandbox", "box"),
        ("history", "History", "clock"),
    ]

    BOTTOM_ITEMS = [
        ("plugins", "Plugins", "puzzle"),
        ("settings", "Settings", "settings"),
        ("about", "About", "info"),
    ]

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize sidebar."""
        super().__init__(parent)

        self._expanded = True
        self._buttons: Dict[str, SidebarButton] = {}
        self._current_item = "dashboard"

        self.setObjectName("sidebar")
        self.setMinimumWidth(220)
        self.setMaximumWidth(220)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up sidebar UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 16, 8, 16)
        layout.setSpacing(4)

        # Header with logo
        header = self._create_header()
        layout.addWidget(header)

        layout.addSpacing(16)

        # Main navigation items
        for key, text, icon in self.MAIN_ITEMS:
            btn = self._create_nav_button(key, text, icon)
            layout.addWidget(btn)

        # Spacer
        layout.addSpacerItem(
            QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(divider)

        layout.addSpacing(8)

        # Bottom items
        for key, text, icon in self.BOTTOM_ITEMS:
            btn = self._create_nav_button(key, text, icon)
            layout.addWidget(btn)

        # Collapse button
        collapse_btn = QPushButton()
        collapse_btn.setText("Collapse")
        collapse_btn.clicked.connect(self._toggle_collapse)
        collapse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(collapse_btn)

        # Set initial active state
        self._set_active("dashboard")

    def _create_header(self) -> QWidget:
        """Create header with app title."""
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(8, 0, 8, 0)

        # App title
        title = QLabel("Malware Analyzer")
        title.setStyleSheet("""
            font-size: 16px;
            font-weight: 700;
            color: #f0f6fc;
        """)
        layout.addWidget(title)

        return header

    def _create_nav_button(self, key: str, text: str, icon: str) -> SidebarButton:
        """Create navigation button."""
        btn = SidebarButton(text, icon)
        btn.clicked.connect(lambda checked, k=key: self._on_nav_click(k))
        self._buttons[key] = btn
        return btn

    def _on_nav_click(self, key: str) -> None:
        """Handle navigation button click."""
        self._set_active(key)
        self.navigation_changed.emit(key)

    def _set_active(self, key: str) -> None:
        """Set active navigation item."""
        self._current_item = key

        for btn_key, btn in self._buttons.items():
            btn.set_active(btn_key == key)

    def _toggle_collapse(self) -> None:
        """Toggle sidebar collapse state."""
        self._expanded = not self._expanded

        target_width = 220 if self._expanded else 64

        # Animate width change
        animation = QPropertyAnimation(self, b"minimumWidth")
        animation.setDuration(200)
        animation.setEndValue(target_width)
        animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        animation.start()

        animation2 = QPropertyAnimation(self, b"maximumWidth")
        animation2.setDuration(200)
        animation2.setEndValue(target_width)
        animation2.setEasingCurve(QEasingCurve.Type.InOutQuad)
        animation2.start()

        # Update buttons
        for btn in self._buttons.values():
            btn.set_expanded(self._expanded)

    def navigate_to(self, key: str) -> None:
        """Programmatically navigate to an item."""
        if key in self._buttons:
            self._on_nav_click(key)

    def get_current_item(self) -> str:
        """Get current navigation item."""
        return self._current_item

    @property
    def is_expanded(self) -> bool:
        """Check if sidebar is expanded."""
        return self._expanded
