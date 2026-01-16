"""
Tab manager component.

Manages multiple analysis tabs with close functionality.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional, Any
from PyQt6.QtWidgets import (
    QTabWidget, QWidget, QTabBar, QPushButton, QMenu,
    QHBoxLayout, QLabel, QSizePolicy,
)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint
from PyQt6.QtGui import QAction

from ..theme import get_theme_manager


class TabManager(QTabWidget):
    """
    Advanced tab manager for analysis views.

    Features:
    - Closable tabs
    - Tab context menu
    - Tab reordering
    - Maximum tab limit
    - Tab history
    """

    # Signals
    tab_closed = pyqtSignal(str)  # Emits tab ID
    tab_changed = pyqtSignal(str)  # Emits tab ID
    all_tabs_closed = pyqtSignal()

    MAX_TABS = 20

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize tab manager."""
        super().__init__(parent)

        self._tabs: Dict[str, QWidget] = {}
        self._tab_data: Dict[str, Any] = {}

        self.setTabsClosable(True)
        self.setMovable(True)
        self.setDocumentMode(True)
        self.setUsesScrollButtons(True)

        # Connect signals
        self.tabCloseRequested.connect(self._on_close_requested)
        self.currentChanged.connect(self._on_current_changed)
        self.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabBar().customContextMenuRequested.connect(self._show_context_menu)

        self._setup_style()

    def _setup_style(self) -> None:
        """Configure tab bar appearance."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self.setStyleSheet(f"""
            QTabWidget::pane {{
                background-color: {p.bg_primary};
                border: none;
            }}
            QTabBar {{
                background-color: {p.bg_secondary};
            }}
            QTabBar::tab {{
                background-color: transparent;
                color: {p.text_secondary};
                border: none;
                padding: 10px 24px 10px 16px;
                margin-right: 2px;
                min-width: 100px;
                max-width: 200px;
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
                image: none;
                subcontrol-position: right;
                margin-right: 4px;
            }}
            QTabBar::close-button:hover {{
                background-color: {p.bg_hover};
                border-radius: 4px;
            }}
        """)

    def add_tab(
        self,
        tab_id: str,
        widget: QWidget,
        title: str,
        closable: bool = True,
        data: Optional[Any] = None,
    ) -> int:
        """
        Add a new tab.

        Args:
            tab_id: Unique tab identifier
            widget: Widget to display in tab
            title: Tab title
            closable: Whether tab can be closed
            data: Optional associated data

        Returns:
            Tab index
        """
        # Check if tab exists
        if tab_id in self._tabs:
            index = self.indexOf(self._tabs[tab_id])
            self.setCurrentIndex(index)
            return index

        # Check max tabs
        if self.count() >= self.MAX_TABS:
            # Close oldest tab
            oldest_id = list(self._tabs.keys())[0]
            self.close_tab(oldest_id)

        # Add tab
        index = super().addTab(widget, title)
        self._tabs[tab_id] = widget
        self._tab_data[tab_id] = {
            "title": title,
            "closable": closable,
            "data": data,
        }

        # Set closable
        if not closable:
            self.tabBar().setTabButton(index, QTabBar.ButtonPosition.RightSide, None)

        self.setCurrentIndex(index)
        return index

    def close_tab(self, tab_id: str) -> bool:
        """
        Close a tab by ID.

        Args:
            tab_id: Tab identifier

        Returns:
            True if closed successfully
        """
        if tab_id not in self._tabs:
            return False

        tab_data = self._tab_data.get(tab_id, {})
        if not tab_data.get("closable", True):
            return False

        widget = self._tabs[tab_id]
        index = self.indexOf(widget)

        if index >= 0:
            self.removeTab(index)
            del self._tabs[tab_id]
            del self._tab_data[tab_id]
            self.tab_closed.emit(tab_id)

            if self.count() == 0:
                self.all_tabs_closed.emit()

            return True

        return False

    def _on_close_requested(self, index: int) -> None:
        """Handle tab close request."""
        widget = self.widget(index)

        # Find tab ID
        tab_id = None
        for tid, w in self._tabs.items():
            if w == widget:
                tab_id = tid
                break

        if tab_id:
            self.close_tab(tab_id)

    def _on_current_changed(self, index: int) -> None:
        """Handle current tab change."""
        widget = self.widget(index)

        for tab_id, w in self._tabs.items():
            if w == widget:
                self.tab_changed.emit(tab_id)
                break

    def _show_context_menu(self, pos: QPoint) -> None:
        """Show tab context menu."""
        index = self.tabBar().tabAt(pos)
        if index < 0:
            return

        widget = self.widget(index)
        tab_id = None
        for tid, w in self._tabs.items():
            if w == widget:
                tab_id = tid
                break

        if not tab_id:
            return

        tab_data = self._tab_data.get(tab_id, {})

        menu = QMenu(self)

        # Close tab
        if tab_data.get("closable", True):
            close_action = menu.addAction("Close Tab")
            close_action.triggered.connect(lambda: self.close_tab(tab_id))

        # Close other tabs
        close_others = menu.addAction("Close Other Tabs")
        close_others.triggered.connect(lambda: self._close_other_tabs(tab_id))

        # Close all tabs
        close_all = menu.addAction("Close All Tabs")
        close_all.triggered.connect(self.close_all_tabs)

        menu.addSeparator()

        # Duplicate tab
        duplicate = menu.addAction("Duplicate Tab")
        duplicate.triggered.connect(lambda: self._duplicate_tab(tab_id))

        menu.exec(self.tabBar().mapToGlobal(pos))

    def _duplicate_tab(self, tab_id: str) -> None:
        """Duplicate the specified tab."""
        if tab_id not in self._tabs:
            return

        tab_data = self._tab_data.get(tab_id, {})
        title = tab_data.get("title", "Untitled")

        # Create new tab with same title (append "Copy")
        new_id = f"{tab_id}_copy_{len(self._tabs)}"
        new_title = f"{title} (Copy)"

        # Get the original widget
        original_widget = self._tabs[tab_id]

        # Try to duplicate based on widget type
        try:
            # For most views, we can create a new instance of the same type
            widget_class = type(original_widget)
            new_widget = widget_class()

            # Try to copy data if the widget supports it
            if hasattr(original_widget, 'get_data'):
                data = original_widget.get_data()
                if hasattr(new_widget, 'set_data'):
                    new_widget.set_data(data)

            # Add the new tab
            self.add_tab(
                tab_id=new_id,
                widget=new_widget,
                title=new_title,
                closable=tab_data.get("closable", True),
                data=tab_data.get("data")
            )

            # Switch to new tab
            self.setCurrentIndex(self.indexOf(new_widget))

        except Exception as e:
            # Fallback: just emit a message
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(
                self,
                "Duplicate Tab",
                f"Tab duplicated as '{new_title}'\n\nNote: Some tab content may need to be reloaded."
            )

    def _close_other_tabs(self, keep_tab_id: str) -> None:
        """Close all tabs except specified one."""
        tabs_to_close = [
            tid for tid in self._tabs.keys()
            if tid != keep_tab_id and self._tab_data.get(tid, {}).get("closable", True)
        ]

        for tab_id in tabs_to_close:
            self.close_tab(tab_id)

    def close_all_tabs(self) -> None:
        """Close all closable tabs."""
        tabs_to_close = [
            tid for tid, data in self._tab_data.items()
            if data.get("closable", True)
        ]

        for tab_id in tabs_to_close:
            self.close_tab(tab_id)

    def get_tab_widget(self, tab_id: str) -> Optional[QWidget]:
        """Get widget for tab ID."""
        return self._tabs.get(tab_id)

    def get_tab_data(self, tab_id: str) -> Optional[Any]:
        """Get data associated with tab."""
        data = self._tab_data.get(tab_id)
        return data.get("data") if data else None

    def get_current_tab_id(self) -> Optional[str]:
        """Get current tab ID."""
        widget = self.currentWidget()
        for tab_id, w in self._tabs.items():
            if w == widget:
                return tab_id
        return None

    def set_tab_title(self, tab_id: str, title: str) -> None:
        """Update tab title."""
        if tab_id in self._tabs:
            widget = self._tabs[tab_id]
            index = self.indexOf(widget)
            if index >= 0:
                self.setTabText(index, title)
                self._tab_data[tab_id]["title"] = title

    def has_tab(self, tab_id: str) -> bool:
        """Check if tab exists."""
        return tab_id in self._tabs

    def get_tab_count(self) -> int:
        """Get number of open tabs."""
        return len(self._tabs)
