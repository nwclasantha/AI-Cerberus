"""
Strings view component.

Displays extracted strings with filtering and categorization.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QLabel, QLineEdit, QPushButton,
    QFrame, QComboBox, QHeaderView, QCheckBox,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor

from ..theme import get_theme_manager


class StringsView(QWidget):
    """
    Strings viewer with filtering and categorization.

    Features:
    - Category filtering (URLs, IPs, paths, APIs)
    - Search functionality
    - Export capability
    - Copy to clipboard
    """

    # Signals
    string_selected = pyqtSignal(str, int)  # string, offset

    CATEGORIES = [
        "All",
        "URLs",
        "IP Addresses",
        "Email Addresses",
        "File Paths",
        "Registry Keys",
        "API Functions",
        "Suspicious",
    ]

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize strings view."""
        super().__init__(parent)

        self._strings: List[Dict] = []
        self._filtered_strings: List[Dict] = []

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up strings view UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Strings table
        self._strings_table = QTableWidget()
        self._strings_table.setColumnCount(4)
        self._strings_table.setHorizontalHeaderLabels([
            "Offset", "String", "Category", "Length"
        ])

        # Configure table
        header = self._strings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self._strings_table.setColumnWidth(0, 100)
        self._strings_table.setColumnWidth(2, 120)
        self._strings_table.setColumnWidth(3, 60)

        self._strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._strings_table.setAlternatingRowColors(True)
        self._strings_table.verticalHeader().setVisible(False)
        self._strings_table.setShowGrid(False)

        self._strings_table.cellDoubleClicked.connect(self._on_string_selected)

        layout.addWidget(self._strings_table)

        # Status bar
        status = self._create_status_bar()
        layout.addWidget(status)

        self._apply_style()

    def _create_toolbar(self) -> QWidget:
        """Create strings view toolbar."""
        toolbar = QFrame()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        theme = get_theme_manager()
        p = theme.get_palette()

        toolbar.setStyleSheet(f"""
            QFrame {{
                background-color: {p.bg_secondary};
                border-bottom: 1px solid {p.border_primary};
            }}
        """)

        # Search
        layout.addWidget(QLabel("Search:"))

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Filter strings...")
        self._search_input.setMaximumWidth(250)
        self._search_input.textChanged.connect(self._apply_filters)
        layout.addWidget(self._search_input)

        layout.addSpacing(16)

        # Category filter
        layout.addWidget(QLabel("Category:"))

        self._category_combo = QComboBox()
        self._category_combo.addItems(self.CATEGORIES)
        self._category_combo.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self._category_combo)

        layout.addSpacing(16)

        # Min length filter
        layout.addWidget(QLabel("Min Length:"))

        self._min_length_input = QLineEdit()
        self._min_length_input.setPlaceholderText("4")
        self._min_length_input.setMaximumWidth(50)
        self._min_length_input.textChanged.connect(self._apply_filters)
        layout.addWidget(self._min_length_input)

        layout.addStretch()

        # Export button
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self._export_strings)
        layout.addWidget(export_btn)

        return toolbar

    def _create_status_bar(self) -> QWidget:
        """Create status bar."""
        status = QFrame()
        layout = QHBoxLayout(status)
        layout.setContentsMargins(8, 4, 8, 4)

        theme = get_theme_manager()
        p = theme.get_palette()

        status.setStyleSheet(f"""
            QFrame {{
                background-color: {p.bg_secondary};
                border-top: 1px solid {p.border_primary};
            }}
        """)

        self._count_label = QLabel("0 strings")
        layout.addWidget(self._count_label)

        layout.addStretch()

        self._filtered_label = QLabel("")
        layout.addWidget(self._filtered_label)

        return status

    def _apply_style(self) -> None:
        """Apply strings view styling."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self._strings_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {p.bg_primary};
                color: {p.text_primary};
                border: none;
                gridline-color: {p.border_secondary};
            }}
            QTableWidget::item {{
                padding: 4px 8px;
            }}
            QTableWidget::item:selected {{
                background-color: {p.bg_selected};
            }}
            QHeaderView::section {{
                background-color: {p.bg_secondary};
                color: {p.text_secondary};
                border: none;
                border-bottom: 1px solid {p.border_primary};
                padding: 8px;
                font-weight: 600;
            }}
        """)

    def set_strings(self, strings: List[Dict]) -> None:
        """
        Set strings to display.

        Args:
            strings: List of string dicts with keys:
                - value: The string value
                - offset: Byte offset in file
                - category: String category
        """
        self._strings = strings
        self._count_label.setText(f"{len(strings)} strings total")
        self._apply_filters()

    def _apply_filters(self) -> None:
        """Apply current filters and update display."""
        search = self._search_input.text().lower()
        category = self._category_combo.currentText()

        try:
            min_length = int(self._min_length_input.text() or "4")
        except ValueError:
            min_length = 4

        # Filter strings
        filtered = []
        for s in self._strings:
            value = s.get("value", "")
            s_category = s.get("category", "")

            # Length filter
            if len(value) < min_length:
                continue

            # Category filter
            if category != "All":
                category_map = {
                    "URLs": "url",
                    "IP Addresses": "ip",
                    "Email Addresses": "email",
                    "File Paths": "path",
                    "Registry Keys": "registry",
                    "API Functions": "api",
                    "Suspicious": "suspicious",
                }
                if s_category != category_map.get(category, ""):
                    continue

            # Search filter
            if search and search not in value.lower():
                continue

            filtered.append(s)

        self._filtered_strings = filtered
        self._update_table()

        if len(filtered) != len(self._strings):
            self._filtered_label.setText(f"Showing {len(filtered)} of {len(self._strings)}")
        else:
            self._filtered_label.setText("")

    def _update_table(self) -> None:
        """Update table with filtered strings."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self._strings_table.setRowCount(len(self._filtered_strings))

        category_colors = {
            "url": p.accent_primary,
            "ip": p.accent_warning,
            "email": p.accent_purple,
            "path": p.accent_cyan,
            "registry": p.accent_warning,
            "api": p.accent_success,
            "suspicious": p.accent_danger,
        }

        for row, s in enumerate(self._filtered_strings):
            # Offset
            offset = s.get("offset", 0)
            offset_item = QTableWidgetItem(f"0x{offset:08X}")
            self._strings_table.setItem(row, 0, offset_item)

            # String value
            value = s.get("value", "")
            value_item = QTableWidgetItem(value[:200])  # Truncate long strings
            value_item.setData(Qt.ItemDataRole.UserRole, value)  # Store full value
            self._strings_table.setItem(row, 1, value_item)

            # Category
            category = s.get("category", "")
            category_item = QTableWidgetItem(category.capitalize())
            color = category_colors.get(category, p.text_muted)
            category_item.setForeground(QColor(color))
            self._strings_table.setItem(row, 2, category_item)

            # Length
            length_item = QTableWidgetItem(str(len(value)))
            self._strings_table.setItem(row, 3, length_item)

    def _on_string_selected(self, row: int, col: int) -> None:
        """Handle string selection."""
        value_item = self._strings_table.item(row, 1)
        offset_item = self._strings_table.item(row, 0)

        if value_item and offset_item:
            value = value_item.data(Qt.ItemDataRole.UserRole)
            offset_text = offset_item.text()

            try:
                offset = int(offset_text, 16)
            except ValueError:
                offset = 0

            self.string_selected.emit(value, offset)

    def _export_strings(self) -> None:
        """Export strings to file."""
        if not self._filtered_strings:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No Data", "No strings to export.")
            return

        from PyQt6.QtWidgets import QFileDialog
        import csv
        import json
        from datetime import datetime, timezone

        # Ask for file type
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Strings",
            f"strings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv);;JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)"
        )

        if not file_path:
            return

        try:
            if "CSV" in selected_filter or file_path.endswith('.csv'):
                # Export as CSV
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Offset', 'String', 'Category', 'Length'])
                    for s in self._filtered_strings:
                        writer.writerow([
                            f"0x{s.get('offset', 0):08X}",
                            s.get('value', ''),
                            s.get('category', ''),
                            len(s.get('value', ''))
                        ])

            elif "JSON" in selected_filter or file_path.endswith('.json'):
                # Export as JSON
                with open(file_path, 'w', encoding='utf-8') as f:
                    export_data = {
                        'export_date': datetime.now(timezone.utc).isoformat(),
                        'total_strings': len(self._filtered_strings),
                        'strings': [{
                            'offset': f"0x{s.get('offset', 0):08X}",
                            'value': s.get('value', ''),
                            'category': s.get('category', ''),
                            'length': len(s.get('value', ''))
                        } for s in self._filtered_strings]
                    }
                    json.dump(export_data, f, indent=2, ensure_ascii=False)

            else:
                # Export as plain text
                with open(file_path, 'w', encoding='utf-8') as f:
                    for s in self._filtered_strings:
                        f.write(f"{s.get('value', '')}\n")

            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(
                self,
                "Export Complete",
                f"Exported {len(self._filtered_strings)} strings to:\n{file_path}"
            )

        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export strings:\n{str(e)}"
            )

    def get_selected_string(self) -> Optional[str]:
        """Get currently selected string."""
        items = self._strings_table.selectedItems()
        if items:
            row = items[0].row()
            value_item = self._strings_table.item(row, 1)
            if value_item:
                return value_item.data(Qt.ItemDataRole.UserRole)
        return None

    def clear(self) -> None:
        """Clear strings view."""
        self._strings = []
        self._filtered_strings = []
        self._strings_table.setRowCount(0)
        self._count_label.setText("0 strings")
        self._filtered_label.setText("")
