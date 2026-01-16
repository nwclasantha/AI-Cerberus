"""
Hex viewer component.

Advanced hex editor for viewing binary data.
"""

from typing import Optional, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit,
    QLabel, QLineEdit, QPushButton, QFrame, QScrollBar,
    QSplitter, QTextEdit,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import (
    QFont, QTextCharFormat, QColor, QTextCursor,
    QSyntaxHighlighter, QTextDocument,
)

from ..theme import get_theme_manager


class HexHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for hex view."""

    def __init__(self, parent: QTextDocument = None):
        super().__init__(parent)

        theme = get_theme_manager()
        p = theme.get_palette()

        # Formats
        self._address_format = QTextCharFormat()
        self._address_format.setForeground(QColor(p.accent_cyan))

        self._hex_format = QTextCharFormat()
        self._hex_format.setForeground(QColor(p.text_primary))

        self._ascii_format = QTextCharFormat()
        self._ascii_format.setForeground(QColor(p.accent_success))

        self._null_format = QTextCharFormat()
        self._null_format.setForeground(QColor(p.text_muted))

    def highlightBlock(self, text: str) -> None:
        """Highlight hex block."""
        if not text:
            return

        # Address (first 8 characters + colon)
        if len(text) > 9 and text[8] == ':':
            self.setFormat(0, 9, self._address_format)

        # Find hex section (between address and ASCII)
        hex_start = 10
        ascii_start = text.find('  ', hex_start)

        if ascii_start > 0:
            # Highlight hex bytes
            hex_text = text[hex_start:ascii_start]
            for i, char in enumerate(hex_text):
                if char == '0' and i + 1 < len(hex_text) and hex_text[i + 1] == '0':
                    self.setFormat(hex_start + i, 2, self._null_format)

            # Highlight ASCII
            self.setFormat(ascii_start + 2, len(text) - ascii_start - 2, self._ascii_format)


class HexView(QWidget):
    """
    Advanced hex viewer for binary data.

    Features:
    - Address + hex + ASCII display
    - Search functionality
    - Go to offset
    - Selection highlighting
    - Copy to clipboard
    """

    # Signals
    selection_changed = pyqtSignal(int, int)  # start, end offset

    BYTES_PER_LINE = 16

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize hex viewer."""
        super().__init__(parent)

        self._data: bytes = b""
        self._offset: int = 0
        self._selection_start: int = -1
        self._selection_end: int = -1

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up hex viewer UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Main content
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Hex display
        self._hex_view = QPlainTextEdit()
        self._hex_view.setReadOnly(True)
        self._hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._hex_view.setObjectName("hexView")

        # Configure font
        theme = get_theme_manager()
        font = theme.get_monospace_font(12)
        self._hex_view.setFont(font)

        # Apply highlighter
        self._highlighter = HexHighlighter(self._hex_view.document())

        splitter.addWidget(self._hex_view)

        # Info panel
        info_panel = self._create_info_panel()
        splitter.addWidget(info_panel)

        splitter.setSizes([600, 100])

        layout.addWidget(splitter)

        self._apply_style()

    def _create_toolbar(self) -> QWidget:
        """Create hex viewer toolbar."""
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

        # Go to offset
        layout.addWidget(QLabel("Offset:"))

        self._offset_input = QLineEdit()
        self._offset_input.setPlaceholderText("0x00000000")
        self._offset_input.setMaximumWidth(120)
        self._offset_input.returnPressed.connect(self._go_to_offset)
        layout.addWidget(self._offset_input)

        go_btn = QPushButton("Go")
        go_btn.clicked.connect(self._go_to_offset)
        layout.addWidget(go_btn)

        layout.addSpacing(16)

        # Search
        layout.addWidget(QLabel("Search:"))

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("hex or text...")
        self._search_input.setMaximumWidth(200)
        self._search_input.returnPressed.connect(self._search)
        layout.addWidget(self._search_input)

        search_btn = QPushButton("Find")
        search_btn.clicked.connect(self._search)
        layout.addWidget(search_btn)

        layout.addStretch()

        # Info
        self._size_label = QLabel("Size: 0 bytes")
        layout.addWidget(self._size_label)

        return toolbar

    def _create_info_panel(self) -> QWidget:
        """Create information panel."""
        panel = QFrame()
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)

        theme = get_theme_manager()
        p = theme.get_palette()

        panel.setStyleSheet(f"""
            QFrame {{
                background-color: {p.bg_secondary};
                border-top: 1px solid {p.border_primary};
            }}
        """)

        # Selection info
        self._selection_label = QLabel("No selection")
        layout.addWidget(self._selection_label)

        layout.addStretch()

        # Data at cursor
        self._cursor_label = QLabel("")
        layout.addWidget(self._cursor_label)

        return panel

    def _apply_style(self) -> None:
        """Apply hex view styling."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self._hex_view.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {p.bg_primary};
                color: {p.text_primary};
                border: none;
                selection-background-color: {p.accent_primary};
            }}
        """)

    def set_data(self, data: bytes) -> None:
        """
        Set binary data to display.

        Args:
            data: Binary data
        """
        self._data = data
        self._offset = 0
        self._selection_start = -1
        self._selection_end = -1

        self._size_label.setText(f"Size: {len(data):,} bytes")
        self._render_hex()

    def _render_hex(self) -> None:
        """Render hex display."""
        if not self._data:
            self._hex_view.setPlainText("No data loaded")
            return

        lines = []
        for offset in range(0, len(self._data), self.BYTES_PER_LINE):
            chunk = self._data[offset:offset + self.BYTES_PER_LINE]

            # Address
            addr = f"{offset:08X}:"

            # Hex bytes
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            hex_bytes = hex_bytes.ljust(self.BYTES_PER_LINE * 3 - 1)

            # ASCII representation
            ascii_repr = ""
            for b in chunk:
                if 32 <= b < 127:
                    ascii_repr += chr(b)
                else:
                    ascii_repr += "."

            lines.append(f"{addr} {hex_bytes}  {ascii_repr}")

        self._hex_view.setPlainText("\n".join(lines))

    def _go_to_offset(self) -> None:
        """Navigate to specified offset."""
        text = self._offset_input.text().strip()

        try:
            if text.startswith("0x") or text.startswith("0X"):
                offset = int(text, 16)
            else:
                offset = int(text)
        except ValueError:
            return

        if 0 <= offset < len(self._data):
            # Calculate line number
            line = offset // self.BYTES_PER_LINE

            cursor = self._hex_view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(
                QTextCursor.MoveOperation.Down,
                QTextCursor.MoveMode.MoveAnchor,
                line
            )
            self._hex_view.setTextCursor(cursor)
            self._hex_view.centerCursor()

    def _search(self) -> None:
        """Search for pattern in data."""
        query = self._search_input.text().strip()

        if not query or not self._data:
            return

        # Try as hex first
        search_bytes = None
        try:
            # Remove spaces and 0x prefix
            hex_str = query.replace(" ", "").replace("0x", "").replace("0X", "")
            if all(c in "0123456789abcdefABCDEF" for c in hex_str) and len(hex_str) % 2 == 0:
                search_bytes = bytes.fromhex(hex_str)
        except ValueError:
            pass

        # Try as ASCII
        if search_bytes is None:
            search_bytes = query.encode("utf-8", errors="ignore")

        # Find in data
        pos = self._data.find(search_bytes, self._offset + 1)

        if pos == -1:
            # Wrap around
            pos = self._data.find(search_bytes, 0)

        if pos >= 0:
            self._offset = pos
            self._offset_input.setText(f"0x{pos:08X}")
            self._go_to_offset()

            # Highlight match
            self._selection_start = pos
            self._selection_end = pos + len(search_bytes)
            self._highlight_selection()

    def _highlight_selection(self) -> None:
        """Highlight selected bytes."""
        if self._selection_start < 0:
            return

        # Update selection label
        length = self._selection_end - self._selection_start
        self._selection_label.setText(
            f"Selection: 0x{self._selection_start:08X} - 0x{self._selection_end:08X} ({length} bytes)"
        )

        self.selection_changed.emit(self._selection_start, self._selection_end)

    def get_selection(self) -> bytes:
        """Get currently selected bytes."""
        if self._selection_start >= 0:
            return self._data[self._selection_start:self._selection_end]
        return b""

    def get_byte_at_offset(self, offset: int) -> Optional[int]:
        """Get byte at offset."""
        if 0 <= offset < len(self._data):
            return self._data[offset]
        return None

    def clear(self) -> None:
        """Clear hex view."""
        self._data = b""
        self._hex_view.setPlainText("No data loaded")
        self._size_label.setText("Size: 0 bytes")
        self._selection_label.setText("No selection")
