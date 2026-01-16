"""
Entropy visualization chart.

Displays entropy distribution across file sections.
"""

from typing import List, Optional, Tuple
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QLinearGradient, QFont

from ...theme import get_theme_manager


class EntropyChart(QWidget):
    """
    Interactive entropy visualization chart.

    Features:
    - Block-level entropy display
    - Color-coded entropy ranges
    - Hover tooltips
    - Section markers
    """

    # Entropy thresholds
    ENCRYPTED_THRESHOLD = 7.5
    PACKED_THRESHOLD = 7.0
    SUSPICIOUS_THRESHOLD = 6.5
    NORMAL_THRESHOLD = 5.0

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize entropy chart."""
        super().__init__(parent)

        self._data: List[float] = []
        self._sections: List[Tuple[int, int, str]] = []  # (start, end, name)
        self._overall_entropy: float = 0.0
        self._hovered_block: int = -1

        self.setMinimumHeight(150)
        self.setMouseTracking(True)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up chart UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Chart canvas
        self._canvas = EntropyCanvas(self)
        layout.addWidget(self._canvas)

        # Legend
        legend = self._create_legend()
        layout.addWidget(legend)

    def _create_legend(self) -> QWidget:
        """Create chart legend."""
        legend = QFrame()
        layout = QHBoxLayout(legend)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(16)

        theme = get_theme_manager()
        p = theme.get_palette()

        items = [
            ("Encrypted/Random", p.severity_critical),
            ("Packed", p.severity_high),
            ("Suspicious", p.severity_medium),
            ("Normal", p.accent_success),
        ]

        for label, color in items:
            item = QWidget()
            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(4)

            # Color box
            box = QLabel()
            box.setFixedSize(12, 12)
            box.setStyleSheet(f"background-color: {color}; border-radius: 2px;")
            item_layout.addWidget(box)

            # Label
            text = QLabel(label)
            text.setStyleSheet(f"color: {p.text_secondary}; font-size: 11px;")
            item_layout.addWidget(text)

            layout.addWidget(item)

        layout.addStretch()
        return legend

    def set_data(
        self,
        entropy_values: List[float],
        overall: float = 0.0,
        sections: Optional[List[Tuple[int, int, str]]] = None,
    ) -> None:
        """
        Set entropy data.

        Args:
            entropy_values: List of entropy values per block
            overall: Overall file entropy
            sections: Optional section markers (start, end, name)
        """
        self._data = entropy_values
        self._overall_entropy = overall
        self._sections = sections or []
        self._canvas.set_data(entropy_values, sections)

    def get_color_for_entropy(self, entropy: float) -> QColor:
        """Get color based on entropy value."""
        theme = get_theme_manager()
        p = theme.get_palette()

        if entropy >= self.ENCRYPTED_THRESHOLD:
            return QColor(p.severity_critical)
        elif entropy >= self.PACKED_THRESHOLD:
            return QColor(p.severity_high)
        elif entropy >= self.SUSPICIOUS_THRESHOLD:
            return QColor(p.severity_medium)
        else:
            return QColor(p.accent_success)


class EntropyCanvas(QWidget):
    """Canvas widget for drawing entropy chart."""

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize canvas."""
        super().__init__(parent)

        self._data: List[float] = []
        self._sections: List[Tuple[int, int, str]] = []
        self._hovered_block: int = -1

        self.setMinimumHeight(100)
        self.setMouseTracking(True)

    def set_data(
        self,
        data: List[float],
        sections: Optional[List[Tuple[int, int, str]]] = None,
    ) -> None:
        """Set chart data."""
        self._data = data
        self._sections = sections or []
        self.update()

    def paintEvent(self, event) -> None:
        """Paint the entropy chart."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        theme = get_theme_manager()
        p = theme.get_palette()

        # Background
        painter.fillRect(rect, QColor(p.bg_secondary))

        if not self._data:
            # Draw placeholder
            painter.setPen(QColor(p.text_muted))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No entropy data")
            return

        # Chart area
        margin = 40
        chart_rect = QRectF(
            margin,
            10,
            rect.width() - margin * 2,
            rect.height() - 30,
        )

        # Draw grid
        self._draw_grid(painter, chart_rect, p)

        # Draw entropy bars
        self._draw_bars(painter, chart_rect, p)

        # Draw Y-axis labels
        self._draw_axis_labels(painter, chart_rect, p)

    def _draw_grid(self, painter: QPainter, rect: QRectF, p) -> None:
        """Draw chart grid lines."""
        painter.setPen(QPen(QColor(p.border_secondary), 1, Qt.PenStyle.DotLine))

        # Horizontal lines at entropy thresholds
        thresholds = [0, 2, 4, 6, 8]
        for thresh in thresholds:
            y = rect.bottom() - (thresh / 8.0) * rect.height()
            painter.drawLine(int(rect.left()), int(y), int(rect.right()), int(y))

    def _draw_bars(self, painter: QPainter, rect: QRectF, p) -> None:
        """Draw entropy bars."""
        if not self._data:
            return

        bar_width = rect.width() / len(self._data)

        for i, entropy in enumerate(self._data):
            # Calculate bar height (scale to 0-8 range)
            height = (entropy / 8.0) * rect.height()

            x = rect.left() + i * bar_width
            y = rect.bottom() - height

            # Get color based on entropy
            color = self._get_entropy_color(entropy, p)

            # Draw bar
            bar_rect = QRectF(x + 1, y, bar_width - 2, height)
            painter.fillRect(bar_rect, color)

            # Highlight hovered block
            if i == self._hovered_block:
                painter.setPen(QPen(QColor(p.accent_primary), 2))
                painter.drawRect(bar_rect)

    def _draw_axis_labels(self, painter: QPainter, rect: QRectF, p) -> None:
        """Draw Y-axis labels."""
        painter.setPen(QColor(p.text_muted))
        font = QFont()
        font.setPointSize(9)
        painter.setFont(font)

        # Y-axis labels
        labels = ["0", "2", "4", "6", "8"]
        for i, label in enumerate(labels):
            y = rect.bottom() - (i * 2 / 8.0) * rect.height()
            painter.drawText(
                int(rect.left() - 25),
                int(y - 5),
                20,
                14,
                Qt.AlignmentFlag.AlignRight,
                label,
            )

    def _get_entropy_color(self, entropy: float, p) -> QColor:
        """Get color for entropy value."""
        if entropy >= 7.5:
            return QColor(p.severity_critical)
        elif entropy >= 7.0:
            return QColor(p.severity_high)
        elif entropy >= 6.5:
            return QColor(p.severity_medium)
        elif entropy >= 5.0:
            return QColor(p.severity_low)
        else:
            return QColor(p.accent_success)

    def mouseMoveEvent(self, event) -> None:
        """Handle mouse move for hover effect."""
        if not self._data:
            return

        rect = self.rect()
        margin = 40
        chart_width = rect.width() - margin * 2
        bar_width = chart_width / len(self._data)

        x = event.position().x() - margin
        if 0 <= x < chart_width:
            self._hovered_block = int(x / bar_width)
        else:
            self._hovered_block = -1

        self.update()

    def leaveEvent(self, event) -> None:
        """Handle mouse leave."""
        self._hovered_block = -1
        self.update()
