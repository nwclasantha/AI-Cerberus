"""
Pie chart visualization component.

Displays categorical data as a pie chart.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont
import math

from ...theme import get_theme_manager


class PieChart(QWidget):
    """
    Interactive pie chart.

    Features:
    - Multiple data segments
    - Hover highlighting
    - Legend display
    - Percentage labels
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize pie chart."""
        super().__init__(parent)

        self._data: Dict[str, float] = {}
        self._colors: Dict[str, str] = {}
        self._hovered_segment: Optional[str] = None
        self._title: str = ""

        self.setMinimumSize(250, 200)
        self.setMouseTracking(True)

    def set_data(
        self,
        data: Dict[str, float],
        colors: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Set chart data.

        Args:
            data: Dict of label to value
            colors: Optional dict of label to color
        """
        self._data = data
        self._colors = colors or {}
        self.update()

    def set_title(self, title: str) -> None:
        """Set chart title."""
        self._title = title
        self.update()

    def paintEvent(self, event) -> None:
        """Paint the pie chart."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        theme = get_theme_manager()
        p = theme.get_palette()

        # Background
        painter.fillRect(rect, QColor(p.bg_secondary))

        if not self._data:
            painter.setPen(QColor(p.text_muted))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No data")
            return

        # Calculate chart area (left side for pie, right for legend)
        chart_size = min(rect.width() * 0.55, rect.height() - 40)
        chart_rect = QRectF(
            20,
            (rect.height() - chart_size) / 2,
            chart_size,
            chart_size,
        )

        # Draw title
        if self._title:
            font = QFont()
            font.setPointSize(12)
            font.setBold(True)
            painter.setFont(font)
            painter.setPen(QColor(p.text_primary))
            painter.drawText(20, 20, self._title)

        # Calculate total
        total = sum(self._data.values())
        if total == 0:
            return

        # Draw pie segments
        start_angle = 90 * 16  # Start from top
        default_colors = [
            p.accent_primary, p.accent_success, p.accent_warning,
            p.accent_danger, p.accent_purple, p.accent_cyan,
        ]

        segments = []
        for i, (label, value) in enumerate(self._data.items()):
            span_angle = int((value / total) * 360 * 16)
            color_hex = self._colors.get(label, default_colors[i % len(default_colors)])
            color = QColor(color_hex)

            # Highlight hovered segment
            if label == self._hovered_segment:
                color = color.lighter(120)

            painter.setPen(QPen(QColor(p.bg_primary), 2))
            painter.setBrush(QBrush(color))
            painter.drawPie(chart_rect, start_angle, span_angle)

            # Store segment info for hit testing
            segments.append({
                "label": label,
                "value": value,
                "start": start_angle / 16,
                "span": span_angle / 16,
                "color": color_hex,
            })

            start_angle += span_angle

        self._segments = segments

        # Draw legend
        self._draw_legend(painter, rect, chart_rect, total, p)

    def _draw_legend(
        self,
        painter: QPainter,
        rect: QRectF,
        chart_rect: QRectF,
        total: float,
        p,
    ) -> None:
        """Draw chart legend."""
        legend_x = chart_rect.right() + 20
        legend_y = chart_rect.top() + 10

        font = QFont()
        font.setPointSize(11)
        painter.setFont(font)

        default_colors = [
            p.accent_primary, p.accent_success, p.accent_warning,
            p.accent_danger, p.accent_purple, p.accent_cyan,
        ]

        for i, (label, value) in enumerate(self._data.items()):
            color_hex = self._colors.get(label, default_colors[i % len(default_colors)])
            percentage = (value / total) * 100 if total > 0 else 0

            # Color box
            box_rect = QRectF(legend_x, legend_y, 14, 14)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color_hex))
            painter.drawRoundedRect(box_rect, 2, 2)

            # Label
            painter.setPen(QColor(p.text_primary))
            painter.drawText(
                int(legend_x + 22),
                int(legend_y + 12),
                f"{label}: {percentage:.1f}%",
            )

            legend_y += 24

    def mouseMoveEvent(self, event) -> None:
        """Handle mouse move for hover effect."""
        if not hasattr(self, "_segments"):
            return

        pos = event.position()
        rect = self.rect()
        chart_size = min(rect.width() * 0.55, rect.height() - 40)
        center = QPointF(
            20 + chart_size / 2,
            rect.height() / 2,
        )

        # Calculate angle from center
        dx = pos.x() - center.x()
        dy = center.y() - pos.y()  # Invert Y for standard angles
        distance = math.sqrt(dx * dx + dy * dy)

        # Check if within pie radius
        if distance > chart_size / 2 or distance < 10:
            self._hovered_segment = None
            self.update()
            return

        angle = math.degrees(math.atan2(dy, dx))
        if angle < 0:
            angle += 360

        # Convert to Qt angle system (0 at 3 o'clock, counter-clockwise)
        qt_angle = (90 - angle) % 360

        # Find which segment contains this angle
        for segment in self._segments:
            start = segment["start"] % 360
            span = segment["span"]
            end = (start + span) % 360

            if span > 0:
                if start <= qt_angle < start + span:
                    self._hovered_segment = segment["label"]
                    self.update()
                    return

        self._hovered_segment = None
        self.update()

    def leaveEvent(self, event) -> None:
        """Handle mouse leave."""
        self._hovered_segment = None
        self.update()
