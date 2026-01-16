"""
Threat score gauge visualization.

Displays threat score as an animated circular gauge.
"""

from __future__ import annotations

from typing import Optional
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt, QRectF, QPropertyAnimation, QEasingCurve, pyqtProperty
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QConicalGradient

from ...theme import get_theme_manager


class ThreatGauge(QWidget):
    """
    Circular gauge displaying threat score.

    Features:
    - Animated value changes
    - Color-coded severity
    - Clean, modern design
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize threat gauge."""
        super().__init__(parent)

        self._value: float = 0.0
        self._display_value: float = 0.0
        self._max_value: float = 100.0
        self._label: str = ""

        self.setMinimumSize(200, 200)

    def set_value(self, value: float, animate: bool = True) -> None:
        """
        Set gauge value.

        Args:
            value: Threat score (0-100)
            animate: Whether to animate the change
        """
        self._value = min(max(value, 0), self._max_value)

        if animate:
            animation = QPropertyAnimation(self, b"displayValue")
            animation.setDuration(800)
            animation.setStartValue(self._display_value)
            animation.setEndValue(self._value)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.start()
        else:
            self._display_value = self._value
            self.update()

    @pyqtProperty(float)
    def displayValue(self) -> float:
        """Get display value property."""
        return self._display_value

    @displayValue.setter
    def displayValue(self, value: float) -> None:
        """Set display value property."""
        self._display_value = value
        self.update()

    def set_label(self, label: str) -> None:
        """Set gauge label."""
        self._label = label
        self.update()

    def paintEvent(self, event) -> None:
        """Paint the gauge."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        size = min(rect.width(), rect.height())
        center_x = rect.width() / 2
        center_y = rect.height() / 2

        theme = get_theme_manager()
        p = theme.get_palette()

        # Gauge dimensions
        outer_radius = size / 2 - 10
        inner_radius = outer_radius - 20
        arc_rect = QRectF(
            center_x - outer_radius,
            center_y - outer_radius,
            outer_radius * 2,
            outer_radius * 2,
        )

        # Draw background arc
        painter.setPen(QPen(QColor(p.bg_tertiary), 20, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc_rect, 225 * 16, -270 * 16)

        # Draw value arc
        value_color = self._get_value_color(self._display_value, p)
        painter.setPen(QPen(value_color, 20, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))

        span_angle = int((-270 * 16) * (self._display_value / self._max_value))
        painter.drawArc(arc_rect, 225 * 16, span_angle)

        # Draw center circle
        center_rect = QRectF(
            center_x - inner_radius + 10,
            center_y - inner_radius + 10,
            (inner_radius - 10) * 2,
            (inner_radius - 10) * 2,
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(p.bg_secondary))
        painter.drawEllipse(center_rect)

        # Draw value text
        font = QFont()
        font.setPointSize(32)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor(value_color))

        value_text = f"{int(self._display_value)}"
        text_rect = QRectF(center_x - 50, center_y - 30, 100, 50)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, value_text)

        # Draw label
        font.setPointSize(12)
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor(p.text_secondary))

        label_text = self._get_severity_label()
        label_rect = QRectF(center_x - 50, center_y + 15, 100, 20)
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, label_text)

        # Draw "Threat Score" label
        if self._label:
            font.setPointSize(10)
            painter.setFont(font)
            painter.setPen(QColor(p.text_muted))
            score_rect = QRectF(center_x - 60, center_y + 35, 120, 20)
            painter.drawText(score_rect, Qt.AlignmentFlag.AlignCenter, self._label)

    def _get_value_color(self, value: float, p) -> QColor:
        """Get color based on threat score."""
        if value >= 80:
            return QColor(p.severity_critical)
        elif value >= 60:
            return QColor(p.severity_high)
        elif value >= 40:
            return QColor(p.severity_medium)
        elif value >= 20:
            return QColor(p.severity_low)
        else:
            return QColor(p.accent_success)

    def _get_severity_label(self) -> str:
        """Get severity label for current value."""
        if self._display_value >= 80:
            return "Critical"
        elif self._display_value >= 60:
            return "High Risk"
        elif self._display_value >= 40:
            return "Medium Risk"
        elif self._display_value >= 20:
            return "Low Risk"
        else:
            return "Clean"

    def get_value(self) -> float:
        """Get current value."""
        return self._value
