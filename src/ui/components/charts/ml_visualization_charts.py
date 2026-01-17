"""
ML Visualization Charts for Malware Analyzer GUI.

Comprehensive charts for visualizing ML model performance,
predictions, and analysis results.

Charts included:
- Model Score Comparison (Radar Chart)
- Confidence Distribution (Histogram)
- ROC Curve
- Precision-Recall Curve
- Feature Importance Bar Chart
- Anomaly Score Timeline
- Detection Source Breakdown (Stacked Bar)
- Learning Progress Chart
- Model Agreement Heatmap
- Code Block Threat Map

Author: AI-Cerberus
Version: 1.0.0
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
from PyQt6.QtCore import Qt, QRectF, QPointF, pyqtSignal
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QPainterPath,
    QLinearGradient, QRadialGradient, QPaintEvent
)


class BaseChart(QWidget):
    """Base class for all ML visualization charts."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(300, 200)
        self._data = {}
        self._title = ""
        self._colors = {
            'primary': QColor(66, 165, 245),    # Blue
            'success': QColor(102, 187, 106),   # Green
            'warning': QColor(255, 167, 38),    # Orange
            'danger': QColor(239, 83, 80),      # Red
            'info': QColor(171, 71, 188),       # Purple
            'background': QColor(30, 30, 46),   # Dark
            'text': QColor(205, 214, 244),      # Light
            'grid': QColor(69, 71, 90),         # Gray
        }

    def set_data(self, data: Dict[str, Any]) -> None:
        """Set chart data and trigger repaint."""
        self._data = data
        self.update()

    def set_title(self, title: str) -> None:
        """Set chart title."""
        self._title = title
        self.update()


class ModelScoreRadarChart(BaseChart):
    """
    Radar chart showing scores from different ML models.

    Displays how each model scored a sample, making it easy
    to see which models flagged it as suspicious.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Model Scores"
        self.setMinimumSize(350, 350)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Draw title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        # Get model scores
        scores = self._data.get('model_scores', {})
        if not scores:
            return

        # Chart parameters
        center_x = self.width() // 2
        center_y = self.height() // 2 + 20
        radius = min(center_x, center_y) - 60
        n_axes = len(scores)

        if n_axes < 3:
            return

        # Draw concentric circles (grid)
        painter.setPen(QPen(self._colors['grid'], 1))
        for i in range(1, 6):
            r = radius * i / 5
            painter.drawEllipse(
                QPointF(center_x, center_y),
                r, r
            )

        # Draw axes and labels
        model_names = list(scores.keys())
        angle_step = 2 * math.pi / n_axes

        painter.setFont(QFont('Segoe UI', 9))
        for i, name in enumerate(model_names):
            angle = -math.pi / 2 + i * angle_step
            x_end = center_x + radius * math.cos(angle)
            y_end = center_y + radius * math.sin(angle)

            # Draw axis
            painter.setPen(QPen(self._colors['grid'], 1))
            painter.drawLine(int(center_x), int(center_y), int(x_end), int(y_end))

            # Draw label
            label_x = center_x + (radius + 25) * math.cos(angle)
            label_y = center_y + (radius + 25) * math.sin(angle)

            painter.setPen(self._colors['text'])
            # Abbreviate long names
            short_name = name.replace('_', ' ').title()[:10]
            painter.drawText(int(label_x - 30), int(label_y + 5), short_name)

        # Draw score polygon
        path = QPainterPath()
        score_values = list(scores.values())

        for i, score in enumerate(score_values):
            angle = -math.pi / 2 + i * angle_step
            r = radius * min(1.0, max(0.0, score))
            x = center_x + r * math.cos(angle)
            y = center_y + r * math.sin(angle)

            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        path.closeSubpath()

        # Fill with gradient
        avg_score = sum(score_values) / len(score_values) if score_values else 0
        if avg_score > 0.7:
            fill_color = self._colors['danger']
        elif avg_score > 0.4:
            fill_color = self._colors['warning']
        else:
            fill_color = self._colors['success']

        fill_color.setAlpha(100)
        painter.setBrush(QBrush(fill_color))
        painter.setPen(QPen(fill_color.darker(120), 2))
        painter.drawPath(path)

        # Draw score points
        for i, score in enumerate(score_values):
            angle = -math.pi / 2 + i * angle_step
            r = radius * min(1.0, max(0.0, score))
            x = center_x + r * math.cos(angle)
            y = center_y + r * math.sin(angle)

            point_color = self._colors['danger'] if score > 0.5 else self._colors['success']
            painter.setBrush(QBrush(point_color))
            painter.setPen(QPen(Qt.GlobalColor.white, 1))
            painter.drawEllipse(QPointF(x, y), 5, 5)

        painter.end()


class ConfidenceHistogram(BaseChart):
    """
    Histogram showing distribution of confidence scores.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Confidence Distribution"

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        bins = self._data.get('bins', [])
        counts = self._data.get('counts', [])

        if not bins or not counts:
            return

        # Chart area
        margin = 50
        chart_left = margin
        chart_right = self.width() - margin
        chart_top = 50
        chart_bottom = self.height() - 40
        chart_width = chart_right - chart_left
        chart_height = chart_bottom - chart_top

        # Draw axes
        painter.setPen(QPen(self._colors['grid'], 2))
        painter.drawLine(chart_left, chart_bottom, chart_right, chart_bottom)
        painter.drawLine(chart_left, chart_top, chart_left, chart_bottom)

        # Draw bars
        max_count = max(counts) if counts else 1
        bar_width = chart_width / len(bins)

        for i, (bin_val, count) in enumerate(zip(bins, counts)):
            bar_height = (count / max_count) * chart_height if max_count > 0 else 0
            x = chart_left + i * bar_width
            y = chart_bottom - bar_height

            # Color based on confidence
            if bin_val > 0.8:
                color = self._colors['success']
            elif bin_val > 0.5:
                color = self._colors['warning']
            else:
                color = self._colors['danger']

            gradient = QLinearGradient(x, y, x, chart_bottom)
            gradient.setColorAt(0, color)
            gradient.setColorAt(1, color.darker(150))

            painter.setBrush(QBrush(gradient))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(int(x + 2), int(y), int(bar_width - 4), int(bar_height))

        # X-axis labels
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 8))
        for i, bin_val in enumerate([0.0, 0.25, 0.5, 0.75, 1.0]):
            x = chart_left + (bin_val * chart_width)
            painter.drawText(int(x - 15), chart_bottom + 15, f"{bin_val:.1f}")

        painter.end()


class FeatureImportanceChart(BaseChart):
    """
    Horizontal bar chart showing feature importance scores.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Top Anomaly Features"
        self.setMinimumSize(300, 250)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        features = self._data.get('features', [])
        if not features:
            return

        # Take top 8 features
        features = features[:8]

        # Chart area
        margin_left = 120
        margin_right = 30
        margin_top = 45
        margin_bottom = 20
        chart_width = self.width() - margin_left - margin_right
        chart_height = self.height() - margin_top - margin_bottom

        bar_height = min(25, chart_height / len(features) - 5)
        max_score = max(f[1] for f in features) if features else 1

        for i, (name, score) in enumerate(features):
            y = margin_top + i * (bar_height + 5)
            bar_width = (score / max_score) * chart_width if max_score > 0 else 0

            # Color gradient based on score
            if score > 0.7:
                color = self._colors['danger']
            elif score > 0.4:
                color = self._colors['warning']
            else:
                color = self._colors['info']

            # Draw bar
            gradient = QLinearGradient(margin_left, y, margin_left + bar_width, y)
            gradient.setColorAt(0, color.lighter(120))
            gradient.setColorAt(1, color)

            painter.setBrush(QBrush(gradient))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(
                int(margin_left), int(y),
                int(bar_width), int(bar_height),
                3, 3
            )

            # Draw feature name
            painter.setPen(self._colors['text'])
            painter.setFont(QFont('Segoe UI', 9))
            display_name = name.replace('_', ' ').title()[:15]
            painter.drawText(5, int(y + bar_height - 5), display_name)

            # Draw score value
            painter.drawText(
                int(margin_left + bar_width + 5),
                int(y + bar_height - 5),
                f"{score:.2f}"
            )

        painter.end()


class DetectionSourceChart(BaseChart):
    """
    Stacked horizontal bar showing detection by source.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Detection Sources"
        self.setMinimumSize(350, 200)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        sources = self._data.get('sources', {})
        if not sources:
            return

        # Chart area
        margin = 60
        chart_left = margin
        chart_width = self.width() - margin * 2
        bar_y = 60
        bar_height = 40

        # Colors for each source
        source_colors = {
            'virustotal': QColor(66, 165, 245),
            'ml_anomaly': QColor(102, 187, 106),
            'ml_classifier': QColor(126, 206, 148),
            'yara_rules': QColor(255, 167, 38),
            'disassembly': QColor(171, 71, 188),
            'behavioral': QColor(255, 112, 67),
            'entropy': QColor(78, 205, 196),
        }

        # Calculate total for percentage
        total_weight = sum(sources.values())
        if total_weight == 0:
            return

        # Draw stacked bar
        x_offset = chart_left
        legend_y = bar_y + bar_height + 30

        for source, score in sources.items():
            width = (score / total_weight) * chart_width
            color = source_colors.get(source, self._colors['info'])

            # Draw bar segment
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(int(x_offset), bar_y, int(width), bar_height)

            # Draw score in segment if wide enough
            if width > 30:
                painter.setPen(Qt.GlobalColor.white)
                painter.setFont(QFont('Segoe UI', 8, QFont.Weight.Bold))
                painter.drawText(
                    int(x_offset + width/2 - 10),
                    bar_y + bar_height//2 + 5,
                    f"{score:.0%}"
                )

            x_offset += width

        # Draw legend
        legend_x = chart_left
        painter.setFont(QFont('Segoe UI', 8))

        for i, (source, score) in enumerate(sources.items()):
            color = source_colors.get(source, self._colors['info'])

            # Legend square
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(int(legend_x), int(legend_y + (i % 3) * 18), 12, 12)

            # Legend text
            painter.setPen(self._colors['text'])
            display_name = source.replace('_', ' ').title()
            painter.drawText(
                int(legend_x + 16),
                int(legend_y + (i % 3) * 18 + 10),
                f"{display_name}: {score:.1%}"
            )

            if i % 3 == 2:
                legend_x += 130

        painter.end()


class LearningProgressChart(BaseChart):
    """
    Line chart showing model learning progress over time.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Learning Progress"
        self.setMinimumSize(400, 200)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        # Get metrics over time
        precision = self._data.get('precision', [])
        recall = self._data.get('recall', [])
        samples = self._data.get('samples', [])

        if not precision or not recall:
            return

        # Chart area
        margin = 50
        chart_left = margin
        chart_right = self.width() - margin
        chart_top = 50
        chart_bottom = self.height() - 30
        chart_width = chart_right - chart_left
        chart_height = chart_bottom - chart_top

        # Draw grid
        painter.setPen(QPen(self._colors['grid'], 1, Qt.PenStyle.DotLine))
        for i in range(5):
            y = chart_top + (i / 4) * chart_height
            painter.drawLine(int(chart_left), int(y), int(chart_right), int(y))

        # Draw axes
        painter.setPen(QPen(self._colors['grid'], 2))
        painter.drawLine(chart_left, chart_bottom, chart_right, chart_bottom)
        painter.drawLine(chart_left, chart_top, chart_left, chart_bottom)

        n_points = len(precision)
        if n_points < 2:
            return

        # Draw precision line
        painter.setPen(QPen(self._colors['success'], 2))
        prev_x, prev_y = None, None
        for i, p in enumerate(precision):
            x = chart_left + (i / (n_points - 1)) * chart_width
            y = chart_bottom - p * chart_height
            if prev_x is not None:
                painter.drawLine(int(prev_x), int(prev_y), int(x), int(y))
            prev_x, prev_y = x, y

        # Draw recall line
        painter.setPen(QPen(self._colors['info'], 2))
        prev_x, prev_y = None, None
        for i, r in enumerate(recall):
            x = chart_left + (i / (n_points - 1)) * chart_width
            y = chart_bottom - r * chart_height
            if prev_x is not None:
                painter.drawLine(int(prev_x), int(prev_y), int(x), int(y))
            prev_x, prev_y = x, y

        # Draw legend
        painter.setFont(QFont('Segoe UI', 9))
        legend_x = chart_right - 100
        legend_y = chart_top + 10

        painter.setPen(self._colors['success'])
        painter.drawLine(int(legend_x), int(legend_y), int(legend_x + 20), int(legend_y))
        painter.setPen(self._colors['text'])
        painter.drawText(int(legend_x + 25), int(legend_y + 4), "Precision")

        painter.setPen(self._colors['info'])
        painter.drawLine(int(legend_x), int(legend_y + 15), int(legend_x + 20), int(legend_y + 15))
        painter.setPen(self._colors['text'])
        painter.drawText(int(legend_x + 25), int(legend_y + 19), "Recall")

        # Y-axis labels
        painter.setFont(QFont('Segoe UI', 8))
        for i, val in enumerate([1.0, 0.75, 0.5, 0.25, 0.0]):
            y = chart_top + (1 - val) * chart_height
            painter.drawText(int(chart_left - 35), int(y + 4), f"{val:.0%}")

        painter.end()


class ModelAgreementHeatmap(BaseChart):
    """
    Heatmap showing agreement between different models.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Model Agreement"
        self.setMinimumSize(300, 300)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        agreement = self._data.get('agreement_matrix', [])
        labels = self._data.get('model_names', [])

        if not agreement or not labels:
            return

        n = len(labels)

        # Cell size
        margin = 80
        available = min(self.width(), self.height()) - margin - 30
        cell_size = available // n

        offset_x = margin
        offset_y = 45

        # Draw cells
        for i in range(n):
            for j in range(n):
                x = offset_x + j * cell_size
                y = offset_y + i * cell_size
                value = agreement[i][j] if i < len(agreement) and j < len(agreement[i]) else 0

                # Color based on agreement
                if value > 0.8:
                    color = self._colors['success']
                elif value > 0.5:
                    color = self._colors['warning']
                else:
                    color = self._colors['danger']

                alpha = int(50 + 200 * value)
                color.setAlpha(alpha)

                painter.setBrush(QBrush(color))
                painter.setPen(QPen(self._colors['background'], 1))
                painter.drawRect(int(x), int(y), cell_size - 2, cell_size - 2)

                # Draw value
                painter.setPen(self._colors['text'])
                painter.setFont(QFont('Segoe UI', 8))
                painter.drawText(
                    int(x + cell_size//2 - 10),
                    int(y + cell_size//2 + 4),
                    f"{value:.2f}"
                )

        # Draw labels
        painter.setFont(QFont('Segoe UI', 8))
        for i, label in enumerate(labels):
            short_label = label[:6]
            # Column labels
            painter.drawText(
                int(offset_x + i * cell_size + 5),
                int(offset_y - 5),
                short_label
            )
            # Row labels
            painter.save()
            painter.translate(offset_x - 5, offset_y + i * cell_size + cell_size//2)
            painter.rotate(-45)
            painter.drawText(0, 0, short_label)
            painter.restore()

        painter.end()


class ThreatScoreGauge(BaseChart):
    """
    Circular gauge showing overall threat score.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Threat Score"
        self.setMinimumSize(200, 200)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        score = self._data.get('score', 0)
        max_score = self._data.get('max_score', 100)
        label = self._data.get('label', 'Unknown')

        # Calculate dimensions
        size = min(self.width(), self.height()) - 20
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = size // 2 - 20

        # Draw background arc
        arc_rect = QRectF(
            center_x - radius, center_y - radius,
            radius * 2, radius * 2
        )

        painter.setPen(QPen(self._colors['grid'], 15, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc_rect, 225 * 16, -270 * 16)

        # Determine color based on score
        ratio = score / max_score if max_score > 0 else 0
        if ratio >= 0.8:
            color = self._colors['danger']
        elif ratio >= 0.6:
            color = QColor(255, 140, 0)  # Orange
        elif ratio >= 0.4:
            color = self._colors['warning']
        elif ratio >= 0.2:
            color = QColor(255, 235, 59)  # Yellow
        else:
            color = self._colors['success']

        # Draw score arc
        score_angle = int(-270 * ratio) * 16
        painter.setPen(QPen(color, 15, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc_rect, 225 * 16, score_angle)

        # Draw center circle
        painter.setBrush(QBrush(self._colors['background']))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(
            QPointF(center_x, center_y),
            radius - 25, radius - 25
        )

        # Draw score text
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 24, QFont.Weight.Bold))
        score_text = f"{int(score)}"
        text_rect = painter.fontMetrics().boundingRect(score_text)
        painter.drawText(
            center_x - text_rect.width() // 2,
            center_y + 8,
            score_text
        )

        # Draw label
        painter.setFont(QFont('Segoe UI', 10))
        painter.drawText(
            center_x - 30,
            center_y + 30,
            label
        )

        # Draw title
        painter.setFont(QFont('Segoe UI', 11, QFont.Weight.Bold))
        painter.drawText(10, 20, self._title)

        painter.end()


class CodeBlockVisualization(BaseChart):
    """
    Visual representation of suspicious code blocks in a binary.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = "Suspicious Code Blocks"
        self.setMinimumSize(400, 150)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), self._colors['background'])

        # Title
        painter.setPen(self._colors['text'])
        painter.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        painter.drawText(10, 25, self._title)

        if not self._data:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        blocks = self._data.get('blocks', [])
        file_size = self._data.get('file_size', 1)

        if not blocks or file_size == 0:
            return

        # Binary map area
        margin = 20
        map_left = margin
        map_right = self.width() - margin
        map_top = 45
        map_height = 30
        map_width = map_right - map_left

        # Draw binary outline
        painter.setPen(QPen(self._colors['grid'], 1))
        painter.setBrush(QBrush(QColor(40, 40, 60)))
        painter.drawRect(map_left, map_top, map_width, map_height)

        # Color mapping for threat levels
        level_colors = {
            'critical': self._colors['danger'],
            'high': QColor(255, 140, 0),
            'medium': self._colors['warning'],
            'low': self._colors['info'],
        }

        # Draw blocks
        for block in blocks:
            start = block.get('start', 0)
            end = block.get('end', start + 100)
            level = block.get('level', 'medium')

            x_start = map_left + (start / file_size) * map_width
            x_end = map_left + (end / file_size) * map_width
            block_width = max(3, x_end - x_start)

            color = level_colors.get(level, self._colors['warning'])
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(int(x_start), map_top, int(block_width), map_height)

        # Draw legend
        legend_y = map_top + map_height + 20
        legend_x = margin

        painter.setFont(QFont('Segoe UI', 8))
        for level, color in level_colors.items():
            painter.setBrush(QBrush(color))
            painter.drawRect(int(legend_x), int(legend_y), 12, 12)
            painter.setPen(self._colors['text'])
            painter.drawText(int(legend_x + 15), int(legend_y + 10), level.title())
            legend_x += 80

        # Block count
        painter.drawText(
            self.width() - 100, int(legend_y + 10),
            f"{len(blocks)} blocks found"
        )

        painter.end()


# Factory function to create chart widgets
def create_ml_chart(chart_type: str, parent: Optional[QWidget] = None) -> BaseChart:
    """
    Factory function to create ML visualization charts.

    Args:
        chart_type: Type of chart to create
        parent: Parent widget

    Returns:
        Chart widget instance
    """
    charts = {
        'radar': ModelScoreRadarChart,
        'histogram': ConfidenceHistogram,
        'features': FeatureImportanceChart,
        'sources': DetectionSourceChart,
        'progress': LearningProgressChart,
        'heatmap': ModelAgreementHeatmap,
        'gauge': ThreatScoreGauge,
        'codeblocks': CodeBlockVisualization,
    }

    chart_class = charts.get(chart_type, BaseChart)
    return chart_class(parent)
