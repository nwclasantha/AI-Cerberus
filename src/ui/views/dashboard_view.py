"""
Dashboard view - main landing page.

Displays overview statistics, recent samples, and quick actions.
"""

from typing import Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGridLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QSizePolicy,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from ..theme import get_theme_manager
from ..components.charts import ThreatGauge, PieChart


class StatCard(QFrame):
    """Statistics card widget."""

    clicked = pyqtSignal()

    def __init__(
        self,
        title: str,
        value: str,
        subtitle: str = "",
        color: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)

        self._title = title
        self._value = value
        self._color = color

        self.setProperty("card", True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._setup_ui(subtitle)
        self._setup_style()

    def _setup_ui(self, subtitle: str) -> None:
        """Set up card UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(8)

        # Title
        title_label = QLabel(self._title)
        title_label.setObjectName("cardTitle")
        layout.addWidget(title_label)

        # Value
        self._value_label = QLabel(self._value)
        self._value_label.setObjectName("cardValue")
        layout.addWidget(self._value_label)

        # Subtitle
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("cardSubtitle")
            layout.addWidget(subtitle_label)

    def _setup_style(self) -> None:
        """Configure card appearance."""
        theme = get_theme_manager()
        p = theme.get_palette()

        accent = self._color or p.accent_primary

        self.setStyleSheet(f"""
            StatCard {{
                background-color: {p.bg_secondary};
                border: 1px solid {p.border_primary};
                border-left: 4px solid {accent};
                border-radius: 8px;
            }}
            StatCard:hover {{
                background-color: {p.bg_tertiary};
                border-color: {accent};
            }}
            #cardTitle {{
                color: {p.text_secondary};
                font-size: 15px;
                font-weight: 500;
            }}
            #cardValue {{
                color: {p.text_primary};
                font-size: 36px;
                font-weight: 700;
            }}
            #cardSubtitle {{
                color: {p.text_muted};
                font-size: 16px;
            }}
        """)

    def set_value(self, value: str) -> None:
        """Update card value."""
        self._value_label.setText(value)

    def mousePressEvent(self, event) -> None:
        """Handle click."""
        self.clicked.emit()
        super().mousePressEvent(event)


class DashboardView(QWidget):
    """
    Main dashboard view.

    Displays:
    - Statistics cards
    - Classification distribution
    - Recent samples table
    - Quick actions
    """

    # Signals
    sample_selected = pyqtSignal(str)  # SHA256
    open_file_requested = pyqtSignal()
    view_all_samples_requested = pyqtSignal()
    clear_all_requested = pyqtSignal()  # Clear all scans

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize dashboard."""
        super().__init__(parent)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up dashboard UI."""
        # Create main layout with scroll area
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("QScrollArea { background-color: transparent; }")

        # Create container widget for all content
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)

        # Header
        header = self._create_header()
        layout.addWidget(header)

        # Stats cards row
        stats_row = self._create_stats_row()
        layout.addLayout(stats_row)

        # Main content area
        content_layout = QHBoxLayout()
        content_layout.setSpacing(24)

        # Left column - charts
        left_column = self._create_left_column()
        content_layout.addLayout(left_column, 1)

        # Right column - recent samples
        right_column = self._create_right_column()
        content_layout.addLayout(right_column, 2)

        layout.addLayout(content_layout, 1)

        # Set container as scroll area widget
        scroll_area.setWidget(container)

        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _create_header(self) -> QWidget:
        """Create dashboard header."""
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 0)

        # Title
        title = QLabel("Dashboard")
        title.setStyleSheet("""
            font-size: 30px;
            font-weight: 700;
            color: #f0f6fc;
        """)
        layout.addWidget(title)

        layout.addStretch()

        # Quick actions
        # Clear All button
        clear_all_btn = QPushButton("Clear All Scans")
        clear_all_btn.setProperty("danger", True)  # Red danger button
        clear_all_btn.clicked.connect(self.clear_all_requested.emit)
        clear_all_btn.setToolTip("Delete all analysis results from database (Ctrl+Shift+D)")
        layout.addWidget(clear_all_btn)

        # Open File button
        open_btn = QPushButton("Open File")
        open_btn.setProperty("primary", True)
        open_btn.clicked.connect(self.open_file_requested.emit)
        layout.addWidget(open_btn)

        return header

    def _create_stats_row(self) -> QHBoxLayout:
        """Create statistics cards row."""
        layout = QHBoxLayout()
        layout.setSpacing(16)

        theme = get_theme_manager()
        p = theme.get_palette()

        # Total samples
        self._total_card = StatCard(
            "Total Samples",
            "0",
            "All analyzed files",
            p.accent_primary,
        )
        layout.addWidget(self._total_card)

        # Malicious
        self._malicious_card = StatCard(
            "Malicious",
            "0",
            "High threat samples",
            p.accent_danger,
        )
        layout.addWidget(self._malicious_card)

        # Suspicious
        self._suspicious_card = StatCard(
            "Suspicious",
            "0",
            "Medium threat samples",
            p.accent_warning,
        )
        layout.addWidget(self._suspicious_card)

        # Clean
        self._clean_card = StatCard(
            "Clean",
            "0",
            "Low/no threat samples",
            p.accent_success,
        )
        layout.addWidget(self._clean_card)

        return layout

    def _create_left_column(self) -> QVBoxLayout:
        """Create left column with charts."""
        layout = QVBoxLayout()
        layout.setSpacing(16)

        # Threat distribution pie chart
        chart_frame = QFrame()
        chart_frame.setProperty("card", True)
        chart_layout = QVBoxLayout(chart_frame)

        self._pie_chart = PieChart()
        self._pie_chart.set_title("Classification Distribution")
        self._pie_chart.setMinimumHeight(250)
        chart_layout.addWidget(self._pie_chart)

        layout.addWidget(chart_frame)

        # Average threat score
        score_frame = QFrame()
        score_frame.setProperty("card", True)
        score_layout = QVBoxLayout(score_frame)

        score_title = QLabel("Average Threat Score")
        score_title.setProperty("header", True)
        score_layout.addWidget(score_title)

        self._threat_gauge = ThreatGauge()
        self._threat_gauge.set_label("Threat Score")
        self._threat_gauge.set_value(0, animate=False)
        score_layout.addWidget(self._threat_gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(score_frame)

        return layout

    def _create_right_column(self) -> QVBoxLayout:
        """Create right column with recent samples."""
        layout = QVBoxLayout()
        layout.setSpacing(16)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel("Recent Samples")
        title.setProperty("header", True)
        header_layout.addWidget(title)

        header_layout.addStretch()

        view_all_btn = QPushButton("View All")
        view_all_btn.clicked.connect(self.view_all_samples_requested.emit)
        header_layout.addWidget(view_all_btn)

        layout.addWidget(header)

        # Samples table
        self._samples_table = QTableWidget()
        self._samples_table.setColumnCount(5)
        self._samples_table.setHorizontalHeaderLabels([
            "Filename", "Classification", "Threat Score", "Type", "Analyzed"
        ])

        # Configure table
        header = self._samples_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self._samples_table.setColumnWidth(1, 100)
        self._samples_table.setColumnWidth(2, 100)
        self._samples_table.setColumnWidth(3, 80)
        self._samples_table.setColumnWidth(4, 120)

        self._samples_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._samples_table.setAlternatingRowColors(True)
        self._samples_table.verticalHeader().setVisible(False)
        self._samples_table.setShowGrid(False)

        self._samples_table.cellDoubleClicked.connect(self._on_sample_double_click)

        layout.addWidget(self._samples_table)

        return layout

    def _on_sample_double_click(self, row: int, col: int) -> None:
        """Handle sample double click."""
        # Get SHA256 from hidden data
        item = self._samples_table.item(row, 0)
        if item:
            sha256 = item.data(Qt.ItemDataRole.UserRole)
            if sha256:
                self.sample_selected.emit(sha256)

    def update_statistics(self, stats: dict) -> None:
        """
        Update dashboard statistics.

        Args:
            stats: Dict with keys: total, malicious, suspicious, benign, avg_score
        """
        self._total_card.set_value(str(stats.get("total", 0)))
        self._malicious_card.set_value(str(stats.get("malicious", 0)))
        self._suspicious_card.set_value(str(stats.get("suspicious", 0)))
        self._clean_card.set_value(str(stats.get("benign", 0)))

        # Update pie chart
        pie_data = {
            "Malicious": stats.get("malicious", 0),
            "Suspicious": stats.get("suspicious", 0),
            "Clean": stats.get("benign", 0),
            "Unknown": stats.get("unknown", 0),
        }
        theme = get_theme_manager()
        p = theme.get_palette()
        pie_colors = {
            "Malicious": p.accent_danger,
            "Suspicious": p.accent_warning,
            "Clean": p.accent_success,
            "Unknown": p.text_muted,
        }
        self._pie_chart.set_data(pie_data, pie_colors)

        # Update threat gauge with database average
        avg_score = stats.get("average_threat_score", 0)
        self._threat_gauge.set_value(avg_score)
        self._threat_gauge.set_label("Average Threat Score")

    def update_current_file_score(self, score: float, classification: str) -> None:
        """
        Update threat gauge to show current file's score.

        Args:
            score: Current file's threat score (0-100)
            classification: Classification (malicious, suspicious, benign)
        """
        self._threat_gauge.set_value(score)
        self._threat_gauge.set_label(f"Current File: {classification.upper()}")

    def update_recent_samples(self, samples: list) -> None:
        """
        Update recent samples table.

        Args:
            samples: List of sample dicts
        """
        self._samples_table.setRowCount(len(samples))

        theme = get_theme_manager()
        p = theme.get_palette()

        for row, sample in enumerate(samples):
            # Filename
            filename_item = QTableWidgetItem(sample.get("filename", "Unknown"))
            filename_item.setData(Qt.ItemDataRole.UserRole, sample.get("sha256"))
            self._samples_table.setItem(row, 0, filename_item)

            # Classification
            classification = sample.get("classification", "unknown")
            class_item = QTableWidgetItem(classification.capitalize())

            color_map = {
                "malicious": p.accent_danger,
                "suspicious": p.accent_warning,
                "benign": p.accent_success,
            }
            color = color_map.get(classification.lower(), p.text_muted)
            class_item.setForeground(QColor(color))
            self._samples_table.setItem(row, 1, class_item)

            # Threat score
            score = sample.get("threat_score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            self._samples_table.setItem(row, 2, score_item)

            # File type
            file_type = sample.get("file_type", "Unknown")
            self._samples_table.setItem(row, 3, QTableWidgetItem(file_type))

            # Analyzed time
            analyzed = sample.get("last_analyzed", "")
            if analyzed:
                # Format date
                analyzed = analyzed[:16].replace("T", " ")
            self._samples_table.setItem(row, 4, QTableWidgetItem(analyzed))
