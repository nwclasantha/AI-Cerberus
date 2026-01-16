"""
History view for displaying past analysis results.

Shows all analyzed samples in a searchable, filterable table.
"""

from __future__ import annotations

from typing import Optional, List
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLineEdit, QComboBox,
    QLabel, QHeaderView, QMenu, QMessageBox, QScrollArea,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QAction

from ...database import get_repository
from ...utils.logger import get_logger

logger = get_logger("history_view")


class HistoryView(QWidget):
    """
    History view for displaying analysis history.

    Features:
    - Table of all analyzed samples
    - Search by filename/hash
    - Filter by classification/threat level
    - Context menu for actions
    - Double-click to open analysis
    """

    # Signals
    sample_selected = pyqtSignal(str)  # Emits SHA256
    analysis_requested = pyqtSignal(str)  # Emits file path

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize history view."""
        super().__init__(parent)

        self._repo = get_repository()
        self._samples = []

        self._setup_ui()
        self._setup_connections()
        self.load_history()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
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
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Button styling
        button_style = """
            QPushButton {
                font-size: 16px;
                padding: 10px 20px;
                min-height: 40px;
                background-color: #21262d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #30363d;
                border: 2px solid #58a6ff;
            }
            QPushButton:pressed {
                background-color: #161b22;
            }
        """

        # Input field styling
        input_style = """
            QLineEdit {
                font-size: 16px;
                padding: 10px;
                min-height: 40px;
                background-color: #21262d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
            }
            QLineEdit:focus {
                border: 2px solid #58a6ff;
                background-color: #161b22;
            }
        """

        # Combo box styling
        combo_style = """
            QComboBox {
                font-size: 16px;
                padding: 10px;
                min-height: 40px;
                background-color: #21262d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
            }
            QComboBox:hover {
                border: 2px solid #58a6ff;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox QAbstractItemView {
                background-color: #21262d;
                color: #f0f6fc;
                selection-background-color: #58a6ff;
                selection-color: #0d1117;
                border: 2px solid #30363d;
            }
        """

        # Table styling
        table_style = """
            QTableWidget {
                background-color: #161b22;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                font-size: 15px;
                gridline-color: #30363d;
            }
            QTableWidget::item {
                padding: 8px;
                color: #f0f6fc;
            }
            QTableWidget::item:selected {
                background-color: #58a6ff;
                color: #0d1117;
            }
            QHeaderView::section {
                background-color: #21262d;
                color: #f0f6fc;
                padding: 10px;
                border: 1px solid #30363d;
                font-weight: bold;
                font-size: 16px;
            }
        """

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("Analysis History")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #f0f6fc;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Refresh button
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setStyleSheet(button_style)
        header_layout.addWidget(self._refresh_btn)

        # Clear history button
        self._clear_btn = QPushButton("Clear History")
        clear_button_style = button_style.replace("background-color: #21262d;", "background-color: #f85149;")
        self._clear_btn.setStyleSheet(clear_button_style)
        header_layout.addWidget(self._clear_btn)

        layout.addLayout(header_layout)

        # Filters
        filter_layout = QHBoxLayout()

        # Search
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search by filename, hash, or classification...")
        self._search_input.setMinimumWidth(300)
        self._search_input.setStyleSheet(input_style)
        filter_layout.addWidget(self._search_input)

        # Classification filter
        class_label = QLabel("Classification:")
        class_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #f0f6fc; padding: 0 10px;")
        filter_layout.addWidget(class_label)

        self._class_filter = QComboBox()
        self._class_filter.addItems([
            "All",
            "Malware",
            "Suspicious",
            "Clean",
            "Unknown",
        ])
        self._class_filter.setStyleSheet(combo_style)
        filter_layout.addWidget(self._class_filter)

        # Threat level filter
        threat_label = QLabel("Threat Level:")
        threat_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #f0f6fc; padding: 0 10px;")
        filter_layout.addWidget(threat_label)

        self._threat_filter = QComboBox()
        self._threat_filter.addItems([
            "All",
            "Critical (>80)",
            "High (60-80)",
            "Medium (40-60)",
            "Low (<40)",
        ])
        self._threat_filter.setStyleSheet(combo_style)
        filter_layout.addWidget(self._threat_filter)

        filter_layout.addStretch()

        layout.addLayout(filter_layout)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(10)
        self._table.setHorizontalHeaderLabels([
            "Filename",
            "Size",
            "MD5",
            "SHA256",
            "Classification",
            "Threat Score",
            "Verdict",
            "First Seen",
            "Last Analyzed",
            "Count",
        ])

        # Configure table
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.setSortingEnabled(True)
        self._table.setStyleSheet(table_style)

        # Column widths
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Filename
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Size
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # MD5
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # SHA256
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Classification
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Threat
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Verdict
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # First
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)  # Last
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.ResizeToContents)  # Count

        layout.addWidget(self._table)

        # Status bar
        self._status_label = QLabel("No samples in history")
        self._status_label.setStyleSheet("color: #8b949e; font-size: 17px; padding: 10px;")
        layout.addWidget(self._status_label)

        # Set container as scroll area widget
        scroll_area.setWidget(container)

        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _setup_connections(self) -> None:
        """Set up signal connections."""
        self._refresh_btn.clicked.connect(self.load_history)
        self._clear_btn.clicked.connect(self._clear_history)
        self._search_input.textChanged.connect(self._filter_table)
        self._class_filter.currentTextChanged.connect(self._filter_table)
        self._threat_filter.currentTextChanged.connect(self._filter_table)
        self._table.doubleClicked.connect(self._on_row_double_clicked)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

    def load_history(self) -> None:
        """Load analysis history from database."""
        try:
            logger.info("Loading analysis history")

            # Get all samples
            self._samples = self._repo.get_all_samples()

            # Update table
            self._populate_table(self._samples)

            # Update status
            count = len(self._samples)
            self._status_label.setText(
                f"Showing {count} sample{'s' if count != 1 else ''}"
            )

            logger.info(f"Loaded {count} samples")

        except Exception as e:
            logger.error(f"Failed to load history: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to load history:\n{str(e)}"
            )

    def _populate_table(self, samples: List) -> None:
        """Populate table with samples."""
        self._table.setRowCount(0)
        self._table.setSortingEnabled(False)

        for sample in samples:
            row = self._table.rowCount()
            self._table.insertRow(row)

            # Filename
            self._table.setItem(row, 0, QTableWidgetItem(sample.filename))

            # Size (formatted)
            size_mb = sample.file_size / (1024 * 1024)
            if size_mb < 1:
                size_str = f"{sample.file_size / 1024:.1f} KB"
            else:
                size_str = f"{size_mb:.2f} MB"
            self._table.setItem(row, 1, QTableWidgetItem(size_str))

            # MD5
            self._table.setItem(row, 2, QTableWidgetItem(sample.md5[:8] + "..."))

            # SHA256
            sha_item = QTableWidgetItem(sample.sha256[:16] + "...")
            sha_item.setData(Qt.ItemDataRole.UserRole, sample.sha256)  # Store full hash
            self._table.setItem(row, 3, sha_item)

            # Classification
            class_item = QTableWidgetItem(sample.classification.upper())
            class_item.setForeground(self._get_classification_color(sample.classification))
            self._table.setItem(row, 4, class_item)

            # Threat Score
            threat_item = QTableWidgetItem(f"{sample.threat_score:.1f}")
            threat_item.setForeground(self._get_threat_color(sample.threat_score))
            self._table.setItem(row, 5, threat_item)

            # Verdict
            verdict_item = QTableWidgetItem(sample.verdict.upper())
            self._table.setItem(row, 6, verdict_item)

            # First Seen
            first_seen = sample.first_seen.strftime("%Y-%m-%d %H:%M")
            self._table.setItem(row, 7, QTableWidgetItem(first_seen))

            # Last Analyzed
            last_analyzed = sample.last_analyzed.strftime("%Y-%m-%d %H:%M")
            self._table.setItem(row, 8, QTableWidgetItem(last_analyzed))

            # Analysis Count
            self._table.setItem(row, 9, QTableWidgetItem(str(sample.analysis_count)))

        self._table.setSortingEnabled(True)

    def _get_classification_color(self, classification: str) -> QBrush:
        """Get color for classification."""
        colors = {
            "malware": QColor("#f85149"),
            "suspicious": QColor("#d29922"),
            "clean": QColor("#3fb950"),
            "unknown": QColor("#8b949e"),
        }
        return QBrush(colors.get(classification.lower(), QColor("#8b949e")))

    def _get_threat_color(self, score: float) -> QBrush:
        """Get color for threat score."""
        if score >= 80:
            return QBrush(QColor("#f85149"))  # Red
        elif score >= 60:
            return QBrush(QColor("#ff7b72"))  # Light red
        elif score >= 40:
            return QBrush(QColor("#d29922"))  # Orange
        else:
            return QBrush(QColor("#3fb950"))  # Green

    def _filter_table(self) -> None:
        """Filter table based on search and filters."""
        search_text = self._search_input.text().lower()
        class_filter = self._class_filter.currentText()
        threat_filter = self._threat_filter.currentText()

        visible_count = 0

        for row in range(self._table.rowCount()):
            show = True

            # Search filter
            if search_text:
                filename = self._table.item(row, 0).text().lower()
                md5 = self._table.item(row, 2).text().lower()
                sha256 = self._table.item(row, 3).text().lower()
                classification = self._table.item(row, 4).text().lower()

                if not any(search_text in field for field in [filename, md5, sha256, classification]):
                    show = False

            # Classification filter
            if show and class_filter != "All":
                classification = self._table.item(row, 4).text()
                if classification.upper() != class_filter.upper():
                    show = False

            # Threat level filter
            if show and threat_filter != "All":
                threat_score = float(self._table.item(row, 5).text())

                if threat_filter == "Critical (>80)" and threat_score <= 80:
                    show = False
                elif threat_filter == "High (60-80)" and not (60 <= threat_score <= 80):
                    show = False
                elif threat_filter == "Medium (40-60)" and not (40 <= threat_score <= 60):
                    show = False
                elif threat_filter == "Low (<40)" and threat_score >= 40:
                    show = False

            self._table.setRowHidden(row, not show)
            if show:
                visible_count += 1

        # Update status
        total = len(self._samples)
        if visible_count < total:
            self._status_label.setText(
                f"Showing {visible_count} of {total} samples"
            )
        else:
            self._status_label.setText(
                f"Showing {total} sample{'s' if total != 1 else ''}"
            )

    def _on_row_double_clicked(self, index) -> None:
        """Handle row double-click."""
        row = index.row()
        sha256 = self._table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        self.sample_selected.emit(sha256)

    def _show_context_menu(self, position) -> None:
        """Show context menu for table row."""
        if self._table.rowCount() == 0:
            return

        menu = QMenu(self)

        # Actions
        view_action = QAction("View Details", self)
        reanalyze_action = QAction("Re-analyze", self)
        export_action = QAction("Export Report", self)
        delete_action = QAction("Delete from History", self)
        delete_action.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_TrashIcon))

        menu.addAction(view_action)
        menu.addAction(reanalyze_action)
        menu.addSeparator()
        menu.addAction(export_action)
        menu.addSeparator()
        menu.addAction(delete_action)

        # Connect actions
        view_action.triggered.connect(self._view_details)
        reanalyze_action.triggered.connect(self._reanalyze_sample)
        export_action.triggered.connect(self._export_report)
        delete_action.triggered.connect(self._delete_sample)

        # Show menu
        menu.exec(self._table.viewport().mapToGlobal(position))

    def _view_details(self) -> None:
        """View sample details."""
        row = self._table.currentRow()
        if row < 0:
            return

        sha256 = self._table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        self.sample_selected.emit(sha256)

    def _reanalyze_sample(self) -> None:
        """Re-analyze selected sample."""
        row = self._table.currentRow()
        if row < 0:
            return

        sha256 = self._table.item(row, 3).data(Qt.ItemDataRole.UserRole)

        # Get sample from database
        try:
            sample = self._repo.get_sample_by_hash(sha256)
            if sample and sample.file_path:
                self.analysis_requested.emit(sample.file_path)
            else:
                QMessageBox.warning(
                    self,
                    "Cannot Re-analyze",
                    "Original file path not available. Please analyze the file again manually."
                )
        except Exception as e:
            logger.error(f"Failed to re-analyze: {e}")
            QMessageBox.critical(self, "Error", f"Failed to re-analyze:\n{str(e)}")

    def _export_report(self) -> None:
        """Export sample report."""
        QMessageBox.information(
            self,
            "Export Report",
            "Report export functionality will be available in the next update.\n\n"
            "You can use the 'Export' button in the Analysis view for now."
        )

    def _delete_sample(self) -> None:
        """Delete sample from history."""
        row = self._table.currentRow()
        if row < 0:
            return

        filename = self._table.item(row, 0).text()
        sha256 = self._table.item(row, 3).data(Qt.ItemDataRole.UserRole)

        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete '{filename}' from history?\n\n"
            f"This will remove all analysis data for this sample.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Get sample to get its ID
                sample = self._repo.get_sample_by_hash(sha256)
                if sample:
                    self._repo.delete_sample(sample.id)
                    self.load_history()  # Reload
                    logger.info(f"Deleted sample: {sha256}")
                else:
                    QMessageBox.warning(self, "Not Found", "Sample not found in database.")
            except Exception as e:
                logger.error(f"Failed to delete sample: {e}")
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to delete sample:\n{str(e)}"
                )

    def _clear_history(self) -> None:
        """Clear all history."""
        if not self._samples:
            QMessageBox.information(self, "No History", "History is already empty.")
            return

        reply = QMessageBox.warning(
            self,
            "Clear History",
            f"Are you sure you want to clear ALL history?\n\n"
            f"This will delete {len(self._samples)} sample(s) and all analysis data.\n"
            f"This action cannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                for sample in self._samples:
                    self._repo.delete_sample(sample.id)

                self.load_history()  # Reload
                logger.info("Cleared all history")
                QMessageBox.information(self, "Success", "History cleared successfully!")

            except Exception as e:
                logger.error(f"Failed to clear history: {e}")
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to clear history:\n{str(e)}"
                )
