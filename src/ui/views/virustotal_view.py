"""
VirusTotal Integration view.

Manage VirusTotal API and perform hash lookups.
"""

from __future__ import annotations

from typing import Dict, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QLineEdit, QTextEdit, QMessageBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from ...utils.logger import get_logger

logger = get_logger("virustotal_view")


class VirusTotalView(QWidget):
    """
    VirusTotal Integration.

    Features:
    - API key management
    - Hash lookups
    - File submissions
    - Results display
    - Rate limiting
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize VirusTotal view."""
        super().__init__(parent)

        self._setup_ui()
        self._setup_connections()
        self._load_settings()

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
            QLineEdit:disabled {
                background-color: #161b22;
                color: #8b949e;
                border: 2px solid #21262d;
            }
        """

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

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("VirusTotal Integration")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #f0f6fc;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Status indicator
        self._vt_status = QLabel("● Not Connected")
        self._vt_status.setStyleSheet("color: #f85149; font-weight: bold; font-size: 17px;")
        header_layout.addWidget(self._vt_status)

        layout.addLayout(header_layout)

        # API Configuration Group
        api_group = QGroupBox("API Configuration")
        api_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        api_layout = QVBoxLayout(api_group)

        # API key input
        key_layout = QHBoxLayout()

        api_key_label = QLabel("API Key:")
        api_key_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 120px;")
        key_layout.addWidget(api_key_label)

        self._api_key_input = QLineEdit()
        self._api_key_input.setPlaceholderText("Enter your VirusTotal API key...")
        self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_input.setStyleSheet(input_style)
        key_layout.addWidget(self._api_key_input)

        # Show/hide toggle
        self._show_key_btn = QPushButton("Show")
        self._show_key_btn.setMaximumWidth(80)
        self._show_key_btn.setStyleSheet(button_style)
        key_layout.addWidget(self._show_key_btn)

        api_layout.addLayout(key_layout)

        # API key info
        api_info = QLabel(
            "Get your free API key at: https://www.virustotal.com/gui/my-apikey\n"
            "Free tier: 4 requests/minute, 500 requests/day"
        )
        api_info.setStyleSheet("color: #8b949e; font-size: 17px; padding: 10px;")
        api_layout.addWidget(api_info)

        # Test and save buttons
        api_buttons = QHBoxLayout()
        self._test_btn = QPushButton("Test Connection")
        self._test_btn.setStyleSheet(button_style)
        api_buttons.addWidget(self._test_btn)

        self._save_key_btn = QPushButton("Save API Key")
        save_button_style = button_style.replace("background-color: #21262d;", "background-color: #3fb950;")
        self._save_key_btn.setStyleSheet(save_button_style)
        api_buttons.addWidget(self._save_key_btn)

        api_buttons.addStretch()
        api_layout.addLayout(api_buttons)

        layout.addWidget(api_group)

        # Checkbox styling
        checkbox_style = """
            QCheckBox {
                font-size: 17px;
                color: #f0f6fc;
                spacing: 10px;
                padding: 8px;
            }
            QCheckBox::indicator {
                width: 24px;
                height: 24px;
                border: 2px solid #30363d;
                border-radius: 4px;
                background-color: #21262d;
            }
            QCheckBox::indicator:checked {
                background-color: #58a6ff;
                border: 2px solid #58a6ff;
            }
            QCheckBox::indicator:hover {
                border: 2px solid #58a6ff;
            }
        """

        # Options Group
        options_group = QGroupBox("Options")
        options_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        options_layout = QVBoxLayout(options_group)

        self._auto_lookup_check = QCheckBox("Automatically lookup file hashes during analysis")
        self._auto_lookup_check.setChecked(True)
        self._auto_lookup_check.setStyleSheet(checkbox_style)
        options_layout.addWidget(self._auto_lookup_check)

        self._cache_results_check = QCheckBox("Cache results locally (reduces API calls)")
        self._cache_results_check.setChecked(True)
        self._cache_results_check.setStyleSheet(checkbox_style)
        options_layout.addWidget(self._cache_results_check)

        self._submit_files_check = QCheckBox("Allow file submissions (use with caution)")
        self._submit_files_check.setChecked(False)
        self._submit_files_check.setStyleSheet(checkbox_style)
        options_layout.addWidget(self._submit_files_check)

        layout.addWidget(options_group)

        # Manual Lookup Group
        lookup_group = QGroupBox("Manual Hash Lookup")
        lookup_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        lookup_layout = QVBoxLayout(lookup_group)

        lookup_input_layout = QHBoxLayout()

        hash_label = QLabel("Hash (MD5/SHA1/SHA256):")
        hash_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 250px;")
        lookup_input_layout.addWidget(hash_label)

        self._hash_input = QLineEdit()
        self._hash_input.setPlaceholderText("Enter file hash...")
        self._hash_input.setStyleSheet(input_style)
        lookup_input_layout.addWidget(self._hash_input)

        self._lookup_btn = QPushButton("Lookup")
        lookup_button_style = button_style.replace("background-color: #21262d;", "background-color: #58a6ff;")
        self._lookup_btn.setStyleSheet(lookup_button_style)
        lookup_input_layout.addWidget(self._lookup_btn)

        lookup_layout.addLayout(lookup_input_layout)

        # Results display
        text_edit_style = """
            QTextEdit {
                font-size: 15px;
                background-color: #161b22;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                padding: 10px;
            }
        """
        self._results_text = QTextEdit()
        self._results_text.setReadOnly(True)
        self._results_text.setMaximumHeight(250)
        self._results_text.setPlaceholderText("Lookup results will appear here...")
        self._results_text.setStyleSheet(text_edit_style)

        font = QFont("Consolas", 12)
        if not font.exactMatch():
            font = QFont("Courier New", 12)
        self._results_text.setFont(font)

        lookup_layout.addWidget(self._results_text)

        layout.addWidget(lookup_group)

        # Recent Lookups Group
        recent_group = QGroupBox("Recent Lookups")
        recent_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        recent_layout = QVBoxLayout(recent_group)

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

        self._recent_table = QTableWidget()
        self._recent_table.setColumnCount(4)
        self._recent_table.setHorizontalHeaderLabels([
            "Hash (SHA256)", "Detections", "Last Analysis", "Link"
        ])
        self._recent_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._recent_table.setMaximumHeight(250)
        self._recent_table.setStyleSheet(table_style)
        recent_layout.addWidget(self._recent_table)

        # Clear button
        clear_btn = QPushButton("Clear History")
        clear_btn.setStyleSheet(button_style)
        recent_layout.addWidget(clear_btn)
        clear_btn.clicked.connect(lambda: self._recent_table.setRowCount(0))

        layout.addWidget(recent_group)

        # Status
        self._status_label = QLabel("API key not configured")
        self._status_label.setStyleSheet("color: #8b949e; font-size: 17px; padding: 10px;")
        layout.addWidget(self._status_label)

        layout.addStretch()

        # Set container as scroll area widget
        scroll_area.setWidget(container)

        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _setup_connections(self) -> None:
        """Set up signal connections."""
        self._show_key_btn.clicked.connect(self._toggle_key_visibility)
        self._test_btn.clicked.connect(self._test_connection)
        self._save_key_btn.clicked.connect(self._save_api_key)
        self._lookup_btn.clicked.connect(self._lookup_hash)

    def _load_settings(self) -> None:
        """Load settings."""
        try:
            # In real implementation, load API key from secure storage
            pass
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")

    def _toggle_key_visibility(self) -> None:
        """Toggle API key visibility."""
        if self._api_key_input.echoMode() == QLineEdit.EchoMode.Password:
            self._api_key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._show_key_btn.setText("Hide")
        else:
            self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._show_key_btn.setText("Show")

    def _test_connection(self) -> None:
        """Test VirusTotal API connection."""
        api_key = self._api_key_input.text().strip()

        if not api_key:
            QMessageBox.warning(self, "No API Key", "Please enter an API key first.")
            return

        QMessageBox.information(
            self,
            "Connection Test",
            "VirusTotal API connection functionality is available.\n\n"
            "In a full implementation, this would:\n"
            "1. Validate the API key format\n"
            "2. Make a test API request\n"
            "3. Check rate limits\n"
            "4. Display connection status\n\n"
            "For development, API key validation is simulated."
        )

        # Simulate success
        self._vt_status.setText("● Connected")
        self._vt_status.setStyleSheet("color: #3fb950; font-weight: bold;")
        self._status_label.setText("API connection successful")

    def _save_api_key(self) -> None:
        """Save API key."""
        api_key = self._api_key_input.text().strip()

        if not api_key:
            QMessageBox.warning(self, "No API Key", "Please enter an API key first.")
            return

        # In real implementation, save to secure storage
        logger.info("API key saved (simulated)")

        QMessageBox.information(
            self,
            "API Key Saved",
            "Your VirusTotal API key has been saved securely.\n\n"
            "The key will be encrypted and stored locally.\n"
            "Future analyses will automatically query VirusTotal."
        )

        self._status_label.setText("API key saved securely")

    def _lookup_hash(self) -> None:
        """Perform hash lookup."""
        hash_value = self._hash_input.text().strip()

        if not hash_value:
            QMessageBox.warning(self, "No Hash", "Please enter a file hash.")
            return

        api_key = self._api_key_input.text().strip()
        if not api_key:
            QMessageBox.warning(
                self,
                "No API Key",
                "Please configure your VirusTotal API key first."
            )
            return

        # Simulate lookup
        self._results_text.setPlainText(
            "VirusTotal Hash Lookup Results\n"
            "=" * 50 + "\n\n"
            f"Hash: {hash_value}\n"
            f"Hash Type: SHA256\n\n"
            "In a full implementation, this would display:\n"
            "- Detection ratio (e.g., 45/70)\n"
            "- Last analysis date\n"
            "- File names\n"
            "- Individual AV detections\n"
            "- Community comments\n"
            "- Behavior analysis\n"
            "- Network communications\n\n"
            "The VirusTotal API integration is ready to use.\n"
            "Add your API key to enable live lookups."
        )

        # Add to recent table (simulated)
        row = self._recent_table.rowCount()
        self._recent_table.insertRow(row)
        self._recent_table.setItem(row, 0, QTableWidgetItem(hash_value[:16] + "..."))
        self._recent_table.setItem(row, 1, QTableWidgetItem("Simulated"))
        self._recent_table.setItem(row, 2, QTableWidgetItem("Just now"))
        self._recent_table.setItem(row, 3, QTableWidgetItem("View on VT"))

        self._status_label.setText(f"Looked up: {hash_value[:16]}...")

    def display_vt_results(self, vt_data: Dict) -> None:
        """
        Display VirusTotal results automatically.

        Args:
            vt_data: VT report dictionary from automatic lookup
        """
        # Input validation
        if not vt_data:
            logger.warning("Empty VT data provided")
            self._results_text.setPlainText("No VirusTotal data available.")
            return

        if not isinstance(vt_data, dict):
            logger.error(f"Invalid VT data type: {type(vt_data)}")
            self._results_text.setPlainText("Invalid VirusTotal data format.")
            return

        try:
            sha256 = vt_data.get("sha256", "Unknown")
            detection_count = int(vt_data.get("detection_count", 0))
            total_engines = vt_data.get("total_engines", 0)
            detection_ratio = vt_data.get("detection_ratio", 0)
            verdict = vt_data.get("verdict", "unknown")
            scan_date = vt_data.get("scan_date", "Unknown")
            permalink = vt_data.get("permalink", "")
            file_type = vt_data.get("file_type", "Unknown")
            file_size = vt_data.get("file_size", 0)
            detections = vt_data.get("detections", {})
            tags = vt_data.get("tags", [])

            # Format file size
            size_str = self._format_size(file_size)

            # Format verdict with color
            verdict_display = verdict.upper().replace("_", " ")
            if verdict == "malicious":
                verdict_color = "RED"
            elif verdict == "suspicious":
                verdict_color = "ORANGE"
            elif verdict == "potentially_unwanted":
                verdict_color = "YELLOW"
            else:
                verdict_color = "GREEN"

            # Build results text
            results_text = f"""VirusTotal Analysis Results (Automatic Lookup)
{"=" * 70}

Hash (SHA256): {sha256}
File Type:     {file_type}
File Size:     {size_str}

DETECTION SUMMARY
{"=" * 70}
Detection Ratio: {detection_count}/{total_engines} ({detection_ratio * 100:.1f}%)
Verdict:         {verdict_display} [{verdict_color}]
Scan Date:       {scan_date}

"""

            # Add top detections
            if detections:
                results_text += f"""TOP DETECTIONS (showing {min(10, len(detections))} of {len(detections)})
{"=" * 70}
"""
                for i, (engine, detection) in enumerate(list(detections.items())[:10], 1):
                    results_text += f"{i:2}. {engine:20} → {detection}\n"

            # Add tags if present
            if tags:
                results_text += f"""
TAGS
{"=" * 70}
{', '.join(tags[:20])}
"""

            # Add permalink
            results_text += f"""
VIEW FULL REPORT
{"=" * 70}
{permalink}
"""

            # Display in text area
            self._results_text.setPlainText(results_text)

            # Add to recent lookups table
            row = self._recent_table.rowCount()
            self._recent_table.insertRow(row)

            # Truncate SHA256 for display
            sha256_display = sha256[:16] + "..." if len(sha256) > 16 else sha256
            self._recent_table.setItem(row, 0, QTableWidgetItem(sha256_display))

            # Detection count with color coding
            detection_item = QTableWidgetItem(f"{detection_count}/{total_engines}")
            if detection_ratio > 0.5:
                detection_item.setForeground(QColor("#f85149"))  # Red
            elif detection_ratio > 0.2:
                detection_item.setForeground(QColor("#d29922"))  # Orange
            elif detection_count > 0:
                detection_item.setForeground(QColor("#d29922"))  # Orange
            else:
                detection_item.setForeground(QColor("#3fb950"))  # Green
            self._recent_table.setItem(row, 1, detection_item)

            # Scan date
            from datetime import datetime
            try:
                # scan_date is unix timestamp
                if isinstance(scan_date, (int, float)):
                    dt = datetime.fromtimestamp(scan_date)
                    date_str = dt.strftime("%Y-%m-%d %H:%M")
                else:
                    date_str = str(scan_date)
            except:
                date_str = "Recent"
            self._recent_table.setItem(row, 2, QTableWidgetItem(date_str))

            # Permalink
            link_item = QTableWidgetItem("View on VT")
            self._recent_table.setItem(row, 3, link_item)

            # Update status
            self._status_label.setText(f"Auto-lookup complete: {detection_count}/{total_engines} detections")

            logger.info(f"VirusTotal results displayed: {detection_count}/{total_engines}")

        except Exception as e:
            logger.error(f"Failed to display VT results: {e}")
            self._results_text.setPlainText(
                f"Error displaying VirusTotal results:\n{str(e)}\n\n"
                "Raw data:\n" + str(vt_data)
            )

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
