"""
Analysis view - displays comprehensive analysis results.

Shows all analysis data for a file including:
- File information
- Threat score
- YARA matches
- Behavioral indicators
- ML classification
"""

from typing import Any, Dict, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QTextEdit, QScrollArea, QGridLayout, QSizePolicy, QSplitter,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from ..theme import get_theme_manager
from ..components.charts import ThreatGauge, EntropyChart


class InfoRow(QWidget):
    """Information row with label and value."""

    def __init__(
        self,
        label: str,
        value: str = "",
        selectable: bool = False,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)

        self._label = QLabel(f"{label}:")
        self._label.setMinimumWidth(120)
        self._label.setStyleSheet("color: #8b949e; font-weight: 500;")
        layout.addWidget(self._label)

        self._value = QLabel(value)
        self._value.setStyleSheet("color: #f0f6fc;")
        if selectable:
            self._value.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
        layout.addWidget(self._value, 1)

    def set_value(self, value: str) -> None:
        """Update value."""
        self._value.setText(value)


class SectionHeader(QLabel):
    """Section header label."""

    def __init__(self, text: str, parent: Optional[QWidget] = None):
        super().__init__(text, parent)

        theme = get_theme_manager()
        p = theme.get_palette()

        self.setStyleSheet(f"""
            font-size: 16px;
            font-weight: 600;
            color: {p.text_primary};
            padding: 8px 0;
            border-bottom: 1px solid {p.border_primary};
            margin-bottom: 8px;
        """)


class AnalysisView(QWidget):
    """
    Comprehensive analysis results view.

    Displays all analysis data in organized tabs:
    - Overview: File info, threat score, summary
    - PE/ELF Info: Binary structure details
    - Imports/Exports: API analysis
    - YARA: Rule matches
    - Behavior: Behavioral indicators
    - ML: Machine learning classification
    """

    # Signals
    export_requested = pyqtSignal()
    reanalyze_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize analysis view."""
        super().__init__(parent)

        self._current_data: Optional[Dict] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up analysis view UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - summary
        left_panel = self._create_summary_panel()
        splitter.addWidget(left_panel)

        # Right panel - detailed tabs
        right_panel = self._create_details_panel()
        splitter.addWidget(right_panel)

        # Set initial sizes (30% left, 70% right)
        splitter.setSizes([300, 700])

        layout.addWidget(splitter)

    def _create_summary_panel(self) -> QWidget:
        """Create summary panel."""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        theme = get_theme_manager()
        p = theme.get_palette()

        panel.setStyleSheet(f"""
            QFrame {{
                background-color: {p.bg_secondary};
                border-right: 1px solid {p.border_primary};
            }}
        """)

        # Threat gauge
        self._threat_gauge = ThreatGauge()
        self._threat_gauge.set_label("Threat Score")
        layout.addWidget(self._threat_gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        # Classification label
        self._classification_label = QLabel("Unknown")
        self._classification_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._classification_label.setStyleSheet("""
            font-size: 22px;
            font-weight: 600;
            padding: 8px;
        """)
        layout.addWidget(self._classification_label)

        # File info section
        info_section = QFrame()
        info_layout = QVBoxLayout(info_section)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(4)

        info_layout.addWidget(SectionHeader("File Information"))

        self._filename_row = InfoRow("Filename", "", True)
        info_layout.addWidget(self._filename_row)

        self._size_row = InfoRow("Size", "")
        info_layout.addWidget(self._size_row)

        self._type_row = InfoRow("Type", "")
        info_layout.addWidget(self._type_row)

        self._arch_row = InfoRow("Architecture", "")
        info_layout.addWidget(self._arch_row)

        layout.addWidget(info_section)

        # Hashes section
        hash_section = QFrame()
        hash_layout = QVBoxLayout(hash_section)
        hash_layout.setContentsMargins(0, 0, 0, 0)
        hash_layout.setSpacing(4)

        hash_layout.addWidget(SectionHeader("Hashes"))

        self._md5_row = InfoRow("MD5", "", True)
        hash_layout.addWidget(self._md5_row)

        self._sha1_row = InfoRow("SHA1", "", True)
        hash_layout.addWidget(self._sha1_row)

        self._sha256_row = InfoRow("SHA256", "", True)
        hash_layout.addWidget(self._sha256_row)

        layout.addWidget(hash_section)

        layout.addStretch()

        return panel

    def _create_details_panel(self) -> QWidget:
        """Create detailed analysis tabs."""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget
        self._tabs = QTabWidget()

        # Overview tab
        overview_tab = self._create_overview_tab()
        self._tabs.addTab(overview_tab, "Overview")

        # Entropy tab
        entropy_tab = self._create_entropy_tab()
        self._tabs.addTab(entropy_tab, "Entropy")

        # Imports tab
        imports_tab = self._create_imports_tab()
        self._tabs.addTab(imports_tab, "Imports")

        # YARA tab
        yara_tab = self._create_yara_tab()
        self._tabs.addTab(yara_tab, "YARA")

        # Behavior tab
        behavior_tab = self._create_behavior_tab()
        self._tabs.addTab(behavior_tab, "Behavior")

        # ML tab
        ml_tab = self._create_ml_tab()
        self._tabs.addTab(ml_tab, "ML Analysis")

        layout.addWidget(self._tabs)

        return panel

    def _create_overview_tab(self) -> QWidget:
        """Create overview tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)

        # Sections table
        self._sections_table = QTableWidget()
        self._sections_table.setColumnCount(5)
        self._sections_table.setHorizontalHeaderLabels([
            "Name", "Virtual Address", "Virtual Size", "Raw Size", "Entropy"
        ])

        header = self._sections_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._sections_table.verticalHeader().setVisible(False)

        layout.addWidget(QLabel("Sections"))
        layout.addWidget(self._sections_table)

        return tab

    def _create_entropy_tab(self) -> QWidget:
        """Create entropy visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)

        # Entropy chart
        self._entropy_chart = EntropyChart()
        layout.addWidget(self._entropy_chart)

        # Entropy statistics
        stats_frame = QFrame()
        stats_layout = QGridLayout(stats_frame)

        self._overall_entropy = InfoRow("Overall Entropy")
        stats_layout.addWidget(self._overall_entropy, 0, 0)

        self._entropy_assessment = InfoRow("Assessment")
        stats_layout.addWidget(self._entropy_assessment, 0, 1)

        layout.addWidget(stats_frame)

        layout.addStretch()

        return tab

    def _create_imports_tab(self) -> QWidget:
        """Create imports tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)

        # Imports table
        self._imports_table = QTableWidget()
        self._imports_table.setColumnCount(3)
        self._imports_table.setHorizontalHeaderLabels([
            "DLL", "Function", "Category"
        ])

        header = self._imports_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._imports_table.setColumnWidth(0, 150)
        self._imports_table.setColumnWidth(2, 120)
        self._imports_table.verticalHeader().setVisible(False)

        layout.addWidget(self._imports_table)

        return tab

    def _create_yara_tab(self) -> QWidget:
        """Create YARA matches tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)

        # YARA matches table
        self._yara_table = QTableWidget()
        self._yara_table.setColumnCount(4)
        self._yara_table.setHorizontalHeaderLabels([
            "Rule", "Severity", "Description", "Matched Strings"
        ])

        header = self._yara_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self._yara_table.setColumnWidth(0, 180)
        self._yara_table.setColumnWidth(1, 80)
        self._yara_table.setColumnWidth(3, 120)
        self._yara_table.verticalHeader().setVisible(False)

        layout.addWidget(self._yara_table)

        return tab

    def _create_behavior_tab(self) -> QWidget:
        """Create behavioral indicators tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)

        # Capabilities grid
        layout.addWidget(SectionHeader("Detected Capabilities"))

        self._capabilities_grid = QGridLayout()
        self._capability_labels = {}

        capabilities = [
            ("Injection", "injection"),
            ("Persistence", "persistence"),
            ("Network", "network"),
            ("Anti-Debug", "anti_debug"),
            ("Anti-VM", "anti_vm"),
            ("Crypto", "crypto"),
            ("Keylogging", "keylogging"),
            ("Screen Capture", "screen_capture"),
            ("Privilege Escalation", "privilege_escalation"),
        ]

        for i, (name, key) in enumerate(capabilities):
            label = QLabel(f"  {name}")
            label.setStyleSheet("padding: 8px;")
            self._capability_labels[key] = label
            self._capabilities_grid.addWidget(label, i // 3, i % 3)

        cap_widget = QWidget()
        cap_widget.setLayout(self._capabilities_grid)
        layout.addWidget(cap_widget)

        # Techniques
        layout.addWidget(SectionHeader("Detected Techniques"))

        self._techniques_text = QTextEdit()
        self._techniques_text.setReadOnly(True)
        self._techniques_text.setMaximumHeight(200)
        layout.addWidget(self._techniques_text)

        layout.addStretch()

        return tab

    def _create_ml_tab(self) -> QWidget:
        """Create ML analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)

        # Classification result
        result_frame = QFrame()
        result_layout = QVBoxLayout(result_frame)

        self._ml_prediction = QLabel("Prediction: Unknown")
        self._ml_prediction.setStyleSheet("font-size: 22px; font-weight: 600;")
        result_layout.addWidget(self._ml_prediction)

        self._ml_confidence = QLabel("Confidence: 0%")
        result_layout.addWidget(self._ml_confidence)

        layout.addWidget(result_frame)

        # Feature importance
        layout.addWidget(SectionHeader("Top Contributing Features"))

        self._features_table = QTableWidget()
        self._features_table.setColumnCount(2)
        self._features_table.setHorizontalHeaderLabels(["Feature", "Importance"])

        header = self._features_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._features_table.setColumnWidth(1, 100)
        self._features_table.verticalHeader().setVisible(False)

        layout.addWidget(self._features_table)

        return tab

    def set_analysis_data(self, data: Dict[str, Any]) -> None:
        """
        Set analysis data to display.

        Args:
            data: Complete analysis result dictionary
        """
        self._current_data = data

        # Update summary panel
        self._update_summary(data)

        # Update tabs
        self._update_overview(data)
        self._update_entropy(data)
        self._update_imports(data)
        self._update_yara(data)
        self._update_behavior(data)
        self._update_ml(data)

    def _update_summary(self, data: Dict) -> None:
        """Update summary panel."""
        theme = get_theme_manager()
        p = theme.get_palette()

        # Threat score - FIXED: Ensure we get the actual score value
        threat_score = data.get("threat_score", {})
        if isinstance(threat_score, dict):
            score = float(threat_score.get("score", 0))
        else:
            score = 0.0

        # CRITICAL FIX: Set gauge value WITHOUT animation and force immediate update
        self._threat_gauge.set_value(score, animate=False)
        # Force the gauge to repaint immediately
        self._threat_gauge.repaint()

        # Classification
        classification = data.get("classification", "unknown")
        self._classification_label.setText(classification.upper())

        color_map = {
            "malicious": p.accent_danger,
            "suspicious": p.accent_warning,
            "benign": p.accent_success,
        }
        color = color_map.get(classification.lower(), p.text_muted)
        self._classification_label.setStyleSheet(f"""
            font-size: 22px;
            font-weight: 600;
            padding: 8px;
            color: {color};
        """)

        # File info
        file_info = data.get("file_info", {})
        self._filename_row.set_value(file_info.get("filename", "Unknown"))
        self._size_row.set_value(file_info.get("size_human", "Unknown"))
        self._type_row.set_value(file_info.get("file_type", "Unknown"))
        self._arch_row.set_value(data.get("architecture", "Unknown"))

        # Hashes
        hashes = data.get("hashes", {})
        self._md5_row.set_value(hashes.get("md5", ""))
        self._sha1_row.set_value(hashes.get("sha1", ""))
        self._sha256_row.set_value(hashes.get("sha256", ""))

    def _update_overview(self, data: Dict) -> None:
        """Update overview tab."""
        sections = data.get("sections", [])
        self._sections_table.setRowCount(len(sections))

        for row, section in enumerate(sections):
            self._sections_table.setItem(row, 0, QTableWidgetItem(section.get("name", "")))
            self._sections_table.setItem(row, 1, QTableWidgetItem(section.get("virtual_address", "")))
            self._sections_table.setItem(row, 2, QTableWidgetItem(str(section.get("virtual_size", 0))))
            self._sections_table.setItem(row, 3, QTableWidgetItem(str(section.get("raw_size", 0))))
            self._sections_table.setItem(row, 4, QTableWidgetItem(f"{section.get('entropy', 0):.2f}"))

    def _update_entropy(self, data: Dict) -> None:
        """Update entropy tab."""
        entropy = data.get("entropy", {})

        if isinstance(entropy, dict):
            overall = entropy.get("overall", 0)
            block_values = entropy.get("block_entropies", [])
            assessment = entropy.get("assessment", "unknown")

            self._overall_entropy.set_value(f"{overall:.4f}")
            self._entropy_assessment.set_value(assessment.capitalize())
            self._entropy_chart.set_data(block_values, overall)

    def _update_imports(self, data: Dict) -> None:
        """Update imports tab."""
        imports = data.get("imports", [])
        self._imports_table.setRowCount(len(imports))

        for row, imp in enumerate(imports):
            if isinstance(imp, dict):
                self._imports_table.setItem(row, 0, QTableWidgetItem(imp.get("dll", "")))
                self._imports_table.setItem(row, 1, QTableWidgetItem(imp.get("function", "")))
                self._imports_table.setItem(row, 2, QTableWidgetItem(imp.get("category", "")))
            else:
                self._imports_table.setItem(row, 1, QTableWidgetItem(str(imp)))

    def _update_yara(self, data: Dict) -> None:
        """Update YARA tab."""
        theme = get_theme_manager()
        p = theme.get_palette()

        matches = data.get("yara_matches", [])
        self._yara_table.setRowCount(len(matches))

        for row, match in enumerate(matches):
            self._yara_table.setItem(row, 0, QTableWidgetItem(match.get("rule", "")))

            severity = match.get("severity", "medium")
            severity_item = QTableWidgetItem(severity.capitalize())
            color_map = {
                "critical": QColor(p.severity_critical),
                "high": QColor(p.severity_high),
                "medium": QColor(p.severity_medium),
                "low": QColor(p.severity_low),
            }
            severity_item.setForeground(color_map.get(severity.lower(), QColor(p.text_muted)))
            self._yara_table.setItem(row, 1, severity_item)

            self._yara_table.setItem(row, 2, QTableWidgetItem(match.get("description", "")))
            self._yara_table.setItem(row, 3, QTableWidgetItem(str(len(match.get("strings", [])))))

    def _update_behavior(self, data: Dict) -> None:
        """Update behavior tab."""
        theme = get_theme_manager()
        p = theme.get_palette()

        behavior = data.get("behavior", {})
        capabilities = behavior.get("capabilities", {})

        for key, label in self._capability_labels.items():
            is_present = capabilities.get(key, False)
            if is_present:
                label.setStyleSheet(f"padding: 8px; color: {p.accent_danger}; font-weight: 600;")
                label.setText(f"+ {label.text().strip()}")
            else:
                label.setStyleSheet(f"padding: 8px; color: {p.text_muted};")
                label.setText(f"  {key.replace('_', ' ').title()}")

        # Techniques
        details = behavior.get("details", {})
        techniques = []
        techniques.extend(details.get("injection_techniques", []))
        techniques.extend(details.get("persistence_mechanisms", []))
        techniques.extend(details.get("evasion_techniques", []))

        self._techniques_text.setText("\n".join(f" {t}" for t in techniques) or "No techniques detected")

    def _update_ml(self, data: Dict) -> None:
        """Update ML tab."""
        theme = get_theme_manager()
        p = theme.get_palette()

        ml = data.get("ml_classification", {})

        prediction = ml.get("prediction", "unknown")
        confidence = ml.get("confidence", 0)

        color_map = {
            "malicious": p.accent_danger,
            "suspicious": p.accent_warning,
            "benign": p.accent_success,
        }
        color = color_map.get(prediction.lower(), p.text_muted)

        self._ml_prediction.setText(f"Prediction: {prediction.upper()}")
        self._ml_prediction.setStyleSheet(f"font-size: 22px; font-weight: 600; color: {color};")
        self._ml_confidence.setText(f"Confidence: {confidence * 100:.1f}%")

        # Feature importance
        importance = ml.get("feature_importance", {})
        sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]

        self._features_table.setRowCount(len(sorted_features))
        for row, (feature, imp) in enumerate(sorted_features):
            self._features_table.setItem(row, 0, QTableWidgetItem(feature))
            self._features_table.setItem(row, 1, QTableWidgetItem(f"{imp:.4f}"))

    def clear(self) -> None:
        """Clear all analysis data."""
        self._current_data = None
        self._threat_gauge.set_value(0, animate=False)
        self._classification_label.setText("Unknown")
        self._sections_table.setRowCount(0)
        self._imports_table.setRowCount(0)
        self._yara_table.setRowCount(0)
        self._features_table.setRowCount(0)
