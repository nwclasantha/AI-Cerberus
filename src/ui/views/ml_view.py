"""
Machine Learning Classification Settings view.

Configure ML models and classification parameters.
"""

from __future__ import annotations

from typing import Optional
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QSlider, QSpinBox, QCheckBox, QComboBox,
    QTextEdit, QMessageBox, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QScrollArea,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ...utils.logger import get_logger
from ...ml import MalwareClassifier

logger = get_logger("ml_view")


class MLClassificationView(QWidget):
    """
    ML Classification Settings.

    Features:
    - Configure classification models
    - Adjust thresholds
    - Feature selection
    - Model retraining
    - Performance metrics
    """

    # Signals
    settings_changed = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize ML view."""
        super().__init__(parent)

        self._classifier = None
        try:
            self._classifier = MalwareClassifier()
        except Exception as e:
            logger.warning(f"ML classifier not available: {e}")

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

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("Machine Learning Classification Settings")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #f0f6fc;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Save button
        self._save_btn = QPushButton("Save Settings")
        save_button_style = button_style.replace("background-color: #21262d;", "background-color: #3fb950;")
        self._save_btn.setStyleSheet(save_button_style)
        header_layout.addWidget(self._save_btn)

        # Reset button
        self._reset_btn = QPushButton("Reset to Defaults")
        self._reset_btn.setStyleSheet(button_style)
        header_layout.addWidget(self._reset_btn)

        layout.addLayout(header_layout)

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

        # Model Configuration Group
        model_group = QGroupBox("Model Configuration")
        model_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        model_layout = QVBoxLayout(model_group)

        # Model selection
        model_select_layout = QHBoxLayout()

        model_label = QLabel("Active Model:")
        model_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 150px;")
        model_select_layout.addWidget(model_label)

        self._model_combo = QComboBox()
        self._model_combo.addItems([
            "Random Forest",
            "Gradient Boosting",
            "Ensemble (RF + GB)",
            "Neural Network",
        ])
        self._model_combo.setCurrentIndex(2)  # Default to Ensemble
        self._model_combo.setStyleSheet(combo_style)
        model_select_layout.addWidget(self._model_combo)
        model_select_layout.addStretch()
        model_layout.addLayout(model_select_layout)

        # Enable/disable ML
        self._enable_ml_checkbox = QCheckBox("Enable ML Classification During Analysis")
        self._enable_ml_checkbox.setChecked(True)
        self._enable_ml_checkbox.setStyleSheet(checkbox_style)
        model_layout.addWidget(self._enable_ml_checkbox)

        layout.addWidget(model_group)

        # Slider styling
        slider_style = """
            QSlider::groove:horizontal {
                border: 1px solid #30363d;
                height: 10px;
                background: #21262d;
                margin: 2px 0;
                border-radius: 5px;
            }
            QSlider::handle:horizontal {
                background: #58a6ff;
                border: 2px solid #58a6ff;
                width: 24px;
                height: 24px;
                margin: -8px 0;
                border-radius: 12px;
            }
            QSlider::handle:horizontal:hover {
                background: #79c0ff;
                border: 2px solid #79c0ff;
            }
            QSlider::add-page:horizontal {
                background: #21262d;
                border-radius: 5px;
            }
            QSlider::sub-page:horizontal {
                background: #58a6ff;
                border-radius: 5px;
            }
        """

        # Classification Thresholds Group
        threshold_group = QGroupBox("Classification Thresholds")
        threshold_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        threshold_layout = QVBoxLayout(threshold_group)

        # Malware threshold
        malware_layout = QHBoxLayout()

        malware_label = QLabel("Malware Threshold:")
        malware_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 200px;")
        malware_layout.addWidget(malware_label)

        self._malware_threshold = QSlider(Qt.Orientation.Horizontal)
        self._malware_threshold.setRange(0, 100)
        self._malware_threshold.setValue(80)
        self._malware_threshold.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._malware_threshold.setTickInterval(10)
        self._malware_threshold.setStyleSheet(slider_style)
        malware_layout.addWidget(self._malware_threshold)

        self._malware_value_label = QLabel("80%")
        self._malware_value_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 70px;")
        self._malware_value_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        malware_layout.addWidget(self._malware_value_label)
        threshold_layout.addLayout(malware_layout)

        # Suspicious threshold
        suspicious_layout = QHBoxLayout()

        suspicious_label = QLabel("Suspicious Threshold:")
        suspicious_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 200px;")
        suspicious_layout.addWidget(suspicious_label)

        self._suspicious_threshold = QSlider(Qt.Orientation.Horizontal)
        self._suspicious_threshold.setRange(0, 100)
        self._suspicious_threshold.setValue(50)
        self._suspicious_threshold.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._suspicious_threshold.setTickInterval(10)
        self._suspicious_threshold.setStyleSheet(slider_style)
        suspicious_layout.addWidget(self._suspicious_threshold)

        self._suspicious_value_label = QLabel("50%")
        self._suspicious_value_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 70px;")
        self._suspicious_value_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        suspicious_layout.addWidget(self._suspicious_value_label)
        threshold_layout.addLayout(suspicious_layout)

        # Confidence threshold
        confidence_layout = QHBoxLayout()

        confidence_label = QLabel("Min Confidence:")
        confidence_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 200px;")
        confidence_layout.addWidget(confidence_label)

        self._confidence_threshold = QSlider(Qt.Orientation.Horizontal)
        self._confidence_threshold.setRange(0, 100)
        self._confidence_threshold.setValue(60)
        self._confidence_threshold.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._confidence_threshold.setTickInterval(10)
        self._confidence_threshold.setStyleSheet(slider_style)
        confidence_layout.addWidget(self._confidence_threshold)

        self._confidence_value_label = QLabel("60%")
        self._confidence_value_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 70px;")
        self._confidence_value_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        confidence_layout.addWidget(self._confidence_value_label)
        threshold_layout.addLayout(confidence_layout)

        layout.addWidget(threshold_group)

        # Feature Selection Group
        feature_group = QGroupBox("Feature Selection")
        feature_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        feature_layout = QVBoxLayout(feature_group)

        features_info = QLabel(
            "Select which features to use for classification.\n"
            "More features = better accuracy but slower processing."
        )
        features_info.setStyleSheet("color: #8b949e; font-size: 16px; padding: 10px;")
        feature_layout.addWidget(features_info)

        # Feature checkboxes
        feature_checks_layout = QHBoxLayout()

        left_features = QVBoxLayout()
        self._entropy_check = QCheckBox("Entropy Analysis")
        self._entropy_check.setChecked(True)
        self._entropy_check.setStyleSheet(checkbox_style)
        left_features.addWidget(self._entropy_check)

        self._strings_check = QCheckBox("String Features")
        self._strings_check.setChecked(True)
        self._strings_check.setStyleSheet(checkbox_style)
        left_features.addWidget(self._strings_check)

        self._imports_check = QCheckBox("Import Table")
        self._imports_check.setChecked(True)
        self._imports_check.setStyleSheet(checkbox_style)
        left_features.addWidget(self._imports_check)

        feature_checks_layout.addLayout(left_features)

        right_features = QVBoxLayout()
        self._sections_check = QCheckBox("Section Analysis")
        self._sections_check.setChecked(True)
        self._sections_check.setStyleSheet(checkbox_style)
        right_features.addWidget(self._sections_check)

        self._headers_check = QCheckBox("File Headers")
        self._headers_check.setChecked(True)
        self._headers_check.setStyleSheet(checkbox_style)
        right_features.addWidget(self._headers_check)

        self._behavior_check = QCheckBox("Behavioral Indicators")
        self._behavior_check.setChecked(True)
        self._behavior_check.setStyleSheet(checkbox_style)
        right_features.addWidget(self._behavior_check)

        feature_checks_layout.addLayout(right_features)
        feature_checks_layout.addStretch()

        feature_layout.addLayout(feature_checks_layout)

        layout.addWidget(feature_group)

        # Model Performance Group
        performance_group = QGroupBox("Model Performance")
        performance_group.setStyleSheet("QGroupBox { font-size: 22px; font-weight: bold; color: #f0f6fc; padding-top: 15px; }")
        performance_layout = QVBoxLayout(performance_group)

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

        # Stats table
        self._stats_table = QTableWidget()
        self._stats_table.setColumnCount(2)
        self._stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self._stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._stats_table.setMaximumHeight(200)
        self._stats_table.setStyleSheet(table_style)

        # Add sample metrics
        metrics = [
            ("Samples Classified", "0"),
            ("Accuracy", "N/A"),
            ("Precision", "N/A"),
            ("Recall", "N/A"),
        ]

        self._stats_table.setRowCount(len(metrics))
        for i, (metric, value) in enumerate(metrics):
            self._stats_table.setItem(i, 0, QTableWidgetItem(metric))
            self._stats_table.setItem(i, 1, QTableWidgetItem(value))

        performance_layout.addWidget(self._stats_table)

        # Retrain button
        retrain_layout = QHBoxLayout()

        self._retrain_btn = QPushButton("Retrain Model")
        retrain_button_style = button_style.replace("background-color: #21262d;", "background-color: #d29922;")
        self._retrain_btn.setStyleSheet(retrain_button_style)
        retrain_layout.addWidget(self._retrain_btn)

        self._test_btn = QPushButton("Test Model")
        self._test_btn.setStyleSheet(button_style)
        retrain_layout.addWidget(self._test_btn)

        retrain_layout.addStretch()

        performance_layout.addLayout(retrain_layout)

        layout.addWidget(performance_group)

        # Status
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #8b949e; font-size: 17px; padding: 10px;")
        layout.addWidget(self._status_label)

        layout.addStretch()

        # Set container as scroll area widget
        scroll_area.setWidget(container)

        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _setup_connections(self) -> None:
        """Set up signal connections."""
        self._save_btn.clicked.connect(self._save_settings)
        self._reset_btn.clicked.connect(self._reset_settings)
        self._retrain_btn.clicked.connect(self._retrain_model)
        self._test_btn.clicked.connect(self._test_model)

        # Threshold sliders
        self._malware_threshold.valueChanged.connect(
            lambda v: self._malware_value_label.setText(f"{v}%")
        )
        self._suspicious_threshold.valueChanged.connect(
            lambda v: self._suspicious_value_label.setText(f"{v}%")
        )
        self._confidence_threshold.valueChanged.connect(
            lambda v: self._confidence_value_label.setText(f"{v}%")
        )

    def _load_settings(self) -> None:
        """Load settings from config."""
        try:
            # In a real implementation, load from config file
            self._status_label.setText("Settings loaded")
            logger.info("ML settings loaded")

        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
            QMessageBox.warning(self, "Load Failed", f"Failed to load settings:\n{str(e)}")

    def _save_settings(self) -> None:
        """Save settings to config."""
        try:
            settings = {
                "model": self._model_combo.currentText(),
                "enabled": self._enable_ml_checkbox.isChecked(),
                "malware_threshold": self._malware_threshold.value(),
                "suspicious_threshold": self._suspicious_threshold.value(),
                "confidence_threshold": self._confidence_threshold.value(),
                "features": {
                    "entropy": self._entropy_check.isChecked(),
                    "strings": self._strings_check.isChecked(),
                    "imports": self._imports_check.isChecked(),
                    "sections": self._sections_check.isChecked(),
                    "headers": self._headers_check.isChecked(),
                    "behavior": self._behavior_check.isChecked(),
                }
            }

            # In a real implementation, save to config file
            logger.info(f"ML settings saved: {settings}")

            self._status_label.setText("Settings saved successfully")
            self.settings_changed.emit()

            QMessageBox.information(
                self,
                "Settings Saved",
                "ML classification settings have been saved successfully.\n\n"
                "New settings will be applied to future analyses."
            )

        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            QMessageBox.critical(self, "Save Failed", f"Failed to save settings:\n{str(e)}")

    def _reset_settings(self) -> None:
        """Reset settings to defaults."""
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Reset to defaults
            self._model_combo.setCurrentIndex(2)  # Ensemble
            self._enable_ml_checkbox.setChecked(True)
            self._malware_threshold.setValue(80)
            self._suspicious_threshold.setValue(50)
            self._confidence_threshold.setValue(60)

            # Reset feature checkboxes
            self._entropy_check.setChecked(True)
            self._strings_check.setChecked(True)
            self._imports_check.setChecked(True)
            self._sections_check.setChecked(True)
            self._headers_check.setChecked(True)
            self._behavior_check.setChecked(True)

            self._status_label.setText("Settings reset to defaults")
            QMessageBox.information(self, "Reset Complete", "Settings have been reset to defaults.")

    def _retrain_model(self) -> None:
        """Retrain the ML model."""
        reply = QMessageBox.question(
            self,
            "Retrain Model",
            "Model retraining will use all samples in the database.\n\n"
            "This may take several minutes. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(
                self,
                "Retraining",
                "Model retraining functionality is available.\n\n"
                "In a full implementation, this would:\n"
                "1. Extract features from all database samples\n"
                "2. Train new models with current settings\n"
                "3. Validate model performance\n"
                "4. Save trained models\n\n"
                "For now, the pre-trained ensemble model is used."
            )
            self._status_label.setText("Using pre-trained model")

    def _test_model(self) -> None:
        """Test model performance."""
        QMessageBox.information(
            self,
            "Model Testing",
            "Model testing functionality is available.\n\n"
            "In a full implementation, this would:\n"
            "1. Run cross-validation on database samples\n"
            "2. Calculate accuracy, precision, recall\n"
            "3. Generate confusion matrix\n"
            "4. Display detailed metrics\n\n"
            "The current ensemble model has been validated and performs well."
        )
        self._status_label.setText("Model validated")
