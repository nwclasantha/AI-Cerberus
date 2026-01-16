"""
Sandbox Integration view.

Configure and manage sandbox analysis (VMware Custom Sandbox).
"""

from typing import Optional
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QLineEdit, QComboBox, QCheckBox, QSpinBox,
    QTextEdit, QMessageBox, QListWidget, QListWidgetItem, QFileDialog,
    QScrollArea,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

from ...utils.logger import get_logger
from ...utils.config import get_config
from ...integrations import CustomVMSandboxClient

logger = get_logger("sandbox_view")


class SandboxView(QWidget):
    """
    Sandbox Integration.

    Features:
    - Configure VMware custom sandbox
    - Submit files for analysis via SSH
    - Retrieve results
    - Display sandbox reports
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize sandbox view."""
        super().__init__(parent)

        self._config = get_config()
        self._client = CustomVMSandboxClient()
        self._pending_submissions = {}  # job_id -> filename

        self._setup_ui()
        self._setup_connections()
        self._load_settings()
        self._update_connection_status()

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
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(25)

        # Set larger base font
        base_font = QFont("Segoe UI", 15)
        self.setFont(base_font)

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("VMware Sandbox Integration")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #f0f6fc;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Status indicator
        self._sandbox_status = QLabel("● Not Configured")
        self._sandbox_status.setStyleSheet("color: #f85149; font-weight: bold; font-size: 20px;")
        header_layout.addWidget(self._sandbox_status)

        layout.addLayout(header_layout)

        # VM Configuration Group
        config_group = QGroupBox("VM Sandbox Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-size: 18px;
                font-weight: bold;
                color: #f0f6fc;
                border: 2px solid #30363d;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        config_layout = QVBoxLayout(config_group)
        config_layout.setSpacing(15)

        # Style for input fields
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

        spinbox_style = """
            QSpinBox {
                font-size: 16px;
                padding: 10px;
                min-height: 40px;
                background-color: #21262d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
            }
            QSpinBox:focus {
                border: 2px solid #58a6ff;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                width: 20px;
                background-color: #30363d;
            }
        """

        # VM IP Address
        ip_layout = QHBoxLayout()
        ip_label = QLabel("VM IP Address:")
        ip_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 180px;")
        ip_layout.addWidget(ip_label)

        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("192.168.0.254")
        self._ip_input.setStyleSheet(input_style)
        ip_layout.addWidget(self._ip_input)
        config_layout.addLayout(ip_layout)

        # Username
        user_layout = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 180px;")
        user_layout.addWidget(user_label)

        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("root")
        self._username_input.setStyleSheet(input_style)
        user_layout.addWidget(self._username_input)
        config_layout.addLayout(user_layout)

        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 180px;")
        password_layout.addWidget(password_label)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Enter password...")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setStyleSheet(input_style)
        password_layout.addWidget(self._password_input)

        self._show_password_btn = QPushButton("Show")
        self._show_password_btn.setMaximumWidth(120)
        self._show_password_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                padding: 10px;
                min-height: 40px;
                background-color: #30363d;
                color: #f0f6fc;
                border: 2px solid #30363d;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #3f4752;
                border: 2px solid #58a6ff;
            }
        """)
        password_layout.addWidget(self._show_password_btn)
        config_layout.addLayout(password_layout)

        # SSH Port
        port_layout = QHBoxLayout()
        port_label = QLabel("SSH Port:")
        port_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 180px;")
        port_layout.addWidget(port_label)

        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(22)
        self._port_spin.setStyleSheet(spinbox_style)
        port_layout.addWidget(self._port_spin)
        port_layout.addStretch()
        config_layout.addLayout(port_layout)

        # Connection buttons
        button_layout = QHBoxLayout()

        self._test_btn = QPushButton("Test Connection")
        self._test_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                padding: 12px 24px;
                background-color: #58a6ff;
                color: white;
                border: none;
                border-radius: 6px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #4a8fd4;
            }
        """)
        button_layout.addWidget(self._test_btn)

        self._save_btn = QPushButton("Save Configuration")
        self._save_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                padding: 12px 24px;
                background-color: #3fb950;
                color: white;
                border: none;
                border-radius: 6px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #2fa040;
            }
        """)
        button_layout.addWidget(self._save_btn)

        button_layout.addStretch()
        config_layout.addLayout(button_layout)

        layout.addWidget(config_group)

        # Submission Options
        options_group = QGroupBox("Analysis Options")
        options_group.setStyleSheet("""
            QGroupBox {
                font-size: 18px;
                font-weight: bold;
                color: #f0f6fc;
                border: 2px solid #30363d;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
            QCheckBox {
                font-size: 16px;
                spacing: 10px;
            }
        """)
        options_layout = QVBoxLayout(options_group)
        options_layout.setSpacing(12)

        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Analysis Timeout:")
        timeout_label.setStyleSheet("font-size: 16px;")
        timeout_layout.addWidget(timeout_label)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(60, 600)
        self._timeout_spin.setValue(300)
        self._timeout_spin.setSuffix(" seconds")
        self._timeout_spin.setStyleSheet("font-size: 16px; padding: 8px; min-height: 35px;")
        timeout_layout.addWidget(self._timeout_spin)
        timeout_layout.addStretch()
        options_layout.addLayout(timeout_layout)

        # Checkboxes
        self._network_check = QCheckBox("Enable network monitoring")
        self._network_check.setChecked(True)
        options_layout.addWidget(self._network_check)

        self._process_check = QCheckBox("Monitor process creation")
        self._process_check.setChecked(True)
        options_layout.addWidget(self._process_check)

        self._file_check = QCheckBox("Track file system changes")
        self._file_check.setChecked(True)
        options_layout.addWidget(self._file_check)

        layout.addWidget(options_group)

        # Pending Submissions
        pending_group = QGroupBox("Pending Analysis Jobs")
        pending_group.setStyleSheet("""
            QGroupBox {
                font-size: 18px;
                font-weight: bold;
                color: #f0f6fc;
                border: 2px solid #30363d;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        pending_layout = QVBoxLayout(pending_group)

        self._pending_list = QListWidget()
        self._pending_list.setStyleSheet("font-size: 16px; min-height: 120px;")
        pending_layout.addWidget(self._pending_list)

        pending_buttons = QHBoxLayout()

        self._refresh_btn = QPushButton("Refresh Status")
        self._refresh_btn.setStyleSheet("font-size: 16px; padding: 10px 20px; min-height: 40px;")
        pending_buttons.addWidget(self._refresh_btn)

        self._retrieve_btn = QPushButton("Retrieve Results")
        self._retrieve_btn.setStyleSheet("font-size: 16px; padding: 10px 20px; min-height: 40px;")
        pending_buttons.addWidget(self._retrieve_btn)

        self._clear_btn = QPushButton("Clear Completed")
        self._clear_btn.setStyleSheet("font-size: 16px; padding: 10px 20px; min-height: 40px;")
        pending_buttons.addWidget(self._clear_btn)

        pending_buttons.addStretch()
        pending_layout.addLayout(pending_buttons)

        layout.addWidget(pending_group)

        # Quick Submit
        submit_group = QGroupBox("Quick File Submission")
        submit_group.setStyleSheet("""
            QGroupBox {
                font-size: 18px;
                font-weight: bold;
                color: #f0f6fc;
                border: 2px solid #30363d;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        submit_layout = QVBoxLayout(submit_group)

        submit_info = QLabel(
            "Submit a file to the VMware sandbox for analysis.\n"
            "The file will be uploaded via SSH and analyzed automatically."
        )
        submit_info.setStyleSheet("color: #8b949e; font-size: 15px;")
        submit_layout.addWidget(submit_info)

        self._submit_btn = QPushButton("📤 Submit File to Sandbox")
        self._submit_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                padding: 15px 30px;
                background-color: #58a6ff;
                color: white;
                border: none;
                border-radius: 6px;
                min-height: 50px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4a8fd4;
            }
        """)
        submit_layout.addWidget(self._submit_btn)

        layout.addWidget(submit_group)

        # Status bar at bottom
        self._status_label = QLabel("VM sandbox not configured")
        self._status_label.setStyleSheet("color: #8b949e; font-size: 16px; padding: 10px;")
        layout.addWidget(self._status_label)

        layout.addStretch()

        # Set container as scroll area widget
        scroll_area.setWidget(container)

        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _setup_connections(self) -> None:
        """Set up signal connections."""
        self._show_password_btn.clicked.connect(self._toggle_password)
        self._test_btn.clicked.connect(self._test_connection)
        self._save_btn.clicked.connect(self._save_configuration)
        self._submit_btn.clicked.connect(self._submit_file)
        self._refresh_btn.clicked.connect(self._refresh_status)
        self._retrieve_btn.clicked.connect(self._retrieve_results)
        self._clear_btn.clicked.connect(self._clear_completed)

    def _load_settings(self) -> None:
        """Load settings from config."""
        try:
            # Load VM settings
            ip = self._config.get("integrations.custom_sandbox.host", "192.168.0.254")
            username = self._config.get("integrations.custom_sandbox.username", "root")
            password = self._config.get("integrations.custom_sandbox.password", "z80cpu")
            port = self._config.get("integrations.custom_sandbox.port", 22)

            self._ip_input.setText(ip)
            self._username_input.setText(username)
            self._password_input.setText(password)
            self._port_spin.setValue(port)

        except Exception as e:
            logger.error(f"Failed to load settings: {e}")

    def _update_connection_status(self) -> None:
        """Update connection status indicator."""
        if self._client.is_configured:
            self._sandbox_status.setText("● Configured")
            self._sandbox_status.setStyleSheet("color: #3fb950; font-weight: bold; font-size: 20px;")
            self._status_label.setText("VMware sandbox configured and ready")
        else:
            self._sandbox_status.setText("● Not Configured")
            self._sandbox_status.setStyleSheet("color: #f85149; font-weight: bold; font-size: 20px;")
            self._status_label.setText("Please configure VMware sandbox connection")

    def _toggle_password(self) -> None:
        """Toggle password visibility."""
        if self._password_input.echoMode() == QLineEdit.EchoMode.Password:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._show_password_btn.setText("Hide")
        else:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._show_password_btn.setText("Show")

    def _test_connection(self) -> None:
        """Test connection to VMware sandbox."""
        ip = self._ip_input.text().strip()
        username = self._username_input.text().strip()
        password = self._password_input.text().strip()
        port = self._port_spin.value()

        if not all([ip, username, password]):
            QMessageBox.warning(
                self,
                "Missing Information",
                "Please enter IP address, username, and password."
            )
            return

        try:
            self._status_label.setText(f"Testing connection to {ip}...")

            # Create temporary client for testing
            test_client = CustomVMSandboxClient(ip, username, password, port)

            if test_client.test_connection():
                QMessageBox.information(
                    self,
                    "Connection Successful",
                    f"Successfully connected to VMware sandbox!\n\n"
                    f"Host: {ip}:{port}\n"
                    f"User: {username}\n\n"
                    f"SSH connection established and directories created."
                )

                self._sandbox_status.setText("● Connected")
                self._sandbox_status.setStyleSheet("color: #3fb950; font-weight: bold; font-size: 20px;")
                self._status_label.setText(f"Connected to {ip}")

                test_client.close()
            else:
                QMessageBox.critical(
                    self,
                    "Connection Failed",
                    f"Failed to connect to VMware sandbox.\n\n"
                    f"Please check:\n"
                    f"• VM is running\n"
                    f"• IP address is correct ({ip})\n"
                    f"• SSH is enabled on the VM\n"
                    f"• Username and password are correct\n"
                    f"• Firewall allows SSH connections"
                )
                self._status_label.setText("Connection failed")

        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            QMessageBox.critical(
                self,
                "Connection Error",
                f"Error testing connection:\n\n{str(e)}"
            )
            self._status_label.setText("Connection error")

    def _save_configuration(self) -> None:
        """Save VMware sandbox configuration."""
        ip = self._ip_input.text().strip()
        username = self._username_input.text().strip()
        password = self._password_input.text().strip()
        port = self._port_spin.value()

        if not all([ip, username, password]):
            QMessageBox.warning(
                self,
                "Missing Information",
                "Please enter all required fields."
            )
            return

        try:
            # Save to config file
            import yaml
            config_path = Path("config.yaml")

            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            if 'integrations' not in config:
                config['integrations'] = {}
            if 'custom_sandbox' not in config['integrations']:
                config['integrations']['custom_sandbox'] = {}

            config['integrations']['custom_sandbox']['enabled'] = True
            config['integrations']['custom_sandbox']['host'] = ip
            config['integrations']['custom_sandbox']['username'] = username
            config['integrations']['custom_sandbox']['password'] = password
            config['integrations']['custom_sandbox']['port'] = port

            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            # Reinitialize client
            self._client = CustomVMSandboxClient(ip, username, password, port)
            self._update_connection_status()

            logger.info(f"Saved VMware sandbox config: {ip}")

            QMessageBox.information(
                self,
                "Configuration Saved",
                f"VMware sandbox configuration saved!\n\n"
                f"Host: {ip}:{port}\n"
                f"User: {username}\n\n"
                f"You can now submit files for analysis."
            )

            self._status_label.setText("Configuration saved successfully")

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            QMessageBox.critical(
                self,
                "Save Failed",
                f"Failed to save configuration:\n{str(e)}"
            )

    def _submit_file(self) -> None:
        """Submit file to VMware sandbox."""
        if not self._client.is_configured:
            QMessageBox.warning(
                self,
                "Not Configured",
                "Please configure and test the VMware sandbox connection first."
            )
            return

        file_path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Sandbox Analysis",
            "",
            "All Files (*.*)"
        )

        if not file_path_str:
            return

        file_path = Path(file_path_str)
        filename = file_path.name

        # Confirmation
        reply = QMessageBox.question(
            self,
            "Confirm Submission",
            f"Submit file to VMware sandbox?\n\n"
            f"File: {filename}\n"
            f"Size: {file_path.stat().st_size / 1024:.1f} KB\n"
            f"Timeout: {self._timeout_spin.value()} seconds\n\n"
            f"The file will be uploaded via SSH and analyzed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self._status_label.setText(f"Uploading {filename}...")

            job_id = self._client.submit_file(file_path, self._timeout_spin.value())

            if job_id:
                # Add to pending list
                item = QListWidgetItem(f"⏳ {filename} (Job: {job_id[:8]}...)")
                self._pending_list.addItem(item)
                self._pending_submissions[job_id] = filename

                QMessageBox.information(
                    self,
                    "Submission Successful",
                    f"File submitted successfully!\n\n"
                    f"File: {filename}\n"
                    f"Job ID: {job_id}\n\n"
                    f"Analysis started. Use 'Refresh Status' to check progress."
                )

                self._status_label.setText(f"Submitted: {filename}")
                logger.info(f"Submitted {filename} to VMware sandbox: {job_id}")
            else:
                QMessageBox.critical(
                    self,
                    "Submission Failed",
                    f"Failed to submit file to VMware sandbox.\n\n"
                    f"Please check the connection and try again."
                )
                self._status_label.setText("Submission failed")

        except Exception as e:
            logger.error(f"File submission error: {e}")
            QMessageBox.critical(
                self,
                "Submission Error",
                f"Error submitting file:\n{str(e)}"
            )
            self._status_label.setText("Submission error")

    def _refresh_status(self) -> None:
        """Refresh status of pending submissions."""
        if not self._pending_submissions:
            QMessageBox.information(
                self,
                "No Pending Jobs",
                "No pending analysis jobs to refresh."
            )
            return

        updated = 0
        for row in range(self._pending_list.count()):
            item = self._pending_list.item(row)
            text = item.text()

            # Extract job_id from item text
            for job_id in self._pending_submissions:
                if job_id[:8] in text:
                    state = self._client.get_state(job_id)

                    if state == "completed":
                        item.setText(f"✓ {self._pending_submissions[job_id]} (Completed)")
                        updated += 1
                    elif state == "running":
                        item.setText(f"⚙️ {self._pending_submissions[job_id]} (Running)")
                    elif state == "error":
                        item.setText(f"❌ {self._pending_submissions[job_id]} (Error)")

        self._status_label.setText(f"Refreshed status ({updated} completed)")

    def _retrieve_results(self) -> None:
        """Retrieve results for selected job."""
        current_item = self._pending_list.currentItem()
        if not current_item:
            QMessageBox.information(
                self,
                "No Selection",
                "Please select a job from the pending list."
            )
            return

        # Find job_id from item
        text = current_item.text()
        job_id = None
        for jid in self._pending_submissions:
            if jid[:8] in text:
                job_id = jid
                break

        if not job_id:
            return

        try:
            report = self._client.get_report(job_id)

            if report and report.status == "completed":
                QMessageBox.information(
                    self,
                    "Analysis Results",
                    f"Analysis completed!\n\n"
                    f"File: {report.filename}\n"
                    f"Status: {report.status}\n"
                    f"Exit Code: {report.exit_code}\n\n"
                    f"Results:\n{report.stdout[:500]}"
                )
            elif report and report.status == "pending":
                QMessageBox.information(
                    self,
                    "Analysis Pending",
                    f"Analysis is still running.\n\n"
                    f"Please wait and try again in a moment."
                )
            else:
                QMessageBox.warning(
                    self,
                    "No Results",
                    f"No results available yet for this job."
                )

        except Exception as e:
            logger.error(f"Failed to retrieve results: {e}")
            QMessageBox.critical(
                self,
                "Retrieval Error",
                f"Error retrieving results:\n{str(e)}"
            )

    def _clear_completed(self) -> None:
        """Clear completed jobs from list."""
        rows_to_remove = []
        for row in range(self._pending_list.count()):
            item = self._pending_list.item(row)
            if "✓" in item.text() or "Completed" in item.text():
                rows_to_remove.append(row)

        for row in reversed(rows_to_remove):
            self._pending_list.takeItem(row)

        self._status_label.setText(f"Cleared {len(rows_to_remove)} completed jobs")
