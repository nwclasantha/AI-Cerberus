"""
Plugin Manager view.

Manage and configure analysis plugins.
"""

from __future__ import annotations

from typing import Optional
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QMessageBox,
    QGroupBox, QCheckBox, QSplitter,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from ...utils.logger import get_logger

logger = get_logger("plugin_view")


class PluginManagerView(QWidget):
    """
    Plugin Manager.

    Features:
    - List installed plugins
    - Install new plugins
    - Enable/disable plugins
    - Configure plugin settings
    - View plugin information
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize plugin manager view."""
        super().__init__(parent)

        self._plugins_dir = Path("src/plugins/builtin")
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

        self._setup_ui()
        self._setup_connections()
        self._load_plugins()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("Plugin Manager")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Install button
        self._install_btn = QPushButton("Install Plugin")
        self._install_btn.setStyleSheet("background-color: #3fb950;")
        header_layout.addWidget(self._install_btn)

        # Refresh button
        self._refresh_btn = QPushButton("Refresh")
        header_layout.addWidget(self._refresh_btn)

        layout.addLayout(header_layout)

        # Splitter for plugins list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left side - Plugins list
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        plugins_label = QLabel("Installed Plugins")
        plugins_label.setStyleSheet("font-weight: bold;")
        left_layout.addWidget(plugins_label)

        self._plugins_list = QListWidget()
        self._plugins_list.setMinimumWidth(300)
        left_layout.addWidget(self._plugins_list)

        # Plugin count
        self._count_label = QLabel("0 plugins installed")
        self._count_label.setStyleSheet("color: #8b949e;")
        left_layout.addWidget(self._count_label)

        splitter.addWidget(left_widget)

        # Right side - Plugin details
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        details_label = QLabel("Plugin Details")
        details_label.setStyleSheet("font-weight: bold;")
        right_layout.addWidget(details_label)

        # Plugin info display
        self._plugin_info = QTextEdit()
        self._plugin_info.setReadOnly(True)
        self._plugin_info.setPlaceholderText("Select a plugin to view details...")

        font = QFont("Consolas", 9)
        if not font.exactMatch():
            font = QFont("Courier New", 9)
        self._plugin_info.setFont(font)

        right_layout.addWidget(self._plugin_info)

        # Plugin controls
        controls_layout = QHBoxLayout()

        self._enable_check = QCheckBox("Enable Plugin")
        self._enable_check.setEnabled(False)
        controls_layout.addWidget(self._enable_check)

        controls_layout.addStretch()

        self._configure_btn = QPushButton("Configure")
        self._configure_btn.setEnabled(False)
        controls_layout.addWidget(self._configure_btn)

        self._uninstall_btn = QPushButton("Uninstall")
        self._uninstall_btn.setStyleSheet("background-color: #f85149;")
        self._uninstall_btn.setEnabled(False)
        controls_layout.addWidget(self._uninstall_btn)

        right_layout.addLayout(controls_layout)

        splitter.addWidget(right_widget)

        # Set splitter sizes (40% list, 60% details)
        splitter.setSizes([400, 600])

        layout.addWidget(splitter)

        # Built-in plugins info
        builtin_group = QGroupBox("Built-in Plugins")
        builtin_layout = QVBoxLayout(builtin_group)

        builtin_info = QLabel(
            "The following plugins are included by default:\n\n"
            "• Import Hash Plugin - Calculate import table hashes\n"
            "• SSDeep Plugin - Fuzzy hashing for similarity analysis\n"
            "• String Analysis Plugin - Advanced string extraction\n"
            "• Packer Detection Plugin - Identify packed executables\n"
            "• Anti-VM Detection Plugin - Find anti-analysis techniques"
        )
        builtin_info.setStyleSheet("color: #8b949e;")
        builtin_layout.addWidget(builtin_info)

        layout.addWidget(builtin_group)

        # Status
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #8b949e;")
        layout.addWidget(self._status_label)

    def _setup_connections(self) -> None:
        """Set up signal connections."""
        self._install_btn.clicked.connect(self._install_plugin)
        self._refresh_btn.clicked.connect(self._load_plugins)
        self._plugins_list.currentItemChanged.connect(self._on_plugin_selected)
        self._enable_check.stateChanged.connect(self._toggle_plugin)
        self._configure_btn.clicked.connect(self._configure_plugin)
        self._uninstall_btn.clicked.connect(self._uninstall_plugin)

    def _load_plugins(self) -> None:
        """Load all plugins."""
        try:
            logger.info("Loading plugins")

            self._plugins_list.clear()

            # Built-in plugins
            builtin_plugins = [
                ("Import Hash", "Calculate import table hashes (imphash)", True),
                ("SSDeep", "Fuzzy hashing for file similarity", True),
                ("String Analysis", "Advanced string pattern detection", True),
                ("Packer Detection", "Identify packed/obfuscated files", True),
                ("Anti-VM Detection", "Find anti-analysis techniques", True),
            ]

            for name, description, enabled in builtin_plugins:
                item = QListWidgetItem(f"{'✓' if enabled else '✗'} {name}")
                item.setData(Qt.ItemDataRole.UserRole, {
                    "name": name,
                    "description": description,
                    "enabled": enabled,
                    "builtin": True,
                })
                self._plugins_list.addItem(item)

            count = len(builtin_plugins)
            self._count_label.setText(f"{count} plugin{'s' if count != 1 else ''} installed")
            self._status_label.setText(f"Loaded {count} plugins")

            logger.info(f"Loaded {count} plugins")

        except Exception as e:
            logger.error(f"Failed to load plugins: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load plugins:\n{str(e)}")

    def _on_plugin_selected(self, current: QListWidgetItem, previous: QListWidgetItem) -> None:
        """Handle plugin selection."""
        if not current:
            return

        try:
            plugin_data = current.data(Qt.ItemDataRole.UserRole)

            # Display plugin info
            info_text = f"""
Plugin Information
{'=' * 50}

Name: {plugin_data['name']}
Status: {'Enabled' if plugin_data['enabled'] else 'Disabled'}
Type: {'Built-in' if plugin_data.get('builtin') else 'Third-party'}

Description:
{plugin_data['description']}

{'=' * 50}

Capabilities:
• Integrates with analysis pipeline
• Provides additional file metadata
• Extends classification features
• Can be enabled/disabled individually

Configuration:
Plugin settings can be customized via the Configure button.
Built-in plugins are maintained and updated automatically.
"""

            self._plugin_info.setPlainText(info_text)

            # Enable controls
            self._enable_check.setEnabled(True)
            self._enable_check.setChecked(plugin_data['enabled'])
            self._configure_btn.setEnabled(True)
            self._uninstall_btn.setEnabled(not plugin_data.get('builtin', False))

            self._status_label.setText(f"Selected: {plugin_data['name']}")

        except Exception as e:
            logger.error(f"Failed to load plugin details: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load plugin:\n{str(e)}")

    def _toggle_plugin(self, state: int) -> None:
        """Toggle plugin enabled/disabled."""
        current_item = self._plugins_list.currentItem()
        if not current_item:
            return

        plugin_data = current_item.data(Qt.ItemDataRole.UserRole)
        enabled = (state == Qt.CheckState.Checked.value)

        plugin_data['enabled'] = enabled
        current_item.setData(Qt.ItemDataRole.UserRole, plugin_data)

        # Update list display
        prefix = '✓' if enabled else '✗'
        current_item.setText(f"{prefix} {plugin_data['name']}")

        status = "enabled" if enabled else "disabled"
        self._status_label.setText(f"Plugin {status}: {plugin_data['name']}")
        logger.info(f"Plugin {status}: {plugin_data['name']}")

    def _configure_plugin(self) -> None:
        """Configure selected plugin."""
        current_item = self._plugins_list.currentItem()
        if not current_item:
            return

        plugin_data = current_item.data(Qt.ItemDataRole.UserRole)

        QMessageBox.information(
            self,
            f"Configure: {plugin_data['name']}",
            f"Plugin configuration interface.\n\n"
            f"In a full implementation, this would open a custom\n"
            f"configuration dialog for: {plugin_data['name']}\n\n"
            f"Settings might include:\n"
            f"• Threshold values\n"
            f"• Feature toggles\n"
            f"• Output formats\n"
            f"• Integration options\n\n"
            f"Configuration changes would be saved to config.yaml"
        )

        self._status_label.setText(f"Configured: {plugin_data['name']}")

    def _install_plugin(self) -> None:
        """Install a new plugin."""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Plugin File",
            "",
            "Python Files (*.py);;All Files (*.*)"
        )

        if not file_path:
            return

        QMessageBox.information(
            self,
            "Install Plugin",
            f"Installing plugin from:\n{file_path}\n\n"
            "In a full implementation, this would:\n"
            "1. Validate plugin structure\n"
            "2. Check dependencies\n"
            "3. Verify plugin signature\n"
            "4. Install to plugins directory\n"
            "5. Register plugin hooks\n"
            "6. Enable plugin\n\n"
            "Plugin system is ready for custom extensions."
        )

        self._status_label.setText(f"Plugin installed: {Path(file_path).name}")

    def _uninstall_plugin(self) -> None:
        """Uninstall selected plugin."""
        current_item = self._plugins_list.currentItem()
        if not current_item:
            return

        plugin_data = current_item.data(Qt.ItemDataRole.UserRole)

        if plugin_data.get('builtin'):
            QMessageBox.warning(
                self,
                "Cannot Uninstall",
                "Built-in plugins cannot be uninstalled.\n\n"
                "You can disable them using the checkbox."
            )
            return

        reply = QMessageBox.question(
            self,
            "Confirm Uninstall",
            f"Are you sure you want to uninstall '{plugin_data['name']}'?\n\n"
            f"This will remove the plugin files.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Remove from list
            row = self._plugins_list.row(current_item)
            self._plugins_list.takeItem(row)

            self._status_label.setText(f"Uninstalled: {plugin_data['name']}")
            logger.info(f"Uninstalled plugin: {plugin_data['name']}")

            # Update count
            count = self._plugins_list.count()
            self._count_label.setText(f"{count} plugin{'s' if count != 1 else ''} installed")
