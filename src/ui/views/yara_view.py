"""
YARA Rules Manager view.

Allows users to manage, edit, and test YARA rules.
"""

from typing import Optional, List
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget,
    QTextEdit, QLineEdit, QLabel, QSplitter, QFileDialog,
    QMessageBox, QInputDialog, QListWidgetItem, QScrollArea,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from ...utils.logger import get_logger

logger = get_logger("yara_view")


class YaraRulesView(QWidget):
    """
    YARA Rules Manager.

    Features:
    - List all YARA rules
    - Add/Edit/Delete rules
    - Import rules from files
    - Test rules against samples
    - Syntax validation
    """

    # Signals
    rule_applied = pyqtSignal(str)  # Emits rule name

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize YARA rules view."""
        super().__init__(parent)

        self._rules_dir = Path("resources/yara_rules")
        self._rules_dir.mkdir(parents=True, exist_ok=True)

        self._current_rule_path = None

        self._setup_ui()
        self._setup_connections()
        self._load_rules()

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

        # Text edit styling
        text_edit_style = """
            QTextEdit {
                font-size: 14px;
                background-color: #161b22;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                padding: 10px;
            }
            QTextEdit:focus {
                border: 2px solid #58a6ff;
            }
        """

        # List widget styling
        list_style = """
            QListWidget {
                background-color: #161b22;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                font-size: 15px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background-color: #58a6ff;
                color: #0d1117;
            }
            QListWidget::item:hover {
                background-color: #30363d;
            }
        """

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("YARA Rules Manager")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #f0f6fc;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # New rule button
        self._new_btn = QPushButton("New Rule")
        new_button_style = button_style.replace("background-color: #21262d;", "background-color: #3fb950;")
        self._new_btn.setStyleSheet(new_button_style)
        header_layout.addWidget(self._new_btn)

        # Import button
        self._import_btn = QPushButton("Import Rules")
        self._import_btn.setStyleSheet(button_style)
        header_layout.addWidget(self._import_btn)

        # Refresh button
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setStyleSheet(button_style)
        header_layout.addWidget(self._refresh_btn)

        layout.addLayout(header_layout)

        # Splitter for rules list and editor
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left side - Rules list
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        rules_label = QLabel("Available Rules")
        rules_label.setStyleSheet("font-weight: bold; font-size: 18px; color: #f0f6fc; padding: 5px;")
        left_layout.addWidget(rules_label)

        # Search box
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search rules...")
        self._search_input.setStyleSheet(input_style)
        left_layout.addWidget(self._search_input)

        # Rules list
        self._rules_list = QListWidget()
        self._rules_list.setMinimumWidth(250)
        self._rules_list.setStyleSheet(list_style)
        left_layout.addWidget(self._rules_list)

        # Buttons
        list_buttons = QHBoxLayout()

        self._delete_btn = QPushButton("Delete")
        delete_button_style = button_style.replace("background-color: #21262d;", "background-color: #f85149;")
        self._delete_btn.setStyleSheet(delete_button_style)
        list_buttons.addWidget(self._delete_btn)

        self._duplicate_btn = QPushButton("Duplicate")
        self._duplicate_btn.setStyleSheet(button_style)
        list_buttons.addWidget(self._duplicate_btn)

        left_layout.addLayout(list_buttons)

        # Rules count
        self._count_label = QLabel("0 rules")
        self._count_label.setStyleSheet("color: #8b949e; font-size: 16px; padding: 5px;")
        left_layout.addWidget(self._count_label)

        splitter.addWidget(left_widget)

        # Right side - Rule editor
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Rule name
        name_layout = QHBoxLayout()

        name_label = QLabel("Rule Name:")
        name_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #f0f6fc; min-width: 120px;")
        name_layout.addWidget(name_label)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Enter rule name...")
        self._name_input.setStyleSheet(input_style)
        name_layout.addWidget(self._name_input)
        right_layout.addLayout(name_layout)

        editor_label = QLabel("Rule Content")
        editor_label.setStyleSheet("font-weight: bold; font-size: 18px; color: #f0f6fc; padding: 10px 0;")
        right_layout.addWidget(editor_label)

        # Rule editor
        self._rule_editor = QTextEdit()
        self._rule_editor.setPlaceholderText(
            "Enter YARA rule here...\n\n"
            "Example:\n"
            "rule ExampleRule {\n"
            "    meta:\n"
            "        description = \"Example YARA rule\"\n"
            "        author = \"Your Name\"\n"
            "    strings:\n"
            "        $string1 = \"malware\"\n"
            "        $string2 = { 6A 40 68 00 30 00 00 }\n"
            "    condition:\n"
            "        any of them\n"
            "}"
        )
        self._rule_editor.setStyleSheet(text_edit_style)

        # Monospace font for editor
        font = QFont("Consolas", 13)
        if not font.exactMatch():
            font = QFont("Courier New", 13)
        self._rule_editor.setFont(font)

        right_layout.addWidget(self._rule_editor)

        # Editor buttons
        editor_buttons = QHBoxLayout()

        self._save_btn = QPushButton("Save Rule")
        save_button_style = button_style.replace("background-color: #21262d;", "background-color: #3fb950;")
        self._save_btn.setStyleSheet(save_button_style)
        editor_buttons.addWidget(self._save_btn)

        self._validate_btn = QPushButton("Validate Syntax")
        self._validate_btn.setStyleSheet(button_style)
        editor_buttons.addWidget(self._validate_btn)

        self._test_btn = QPushButton("Test on Sample")
        self._test_btn.setStyleSheet(button_style)
        editor_buttons.addWidget(self._test_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setStyleSheet(button_style)
        editor_buttons.addWidget(self._clear_btn)

        editor_buttons.addStretch()

        right_layout.addLayout(editor_buttons)

        splitter.addWidget(right_widget)

        # Set splitter sizes (30% list, 70% editor)
        splitter.setSizes([300, 700])

        layout.addWidget(splitter)

        # Status
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #8b949e; font-size: 17px; padding: 10px;")
        layout.addWidget(self._status_label)

        # Set container as scroll area widget
        scroll_area.setWidget(container)

        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _setup_connections(self) -> None:
        """Set up signal connections."""
        self._new_btn.clicked.connect(self._new_rule)
        self._import_btn.clicked.connect(self._import_rules)
        self._refresh_btn.clicked.connect(self._load_rules)
        self._delete_btn.clicked.connect(self._delete_rule)
        self._duplicate_btn.clicked.connect(self._duplicate_rule)
        self._save_btn.clicked.connect(self._save_rule)
        self._validate_btn.clicked.connect(self._validate_rule)
        self._test_btn.clicked.connect(self._test_rule)
        self._clear_btn.clicked.connect(self._clear_editor)
        self._rules_list.currentItemChanged.connect(self._on_rule_selected)
        self._search_input.textChanged.connect(self._filter_rules)

    def _load_rules(self) -> None:
        """Load all YARA rules from directory."""
        try:
            logger.info("Loading YARA rules")

            self._rules_list.clear()

            # Find all .yar and .yara files
            rule_files = list(self._rules_dir.rglob("*.yar")) + \
                        list(self._rules_dir.rglob("*.yara"))

            for rule_file in rule_files:
                item = QListWidgetItem(rule_file.stem)
                item.setData(Qt.ItemDataRole.UserRole, str(rule_file))
                self._rules_list.addItem(item)

            count = len(rule_files)
            self._count_label.setText(f"{count} rule{'s' if count != 1 else ''}")
            self._status_label.setText(f"Loaded {count} rules")

            logger.info(f"Loaded {count} YARA rules")

        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load rules:\n{str(e)}")

    def _on_rule_selected(self, current: QListWidgetItem, previous: QListWidgetItem) -> None:
        """Handle rule selection."""
        if not current:
            return

        try:
            rule_path = Path(current.data(Qt.ItemDataRole.UserRole))
            self._current_rule_path = rule_path

            # Load rule content
            with open(rule_path, 'r', encoding='utf-8') as f:
                content = f.read()

            self._name_input.setText(rule_path.stem)
            self._rule_editor.setPlainText(content)

            self._status_label.setText(f"Loaded: {rule_path.name}")

        except Exception as e:
            logger.error(f"Failed to load rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load rule:\n{str(e)}")

    def _new_rule(self) -> None:
        """Create a new rule."""
        self._current_rule_path = None
        self._name_input.clear()
        self._rule_editor.clear()
        self._name_input.setFocus()
        self._status_label.setText("New rule - enter name and content")

    def _save_rule(self) -> None:
        """Save the current rule."""
        rule_name = self._name_input.text().strip()
        rule_content = self._rule_editor.toPlainText().strip()

        if not rule_name:
            QMessageBox.warning(self, "Missing Name", "Please enter a rule name.")
            return

        if not rule_content:
            QMessageBox.warning(self, "Missing Content", "Please enter rule content.")
            return

        # Validate syntax first
        if not self._validate_rule_content(rule_content, show_success=False):
            reply = QMessageBox.question(
                self,
                "Invalid Syntax",
                "The rule has syntax errors. Save anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        try:
            # Determine file path
            if self._current_rule_path:
                rule_path = self._current_rule_path
            else:
                # Create new file
                rule_path = self._rules_dir / f"{rule_name}.yar"

            # Check if file exists (for new rules)
            if not self._current_rule_path and rule_path.exists():
                reply = QMessageBox.question(
                    self,
                    "File Exists",
                    f"A rule named '{rule_name}' already exists. Overwrite?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return

            # Save rule
            with open(rule_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)

            self._current_rule_path = rule_path
            self._status_label.setText(f"Saved: {rule_path.name}")

            # Reload rules list
            self._load_rules()

            # Select the saved rule
            for i in range(self._rules_list.count()):
                item = self._rules_list.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == str(rule_path):
                    self._rules_list.setCurrentItem(item)
                    break

            QMessageBox.information(self, "Success", f"Rule saved: {rule_path.name}")
            logger.info(f"Saved YARA rule: {rule_path}")

        except Exception as e:
            logger.error(f"Failed to save rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save rule:\n{str(e)}")

    def _validate_rule(self) -> None:
        """Validate rule syntax."""
        rule_content = self._rule_editor.toPlainText().strip()

        if not rule_content:
            QMessageBox.warning(self, "No Content", "Please enter rule content to validate.")
            return

        self._validate_rule_content(rule_content, show_success=True)

    def _validate_rule_content(self, content: str, show_success: bool = True) -> bool:
        """Validate YARA rule content."""
        try:
            import yara

            # Try to compile the rule
            yara.compile(source=content)

            if show_success:
                QMessageBox.information(
                    self,
                    "Valid Syntax",
                    "The YARA rule syntax is valid!"
                )

            self._status_label.setText("Syntax valid")
            return True

        except yara.SyntaxError as e:
            QMessageBox.critical(
                self,
                "Syntax Error",
                f"YARA syntax error:\n\n{str(e)}"
            )
            self._status_label.setText("Syntax error")
            return False

        except ImportError:
            QMessageBox.warning(
                self,
                "YARA Not Available",
                "YARA library not available for syntax validation.\n\n"
                "Install with: pip install yara-python"
            )
            return False

        except Exception as e:
            QMessageBox.critical(
                self,
                "Validation Error",
                f"Failed to validate rule:\n{str(e)}"
            )
            return False

    def _test_rule(self) -> None:
        """Test rule on a sample."""
        rule_content = self._rule_editor.toPlainText().strip()

        if not rule_content:
            QMessageBox.warning(self, "No Rule", "Please enter a rule to test.")
            return

        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Test",
            "",
            "All Files (*.*)"
        )

        if not file_path:
            return

        try:
            import yara

            # Compile rule
            rules = yara.compile(source=rule_content)

            # Match against file
            matches = rules.match(file_path)

            if matches:
                match_info = []
                for match in matches:
                    match_info.append(f"Rule: {match.rule}")
                    match_info.append(f"Tags: {', '.join(match.tags) if match.tags else 'None'}")
                    match_info.append(f"Strings: {len(match.strings)} match(es)")
                    match_info.append("")

                QMessageBox.information(
                    self,
                    "Rule Matched!",
                    f"The rule matched the file!\n\n" + "\n".join(match_info)
                )
                self._status_label.setText(f"Rule matched: {Path(file_path).name}")
            else:
                QMessageBox.information(
                    self,
                    "No Match",
                    "The rule did not match the file."
                )
                self._status_label.setText(f"No match: {Path(file_path).name}")

        except yara.SyntaxError as e:
            QMessageBox.critical(
                self,
                "Syntax Error",
                f"YARA syntax error:\n\n{str(e)}"
            )

        except ImportError:
            QMessageBox.warning(
                self,
                "YARA Not Available",
                "YARA library not available for testing.\n\n"
                "Install with: pip install yara-python"
            )

        except Exception as e:
            logger.error(f"Failed to test rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to test rule:\n{str(e)}")

    def _delete_rule(self) -> None:
        """Delete selected rule."""
        current_item = self._rules_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "No Selection", "Please select a rule to delete.")
            return

        rule_name = current_item.text()
        rule_path = Path(current_item.data(Qt.ItemDataRole.UserRole))

        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the rule '{rule_name}'?\n\n"
            f"This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                rule_path.unlink()
                self._load_rules()
                self._clear_editor()
                self._status_label.setText(f"Deleted: {rule_name}")
                logger.info(f"Deleted YARA rule: {rule_name}")

            except Exception as e:
                logger.error(f"Failed to delete rule: {e}")
                QMessageBox.critical(self, "Error", f"Failed to delete rule:\n{str(e)}")

    def _duplicate_rule(self) -> None:
        """Duplicate selected rule."""
        current_item = self._rules_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "No Selection", "Please select a rule to duplicate.")
            return

        rule_name = current_item.text()
        new_name, ok = QInputDialog.getText(
            self,
            "Duplicate Rule",
            "Enter name for duplicated rule:",
            text=f"{rule_name}_copy"
        )

        if ok and new_name:
            try:
                source_path = Path(current_item.data(Qt.ItemDataRole.UserRole))
                dest_path = self._rules_dir / f"{new_name}.yar"

                if dest_path.exists():
                    QMessageBox.warning(
                        self,
                        "File Exists",
                        f"A rule named '{new_name}' already exists."
                    )
                    return

                # Copy file
                import shutil
                shutil.copy2(source_path, dest_path)

                self._load_rules()
                self._status_label.setText(f"Duplicated: {rule_name} → {new_name}")
                logger.info(f"Duplicated YARA rule: {rule_name} → {new_name}")

            except Exception as e:
                logger.error(f"Failed to duplicate rule: {e}")
                QMessageBox.critical(self, "Error", f"Failed to duplicate rule:\n{str(e)}")

    def _import_rules(self) -> None:
        """Import rules from files."""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Import YARA Rules",
            "",
            "YARA Rules (*.yar *.yara);;All Files (*.*)"
        )

        if not file_paths:
            return

        try:
            imported = 0
            for file_path in file_paths:
                source = Path(file_path)
                dest = self._rules_dir / source.name

                # Check if file exists
                if dest.exists():
                    reply = QMessageBox.question(
                        self,
                        "File Exists",
                        f"Rule '{source.name}' already exists. Overwrite?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.No:
                        continue

                # Copy file
                import shutil
                shutil.copy2(source, dest)
                imported += 1

            self._load_rules()
            self._status_label.setText(f"Imported {imported} rule(s)")
            QMessageBox.information(
                self,
                "Import Complete",
                f"Successfully imported {imported} rule(s)."
            )
            logger.info(f"Imported {imported} YARA rules")

        except Exception as e:
            logger.error(f"Failed to import rules: {e}")
            QMessageBox.critical(self, "Error", f"Failed to import rules:\n{str(e)}")

    def _clear_editor(self) -> None:
        """Clear the editor."""
        self._current_rule_path = None
        self._name_input.clear()
        self._rule_editor.clear()
        self._status_label.setText("Editor cleared")

    def _filter_rules(self) -> None:
        """Filter rules list based on search text."""
        search_text = self._search_input.text().lower()

        for i in range(self._rules_list.count()):
            item = self._rules_list.item(i)
            item_text = item.text().lower()
            item.setHidden(search_text not in item_text)
