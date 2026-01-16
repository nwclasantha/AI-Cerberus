"""
Disassembly view component.

Displays disassembled instructions with syntax highlighting.
"""

from typing import Dict, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLabel, QLineEdit, QPushButton, QFrame, QComboBox,
    QSplitter, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import (
    QFont, QTextCharFormat, QColor, QTextCursor,
    QSyntaxHighlighter, QTextDocument,
)

from ..theme import get_theme_manager


class DisassemblyHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for disassembly."""

    # x86/x64 instruction categories
    CONTROL_FLOW = {
        "jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe",
        "jg", "jl", "jge", "jle", "call", "ret", "retn", "leave",
        "loop", "loope", "loopne", "int", "syscall",
    }

    DATA_MOVEMENT = {
        "mov", "movzx", "movsx", "lea", "push", "pop", "xchg",
        "movaps", "movups", "movdqa", "movdqu",
    }

    ARITHMETIC = {
        "add", "sub", "mul", "imul", "div", "idiv", "inc", "dec",
        "neg", "adc", "sbb",
    }

    LOGIC = {
        "and", "or", "xor", "not", "shl", "shr", "sar", "sal",
        "rol", "ror", "test", "cmp",
    }

    REGISTERS = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "rip", "eip", "ip",
    }

    def __init__(self, parent: QTextDocument = None):
        super().__init__(parent)

        theme = get_theme_manager()
        p = theme.get_palette()

        # Address format
        self._address_format = QTextCharFormat()
        self._address_format.setForeground(QColor(p.accent_cyan))
        self._address_format.setFontWeight(QFont.Weight.Bold)

        # Bytes format
        self._bytes_format = QTextCharFormat()
        self._bytes_format.setForeground(QColor(p.text_muted))

        # Control flow format
        self._control_format = QTextCharFormat()
        self._control_format.setForeground(QColor(p.syntax_keyword))
        self._control_format.setFontWeight(QFont.Weight.Bold)

        # Data movement format
        self._data_format = QTextCharFormat()
        self._data_format.setForeground(QColor(p.accent_primary))

        # Arithmetic format
        self._arith_format = QTextCharFormat()
        self._arith_format.setForeground(QColor(p.accent_success))

        # Logic format
        self._logic_format = QTextCharFormat()
        self._logic_format.setForeground(QColor(p.accent_warning))

        # Register format
        self._register_format = QTextCharFormat()
        self._register_format.setForeground(QColor(p.accent_purple))

        # Number format
        self._number_format = QTextCharFormat()
        self._number_format.setForeground(QColor(p.syntax_number))

        # Comment format
        self._comment_format = QTextCharFormat()
        self._comment_format.setForeground(QColor(p.syntax_comment))
        self._comment_format.setFontItalic(True)

    def highlightBlock(self, text: str) -> None:
        """Highlight disassembly block."""
        if not text.strip():
            return

        # Parse line structure: ADDRESS  BYTES  MNEMONIC OPERANDS  ; comment
        parts = text.split()
        if not parts:
            return

        pos = 0

        # Address (first part, should end with colon or be hex)
        if parts[0].endswith(':') or (len(parts[0]) >= 4 and all(c in '0123456789abcdefABCDEF' for c in parts[0].rstrip(':'))):
            addr_end = text.find(parts[0]) + len(parts[0])
            self.setFormat(0, addr_end, self._address_format)
            pos = addr_end

        # Find mnemonic (skip bytes)
        for i, part in enumerate(parts[1:], 1):
            # Skip hex byte sequences
            if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                byte_pos = text.find(part, pos)
                if byte_pos >= 0:
                    self.setFormat(byte_pos, len(part), self._bytes_format)
                    pos = byte_pos + len(part)
                continue

            # Found mnemonic
            mnemonic = part.lower()
            mnem_pos = text.find(part, pos)
            if mnem_pos < 0:
                continue

            # Apply mnemonic format
            if mnemonic in self.CONTROL_FLOW:
                self.setFormat(mnem_pos, len(part), self._control_format)
            elif mnemonic in self.DATA_MOVEMENT:
                self.setFormat(mnem_pos, len(part), self._data_format)
            elif mnemonic in self.ARITHMETIC:
                self.setFormat(mnem_pos, len(part), self._arith_format)
            elif mnemonic in self.LOGIC:
                self.setFormat(mnem_pos, len(part), self._logic_format)

            # Highlight remaining operands
            self._highlight_operands(text, mnem_pos + len(part))
            break

    def _highlight_operands(self, text: str, start: int) -> None:
        """Highlight instruction operands."""
        operand_text = text[start:]

        # Find and highlight registers
        for reg in self.REGISTERS:
            idx = 0
            while True:
                pos = operand_text.lower().find(reg, idx)
                if pos < 0:
                    break

                # Check word boundary
                before_ok = pos == 0 or not operand_text[pos - 1].isalnum()
                after_ok = pos + len(reg) >= len(operand_text) or not operand_text[pos + len(reg)].isalnum()

                if before_ok and after_ok:
                    self.setFormat(start + pos, len(reg), self._register_format)

                idx = pos + 1

        # Find and highlight numbers (hex)
        import re
        for match in re.finditer(r'0x[0-9a-fA-F]+|\b[0-9a-fA-F]+h\b', operand_text):
            self.setFormat(start + match.start(), match.end() - match.start(), self._number_format)

        # Find and highlight comments
        comment_pos = operand_text.find(';')
        if comment_pos >= 0:
            self.setFormat(start + comment_pos, len(operand_text) - comment_pos, self._comment_format)


class DisassemblyView(QWidget):
    """
    Disassembly viewer with syntax highlighting.

    Features:
    - Multi-architecture support
    - Syntax highlighting
    - Navigation
    - Cross-references
    """

    # Signals
    address_selected = pyqtSignal(int)

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize disassembly view."""
        super().__init__(parent)

        self._instructions: List[Dict] = []
        self._current_arch = "x64"
        self._show_only_suspicious = False  # Filter for suspicious instructions

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up disassembly view UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Disassembly display (use QTextEdit for HTML support)
        self._disasm_view = QTextEdit()
        self._disasm_view.setReadOnly(True)
        self._disasm_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self._disasm_view.setObjectName("disasmView")

        # Configure font
        theme = get_theme_manager()
        font = theme.get_monospace_font(12)
        self._disasm_view.setFont(font)

        # Don't use syntax highlighter - we'll use HTML formatting instead
        # self._highlighter = DisassemblyHighlighter(self._disasm_view.document())

        splitter.addWidget(self._disasm_view)

        # Side panel (functions, xrefs)
        side_panel = self._create_side_panel()
        splitter.addWidget(side_panel)

        splitter.setSizes([700, 250])

        layout.addWidget(splitter)

        self._apply_style()

    def _create_toolbar(self) -> QWidget:
        """Create disassembly toolbar."""
        toolbar = QFrame()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        theme = get_theme_manager()
        p = theme.get_palette()

        toolbar.setStyleSheet(f"""
            QFrame {{
                background-color: {p.bg_secondary};
                border-bottom: 1px solid {p.border_primary};
            }}
        """)

        # Architecture selector
        layout.addWidget(QLabel("Architecture:"))

        self._arch_combo = QComboBox()
        self._arch_combo.addItems(["x64", "x86", "ARM", "ARM64", "MIPS"])
        self._arch_combo.currentTextChanged.connect(self._on_arch_changed)
        layout.addWidget(self._arch_combo)

        layout.addSpacing(16)

        # Go to address
        layout.addWidget(QLabel("Address:"))

        self._address_input = QLineEdit()
        self._address_input.setPlaceholderText("0x00000000")
        self._address_input.setMaximumWidth(120)
        self._address_input.returnPressed.connect(self._go_to_address)
        layout.addWidget(self._address_input)

        go_btn = QPushButton("Go")
        go_btn.clicked.connect(self._go_to_address)
        layout.addWidget(go_btn)

        layout.addSpacing(16)

        # Filter for suspicious instructions
        self._suspicious_filter = QPushButton("Show Only Suspicious")
        self._suspicious_filter.setCheckable(True)
        self._suspicious_filter.setChecked(False)
        self._suspicious_filter.clicked.connect(self._toggle_suspicious_filter)
        layout.addWidget(self._suspicious_filter)

        layout.addStretch()

        # Info
        self._info_label = QLabel("0 instructions")
        layout.addWidget(self._info_label)

        return toolbar

    def _create_side_panel(self) -> QWidget:
        """Create side panel with functions and xrefs."""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        theme = get_theme_manager()
        p = theme.get_palette()

        panel.setStyleSheet(f"""
            QFrame {{
                background-color: {p.bg_secondary};
                border-left: 1px solid {p.border_primary};
            }}
        """)

        # Functions table
        layout.addWidget(QLabel("  Functions"))

        self._functions_table = QTableWidget()
        self._functions_table.setColumnCount(2)
        self._functions_table.setHorizontalHeaderLabels(["Address", "Name"])
        self._functions_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._functions_table.verticalHeader().setVisible(False)
        self._functions_table.cellDoubleClicked.connect(self._on_function_selected)
        layout.addWidget(self._functions_table)

        # Call targets
        layout.addWidget(QLabel("  Call Targets"))

        self._calls_table = QTableWidget()
        self._calls_table.setColumnCount(2)
        self._calls_table.setHorizontalHeaderLabels(["From", "Target"])
        self._calls_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._calls_table.verticalHeader().setVisible(False)
        layout.addWidget(self._calls_table)

        return panel

    def _apply_style(self) -> None:
        """Apply disassembly view styling."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self._disasm_view.setStyleSheet(f"""
            QTextEdit {{
                background-color: {p.bg_primary};
                color: {p.text_primary};
                border: none;
                selection-background-color: {p.accent_primary};
            }}
        """)

    def set_instructions(self, instructions: List[Dict]) -> None:
        """
        Set disassembly instructions to display.

        Args:
            instructions: List of instruction dicts
        """
        self._instructions = instructions
        self._render_disassembly()

        # Count suspicious instructions by threat level
        suspicious_count = sum(1 for i in instructions if i.get("is_suspicious", False))
        critical_count = sum(1 for i in instructions if i.get("threat_level") == "critical")
        high_count = sum(1 for i in instructions if i.get("threat_level") == "high")
        medium_count = sum(1 for i in instructions if i.get("threat_level") == "medium")

        # Update info label
        info_parts = [f"{len(instructions)} instructions"]
        if suspicious_count > 0:
            info_parts.append(f"⚠ {suspicious_count} suspicious")
            if critical_count > 0:
                info_parts.append(f"🔴 {critical_count} critical")
            if high_count > 0:
                info_parts.append(f"🟠 {high_count} high")
            if medium_count > 0:
                info_parts.append(f"🟡 {medium_count} medium")

        self._info_label.setText(" | ".join(info_parts))

    def _render_disassembly(self) -> None:
        """Render disassembly display with suspicious instruction highlighting using HTML."""
        if not self._instructions:
            self._disasm_view.setPlainText("No instructions loaded")
            return

        # DEBUG: Count suspicious instructions
        total_instructions = len(self._instructions)
        suspicious_instructions = [i for i in self._instructions if i.get("is_suspicious", False)]
        critical_instructions = [i for i in self._instructions if i.get("threat_level") == "critical"]
        high_instructions = [i for i in self._instructions if i.get("threat_level") == "high"]

        print(f"\n{'='*80}")
        print(f"DEBUG DISASSEMBLY VIEW:")
        print(f"Total instructions: {total_instructions}")
        print(f"Suspicious instructions: {len(suspicious_instructions)}")
        print(f"  - Critical: {len(critical_instructions)}")
        print(f"  - High: {len(high_instructions)}")

        if suspicious_instructions:
            print(f"\nFirst 5 suspicious instructions:")
            for i, insn in enumerate(suspicious_instructions[:5]):
                print(f"  {i+1}. {insn.get('address', '?')}: {insn.get('mnemonic', '?')} - [{insn.get('threat_level', '?')}] {insn.get('suspicion_reasons', [])}")
        else:
            print("WARNING: NO SUSPICIOUS INSTRUCTIONS FOUND!")
        print(f"{'='*80}\n")

        theme = get_theme_manager()
        p = theme.get_palette()

        # Background colors for threat levels
        threat_bg_colors = {
            "critical": "rgba(248, 81, 73, 0.25)",   # Red with transparency
            "high": "rgba(255, 123, 114, 0.20)",     # Light red
            "medium": "rgba(210, 153, 34, 0.15)",    # Orange
            "low": "rgba(227, 179, 65, 0.12)",       # Yellow
        }

        # Text colors for threat levels
        threat_text_colors = {
            "critical": "#f85149",  # Red
            "high": "#ff7b72",      # Light red
            "medium": "#d29922",    # Orange
            "low": "#e3b341",       # Yellow
        }

        # Filter instructions if needed
        instructions_to_show = self._instructions
        if self._show_only_suspicious:
            instructions_to_show = [
                insn for insn in self._instructions
                if insn.get("is_suspicious", False)
            ]

        if not instructions_to_show:
            self._disasm_view.setPlainText("No suspicious instructions found")
            return

        # Build HTML with color-coded backgrounds
        html_lines = []
        html_lines.append(f'<pre style="font-family: monospace; color: {p.text_primary}; background-color: {p.bg_primary}; margin: 0; padding: 5px;">')

        for insn in instructions_to_show:
            addr = insn.get("address", "00000000")
            bytes_hex = insn.get("bytes", "")
            mnemonic = insn.get("mnemonic", "")
            op_str = insn.get("op_str", "")

            # Get suspicious info
            is_suspicious = insn.get("is_suspicious", False)
            threat_level = insn.get("threat_level", "clean")
            suspicion_reasons = insn.get("suspicion_reasons", [])

            # Format base instruction
            line_text = f"{addr}:  {bytes_hex:<24} {mnemonic:<8} {op_str}"

            # Build HTML line with background color if suspicious
            if is_suspicious and threat_level in threat_bg_colors:
                bg_color = threat_bg_colors[threat_level]
                text_color = threat_text_colors.get(threat_level, p.text_primary)

                # Add threat indicator
                threat_indicator = f"<b style='color: {text_color};'>[{threat_level.upper()}]</b>"
                line_text = f"{line_text:<80} {threat_indicator}"

                # Add first reason if available
                if suspicion_reasons:
                    line_text += f"  <span style='color: {text_color};'>⚠ {suspicion_reasons[0]}</span>"

                # Wrap in span with background color
                html_line = f'<span style="background-color: {bg_color}; display: block;">{line_text}</span>'
            else:
                # Normal instruction - add comments if needed
                if insn.get("is_call"):
                    line_text += "  <span style='color: #8b949e;'>; call</span>"
                elif insn.get("is_ret"):
                    line_text += "  <span style='color: #8b949e;'>; return</span>"

                html_line = f'<span style="display: block;">{line_text}</span>'

            html_lines.append(html_line)

        html_lines.append('</pre>')

        # DEBUG: Show HTML generation
        html_content = '\n'.join(html_lines)
        print(f"DEBUG: Generated HTML with {len(html_lines)} lines")
        print(f"DEBUG: HTML contains 'background-color': {('background-color' in html_content)}")
        if 'background-color' in html_content:
            print(f"DEBUG: Found {html_content.count('background-color')} background colors in HTML")

        # Set HTML content
        self._disasm_view.setHtml(html_content)

    def _toggle_suspicious_filter(self) -> None:
        """Toggle suspicious instruction filter."""
        self._show_only_suspicious = self._suspicious_filter.isChecked()
        if self._show_only_suspicious:
            self._suspicious_filter.setText("Show All Instructions")
        else:
            self._suspicious_filter.setText("Show Only Suspicious")
        self._render_disassembly()

    def set_functions(self, functions: List[Dict]) -> None:
        """Set detected functions."""
        self._functions_table.setRowCount(len(functions))

        for row, func in enumerate(functions):
            addr_item = QTableWidgetItem(func.get("address", ""))
            name_item = QTableWidgetItem(func.get("name", f"sub_{row}"))

            self._functions_table.setItem(row, 0, addr_item)
            self._functions_table.setItem(row, 1, name_item)

    def set_call_targets(self, targets: List[Dict]) -> None:
        """Set call target references."""
        self._calls_table.setRowCount(len(targets))

        for row, target in enumerate(targets):
            from_item = QTableWidgetItem(target.get("from", ""))
            to_item = QTableWidgetItem(target.get("target", ""))

            self._calls_table.setItem(row, 0, from_item)
            self._calls_table.setItem(row, 1, to_item)

    def _on_arch_changed(self, arch: str) -> None:
        """Handle architecture change."""
        self._current_arch = arch.lower()
        # Would trigger re-disassembly in real implementation

    def _go_to_address(self) -> None:
        """Navigate to specified address."""
        text = self._address_input.text().strip()

        try:
            if text.startswith("0x") or text.startswith("0X"):
                target_addr = int(text, 16)
            else:
                target_addr = int(text)
        except ValueError:
            return

        # Find instruction at address
        for i, insn in enumerate(self._instructions):
            addr_str = insn.get("address", "").lstrip("0x")
            try:
                addr = int(addr_str, 16)
                if addr >= target_addr:
                    cursor = self._disasm_view.textCursor()
                    cursor.movePosition(QTextCursor.MoveOperation.Start)
                    cursor.movePosition(
                        QTextCursor.MoveOperation.Down,
                        QTextCursor.MoveMode.MoveAnchor,
                        i
                    )
                    self._disasm_view.setTextCursor(cursor)
                    self._disasm_view.centerCursor()
                    break
            except ValueError:
                continue

    def _on_function_selected(self, row: int, col: int) -> None:
        """Handle function selection."""
        addr_item = self._functions_table.item(row, 0)
        if addr_item:
            self._address_input.setText(addr_item.text())
            self._go_to_address()

    def clear(self) -> None:
        """Clear disassembly view."""
        self._instructions = []
        self._disasm_view.setPlainText("No instructions loaded")
        self._functions_table.setRowCount(0)
        self._calls_table.setRowCount(0)
        self._info_label.setText("0 instructions")
