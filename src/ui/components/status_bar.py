"""
Enhanced status bar component.

Provides detailed status information and quick indicators.
"""

from __future__ import annotations

from typing import Optional
from PyQt6.QtWidgets import (
    QStatusBar, QWidget, QHBoxLayout, QLabel, QProgressBar,
    QFrame, QSizePolicy,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
import psutil
from datetime import datetime

from ..theme import get_theme_manager
from ...utils.logger import get_logger

logger = get_logger("status_bar")


class StatusIndicator(QFrame):
    """Status indicator with colored dot and label."""

    def __init__(
        self,
        label: str,
        status: str = "disconnected",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)

        self._label = label
        self._status = status

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 0, 8, 0)
        layout.setSpacing(6)

        # Status dot
        self._dot = QLabel()
        self._dot.setFixedSize(8, 8)
        layout.addWidget(self._dot)

        # Label
        self._label_widget = QLabel(f"{label}: {status}")
        layout.addWidget(self._label_widget)

        self._update_style()

    def set_status(self, status: str) -> None:
        """Update status."""
        self._status = status
        self._label_widget.setText(f"{self._label}: {status}")
        self._update_style()

    def _update_style(self) -> None:
        """Update indicator style based on status."""
        theme = get_theme_manager()
        p = theme.get_palette()

        colors = {
            "connected": p.accent_success,
            "disconnected": p.text_muted,
            "error": p.accent_danger,
            "warning": p.accent_warning,
            "active": p.accent_primary,
        }

        color = colors.get(self._status.lower(), p.text_muted)

        self._dot.setStyleSheet(f"""
            background-color: {color};
            border-radius: 4px;
        """)


class EnhancedStatusBar(QStatusBar):
    """
    Enhanced status bar with multiple indicators.

    Features:
    - Database connection status
    - VirusTotal API status
    - Sample count
    - CPU/Memory usage
    - Current time
    - Analysis progress
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize status bar."""
        super().__init__(parent)

        self._setup_ui()
        self._setup_style()

        # Update timer for dynamic info
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_dynamic_info)
        self._timer.start(1000)  # Update every second

    def _setup_ui(self) -> None:
        """Set up status bar UI."""
        # Ready message
        self._message_label = QLabel("Ready")
        self.addWidget(self._message_label, 1)

        # Progress bar (hidden by default)
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(150)
        self._progress.setMaximumHeight(16)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self.addWidget(self._progress)

        # Database indicator
        self._db_indicator = StatusIndicator("Database", "connected")
        self.addPermanentWidget(self._db_indicator)

        # Separator
        self._add_separator()

        # VirusTotal indicator
        self._vt_indicator = StatusIndicator("VT", "disconnected")
        self.addPermanentWidget(self._vt_indicator)

        # Separator
        self._add_separator()

        # Sample count
        self._sample_label = QLabel("0 samples")
        self.addPermanentWidget(self._sample_label)

        # Separator
        self._add_separator()

        # CPU usage
        self._cpu_label = QLabel("CPU: 0%")
        self.addPermanentWidget(self._cpu_label)

        # Memory usage
        self._memory_label = QLabel("RAM: 0%")
        self.addPermanentWidget(self._memory_label)

        # Separator
        self._add_separator()

        # Time
        self._time_label = QLabel()
        self._time_label.setMinimumWidth(60)
        self.addPermanentWidget(self._time_label)

    def _add_separator(self) -> None:
        """Add vertical separator."""
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setMaximumHeight(16)
        self.addPermanentWidget(sep)

    def _setup_style(self) -> None:
        """Configure status bar appearance."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self.setStyleSheet(f"""
            QStatusBar {{
                background-color: {p.bg_secondary};
                border-top: 1px solid {p.border_primary};
                color: {p.text_secondary};
                padding: 4px 8px;
            }}
            QStatusBar::item {{
                border: none;
            }}
            QLabel {{
                color: {p.text_secondary};
                padding: 0 4px;
            }}
            QFrame[frameShape="5"] {{
                background-color: {p.border_primary};
                max-width: 1px;
            }}
            QProgressBar {{
                background-color: {p.bg_tertiary};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {p.accent_primary};
                border-radius: 3px;
            }}
        """)

    def _update_dynamic_info(self) -> None:
        """Update dynamic information (CPU, memory, time)."""
        # CPU usage
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            self._cpu_label.setText(f"CPU: {cpu_percent:.0f}%")
        except Exception as e:
            self._cpu_label.setText("CPU: N/A")
            logger.warning(f"Failed to get CPU usage: {e}")

        # Memory usage
        try:
            memory = psutil.virtual_memory()
            self._memory_label.setText(f"RAM: {memory.percent:.0f}%")
        except Exception as e:
            self._memory_label.setText("RAM: N/A")
            logger.warning(f"Failed to get memory usage: {e}")

        # Time
        now = datetime.now()
        self._time_label.setText(now.strftime("%H:%M"))

    def set_message(self, message: str, timeout: int = 0) -> None:
        """
        Set status message.

        Args:
            message: Message to display
            timeout: Auto-clear timeout in ms (0 = permanent)
        """
        self._message_label.setText(message)
        if timeout > 0:
            QTimer.singleShot(timeout, lambda: self._message_label.setText("Ready"))

    def set_progress(self, value: int, maximum: int = 100) -> None:
        """
        Set progress bar value.

        Args:
            value: Current value
            maximum: Maximum value
        """
        if value < 0:
            self._progress.hide()
        else:
            self._progress.setMaximum(maximum)
            self._progress.setValue(value)
            self._progress.show()

    def hide_progress(self) -> None:
        """Hide progress bar."""
        self._progress.hide()

    def set_database_status(self, connected: bool) -> None:
        """Set database connection status."""
        status = "connected" if connected else "disconnected"
        self._db_indicator.set_status(status)

    def set_virustotal_status(self, status: str) -> None:
        """Set VirusTotal API status."""
        self._vt_indicator.set_status(status)

    def set_sample_count(self, count: int) -> None:
        """Set sample count display."""
        self._sample_label.setText(f"{count} samples")

    def start_analysis(self, filename: str) -> None:
        """Show analysis started status."""
        self.set_message(f"Analyzing: {filename}")
        self.set_progress(0)

    def finish_analysis(self) -> None:
        """Show analysis completed status."""
        self.set_message("Analysis complete", timeout=3000)
        self.hide_progress()
