"""
Progress overlay component.

Provides a loading overlay with progress indication.
"""

from typing import Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QPushButton, QFrame, QGraphicsOpacityEffect,
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, pyqtSignal
from PyQt6.QtGui import QPainter, QColor

from ..theme import get_theme_manager


class ProgressOverlay(QWidget):
    """
    Full-screen progress overlay.

    Features:
    - Semi-transparent background
    - Progress bar with percentage
    - Status message
    - Cancel button
    - Smooth animations
    """

    # Signals
    cancelled = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize progress overlay."""
        super().__init__(parent)

        self._is_visible = False

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._setup_ui()
        self._setup_style()

        # Start hidden
        self.hide()

    def _setup_ui(self) -> None:
        """Set up overlay UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Center container
        container = QFrame()
        container.setObjectName("progressContainer")
        container.setFixedWidth(400)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(32, 32, 32, 32)
        container_layout.setSpacing(16)

        # Title
        self._title = QLabel("Processing...")
        self._title.setObjectName("progressTitle")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self._title)

        # Status message
        self._status = QLabel("Please wait...")
        self._status.setObjectName("progressStatus")
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setWordWrap(True)
        container_layout.addWidget(self._status)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setMinimum(0)
        self._progress.setMaximum(100)
        self._progress.setValue(0)
        self._progress.setTextVisible(True)
        container_layout.addWidget(self._progress)

        # Percentage label
        self._percentage = QLabel("0%")
        self._percentage.setObjectName("progressPercentage")
        self._percentage.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self._percentage)

        container_layout.addSpacing(16)

        # Cancel button
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._cancel_btn.clicked.connect(self._on_cancel)
        container_layout.addWidget(self._cancel_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Center the container
        layout.addStretch()
        layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()

    def _setup_style(self) -> None:
        """Configure overlay appearance."""
        theme = get_theme_manager()
        p = theme.get_palette()

        self.setStyleSheet(f"""
            ProgressOverlay {{
                background-color: rgba(0, 0, 0, 0.7);
            }}
            #progressContainer {{
                background-color: {p.bg_secondary};
                border: 1px solid {p.border_primary};
                border-radius: 12px;
            }}
            #progressTitle {{
                font-size: 18px;
                font-weight: 600;
                color: {p.text_primary};
            }}
            #progressStatus {{
                font-size: 13px;
                color: {p.text_secondary};
            }}
            #progressPercentage {{
                font-size: 24px;
                font-weight: 700;
                color: {p.accent_primary};
            }}
            QProgressBar {{
                background-color: {p.bg_tertiary};
                border: none;
                border-radius: 6px;
                height: 12px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {p.accent_primary};
                border-radius: 6px;
            }}
            QPushButton {{
                background-color: {p.bg_tertiary};
                color: {p.text_primary};
                border: 1px solid {p.border_primary};
                border-radius: 6px;
                padding: 10px 32px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {p.bg_hover};
                border-color: {p.accent_danger};
            }}
        """)

    def paintEvent(self, event) -> None:
        """Paint semi-transparent background."""
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 180))

    def show_progress(
        self,
        title: str = "Processing...",
        status: str = "Please wait...",
        cancellable: bool = True,
    ) -> None:
        """
        Show progress overlay.

        Args:
            title: Progress title
            status: Status message
            cancellable: Whether cancel button is shown
        """
        self._title.setText(title)
        self._status.setText(status)
        self._progress.setValue(0)
        self._percentage.setText("0%")
        self._cancel_btn.setVisible(cancellable)

        # Resize to parent
        if self.parent():
            self.resize(self.parent().size())

        self.show()
        self.raise_()
        self._is_visible = True

    def update_progress(
        self,
        value: int,
        status: Optional[str] = None,
    ) -> None:
        """
        Update progress value.

        Args:
            value: Progress value (0-100)
            status: Optional status update
        """
        self._progress.setValue(value)
        self._percentage.setText(f"{value}%")

        if status:
            self._status.setText(status)

    def hide_progress(self) -> None:
        """Hide progress overlay."""
        self.hide()
        self._is_visible = False

    def _on_cancel(self) -> None:
        """Handle cancel button click."""
        self.cancelled.emit()
        self.hide_progress()

    def set_indeterminate(self, indeterminate: bool = True) -> None:
        """
        Set indeterminate mode (no specific progress).

        Args:
            indeterminate: Whether to show indeterminate progress
        """
        if indeterminate:
            self._progress.setMaximum(0)
            self._percentage.setText("")
        else:
            self._progress.setMaximum(100)

    @property
    def is_visible(self) -> bool:
        """Check if overlay is visible."""
        return self._is_visible


class SpinnerOverlay(QWidget):
    """
    Simple spinner overlay for quick operations.

    Shows a spinning indicator without progress percentage.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize spinner overlay."""
        super().__init__(parent)

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._setup_ui()
        self.hide()

    def _setup_ui(self) -> None:
        """Set up spinner UI."""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Status label
        self._status = QLabel("Loading...")
        self._status.setStyleSheet("""
            QLabel {
                color: #f0f6fc;
                font-size: 14px;
                font-weight: 500;
            }
        """)
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status)

    def paintEvent(self, event) -> None:
        """Paint semi-transparent background."""
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 150))

    def show_spinner(self, message: str = "Loading...") -> None:
        """Show spinner with message."""
        self._status.setText(message)
        if self.parent():
            self.resize(self.parent().size())
        self.show()
        self.raise_()

    def hide_spinner(self) -> None:
        """Hide spinner."""
        self.hide()
