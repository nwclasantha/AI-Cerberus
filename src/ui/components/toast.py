"""
Toast notification component - ENHANCED BEAUTIFUL VERSION.

Provides stunning non-intrusive notifications with:
- Beautiful icons and colors
- Smooth slide + fade animations
- Progress bar showing time remaining
- Modern glassmorphism design
- Box shadows for depth
"""

from __future__ import annotations

from typing import Optional, List
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QPushButton,
    QGraphicsOpacityEffect, QFrame, QProgressBar,
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve,
    pyqtSignal, QPoint, QRect, QParallelAnimationGroup,
    pyqtProperty,
)
from PyQt6.QtGui import QColor, QFont

from ..theme import get_theme_manager


class Toast(QFrame):
    """
    Beautiful toast notification with modern design.

    Features:
    - Animated icons with Unicode symbols
    - Smooth slide-in animation
    - Progress bar showing time remaining
    - Glassmorphism background
    - Elegant close button
    """

    # Signals
    closed = pyqtSignal()
    action_clicked = pyqtSignal()

    # Toast types
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"

    # Beautiful icons for each type
    ICONS = {
        INFO: "ℹ️",
        SUCCESS: "✓",
        WARNING: "⚠",
        ERROR: "✕",
    }

    def __init__(
        self,
        message: str,
        toast_type: str = INFO,
        duration: int = 4000,
        action_text: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ):
        """
        Initialize beautiful toast notification.

        Args:
            message: Notification message
            toast_type: Type (info, success, warning, error)
            duration: Display duration in ms (0 = manual close)
            action_text: Optional action button text
            parent: Parent widget
        """
        super().__init__(parent)

        self._message = message
        self._type = toast_type
        self._duration = duration
        self._slide_pos = 0

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.Tool |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedWidth(380)

        self._setup_ui(action_text)
        self._setup_style()
        self._setup_animation()

    def _setup_ui(self, action_text: Optional[str]) -> None:
        """Set up beautiful toast UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Main content frame
        content_frame = QFrame()
        content_layout = QHBoxLayout(content_frame)
        content_layout.setContentsMargins(20, 16, 16, 16)
        content_layout.setSpacing(14)

        # Beautiful icon with styled background
        icon_container = QFrame()
        icon_container.setFixedSize(40, 40)
        icon_container.setObjectName("iconContainer")
        icon_layout = QVBoxLayout(icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)

        self._icon_label = QLabel(self.ICONS.get(self._type, "•"))
        self._icon_label.setObjectName("toastIcon")
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_font = QFont()
        icon_font.setPointSize(20)
        icon_font.setBold(True)
        self._icon_label.setFont(icon_font)
        icon_layout.addWidget(self._icon_label)

        content_layout.addWidget(icon_container)

        # Message container
        message_layout = QVBoxLayout()
        message_layout.setSpacing(4)

        # Title (toast type)
        title_map = {
            self.INFO: "Information",
            self.SUCCESS: "Success",
            self.WARNING: "Warning",
            self.ERROR: "Error",
        }
        title_label = QLabel(title_map.get(self._type, "Notification"))
        title_label.setObjectName("toastTitle")
        message_layout.addWidget(title_label)

        # Message
        self._message_label = QLabel(self._message)
        self._message_label.setObjectName("toastMessage")
        self._message_label.setWordWrap(True)
        self._message_label.setMaximumWidth(240)
        message_layout.addWidget(self._message_label)

        # Action button (if provided)
        if action_text:
            action_btn = QPushButton(action_text)
            action_btn.setObjectName("toastAction")
            action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            action_btn.clicked.connect(self._on_action)
            message_layout.addWidget(action_btn)

        content_layout.addLayout(message_layout, 1)

        # Elegant close button
        close_btn = QPushButton("✕")
        close_btn.setObjectName("toastClose")
        close_btn.setFixedSize(32, 32)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.dismiss)
        content_layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignTop)

        main_layout.addWidget(content_frame)

        # Beautiful progress bar
        if self._duration > 0:
            self._progress_bar = QProgressBar()
            self._progress_bar.setObjectName("toastProgress")
            self._progress_bar.setFixedHeight(3)
            self._progress_bar.setTextVisible(False)
            self._progress_bar.setMaximum(self._duration)
            self._progress_bar.setValue(self._duration)
            main_layout.addWidget(self._progress_bar)

            # Update progress bar
            self._progress_timer = QTimer(self)
            self._progress_timer.setInterval(10)
            self._progress_timer.timeout.connect(self._update_progress)
        else:
            self._progress_bar = None
            self._progress_timer = None

    def _setup_style(self) -> None:
        """Configure beautiful toast appearance based on type."""
        theme = get_theme_manager()
        p = theme.get_palette()

        # Color schemes for each type
        colors = {
            self.INFO: {
                "bg": "rgba(88, 166, 255, 0.15)",
                "border": "#58a6ff",
                "icon_bg": "rgba(88, 166, 255, 0.25)",
                "icon_color": "#58a6ff",
                "progress": "#58a6ff",
            },
            self.SUCCESS: {
                "bg": "rgba(63, 185, 80, 0.15)",
                "border": "#3fb950",
                "icon_bg": "rgba(63, 185, 80, 0.25)",
                "icon_color": "#3fb950",
                "progress": "#3fb950",
            },
            self.WARNING: {
                "bg": "rgba(210, 153, 34, 0.15)",
                "border": "#d29922",
                "icon_bg": "rgba(210, 153, 34, 0.25)",
                "icon_color": "#d29922",
                "progress": "#d29922",
            },
            self.ERROR: {
                "bg": "rgba(248, 81, 73, 0.15)",
                "border": "#f85149",
                "icon_bg": "rgba(248, 81, 73, 0.25)",
                "icon_color": "#f85149",
                "progress": "#f85149",
            },
        }

        c = colors.get(self._type, colors[self.INFO])

        self.setStyleSheet(f"""
            Toast {{
                background-color: {c["bg"]};
                border: 2px solid {c["border"]};
                border-radius: 12px;
            }}

            #iconContainer {{
                background-color: {c["icon_bg"]};
                border-radius: 20px;
                border: 2px solid {c["border"]};
            }}

            #toastIcon {{
                color: {c["icon_color"]};
            }}

            #toastTitle {{
                color: {p.text_primary};
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 0.3px;
            }}

            #toastMessage {{
                color: {p.text_secondary};
                font-size: 13px;
                line-height: 1.5;
            }}

            #toastAction {{
                background-color: {c["border"]};
                color: {p.text_primary};
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: 600;
                font-size: 12px;
                margin-top: 4px;
            }}

            #toastAction:hover {{
                background-color: {c["icon_color"]};
                opacity: 0.9;
            }}

            #toastClose {{
                background-color: transparent;
                color: {p.text_muted};
                border: none;
                border-radius: 16px;
                font-size: 18px;
                font-weight: 600;
            }}

            #toastClose:hover {{
                background-color: rgba(255, 255, 255, 0.1);
                color: {p.text_primary};
            }}

            #toastProgress {{
                background-color: rgba(255, 255, 255, 0.1);
                border: none;
                border-bottom-left-radius: 10px;
                border-bottom-right-radius: 10px;
            }}

            #toastProgress::chunk {{
                background-color: {c["progress"]};
                border-bottom-left-radius: 10px;
                border-bottom-right-radius: 10px;
            }}
        """)

    def _setup_animation(self) -> None:
        """Set up fade and slide animations."""
        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)
        self._opacity.setOpacity(0)

    @pyqtProperty(int)
    def slidePos(self) -> int:
        """Get slide position property."""
        return self._slide_pos

    @slidePos.setter
    def slidePos(self, value: int) -> None:
        """Set slide position property."""
        self._slide_pos = value
        current_pos = self.pos()
        self.move(current_pos.x() + value, current_pos.y())

    def show_toast(self) -> None:
        """Show toast with beautiful slide + fade animation."""
        self.show()
        self.raise_()

        # Start position (off-screen to the right)
        start_pos = self.pos()
        self.move(start_pos.x() + 50, start_pos.y())

        # Create parallel animation group
        animation_group = QParallelAnimationGroup(self)

        # Fade in animation
        fade_in = QPropertyAnimation(self._opacity, b"opacity")
        fade_in.setDuration(400)
        fade_in.setStartValue(0)
        fade_in.setEndValue(1)
        fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation_group.addAnimation(fade_in)

        # Slide in animation
        slide_in = QPropertyAnimation(self, b"pos")
        slide_in.setDuration(400)
        slide_in.setStartValue(QPoint(start_pos.x() + 50, start_pos.y()))
        slide_in.setEndValue(start_pos)
        slide_in.setEasingCurve(QEasingCurve.Type.OutBack)
        animation_group.addAnimation(slide_in)

        animation_group.start()

        # Start progress bar
        if self._progress_timer:
            self._progress_timer.start()

        # Auto dismiss
        if self._duration > 0:
            QTimer.singleShot(self._duration, self.dismiss)

    def _update_progress(self) -> None:
        """Update progress bar."""
        if self._progress_bar:
            current = self._progress_bar.value()
            if current > 0:
                self._progress_bar.setValue(current - 10)
            else:
                if self._progress_timer:
                    self._progress_timer.stop()

    def dismiss(self) -> None:
        """Dismiss toast with beautiful slide + fade animation."""
        # Stop progress timer
        if self._progress_timer:
            self._progress_timer.stop()

        # Create parallel animation group
        animation_group = QParallelAnimationGroup(self)

        # Fade out animation
        fade_out = QPropertyAnimation(self._opacity, b"opacity")
        fade_out.setDuration(300)
        fade_out.setStartValue(1)
        fade_out.setEndValue(0)
        fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
        animation_group.addAnimation(fade_out)

        # Slide out animation
        current_pos = self.pos()
        slide_out = QPropertyAnimation(self, b"pos")
        slide_out.setDuration(300)
        slide_out.setStartValue(current_pos)
        slide_out.setEndValue(QPoint(current_pos.x() + 50, current_pos.y()))
        slide_out.setEasingCurve(QEasingCurve.Type.InCubic)
        animation_group.addAnimation(slide_out)

        animation_group.finished.connect(self._on_dismissed)
        animation_group.start()

    def _on_dismissed(self) -> None:
        """Handle dismissal complete."""
        self.closed.emit()
        self.deleteLater()

    def _on_action(self) -> None:
        """Handle action button click."""
        self.action_clicked.emit()
        self.dismiss()


class ToastManager(QWidget):
    """
    Manages beautiful toast notifications for an application.

    Features:
    - Stack multiple toasts with beautiful spacing
    - Auto-positioning with smooth transitions
    - Maximum toast limit
    - Smooth repositioning animations
    """

    MAX_TOASTS = 5

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize toast manager."""
        super().__init__(parent)

        self._toasts: List[Toast] = []
        self._parent_widget = parent

    def show_toast(
        self,
        message: str,
        toast_type: str = Toast.INFO,
        duration: int = 4000,
        action_text: Optional[str] = None,
    ) -> Toast:
        """
        Show a beautiful toast notification.

        Args:
            message: Notification message
            toast_type: Type (info, success, warning, error)
            duration: Display duration in ms
            action_text: Optional action button text

        Returns:
            Toast instance
        """
        # Remove oldest if at limit
        while len(self._toasts) >= self.MAX_TOASTS:
            self._toasts[0].dismiss()

        toast = Toast(
            message=message,
            toast_type=toast_type,
            duration=duration,
            action_text=action_text,
            parent=self._parent_widget,
        )

        toast.closed.connect(lambda: self._remove_toast(toast))
        self._toasts.append(toast)

        self._position_toasts()
        toast.show_toast()

        return toast

    def _remove_toast(self, toast: Toast) -> None:
        """Remove toast from manager and reposition."""
        if toast in self._toasts:
            self._toasts.remove(toast)
            # Smooth repositioning after removal
            QTimer.singleShot(100, self._position_toasts)

    def _position_toasts(self) -> None:
        """Position all active toasts with beautiful spacing."""
        if not self._parent_widget:
            return

        parent_rect = self._parent_widget.rect()
        parent_pos = self._parent_widget.mapToGlobal(QPoint(0, 0))

        margin = 20
        spacing = 12
        y_offset = margin

        for toast in self._toasts:
            toast.adjustSize()
            toast_width = toast.width()
            toast_height = toast.height()

            # Position from top-right with margin
            x = parent_pos.x() + parent_rect.width() - toast_width - margin
            y = parent_pos.y() + y_offset

            # Smooth move animation
            if toast.pos() != QPoint(x, y):
                animation = QPropertyAnimation(toast, b"pos")
                animation.setDuration(300)
                animation.setStartValue(toast.pos())
                animation.setEndValue(QPoint(x, y))
                animation.setEasingCurve(QEasingCurve.Type.OutCubic)
                animation.start()
            else:
                toast.move(x, y)

            y_offset += toast_height + spacing

    def info(self, message: str, **kwargs) -> Toast:
        """Show beautiful info toast."""
        return self.show_toast(message, Toast.INFO, **kwargs)

    def success(self, message: str, **kwargs) -> Toast:
        """Show beautiful success toast."""
        return self.show_toast(message, Toast.SUCCESS, **kwargs)

    def warning(self, message: str, **kwargs) -> Toast:
        """Show beautiful warning toast."""
        return self.show_toast(message, Toast.WARNING, **kwargs)

    def error(self, message: str, **kwargs) -> Toast:
        """Show beautiful error toast."""
        return self.show_toast(message, Toast.ERROR, **kwargs)

    def clear_all(self) -> None:
        """Dismiss all toasts."""
        for toast in self._toasts[:]:
            toast.dismiss()
