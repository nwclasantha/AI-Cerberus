"""
Application initialization and configuration.

Sets up PyQt6 application with theming and global settings.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QCoreApplication
from PyQt6.QtGui import QFont, QIcon

from .theme import get_theme_manager
from ..utils.config import get_config
from ..utils.logger import get_logger

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Type

logger = get_logger("app")


class MalwareAnalyzerApp(QApplication):
    """
    Main application class.

    Handles:
    - Application initialization
    - Theme setup
    - Global configuration
    - Exception handling
    """

    APP_NAME = "AI-Cerberus"
    APP_VERSION = "1.0.0"
    ORG_NAME = "AI-Cerberus"
    ORG_DOMAIN = "ai-cerberus.local"

    def __init__(self, argv: Optional[List[str]] = None) -> None:
        """
        Initialize application.

        Args:
            argv: Command line arguments
        """
        if argv is None:
            argv = sys.argv

        super().__init__(argv)

        # Set application metadata
        self.setApplicationName(self.APP_NAME)
        self.setApplicationVersion(self.APP_VERSION)
        self.setOrganizationName(self.ORG_NAME)
        self.setOrganizationDomain(self.ORG_DOMAIN)

        # Load configuration
        self._config = get_config()

        # Initialize theme
        self._init_theme()

        # Set up exception handling
        self._setup_exception_handling()

        logger.info(f"Application initialized: {self.APP_NAME} v{self.APP_VERSION}")

    def _init_theme(self) -> None:
        """Initialize application theme."""
        theme_manager = get_theme_manager()
        theme_manager.initialize(self)

        # Set default font
        font_family = self._config.get("ui.font_family", "Segoe UI")
        font_size = self._config.get("ui.font_size", 13)

        # Validate font size
        if not isinstance(font_size, int) or font_size < 8:
            font_size = 13
        elif font_size > 24:
            font_size = 24

        self.setFont(QFont(font_family, font_size))

        # Set application icon (.ico for Windows, multi-resolution)
        icon_path = Path(__file__).resolve().parent.parent.parent / "resources" / "icons" / "cerberus.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
            logger.info(f"Application icon loaded: {icon_path}")
        else:
            logger.warning(f"Application icon not found: {icon_path}")

    def _setup_exception_handling(self) -> None:
        """Set up global exception handling."""
        # Store original excepthook
        self._original_excepthook = sys.excepthook

        def exception_hook(
            exc_type: Type[BaseException],
            exc_value: BaseException,
            exc_tb: Optional[TracebackType],
        ) -> None:
            """Handle uncaught exceptions."""
            # Don't log KeyboardInterrupt as critical
            if issubclass(exc_type, KeyboardInterrupt):
                logger.info("Application interrupted by user")
                sys.exit(0)
                return

            # Don't log SystemExit as critical
            if issubclass(exc_type, SystemExit):
                sys.exit(exc_value.code if hasattr(exc_value, 'code') else 0)
                return

            logger.critical(
                "Unhandled exception",
                exc_info=(exc_type, exc_value, exc_tb),
            )

            # Call original handler
            if self._original_excepthook is not None:
                self._original_excepthook(exc_type, exc_value, exc_tb)

        sys.excepthook = exception_hook

    @classmethod
    def get_instance(cls) -> Optional[MalwareAnalyzerApp]:
        """
        Get the application instance.

        Returns:
            The current application instance, or None if not running.
        """
        instance = QCoreApplication.instance()
        if isinstance(instance, MalwareAnalyzerApp):
            return instance
        return None


def create_application(argv: Optional[List[str]] = None) -> MalwareAnalyzerApp:
    """
    Create and configure the application.

    Args:
        argv: Command line arguments

    Returns:
        Configured MalwareAnalyzerApp instance
    """
    # Must set High DPI policy BEFORE creating QApplication
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    except AttributeError:
        # Older PyQt6 versions may not have this
        logger.debug("High DPI scale factor policy not available")

    return MalwareAnalyzerApp(argv)
