"""
Structured logging for the Malware Analysis Platform.

Provides consistent, structured logging with support for:
- JSON formatted output for production
- Pretty console output for development
- Log rotation and file management
- Context injection
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, MutableMapping, Optional, Tuple


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured log output."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields
        if hasattr(record, "extra_data") and record.extra_data:
            log_data.update(record.extra_data)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


class PrettyFormatter(logging.Formatter):
    """Colorized formatter for console output."""

    COLORS: Dict[str, str] = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREY = "\033[90m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, "")

        # Format timestamp
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Format level with padding
        level = f"{record.levelname:8}"

        # Format logger name (shortened if too long)
        logger_name = record.name
        if len(logger_name) > 20:
            parts = logger_name.split(".")
            if len(parts) > 1:
                logger_name = ".".join(p[0] for p in parts[:-1]) + "." + parts[-1]
            # If only one part and still too long, truncate
            if len(logger_name) > 20:
                logger_name = logger_name[:17] + "..."

        # Build message
        message = record.getMessage()

        # Add extra data if present
        extra = ""
        if hasattr(record, "extra_data") and record.extra_data:
            extra_items = [f"{k}={v}" for k, v in record.extra_data.items()]
            extra = f" | {', '.join(extra_items)}"

        formatted = (
            f"{self.BOLD}[{timestamp}]{self.RESET} "
            f"{color}{level}{self.RESET} "
            f"{self.GREY}{logger_name:20}{self.RESET} "
            f"{message}{extra}"
        )

        # Add exception if present
        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"

        return formatted


class ContextLogger(logging.LoggerAdapter):
    """Logger adapter that injects context into all log messages."""

    def process(
        self, msg: str, kwargs: MutableMapping[str, Any]
    ) -> Tuple[str, MutableMapping[str, Any]]:
        """Process log message and inject extra context."""
        # Handle extra_data passed as direct kwarg (non-standard but used in codebase)
        extra_data_direct = kwargs.pop("extra_data", None)

        extra = kwargs.get("extra", {})
        if extra is None:
            extra = {}

        # Safely get adapter's extra context (could be None)
        adapter_extra = self.extra if self.extra else {}

        # Merge adapter extra with call extra
        combined_extra = {**adapter_extra, **extra}

        # Add directly passed extra_data
        if extra_data_direct:
            combined_extra.update(extra_data_direct)

        # Store as extra_data for formatters
        kwargs["extra"] = {"extra_data": combined_extra}

        return msg, kwargs


class LoggerManager:
    """
    Manages logging configuration and logger instances.

    Thread-safe singleton implementation.
    """

    _instance: Optional[LoggerManager] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> LoggerManager:
        """Thread-safe singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                # Double-check locking pattern
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._loggers: Dict[str, logging.Logger] = {}
                    instance._initialized: bool = False
                    cls._instance = instance
        return cls._instance

    def setup(
        self,
        level: str = "INFO",
        log_file: Optional[str] = None,
        format_type: str = "pretty",
        max_size_mb: int = 50,
        backup_count: int = 5,
    ) -> None:
        """
        Configure the logging system.

        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (None for console only)
            format_type: "json" for structured or "pretty" for colored
            max_size_mb: Maximum log file size before rotation
            backup_count: Number of backup files to keep
        """
        if self._initialized:
            return

        with self._lock:
            # Double-check after acquiring lock
            if self._initialized:
                return

            root_logger = logging.getLogger("malware_analyzer")

            # Validate and set log level
            log_level = getattr(logging, level.upper(), logging.INFO)
            root_logger.setLevel(log_level)

            # Clear existing handlers
            root_logger.handlers.clear()

            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.DEBUG)

            if format_type == "json":
                console_handler.setFormatter(StructuredFormatter())
            else:
                console_handler.setFormatter(PrettyFormatter())

            root_logger.addHandler(console_handler)

            # File handler (always JSON for parsing)
            if log_file:
                try:
                    log_path = Path(log_file)
                    log_path.parent.mkdir(parents=True, exist_ok=True)

                    file_handler = RotatingFileHandler(
                        log_path,
                        maxBytes=max_size_mb * 1024 * 1024,
                        backupCount=backup_count,
                        encoding="utf-8",
                    )
                    file_handler.setLevel(logging.DEBUG)
                    file_handler.setFormatter(StructuredFormatter())
                    root_logger.addHandler(file_handler)
                except (OSError, PermissionError) as e:
                    # Log to console if file handler fails
                    root_logger.warning(f"Failed to create log file handler: {e}")

            self._initialized = True

    def get_logger(
        self,
        name: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ContextLogger:
        """
        Get a logger instance with optional context.

        Args:
            name: Logger name (usually module name)
            context: Optional context to inject into all log messages

        Returns:
            ContextLogger instance
        """
        if name not in self._loggers:
            with self._lock:
                # Double-check after acquiring lock
                if name not in self._loggers:
                    logger = logging.getLogger(f"malware_analyzer.{name}")
                    self._loggers[name] = logger

        return ContextLogger(self._loggers[name], context or {})

    def reset(self) -> None:
        """
        Reset the logger manager state.

        Useful for testing or reconfiguration.
        """
        with self._lock:
            self._initialized = False
            self._loggers.clear()

            # Clear handlers from root logger
            root_logger = logging.getLogger("malware_analyzer")
            root_logger.handlers.clear()


# Global manager instance
_manager = LoggerManager()


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_type: str = "pretty",
) -> None:
    """
    Configure the global logging system.

    Args:
        level: Logging level
        log_file: Optional log file path
        format_type: "json" or "pretty"
    """
    _manager.setup(level=level, log_file=log_file, format_type=format_type)


def get_logger(
    name: str,
    context: Optional[Dict[str, Any]] = None,
) -> ContextLogger:
    """
    Get a logger instance.

    Args:
        name: Logger name
        context: Optional context dict

    Returns:
        ContextLogger instance
    """
    return _manager.get_logger(name, context)


def reset_logging() -> None:
    """
    Reset the logging system.

    Useful for testing or reconfiguration.
    """
    _manager.reset()
