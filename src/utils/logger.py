"""
Structured logging for the Malware Analysis Platform.

Provides consistent, structured logging with support for:
- JSON formatted output for production
- Pretty console output for development
- Log rotation and file management
- Context injection
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from logging.handlers import RotatingFileHandler
import json


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured log output."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


class PrettyFormatter(logging.Formatter):
    """Colorized formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, "")

        # Format timestamp
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Format level with padding
        level = f"{record.levelname:8}"

        # Format logger name (shortened)
        logger_name = record.name
        if len(logger_name) > 20:
            parts = logger_name.split(".")
            logger_name = ".".join(p[0] for p in parts[:-1]) + "." + parts[-1]

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
            f"\033[90m{logger_name:20}\033[0m "
            f"{message}{extra}"
        )

        # Add exception if present
        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"

        return formatted


class ContextLogger(logging.LoggerAdapter):
    """Logger adapter that injects context into all log messages."""

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log message and inject extra context."""
        extra = kwargs.get("extra", {})

        # Merge adapter extra with call extra
        combined_extra = {**self.extra, **extra}

        # Store as extra_data for formatters
        if "extra_data" not in kwargs:
            kwargs["extra"] = {"extra_data": combined_extra}
        else:
            kwargs["extra"]["extra_data"].update(combined_extra)

        return msg, kwargs


class LoggerManager:
    """Manages logging configuration and logger instances."""

    _instance: Optional["LoggerManager"] = None
    _loggers: Dict[str, logging.Logger] = {}
    _initialized: bool = False

    def __new__(cls) -> "LoggerManager":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
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

        root_logger = logging.getLogger("malware_analyzer")
        root_logger.setLevel(getattr(logging, level.upper()))

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
            logger = logging.getLogger(f"malware_analyzer.{name}")
            self._loggers[name] = logger

        return ContextLogger(self._loggers[name], context or {})


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
