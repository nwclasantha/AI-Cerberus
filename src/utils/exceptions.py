"""
Custom exceptions for the Malware Analysis Platform.

This module defines a hierarchy of exceptions used throughout the application
for proper error handling and reporting.
"""

from typing import Optional, Any


class MalwareAnalyzerError(Exception):
    """Base exception for all Malware Analyzer errors."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or "UNKNOWN_ERROR"
        self.details = details or {}

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"

    def to_dict(self) -> dict:
        """Convert exception to dictionary for serialization."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(MalwareAnalyzerError):
    """Raised when there is a configuration-related error."""

    def __init__(self, message: str, config_key: Optional[str] = None):
        super().__init__(
            message,
            code="CONFIG_ERROR",
            details={"config_key": config_key} if config_key else {},
        )


class AnalysisError(MalwareAnalyzerError):
    """Raised when file analysis fails."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        analysis_type: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="ANALYSIS_ERROR",
            details={
                "file_path": file_path,
                "analysis_type": analysis_type,
            },
        )


class FileFormatError(AnalysisError):
    """Raised when a file format is not supported or invalid."""

    def __init__(self, message: str, file_path: Optional[str] = None):
        super().__init__(message, file_path, "format_detection")
        self.code = "FILE_FORMAT_ERROR"


class FileTooLargeError(AnalysisError):
    """Raised when a file exceeds the maximum allowed size."""

    def __init__(
        self,
        file_path: str,
        file_size: int,
        max_size: int,
    ):
        message = f"File size ({file_size:,} bytes) exceeds maximum ({max_size:,} bytes)"
        super().__init__(message, file_path, "size_check")
        self.code = "FILE_TOO_LARGE"
        self.details.update({
            "file_size": file_size,
            "max_size": max_size,
        })


class DatabaseError(MalwareAnalyzerError):
    """Raised when a database operation fails."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        table: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="DATABASE_ERROR",
            details={
                "operation": operation,
                "table": table,
            },
        )


class PluginError(MalwareAnalyzerError):
    """Raised when a plugin operation fails."""

    def __init__(
        self,
        message: str,
        plugin_name: Optional[str] = None,
        plugin_version: Optional[str] = None,
    ):
        super().__init__(
            message,
            code="PLUGIN_ERROR",
            details={
                "plugin_name": plugin_name,
                "plugin_version": plugin_version,
            },
        )


class PluginLoadError(PluginError):
    """Raised when a plugin fails to load."""

    def __init__(self, plugin_name: str, reason: str):
        super().__init__(
            f"Failed to load plugin '{plugin_name}': {reason}",
            plugin_name=plugin_name,
        )
        self.code = "PLUGIN_LOAD_ERROR"


class IntegrationError(MalwareAnalyzerError):
    """Raised when an external integration fails."""

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        super().__init__(
            message,
            code="INTEGRATION_ERROR",
            details={
                "service": service,
                "status_code": status_code,
            },
        )


class RateLimitError(IntegrationError):
    """Raised when an API rate limit is exceeded."""

    def __init__(self, service: str, retry_after: Optional[int] = None):
        message = f"Rate limit exceeded for {service}"
        if retry_after:
            message += f". Retry after {retry_after} seconds"
        super().__init__(message, service=service)
        self.code = "RATE_LIMIT_ERROR"
        self.details["retry_after"] = retry_after


class YaraError(AnalysisError):
    """Raised when YARA scanning fails."""

    def __init__(self, message: str, rule_file: Optional[str] = None):
        super().__init__(message, analysis_type="yara_scan")
        self.code = "YARA_ERROR"
        self.details["rule_file"] = rule_file


class DisassemblyError(AnalysisError):
    """Raised when disassembly fails."""

    def __init__(
        self,
        message: str,
        architecture: Optional[str] = None,
        offset: Optional[int] = None,
    ):
        super().__init__(message, analysis_type="disassembly")
        self.code = "DISASSEMBLY_ERROR"
        self.details.update({
            "architecture": architecture,
            "offset": offset,
        })


class MLClassificationError(MalwareAnalyzerError):
    """Raised when ML classification fails."""

    def __init__(self, message: str, model_name: Optional[str] = None):
        super().__init__(
            message,
            code="ML_ERROR",
            details={"model_name": model_name},
        )
