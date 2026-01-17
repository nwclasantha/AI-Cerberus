"""
Base analyzer class and common data structures.

Defines the interface that all analyzers must implement
and common result types used throughout the application.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import magic

from ..utils.exceptions import AnalysisError, FileFormatError, FileTooLargeError
from ..utils.logger import get_logger
from ..utils.helpers import format_bytes

logger = get_logger("analyzer")


@dataclass
class FileInfo:
    """Basic file information."""

    filename: str
    file_path: str
    file_size: int
    file_type: str
    mime_type: str
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None

    @classmethod
    def from_path(cls, file_path: Path) -> FileInfo:
        """Create FileInfo from file path."""
        stats = file_path.stat()

        try:
            file_type = magic.from_file(str(file_path))
            mime_type = magic.from_file(str(file_path), mime=True)
        except Exception:
            file_type = "Unknown"
            mime_type = "application/octet-stream"

        return cls(
            filename=file_path.name,
            file_path=str(file_path.absolute()),
            file_size=stats.st_size,
            file_type=file_type,
            mime_type=mime_type,
            created=datetime.fromtimestamp(stats.st_ctime, tz=timezone.utc),
            modified=datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc),
            accessed=datetime.fromtimestamp(stats.st_atime, tz=timezone.utc),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "filename": self.filename,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_size_formatted": format_bytes(self.file_size),
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
        }


@dataclass
class ThreatScore:
    """Threat assessment score and breakdown."""

    score: float  # 0-100
    verdict: str  # malicious, suspicious, benign, unknown
    confidence: float  # 0-1
    indicators: List[str] = field(default_factory=list)
    breakdown: Dict[str, float] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        """Get severity level based on score."""
        if self.score >= 70:
            return "critical"
        elif self.score >= 50:
            return "high"
        elif self.score >= 30:
            return "medium"
        elif self.score >= 15:
            return "low"
        return "info"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "score": self.score,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "indicators": self.indicators,
            "breakdown": self.breakdown,
        }


def _utcnow() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


@dataclass
class AnalysisResult:
    """Complete analysis result container."""

    file_info: FileInfo
    timestamp: datetime = field(default_factory=_utcnow)
    duration_seconds: float = 0.0

    # Analysis components (populated by analyzers)
    hashes: Optional[Any] = None
    entropy: Optional[Any] = None
    strings: Optional[Any] = None
    binary_info: Optional[Any] = None
    yara_matches: List[Any] = field(default_factory=list)
    behavioral_indicators: Optional[Any] = None
    network_iocs: Optional[Any] = None
    disassembly: Optional[Any] = None
    ml_classification: Optional[Any] = None

    # Threat assessment
    threat_score: Optional[ThreatScore] = None

    # Additional metadata
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "file_info": self.file_info.to_dict() if self.file_info else None,
            "timestamp": self.timestamp.isoformat(),
            "duration_seconds": self.duration_seconds,
            "threat_score": self.threat_score.to_dict() if self.threat_score else None,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }

        # Add component results if they have to_dict method
        components = [
            "hashes", "entropy", "strings", "binary_info",
            "behavioral_indicators", "network_iocs", "disassembly",
            "ml_classification",
        ]

        for component in components:
            value = getattr(self, component)
            if value is not None:
                if hasattr(value, "to_dict"):
                    result[component] = value.to_dict()
                elif isinstance(value, dict):
                    result[component] = value
                else:
                    result[component] = str(value)

        # YARA matches
        if self.yara_matches:
            result["yara_matches"] = [
                m.to_dict() if hasattr(m, "to_dict") else m
                for m in self.yara_matches
            ]

        return result


class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers.

    Provides common functionality and defines the interface
    that all analyzer implementations must follow.
    """

    def __init__(
        self,
        max_file_size: int = 500 * 1024 * 1024,  # 500 MB
    ):
        """
        Initialize analyzer.

        Args:
            max_file_size: Maximum file size to analyze in bytes
        """
        self.max_file_size = max_file_size
        self._logger = get_logger(self.__class__.__name__)

    @property
    @abstractmethod
    def name(self) -> str:
        """Analyzer name for logging and display."""
        raise NotImplementedError("Subclass must implement 'name' property")

    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """List of supported file format magic strings."""
        raise NotImplementedError("Subclass must implement 'supported_formats' property")

    def validate_file(self, file_path: Path) -> FileInfo:
        """
        Validate file before analysis.

        Args:
            file_path: Path to file

        Returns:
            FileInfo object

        Raises:
            AnalysisError: If file is invalid
        """
        if not file_path.exists():
            raise AnalysisError(
                f"File not found: {file_path}",
                file_path=str(file_path),
            )

        if not file_path.is_file():
            raise AnalysisError(
                f"Not a regular file: {file_path}",
                file_path=str(file_path),
            )

        file_info = FileInfo.from_path(file_path)

        if file_info.file_size > self.max_file_size:
            raise FileTooLargeError(
                str(file_path),
                file_info.file_size,
                self.max_file_size,
            )

        if file_info.file_size == 0:
            raise AnalysisError(
                "Empty file",
                file_path=str(file_path),
            )

        return file_info

    def is_supported(self, file_info: FileInfo) -> bool:
        """
        Check if file format is supported.

        Args:
            file_info: File information

        Returns:
            True if format is supported
        """
        file_type_lower = file_info.file_type.lower()
        return any(fmt.lower() in file_type_lower for fmt in self.supported_formats)

    @abstractmethod
    def analyze(self, file_path: Path, data: Optional[bytes] = None) -> Any:
        """
        Perform analysis on file.

        Args:
            file_path: Path to file
            data: Optional pre-loaded file data

        Returns:
            Analysis result specific to this analyzer
        """
        raise NotImplementedError("Subclass must implement 'analyze' method")

    def _load_file(self, file_path: Path) -> bytes:
        """
        Load file data.

        Args:
            file_path: Path to file

        Returns:
            File contents as bytes
        """
        with open(file_path, "rb") as f:
            return f.read()

    def _log_start(self, file_path: Path) -> None:
        """Log analysis start."""
        self._logger.info(
            f"Starting {self.name} analysis",
            extra_data={"file": str(file_path)},
        )

    def _log_complete(self, file_path: Path, duration: float) -> None:
        """Log analysis completion."""
        self._logger.info(
            f"Completed {self.name} analysis",
            extra_data={
                "file": str(file_path),
                "duration": f"{duration:.2f}s",
            },
        )

    def _log_error(self, file_path: Path, error: Exception) -> None:
        """Log analysis error."""
        self._logger.error(
            f"{self.name} analysis failed",
            extra_data={
                "file": str(file_path),
                "error": str(error),
            },
        )
