"""
Base plugin interface.

Defines the contract for all plugins in the system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PluginContext:
    """Context passed to plugins during execution."""

    file_path: Optional[Path] = None
    file_data: Optional[bytes] = None
    file_hash: str = ""
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginResult:
    """Result returned by plugin execution."""

    success: bool = True
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "data": self.data,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class BasePlugin(ABC):
    """
    Abstract base class for all plugins.

    Plugins must implement:
    - name: Unique plugin identifier
    - version: Plugin version string
    - description: Human-readable description
    - execute: Main execution logic

    Optional:
    - on_load: Called when plugin is loaded
    - on_unload: Called when plugin is unloaded
    - get_settings_widget: Return PyQt widget for settings
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""
        raise NotImplementedError("Plugin must implement 'name' property")

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version string."""
        raise NotImplementedError("Plugin must implement 'version' property")

    @property
    def description(self) -> str:
        """Human-readable description."""
        return ""

    @property
    def author(self) -> str:
        """Plugin author."""
        return ""

    @property
    def dependencies(self) -> List[str]:
        """List of required Python packages."""
        return []

    @property
    def category(self) -> str:
        """Plugin category for organization."""
        return "general"

    @abstractmethod
    def execute(self, context: PluginContext) -> PluginResult:
        """
        Execute plugin logic.

        Args:
            context: Execution context with file info and config

        Returns:
            PluginResult with execution results
        """
        raise NotImplementedError("Plugin must implement 'execute' method")

    def on_load(self) -> None:
        """Called when plugin is loaded."""
        pass

    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        pass

    def get_settings_widget(self):
        """
        Return a PyQt widget for plugin settings.

        Returns:
            QWidget or None
        """
        return None

    def validate_dependencies(self) -> bool:
        """Check if all dependencies are installed."""
        for dep in self.dependencies:
            try:
                __import__(dep)
            except ImportError:
                return False
        return True
