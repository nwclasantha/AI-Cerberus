"""
Analysis mode configuration and management.

Provides automated and manual analysis modes with configurable components.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pathlib import Path
import json

from ..utils.logger import get_logger

logger = get_logger("analysis_modes")


@dataclass
class AnalysisComponent:
    """Single analysis component."""

    id: str
    name: str
    description: str
    category: str  # "static", "dynamic", "ml", "external"
    enabled: bool = True
    required: bool = False  # Cannot be disabled
    estimated_time_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "enabled": self.enabled,
            "required": self.required,
            "estimated_time_ms": self.estimated_time_ms,
        }


@dataclass
class AnalysisMode:
    """Analysis mode configuration."""

    name: str
    description: str
    components: List[str] = field(default_factory=list)
    is_automated: bool = False
    parallel_execution: bool = True
    timeout_seconds: int = 300

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "components": self.components,
            "is_automated": self.is_automated,
            "parallel_execution": self.parallel_execution,
            "timeout_seconds": self.timeout_seconds,
        }


class AnalysisModeManager:
    """
    Manages analysis modes and component configurations.

    Features:
    - Predefined automated and manual modes
    - Custom mode creation
    - Component enable/disable
    - Mode persistence
    """

    # Available analysis components
    COMPONENTS = {
        # Static analysis
        "hash": AnalysisComponent(
            id="hash",
            name="Hash Calculation",
            description="Calculate file hashes (MD5, SHA1, SHA256, SHA512)",
            category="static",
            required=True,
            estimated_time_ms=100,
        ),
        "entropy": AnalysisComponent(
            id="entropy",
            name="Entropy Analysis",
            description="Analyze file entropy and detect packing",
            category="static",
            estimated_time_ms=200,
        ),
        "strings": AnalysisComponent(
            id="strings",
            name="String Extraction",
            description="Extract and categorize strings",
            category="static",
            estimated_time_ms=500,
        ),
        "pe_analysis": AnalysisComponent(
            id="pe_analysis",
            name="PE/ELF Analysis",
            description="Analyze binary structure (headers, sections, imports)",
            category="static",
            estimated_time_ms=300,
        ),
        "disassembly": AnalysisComponent(
            id="disassembly",
            name="Disassembly",
            description="Disassemble code sections",
            category="static",
            estimated_time_ms=2000,
        ),
        "yara": AnalysisComponent(
            id="yara",
            name="YARA Scanning",
            description="Scan with YARA rules",
            category="static",
            estimated_time_ms=1000,
        ),
        "behavior": AnalysisComponent(
            id="behavior",
            name="Behavior Analysis",
            description="Detect behavioral indicators from static features",
            category="static",
            estimated_time_ms=500,
        ),

        # ML analysis
        "ml_classification": AnalysisComponent(
            id="ml_classification",
            name="ML Classification",
            description="Machine learning-based classification",
            category="ml",
            estimated_time_ms=1500,
        ),
        "anomaly_detection": AnalysisComponent(
            id="anomaly_detection",
            name="Anomaly Detection",
            description="Detect anomalous samples using ML",
            category="ml",
            estimated_time_ms=800,
        ),

        # External integrations
        "virustotal": AnalysisComponent(
            id="virustotal",
            name="VirusTotal Lookup",
            description="Query VirusTotal API",
            category="external",
            estimated_time_ms=15000,  # Rate limited
        ),
        "hybrid_analysis": AnalysisComponent(
            id="hybrid_analysis",
            name="Hybrid Analysis",
            description="Query Hybrid Analysis sandbox",
            category="external",
            estimated_time_ms=2000,
        ),

        # Dynamic analysis
        "sandbox": AnalysisComponent(
            id="sandbox",
            name="Sandbox Execution",
            description="Execute in sandbox and capture behavior",
            category="dynamic",
            estimated_time_ms=60000,  # 1 minute minimum
        ),
    }

    # Predefined modes
    PREDEFINED_MODES = {
        "automated_full": AnalysisMode(
            name="Fully Automated",
            description="Run all available analysis components automatically",
            components=[
                "hash", "entropy", "strings", "pe_analysis",
                "yara", "behavior", "ml_classification",
                "anomaly_detection", "virustotal",
            ],
            is_automated=True,
            parallel_execution=True,
            timeout_seconds=300,
        ),
        "automated_quick": AnalysisMode(
            name="Quick Automated",
            description="Fast automated analysis with essential components",
            components=[
                "hash", "entropy", "pe_analysis", "yara", "ml_classification",
            ],
            is_automated=True,
            parallel_execution=True,
            timeout_seconds=60,
        ),
        "automated_deep": AnalysisMode(
            name="Deep Automated",
            description="Comprehensive analysis including sandbox",
            components=[
                "hash", "entropy", "strings", "pe_analysis", "disassembly",
                "yara", "behavior", "ml_classification", "anomaly_detection",
                "virustotal", "sandbox",
            ],
            is_automated=True,
            parallel_execution=False,  # Sandbox needs to run last
            timeout_seconds=600,
        ),
        "manual": AnalysisMode(
            name="Manual Mode",
            description="User selects which components to run",
            components=[],  # User configures
            is_automated=False,
            parallel_execution=True,
            timeout_seconds=300,
        ),
    }

    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize analysis mode manager.

        Args:
            config_dir: Directory for storing configurations
        """
        if config_dir is None:
            config_dir = Path.home() / ".malware_analyzer" / "config"
        self._config_dir = config_dir
        self._config_dir.mkdir(parents=True, exist_ok=True)

        self._current_mode: str = "automated_full"
        self._custom_modes: Dict[str, AnalysisMode] = {}
        self._component_overrides: Dict[str, bool] = {}  # Component ID -> enabled

        # Load saved configuration
        self._load_config()

    def get_current_mode(self) -> AnalysisMode:
        """Get current analysis mode configuration."""
        if self._current_mode in self.PREDEFINED_MODES:
            mode = self.PREDEFINED_MODES[self._current_mode]
        elif self._current_mode in self._custom_modes:
            mode = self._custom_modes[self._current_mode]
        else:
            logger.warning(f"Unknown mode '{self._current_mode}', using automated_full")
            mode = self.PREDEFINED_MODES["automated_full"]

        return mode

    def set_mode(self, mode_name: str) -> bool:
        """
        Set current analysis mode.

        Args:
            mode_name: Name of mode to activate

        Returns:
            True if mode exists and was set
        """
        if mode_name not in self.PREDEFINED_MODES and mode_name not in self._custom_modes:
            logger.error(f"Mode '{mode_name}' not found")
            return False

        self._current_mode = mode_name
        self._save_config()
        logger.info(f"Analysis mode set to: {mode_name}")
        return True

    def get_enabled_components(self) -> List[AnalysisComponent]:
        """Get list of enabled components for current mode."""
        mode = self.get_current_mode()
        components = []

        for comp_id in mode.components:
            if comp_id in self.COMPONENTS:
                comp = self.COMPONENTS[comp_id]
                # Check for overrides
                if comp_id in self._component_overrides:
                    if not self._component_overrides[comp_id]:
                        continue  # Disabled by user
                components.append(comp)

        return components

    def is_component_enabled(self, component_id: str) -> bool:
        """Check if a specific component is enabled."""
        if component_id in self._component_overrides:
            return self._component_overrides[component_id]

        mode = self.get_current_mode()
        return component_id in mode.components

    def set_component_enabled(self, component_id: str, enabled: bool) -> bool:
        """
        Enable or disable a specific component.

        Args:
            component_id: Component identifier
            enabled: True to enable, False to disable

        Returns:
            True if component exists and was updated
        """
        if component_id not in self.COMPONENTS:
            logger.error(f"Component '{component_id}' not found")
            return False

        component = self.COMPONENTS[component_id]
        if component.required and not enabled:
            logger.warning(f"Component '{component_id}' is required and cannot be disabled")
            return False

        self._component_overrides[component_id] = enabled
        self._save_config()
        logger.info(f"Component '{component_id}' {'enabled' if enabled else 'disabled'}")
        return True

    def create_custom_mode(
        self,
        name: str,
        description: str,
        components: List[str],
        is_automated: bool = False,
    ) -> bool:
        """
        Create a custom analysis mode.

        Args:
            name: Mode name (alphanumeric, spaces, underscores, hyphens only)
            description: Mode description
            components: List of component IDs
            is_automated: Whether mode runs automatically

        Returns:
            True if mode was created
        """
        # Validate mode name: only allow safe characters
        import re
        if not name or not re.match(r'^[a-zA-Z0-9_\- ]+$', name):
            logger.error(f"Invalid mode name: '{name}'. Use only alphanumeric, spaces, underscores, and hyphens.")
            return False

        # Limit name length to prevent issues
        if len(name) > 64:
            logger.error(f"Mode name too long: {len(name)} characters (max 64)")
            return False

        # Validate components
        invalid = [c for c in components if c not in self.COMPONENTS]
        if invalid:
            logger.error(f"Invalid components: {invalid}")
            return False

        mode_id = name.lower().replace(" ", "_").replace("-", "_")
        self._custom_modes[mode_id] = AnalysisMode(
            name=name,
            description=description,
            components=components,
            is_automated=is_automated,
        )

        self._save_config()
        logger.info(f"Custom mode created: {name}")
        return True

    def get_all_modes(self) -> Dict[str, AnalysisMode]:
        """Get all available modes (predefined + custom)."""
        modes = dict(self.PREDEFINED_MODES)
        modes.update(self._custom_modes)
        return modes

    def get_all_components(self) -> Dict[str, AnalysisComponent]:
        """Get all available components."""
        return self.COMPONENTS.copy()

    def estimate_analysis_time(self) -> int:
        """
        Estimate total analysis time for current mode in milliseconds.

        Returns:
            Estimated time in milliseconds
        """
        components = self.get_enabled_components()
        total_time = sum(comp.estimated_time_ms for comp in components)
        return total_time

    def _save_config(self) -> None:
        """Save configuration to disk."""
        try:
            config = {
                "current_mode": self._current_mode,
                "component_overrides": self._component_overrides,
                "custom_modes": {
                    name: mode.to_dict()
                    for name, mode in self._custom_modes.items()
                },
            }

            config_file = self._config_dir / "analysis_modes.json"
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)

            logger.debug("Analysis mode configuration saved")

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def _load_config(self) -> None:
        """Load configuration from disk with validation."""
        try:
            config_file = self._config_dir / "analysis_modes.json"
            if not config_file.exists():
                logger.info("No saved configuration, using defaults")
                return

            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Validate and load current mode
            current_mode = config.get("current_mode", "automated_full")
            if current_mode in self.PREDEFINED_MODES:
                self._current_mode = current_mode
            else:
                logger.warning(f"Invalid current_mode '{current_mode}', using 'automated_full'")
                self._current_mode = "automated_full"

            # Validate and load component overrides
            component_overrides = config.get("component_overrides", {})
            for comp_id, enabled in component_overrides.items():
                if comp_id in self.COMPONENTS:
                    if isinstance(enabled, bool):
                        self._component_overrides[comp_id] = enabled
                    else:
                        logger.warning(f"Invalid override value for '{comp_id}': {enabled}")
                else:
                    logger.warning(f"Unknown component in overrides: '{comp_id}'")

            # Validate and load custom modes
            custom_modes_data = config.get("custom_modes", {})
            for mode_id, mode_data in custom_modes_data.items():
                try:
                    # Validate mode structure
                    if not isinstance(mode_data, dict):
                        logger.warning(f"Invalid custom mode data for '{mode_id}'")
                        continue

                    components = mode_data.get("components", [])
                    if not isinstance(components, list):
                        logger.warning(f"Invalid components list for mode '{mode_id}'")
                        continue

                    # Validate all components exist
                    invalid_components = [c for c in components if c not in self.COMPONENTS]
                    if invalid_components:
                        logger.warning(
                            f"Custom mode '{mode_id}' has invalid components: {invalid_components}"
                        )
                        # Filter out invalid components
                        mode_data["components"] = [c for c in components if c in self.COMPONENTS]

                    # Only load if there's at least one valid component
                    if mode_data["components"]:
                        self._custom_modes[mode_id] = AnalysisMode(**mode_data)
                    else:
                        logger.warning(f"Custom mode '{mode_id}' has no valid components, skipping")

                except Exception as e:
                    logger.warning(f"Failed to load custom mode '{mode_id}': {e}")

            logger.info(f"Configuration loaded: {len(self._custom_modes)} custom modes")

        except json.JSONDecodeError as e:
            logger.error(f"Configuration file is corrupted: {e}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")


# Global instance
_mode_manager: Optional[AnalysisModeManager] = None


def get_mode_manager() -> AnalysisModeManager:
    """Get global analysis mode manager instance."""
    global _mode_manager
    if _mode_manager is None:
        _mode_manager = AnalysisModeManager()
    return _mode_manager
