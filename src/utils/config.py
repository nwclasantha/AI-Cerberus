"""
Configuration management for the Malware Analysis Platform.

Handles loading, validation, and access to application configuration
from YAML files with support for environment variable overrides.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from .exceptions import ConfigurationError


class Config:
    """
    Configuration manager with hierarchical access and validation.

    Supports:
    - YAML configuration files
    - Environment variable overrides
    - Dot-notation access (config.get("ui.theme"))
    - Default values
    - Path expansion (~/ -> home directory)
    """

    _instance: Optional["Config"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls, config_path: Optional[Path] = None) -> "Config":
        """Singleton pattern to ensure single configuration instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration from file.

        Args:
            config_path: Path to YAML configuration file.
                        If None, looks for config.yaml in project root.
        """
        if self._initialized:
            return

        self._config_path = config_path or self._find_config_file()
        self._load_config()
        self._apply_env_overrides()
        self._expand_paths()
        self._initialized = True

    def _find_config_file(self) -> Path:
        """Find configuration file in standard locations."""
        search_paths = [
            Path(__file__).parent.parent.parent / "config.yaml",
            Path.home() / ".malware_analyzer" / "config.yaml",
            Path.cwd() / "config.yaml",
        ]

        for path in search_paths:
            if path.exists():
                return path

        raise ConfigurationError(
            "Configuration file not found",
            config_key="config_path",
        )

    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except IOError as e:
            raise ConfigurationError(f"Cannot read config file: {e}")

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        env_mappings = {
            "MA_VT_API_KEY": "integrations.virustotal.api_key",
            "MA_HA_API_KEY": "integrations.hybrid_analysis.api_key",
            "MA_CUCKOO_URL": "integrations.cuckoo.api_url",
            "MA_CUCKOO_KEY": "integrations.cuckoo.api_key",
            "MA_LOG_LEVEL": "logging.level",
            "MA_DB_PATH": "database.path",
        }

        for env_var, config_key in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self.set(config_key, value)

    def _expand_paths(self) -> None:
        """Expand ~ and environment variables in path configurations."""
        path_keys = [
            "database.path",
            "logging.file",
            "plugins.directory",
            "ml.model_path",
        ]

        for key in path_keys:
            value = self.get(key)
            if value and isinstance(value, str):
                expanded = os.path.expanduser(value)
                expanded = os.path.expandvars(expanded)
                self.set(key, expanded)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key: Configuration key (e.g., "ui.theme" or "database.path")
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

            if value is None:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation.

        Args:
            key: Configuration key (e.g., "ui.theme")
            value: Value to set
        """
        keys = key.split(".")
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.

        Args:
            section: Section name (e.g., "ui", "database")

        Returns:
            Dictionary containing section configuration
        """
        return self.get(section, {})

    def ensure_directories(self) -> None:
        """Create necessary directories from configuration."""
        directories = [
            Path(self.get("database.path", "")).parent,
            Path(self.get("logging.file", "")).parent,
            Path(self.get("plugins.directory", "")),
            Path(self.get("ml.model_path", "")),
        ]

        for directory in directories:
            if directory and str(directory) != ".":
                directory.mkdir(parents=True, exist_ok=True)

    @property
    def config_path(self) -> Path:
        """Return path to loaded configuration file."""
        return self._config_path

    def to_dict(self) -> Dict[str, Any]:
        """Return full configuration as dictionary."""
        return self._config.copy()

    def reload(self) -> None:
        """Reload configuration from file."""
        self._load_config()
        self._apply_env_overrides()
        self._expand_paths()


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def init_config(config_path: Optional[Path] = None) -> Config:
    """
    Initialize global configuration with custom path.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration instance
    """
    global _config
    _config = Config(config_path)
    return _config
