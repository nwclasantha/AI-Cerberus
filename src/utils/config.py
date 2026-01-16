"""
Configuration management for the Malware Analysis Platform.

Handles loading, validation, and access to application configuration
from YAML files with support for environment variable overrides.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .exceptions import ConfigurationError
from .logger import get_logger

logger = get_logger("config")


class Config:
    """
    Configuration manager with hierarchical access and validation.

    Supports:
    - YAML configuration files
    - Environment variable overrides
    - Dot-notation access (config.get("ui.theme"))
    - Default values
    - Path expansion (~/ -> home directory)

    Thread-safe singleton implementation.
    """

    _instance: Optional[Config] = None
    _lock: threading.Lock = threading.Lock()

    # Default configuration values
    DEFAULTS: Dict[str, Any] = {
        "ui": {
            "theme": "dark",
            "font_family": "Segoe UI",
            "font_size": 13,
        },
        "analysis": {
            "max_file_size": 104857600,  # 100MB
            "timeout": 300,
        },
        "ml": {
            "confidence_threshold": 0.7,
            "model_path": "models",
        },
        "database": {
            "path": "data/malware_analyzer.db",
        },
        "logging": {
            "level": "INFO",
            "file": None,
        },
        "integrations": {
            "virustotal": {
                "enabled": False,
                "api_key": "",
            },
        },
        "plugins": {
            "directory": "plugins",
        },
    }

    def __new__(cls, config_path: Optional[Path] = None) -> Config:
        """Thread-safe singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._config: Dict[str, Any] = {}
                    instance._config_path: Optional[Path] = None
                    instance._initialized: bool = False
                    cls._instance = instance
        return cls._instance

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Initialize configuration from file.

        Args:
            config_path: Path to YAML configuration file.
                        If None, looks for config.yaml in project root.
        """
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            # Start with defaults
            self._config = self._deep_copy_dict(self.DEFAULTS)

            # Try to find and load config file
            try:
                self._config_path = config_path or self._find_config_file()
                if self._config_path:
                    self._load_config()
            except ConfigurationError as e:
                logger.warning(f"Config file not found, using defaults: {e}")
                self._config_path = None

            self._apply_env_overrides()
            self._expand_paths()
            self._initialized = True

    def _deep_copy_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Deep copy a dictionary."""
        result: Dict[str, Any] = {}
        for key, value in d.items():
            if isinstance(value, dict):
                result[key] = self._deep_copy_dict(value)
            else:
                result[key] = value
        return result

    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file in standard locations."""
        search_paths = [
            Path(__file__).resolve().parent.parent.parent / "config.yaml",
            Path.home() / ".malware_analyzer" / "config.yaml",
            Path.cwd() / "config.yaml",
        ]

        for path in search_paths:
            try:
                if path.exists() and path.is_file():
                    return path
            except (OSError, PermissionError):
                continue

        return None

    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if self._config_path is None:
            return

        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                loaded_config = yaml.safe_load(f) or {}

            # Merge loaded config with defaults
            self._merge_config(self._config, loaded_config)
            logger.info(f"Configuration loaded from: {self._config_path}")

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except (IOError, OSError) as e:
            raise ConfigurationError(f"Cannot read config file: {e}")

    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Merge override config into base config."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

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
                logger.debug(f"Config override from env: {config_key}")

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
        value: Any = self._config

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
            Path(self.get("logging.file", "") or "").parent,
            Path(self.get("plugins.directory", "")),
            Path(self.get("ml.model_path", "")),
        ]

        for directory in directories:
            if directory and str(directory) not in (".", ""):
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                except (OSError, PermissionError) as e:
                    logger.warning(f"Could not create directory {directory}: {e}")

    @property
    def config_path(self) -> Optional[Path]:
        """Return path to loaded configuration file."""
        return self._config_path

    def to_dict(self) -> Dict[str, Any]:
        """Return full configuration as dictionary."""
        return self._deep_copy_dict(self._config)

    def reload(self) -> None:
        """Reload configuration from file."""
        with self._lock:
            if self._config_path and self._config_path.exists():
                # Reset to defaults first
                self._config = self._deep_copy_dict(self.DEFAULTS)
                self._load_config()
                self._apply_env_overrides()
                self._expand_paths()


# Global configuration instance
_config: Optional[Config] = None
_config_lock = threading.Lock()


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        with _config_lock:
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
    with _config_lock:
        # Reset instance for reinitialization
        Config._instance = None
        _config = Config(config_path)
    return _config
