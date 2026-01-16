"""
Plugin manager for loading and executing plugins.

Handles plugin discovery, loading, and lifecycle management.
"""

from pathlib import Path
from typing import Dict, List, Optional, Type
import importlib
import importlib.util
import sys

from .base_plugin import BasePlugin, PluginContext, PluginResult
from ..utils.config import get_config
from ..utils.logger import get_logger
from ..utils.exceptions import PluginError

logger = get_logger("plugin_manager")


class PluginManager:
    """
    Manages plugin lifecycle and execution.

    Features:
    - Plugin discovery from directory
    - Dynamic loading/unloading
    - Dependency validation
    - Plugin execution
    """

    _instance: Optional["PluginManager"] = None

    def __new__(cls) -> "PluginManager":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize plugin manager."""
        if self._initialized:
            return

        self._config = get_config()
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugin_classes: Dict[str, Type[BasePlugin]] = {}

        # Plugin directories
        self._plugin_dirs: List[Path] = []

        # Built-in plugins directory
        builtin_dir = Path(__file__).parent / "builtin"
        if builtin_dir.exists():
            self._plugin_dirs.append(builtin_dir)

        # User plugins directory
        user_dir = self._config.get("plugins.directory")
        if user_dir:
            user_path = Path(user_dir).expanduser()
            if user_path.exists():
                self._plugin_dirs.append(user_path)

        self._initialized = True
        logger.info("Plugin manager initialized")

    def discover_plugins(self) -> List[str]:
        """
        Discover available plugins.

        Returns:
            List of discovered plugin names
        """
        discovered = []

        for plugin_dir in self._plugin_dirs:
            if not plugin_dir.exists():
                continue

            for file_path in plugin_dir.glob("*.py"):
                if file_path.name.startswith("_"):
                    continue

                try:
                    plugin_class = self._load_plugin_class(file_path)
                    if plugin_class:
                        name = plugin_class.name.fget(None)  # Get property value
                        # Create temporary instance to get name
                        try:
                            temp = plugin_class()
                            name = temp.name
                            self._plugin_classes[name] = plugin_class
                            discovered.append(name)
                            logger.debug(f"Discovered plugin: {name}")
                        except Exception:
                            pass
                except Exception as e:
                    logger.warning(f"Failed to discover plugin {file_path}: {e}")

        return discovered

    def _load_plugin_class(self, file_path: Path) -> Optional[Type[BasePlugin]]:
        """Load plugin class from file."""
        try:
            spec = importlib.util.spec_from_file_location(
                file_path.stem,
                file_path,
            )
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[file_path.stem] = module
            spec.loader.exec_module(module)

            # Find BasePlugin subclass
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type) and
                    issubclass(attr, BasePlugin) and
                    attr is not BasePlugin
                ):
                    return attr

        except Exception as e:
            logger.error(f"Failed to load plugin class: {e}")

        return None

    def load_plugin(self, name: str) -> bool:
        """
        Load a plugin by name.

        Args:
            name: Plugin name

        Returns:
            True if loaded successfully
        """
        if name in self._plugins:
            logger.warning(f"Plugin already loaded: {name}")
            return True

        if name not in self._plugin_classes:
            # Try to discover first
            self.discover_plugins()
            if name not in self._plugin_classes:
                logger.error(f"Plugin not found: {name}")
                return False

        try:
            plugin_class = self._plugin_classes[name]
            plugin = plugin_class()

            # Validate dependencies
            if not plugin.validate_dependencies():
                logger.error(f"Plugin dependencies not met: {name}")
                return False

            # Call on_load
            plugin.on_load()

            self._plugins[name] = plugin
            logger.info(f"Loaded plugin: {name} v{plugin.version}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {name}: {e}")
            return False

    def unload_plugin(self, name: str) -> bool:
        """
        Unload a plugin.

        Args:
            name: Plugin name

        Returns:
            True if unloaded successfully
        """
        if name not in self._plugins:
            return False

        try:
            plugin = self._plugins[name]
            plugin.on_unload()
            del self._plugins[name]
            logger.info(f"Unloaded plugin: {name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin {name}: {e}")
            return False

    def execute_plugin(
        self,
        name: str,
        context: PluginContext,
    ) -> PluginResult:
        """
        Execute a plugin.

        Args:
            name: Plugin name
            context: Execution context

        Returns:
            PluginResult from execution
        """
        if name not in self._plugins:
            if not self.load_plugin(name):
                return PluginResult(
                    success=False,
                    errors=[f"Plugin not found: {name}"],
                )

        try:
            plugin = self._plugins[name]
            result = plugin.execute(context)
            logger.debug(f"Plugin {name} executed successfully")
            return result

        except Exception as e:
            logger.error(f"Plugin {name} execution failed: {e}")
            return PluginResult(
                success=False,
                errors=[str(e)],
            )

    def execute_all(
        self,
        context: PluginContext,
        category: Optional[str] = None,
    ) -> Dict[str, PluginResult]:
        """
        Execute all loaded plugins.

        Args:
            context: Execution context
            category: Optional category filter

        Returns:
            Dict of plugin name to result
        """
        results = {}

        for name, plugin in self._plugins.items():
            if category and plugin.category != category:
                continue

            results[name] = self.execute_plugin(name, context)

        return results

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get loaded plugin instance."""
        return self._plugins.get(name)

    def get_loaded_plugins(self) -> List[str]:
        """Get list of loaded plugin names."""
        return list(self._plugins.keys())

    def get_plugin_info(self, name: str) -> Optional[Dict]:
        """Get plugin information."""
        plugin = self._plugins.get(name)
        if plugin is None and name in self._plugin_classes:
            # Create temporary instance
            try:
                plugin = self._plugin_classes[name]()
            except Exception:
                return None

        if plugin:
            return {
                "name": plugin.name,
                "version": plugin.version,
                "description": plugin.description,
                "author": plugin.author,
                "category": plugin.category,
                "loaded": name in self._plugins,
            }

        return None

    def reload_plugin(self, name: str) -> bool:
        """Reload a plugin."""
        self.unload_plugin(name)

        # Remove from class cache
        if name in self._plugin_classes:
            del self._plugin_classes[name]

        # Re-discover and load
        self.discover_plugins()
        return self.load_plugin(name)


# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Get global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager
