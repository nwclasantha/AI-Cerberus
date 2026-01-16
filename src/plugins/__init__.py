"""Plugin system for extensibility."""

from .base_plugin import BasePlugin, PluginContext, PluginResult
from .plugin_manager import PluginManager, get_plugin_manager

__all__ = [
    "BasePlugin",
    "PluginContext",
    "PluginResult",
    "PluginManager",
    "get_plugin_manager",
]
