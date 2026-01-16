"""Main view panels for the Malware Analysis Platform."""

from .dashboard_view import DashboardView
from .analysis_view import AnalysisView
from .hex_view import HexView
from .disasm_view import DisassemblyView
from .strings_view import StringsView
from .history_view import HistoryView
from .yara_view import YaraRulesView
from .ml_view import MLClassificationView
from .virustotal_view import VirusTotalView
from .sandbox_view import SandboxView
from .plugin_view import PluginManagerView

__all__ = [
    "DashboardView",
    "AnalysisView",
    "HexView",
    "DisassemblyView",
    "StringsView",
    "HistoryView",
    "YaraRulesView",
    "MLClassificationView",
    "VirusTotalView",
    "SandboxView",
    "PluginManagerView",
]
