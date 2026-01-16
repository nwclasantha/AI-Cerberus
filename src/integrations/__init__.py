"""External integrations module."""

from .virustotal import VirusTotalClient, VTReport
from .hybrid_analysis import HybridAnalysisClient, SandboxReport
from .custom_sandbox import CustomVMSandboxClient, VMSandboxReport

__all__ = [
    "VirusTotalClient",
    "VTReport",
    "HybridAnalysisClient",
    "SandboxReport",
    "CustomVMSandboxClient",
    "VMSandboxReport",
]
