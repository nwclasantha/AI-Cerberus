"""Core analysis engines for the Malware Analysis Platform."""

from .base_analyzer import BaseAnalyzer, AnalysisResult, FileInfo
from .hash_calculator import HashCalculator, HashCollection
from .entropy_analyzer import EntropyAnalyzer, EntropyResult
from .string_extractor import StringExtractor, StringsResult
from .pe_analyzer import PEAnalyzer, PEInfo
from .elf_analyzer import ELFAnalyzer, ELFInfo
from .yara_engine import YaraEngine, YaraMatch
from .behavior_analyzer import BehaviorAnalyzer, BehavioralIndicators
from .disassembler import Disassembler, DisassemblyResult
from .analysis_modes import AnalysisModeManager, AnalysisMode, AnalysisComponent, get_mode_manager
from .combined_analysis_engine import (
    CombinedAnalysisEngine,
    CombinedAnalysisResult,
    ThreatVerdict,
    DetectionSource,
    SourceDetection,
    CodeBlock,
    get_combined_engine,
)
from .false_positive_prevention import (
    FalsePositivePrevention,
    LegitimacyResult,
    DigitalSignatureVerifier,
    KnownGoodHashDatabase,
    WhitelistManager,
    LegitimatePatternDetector,
    SystemFileDetector,
    get_false_positive_prevention,
)
from .auto_learning_engine import (
    AutoLearningEngine,
    AutoLearningDatabase,
    AutoLearnDecision,
    get_auto_learning_engine,
)

__all__ = [
    "BaseAnalyzer",
    "AnalysisResult",
    "FileInfo",
    "HashCalculator",
    "HashCollection",
    "EntropyAnalyzer",
    "EntropyResult",
    "StringExtractor",
    "StringsResult",
    "PEAnalyzer",
    "PEInfo",
    "ELFAnalyzer",
    "ELFInfo",
    "YaraEngine",
    "YaraMatch",
    "BehaviorAnalyzer",
    "BehavioralIndicators",
    "Disassembler",
    "DisassemblyResult",
    "AnalysisModeManager",
    "AnalysisMode",
    "AnalysisComponent",
    "get_mode_manager",
    # Combined Analysis Engine
    "CombinedAnalysisEngine",
    "CombinedAnalysisResult",
    "ThreatVerdict",
    "DetectionSource",
    "SourceDetection",
    "CodeBlock",
    "get_combined_engine",
    # False Positive Prevention
    "FalsePositivePrevention",
    "LegitimacyResult",
    "DigitalSignatureVerifier",
    "KnownGoodHashDatabase",
    "WhitelistManager",
    "LegitimatePatternDetector",
    "SystemFileDetector",
    "get_false_positive_prevention",
    # Auto-Learning Engine (FULLY AUTOMATED)
    "AutoLearningEngine",
    "AutoLearningDatabase",
    "AutoLearnDecision",
    "get_auto_learning_engine",
]
