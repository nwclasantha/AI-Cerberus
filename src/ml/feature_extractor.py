"""
Feature extraction for malware classification.

Extracts 100+ features from binary files for ML-based classification.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..utils.logger import get_logger

if TYPE_CHECKING:
    import pefile

logger = get_logger("feature_extractor")


@dataclass
class FeatureVector:
    """Feature vector for ML classification."""

    # File metadata features
    file_size: int = 0
    file_size_log: float = 0.0

    # Entropy features
    overall_entropy: float = 0.0
    entropy_variance: float = 0.0
    high_entropy_sections: int = 0
    low_entropy_sections: int = 0

    # PE Header features
    num_sections: int = 0
    num_imports: int = 0
    num_exports: int = 0
    image_base: int = 0
    entry_point: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    size_of_code: int = 0
    size_of_initialized_data: int = 0
    size_of_uninitialized_data: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: int = 0
    timestamp: int = 0

    # Section features
    executable_sections: int = 0
    writable_sections: int = 0
    sections_with_no_name: int = 0
    sections_high_entropy: int = 0
    avg_section_entropy: float = 0.0
    max_section_entropy: float = 0.0
    min_section_entropy: float = 0.0
    avg_section_size: float = 0.0
    max_section_size: int = 0
    min_section_size: int = 0
    total_section_size: int = 0
    virtual_size_ratio: float = 0.0

    # Import features
    suspicious_import_count: int = 0
    networking_imports: int = 0
    registry_imports: int = 0
    process_imports: int = 0
    file_imports: int = 0
    crypto_imports: int = 0
    anti_debug_imports: int = 0
    injection_imports: int = 0
    keylogging_imports: int = 0
    unique_dlls: int = 0

    # String features
    total_strings: int = 0
    avg_string_length: float = 0.0
    url_count: int = 0
    ip_count: int = 0
    email_count: int = 0
    path_count: int = 0
    registry_path_count: int = 0
    suspicious_strings: int = 0

    # Byte distribution features
    byte_entropy: float = 0.0
    byte_mean: float = 0.0
    byte_std: float = 0.0
    null_byte_ratio: float = 0.0
    printable_ratio: float = 0.0
    high_byte_ratio: float = 0.0

    # Resource features
    num_resources: int = 0
    resource_entropy: float = 0.0
    has_version_info: int = 0
    has_manifest: int = 0

    # Packer indicators
    upx_signature: int = 0
    themida_signature: int = 0
    vmprotect_signature: int = 0
    packed_indicator: int = 0

    # Anomaly features
    entry_point_in_last_section: int = 0
    suspicious_section_names: int = 0
    zero_checksum: int = 0
    debug_stripped: int = 0
    relocations_stripped: int = 0
    no_imports: int = 0
    no_exports: int = 0
    large_overlay: int = 0
    small_code_section: int = 0

    # Additional computed features
    import_to_export_ratio: float = 0.0
    code_to_data_ratio: float = 0.0
    header_to_file_ratio: float = 0.0

    # Raw feature dict for extensibility
    raw_features: Dict[str, Any] = field(default_factory=dict)

    def to_array(self) -> List[float]:
        """Convert to numpy-compatible array."""
        return [
            float(self.file_size),
            self.file_size_log,
            self.overall_entropy,
            self.entropy_variance,
            float(self.high_entropy_sections),
            float(self.low_entropy_sections),
            float(self.num_sections),
            float(self.num_imports),
            float(self.num_exports),
            float(self.image_base),
            float(self.entry_point),
            float(self.section_alignment),
            float(self.file_alignment),
            float(self.subsystem),
            float(self.dll_characteristics),
            float(self.size_of_code),
            float(self.size_of_initialized_data),
            float(self.size_of_uninitialized_data),
            float(self.size_of_image),
            float(self.size_of_headers),
            float(self.checksum),
            float(self.timestamp),
            float(self.executable_sections),
            float(self.writable_sections),
            float(self.sections_with_no_name),
            float(self.sections_high_entropy),
            self.avg_section_entropy,
            self.max_section_entropy,
            self.min_section_entropy,
            self.avg_section_size,
            float(self.max_section_size),
            float(self.min_section_size),
            float(self.total_section_size),
            self.virtual_size_ratio,
            float(self.suspicious_import_count),
            float(self.networking_imports),
            float(self.registry_imports),
            float(self.process_imports),
            float(self.file_imports),
            float(self.crypto_imports),
            float(self.anti_debug_imports),
            float(self.injection_imports),
            float(self.keylogging_imports),
            float(self.unique_dlls),
            float(self.total_strings),
            self.avg_string_length,
            float(self.url_count),
            float(self.ip_count),
            float(self.email_count),
            float(self.path_count),
            float(self.registry_path_count),
            float(self.suspicious_strings),
            self.byte_entropy,
            self.byte_mean,
            self.byte_std,
            self.null_byte_ratio,
            self.printable_ratio,
            self.high_byte_ratio,
            float(self.num_resources),
            self.resource_entropy,
            float(self.has_version_info),
            float(self.has_manifest),
            float(self.upx_signature),
            float(self.themida_signature),
            float(self.vmprotect_signature),
            float(self.packed_indicator),
            float(self.entry_point_in_last_section),
            float(self.suspicious_section_names),
            float(self.zero_checksum),
            float(self.debug_stripped),
            float(self.relocations_stripped),
            float(self.no_imports),
            float(self.no_exports),
            float(self.large_overlay),
            float(self.small_code_section),
            self.import_to_export_ratio,
            self.code_to_data_ratio,
            self.header_to_file_ratio,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        """Get feature names for ML model."""
        return [
            "file_size", "file_size_log", "overall_entropy", "entropy_variance",
            "high_entropy_sections", "low_entropy_sections", "num_sections",
            "num_imports", "num_exports", "image_base", "entry_point",
            "section_alignment", "file_alignment", "subsystem", "dll_characteristics",
            "size_of_code", "size_of_initialized_data", "size_of_uninitialized_data",
            "size_of_image", "size_of_headers", "checksum", "timestamp",
            "executable_sections", "writable_sections", "sections_with_no_name",
            "sections_high_entropy", "avg_section_entropy", "max_section_entropy",
            "min_section_entropy", "avg_section_size", "max_section_size",
            "min_section_size", "total_section_size", "virtual_size_ratio",
            "suspicious_import_count", "networking_imports", "registry_imports",
            "process_imports", "file_imports", "crypto_imports", "anti_debug_imports",
            "injection_imports", "keylogging_imports", "unique_dlls",
            "total_strings", "avg_string_length", "url_count", "ip_count",
            "email_count", "path_count", "registry_path_count", "suspicious_strings",
            "byte_entropy", "byte_mean", "byte_std", "null_byte_ratio",
            "printable_ratio", "high_byte_ratio", "num_resources", "resource_entropy",
            "has_version_info", "has_manifest", "upx_signature", "themida_signature",
            "vmprotect_signature", "packed_indicator", "entry_point_in_last_section",
            "suspicious_section_names", "zero_checksum", "debug_stripped",
            "relocations_stripped", "no_imports", "no_exports", "large_overlay",
            "small_code_section", "import_to_export_ratio", "code_to_data_ratio",
            "header_to_file_ratio",
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            name: value
            for name, value in zip(self.feature_names(), self.to_array())
        }


class FeatureExtractor:
    """
    Extract features from binary files for ML classification.

    Extracts 100+ features including:
    - File metadata
    - PE header features
    - Section characteristics
    - Import/export analysis
    - String features
    - Byte distribution
    - Packer indicators
    - Anomaly indicators
    """

    # Suspicious API sets
    NETWORKING_APIS = {
        "WSAStartup", "socket", "connect", "send", "recv", "bind", "listen",
        "InternetOpen", "HttpOpenRequest", "URLDownloadToFile", "WinHttpOpen",
    }

    REGISTRY_APIS = {
        "RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey",
        "RegQueryValue", "RegEnumKey", "RegEnumValue",
    }

    PROCESS_APIS = {
        "CreateProcess", "OpenProcess", "TerminateProcess", "CreateThread",
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    }

    FILE_APIS = {
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile",
        "MoveFile", "FindFirstFile", "FindNextFile",
    }

    CRYPTO_APIS = {
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "BCryptEncrypt", "BCryptDecrypt", "CryptImportKey",
    }

    ANTI_DEBUG_APIS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
    }

    INJECTION_APIS = {
        "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
        "NtWriteVirtualMemory", "QueueUserAPC", "SetThreadContext",
    }

    KEYLOGGING_APIS = {
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "SetWindowsHookEx",
    }

    SUSPICIOUS_SECTION_NAMES = {
        ".upx", "upx0", "upx1", ".vmp", ".themida", ".packed", ".enigma",
        ".nsp", ".aspack", ".adata", ".pec", ".petite",
    }

    def __init__(self):
        """Initialize feature extractor."""
        self._pefile_available = self._check_pefile()

    def _check_pefile(self) -> bool:
        """Check if pefile is available."""
        try:
            import pefile
            return True
        except ImportError:
            logger.warning("pefile not installed - PE feature extraction limited")
            return False

    def extract(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> FeatureVector:
        """
        Extract all features from a binary file.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data

        Returns:
            FeatureVector with all extracted features
        """
        if data is None:
            data = file_path.read_bytes()

        features = FeatureVector()

        # Extract file metadata features
        self._extract_file_features(features, data)

        # Extract byte distribution features
        self._extract_byte_features(features, data)

        # Extract string features
        self._extract_string_features(features, data)

        # Extract PE features if applicable
        if data[:2] == b"MZ" and self._pefile_available:
            self._extract_pe_features(features, data)

        # Calculate derived features
        self._calculate_derived_features(features)

        logger.debug(
            "Feature extraction complete",
            extra_data={"file": str(file_path), "features": len(features.to_array())},
        )

        return features

    def _extract_file_features(self, features: FeatureVector, data: bytes) -> None:
        """Extract basic file metadata features."""
        features.file_size = len(data)
        features.file_size_log = math.log2(len(data) + 1)

        # Overall entropy
        features.overall_entropy = self._calculate_entropy(data)

    def _extract_byte_features(self, features: FeatureVector, data: bytes) -> None:
        """Extract byte distribution features."""
        if not data:
            return

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        total = len(data)

        # Calculate byte statistics
        byte_values = list(range(256))
        mean = sum(b * c for b, c in zip(byte_values, byte_counts)) / total
        variance = sum(
            c * (b - mean) ** 2 for b, c in zip(byte_values, byte_counts)
        ) / total

        features.byte_mean = mean
        features.byte_std = math.sqrt(variance)

        # Calculate byte entropy
        features.byte_entropy = self._calculate_entropy(data)

        # Special byte ratios
        features.null_byte_ratio = byte_counts[0] / total
        features.printable_ratio = sum(
            byte_counts[b] for b in range(32, 127)
        ) / total
        features.high_byte_ratio = sum(
            byte_counts[b] for b in range(128, 256)
        ) / total

    def _extract_string_features(self, features: FeatureVector, data: bytes) -> None:
        """Extract string-based features."""
        import re

        text = data.decode("latin-1", errors="ignore")

        # Extract ASCII strings
        strings = re.findall(r"[\x20-\x7e]{4,}", text)
        features.total_strings = len(strings)

        if strings:
            features.avg_string_length = sum(len(s) for s in strings) / len(strings)

        text_lower = text.lower()

        # Count specific patterns
        features.url_count = len(re.findall(
            r"https?://[^\s<>\"']+", text_lower
        ))
        features.ip_count = len(re.findall(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text
        ))
        features.email_count = len(re.findall(
            r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", text_lower
        ))
        features.path_count = len(re.findall(
            r"[A-Za-z]:\\[^\s<>\"']+", text
        ))
        features.registry_path_count = len(re.findall(
            r"(HKEY_|SOFTWARE\\|CurrentVersion)", text, re.IGNORECASE
        ))

        # Suspicious strings
        suspicious_patterns = [
            r"hack", r"exploit", r"payload", r"inject", r"shellcode",
            r"backdoor", r"keylog", r"password", r"credential",
        ]
        features.suspicious_strings = sum(
            1 for pattern in suspicious_patterns
            if re.search(pattern, text_lower)
        )

    def _extract_pe_features(self, features: FeatureVector, data: bytes) -> None:
        """Extract PE-specific features."""
        try:
            import pefile

            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories()

            # Optional header features
            if hasattr(pe, "OPTIONAL_HEADER"):
                oh = pe.OPTIONAL_HEADER
                features.image_base = oh.ImageBase
                features.entry_point = oh.AddressOfEntryPoint
                features.section_alignment = oh.SectionAlignment
                features.file_alignment = oh.FileAlignment
                features.subsystem = oh.Subsystem
                features.dll_characteristics = oh.DllCharacteristics
                features.size_of_code = oh.SizeOfCode
                features.size_of_initialized_data = oh.SizeOfInitializedData
                features.size_of_uninitialized_data = oh.SizeOfUninitializedData
                features.size_of_image = oh.SizeOfImage
                features.size_of_headers = oh.SizeOfHeaders
                features.checksum = oh.CheckSum

            # File header features
            if hasattr(pe, "FILE_HEADER"):
                features.timestamp = pe.FILE_HEADER.TimeDateStamp
                features.num_sections = pe.FILE_HEADER.NumberOfSections

            # Section features
            self._extract_section_features(features, pe, data)

            # Import features
            self._extract_import_features(features, pe)

            # Export features
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                features.num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            else:
                features.no_exports = 1

            # Resource features
            self._extract_resource_features(features, pe)

            # Packer detection
            self._detect_packers(features, pe, data)

            # Anomaly detection
            self._detect_anomalies(features, pe, data)

            pe.close()

        except Exception as e:
            logger.warning(f"PE feature extraction failed: {e}")

    def _extract_section_features(
        self,
        features: FeatureVector,
        pe: Any,
        data: bytes,
    ) -> None:
        """Extract section-specific features."""
        if not hasattr(pe, "sections"):
            return

        section_entropies = []
        section_sizes = []
        total_virtual = 0
        total_raw = 0

        for section in pe.sections:
            # Section characteristics
            chars = section.Characteristics

            if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                features.executable_sections += 1
            if chars & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                features.writable_sections += 1

            # Section name analysis
            try:
                name = section.Name.decode("utf-8").strip("\x00").lower()
                if not name or name.startswith("\x00"):
                    features.sections_with_no_name += 1
                if name in self.SUSPICIOUS_SECTION_NAMES:
                    features.suspicious_section_names += 1
            except Exception:
                features.sections_with_no_name += 1

            # Section entropy
            section_data = section.get_data()
            if section_data:
                entropy = self._calculate_entropy(section_data)
                section_entropies.append(entropy)

                if entropy > 7.0:
                    features.sections_high_entropy += 1
                    features.high_entropy_sections += 1
                elif entropy < 1.0:
                    features.low_entropy_sections += 1

            # Section sizes
            raw_size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize
            section_sizes.append(raw_size)
            total_virtual += virtual_size
            total_raw += raw_size

        # Aggregate section features
        if section_entropies:
            features.avg_section_entropy = sum(section_entropies) / len(section_entropies)
            features.max_section_entropy = max(section_entropies)
            features.min_section_entropy = min(section_entropies)
            features.entropy_variance = sum(
                (e - features.avg_section_entropy) ** 2 for e in section_entropies
            ) / len(section_entropies)

        if section_sizes:
            features.avg_section_size = sum(section_sizes) / len(section_sizes)
            features.max_section_size = max(section_sizes)
            features.min_section_size = min(section_sizes)
            features.total_section_size = sum(section_sizes)

        if total_raw > 0:
            features.virtual_size_ratio = total_virtual / total_raw

    def _extract_import_features(self, features: FeatureVector, pe: Any) -> None:
        """Extract import-based features."""
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            features.no_imports = 1
            return

        dlls = set()
        all_imports = set()

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode("utf-8").lower()
                dlls.add(dll_name)
            except Exception:
                pass

            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode("utf-8")
                        all_imports.add(func_name)
                    except Exception:
                        pass

        features.num_imports = len(all_imports)
        features.unique_dlls = len(dlls)

        # Categorize imports
        features.networking_imports = len(all_imports & self.NETWORKING_APIS)
        features.registry_imports = len(all_imports & self.REGISTRY_APIS)
        features.process_imports = len(all_imports & self.PROCESS_APIS)
        features.file_imports = len(all_imports & self.FILE_APIS)
        features.crypto_imports = len(all_imports & self.CRYPTO_APIS)
        features.anti_debug_imports = len(all_imports & self.ANTI_DEBUG_APIS)
        features.injection_imports = len(all_imports & self.INJECTION_APIS)
        features.keylogging_imports = len(all_imports & self.KEYLOGGING_APIS)

        # Total suspicious imports
        features.suspicious_import_count = (
            features.injection_imports +
            features.anti_debug_imports +
            features.keylogging_imports
        )

    def _extract_resource_features(self, features: FeatureVector, pe: Any) -> None:
        """Extract resource-based features."""
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return

        resource_count = 0
        resource_data = b""

        def count_resources(entry):
            nonlocal resource_count, resource_data
            if hasattr(entry, "directory"):
                for e in entry.directory.entries:
                    count_resources(e)
            else:
                resource_count += 1
                if hasattr(entry, "data"):
                    try:
                        rva = entry.data.struct.OffsetToData
                        size = entry.data.struct.Size
                        resource_data += pe.get_data(rva, min(size, 1024))
                    except Exception:
                        pass

        for resource_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            count_resources(resource_entry)

            # Check for specific resources
            if resource_entry.id == 16:  # RT_VERSION
                features.has_version_info = 1
            elif resource_entry.id == 24:  # RT_MANIFEST
                features.has_manifest = 1

        features.num_resources = resource_count
        if resource_data:
            features.resource_entropy = self._calculate_entropy(resource_data)

    def _detect_packers(
        self,
        features: FeatureVector,
        pe: Any,
        data: bytes,
    ) -> None:
        """Detect common packers."""
        text = data.decode("latin-1", errors="ignore")

        # UPX detection
        if b"UPX0" in data or b"UPX1" in data or b"UPX!" in data:
            features.upx_signature = 1
            features.packed_indicator = 1

        # Themida detection
        if b".themida" in data.lower() or b"themida" in data.lower():
            features.themida_signature = 1
            features.packed_indicator = 1

        # VMProtect detection
        if b".vmp" in data.lower() or b"vmprotect" in data.lower():
            features.vmprotect_signature = 1
            features.packed_indicator = 1

        # Generic packing indicator based on entropy
        if features.overall_entropy > 7.2:
            features.packed_indicator = 1

    def _detect_anomalies(
        self,
        features: FeatureVector,
        pe: Any,
        data: bytes,
    ) -> None:
        """Detect PE anomalies."""
        # Entry point in last section
        if hasattr(pe, "sections") and pe.sections:
            last_section = pe.sections[-1]
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            section_start = last_section.VirtualAddress
            section_end = section_start + last_section.Misc_VirtualSize
            if section_start <= ep < section_end:
                features.entry_point_in_last_section = 1

        # Zero checksum
        if features.checksum == 0:
            features.zero_checksum = 1

        # Debug info stripped
        if hasattr(pe, "FILE_HEADER"):
            chars = pe.FILE_HEADER.Characteristics
            if chars & 0x0200:  # IMAGE_FILE_DEBUG_STRIPPED
                features.debug_stripped = 1
            if chars & 0x0001:  # IMAGE_FILE_RELOCS_STRIPPED
                features.relocations_stripped = 1

        # Large overlay
        if hasattr(pe, "get_overlay"):
            overlay = pe.get_overlay()
            if overlay and len(overlay) > len(data) * 0.3:
                features.large_overlay = 1

        # Small code section
        if features.size_of_code > 0 and features.size_of_code < 512:
            features.small_code_section = 1

    def _calculate_derived_features(self, features: FeatureVector) -> None:
        """Calculate derived features from extracted values."""
        # Import to export ratio
        if features.num_exports > 0:
            features.import_to_export_ratio = features.num_imports / features.num_exports
        else:
            features.import_to_export_ratio = float(features.num_imports)

        # Code to data ratio
        total_data = features.size_of_initialized_data + features.size_of_uninitialized_data
        if total_data > 0:
            features.code_to_data_ratio = features.size_of_code / total_data
        elif features.size_of_code > 0:
            features.code_to_data_ratio = float(features.size_of_code)

        # Header to file ratio
        if features.file_size > 0:
            features.header_to_file_ratio = features.size_of_headers / features.file_size

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        length = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy
