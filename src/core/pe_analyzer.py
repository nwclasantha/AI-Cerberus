"""
Windows PE (Portable Executable) file analyzer.

Comprehensive analysis of PE files including:
- Headers, sections, imports/exports
- Anomaly detection
- Resource extraction
- Digital signature verification
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_analyzer import BaseAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from ..utils.logger import get_logger
from ..utils.helpers import format_hex

logger = get_logger("pe_analyzer")


@dataclass
class PESection:
    """PE section information."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float = 0.0
    md5: str = ""

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def is_suspicious(self) -> bool:
        """Check for suspicious section characteristics."""
        # High entropy
        if self.entropy > 7.0:
            return True
        # Writable and executable
        if self.is_executable and self.is_writable:
            return True
        # Raw size is 0 but virtual size is not
        if self.raw_size == 0 and self.virtual_size > 0:
            return True
        # Unusual name
        suspicious_names = [".packed", ".upx", ".aspack", ".themida"]
        if any(n in self.name.lower() for n in suspicious_names):
            return True
        return False

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "virtual_address": format_hex(self.virtual_address),
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "raw_offset": format_hex(self.raw_offset),
            "characteristics": format_hex(self.characteristics),
            "entropy": round(self.entropy, 4),
            "is_executable": self.is_executable,
            "is_writable": self.is_writable,
            "is_suspicious": self.is_suspicious,
            "md5": self.md5,
        }


@dataclass
class PEImport:
    """PE import information."""

    dll: str
    functions: List[str] = field(default_factory=list)
    is_delayed: bool = False

    def to_dict(self) -> Dict:
        return {
            "dll": self.dll,
            "functions": self.functions,
            "function_count": len(self.functions),
            "is_delayed": self.is_delayed,
        }


@dataclass
class PEInfo:
    """Complete PE analysis result."""

    is_pe: bool = True
    is_dll: bool = False
    is_driver: bool = False
    is_dotnet: bool = False

    # Headers
    architecture: str = ""
    machine: int = 0
    subsystem: str = ""
    subsystem_id: int = 0
    timestamp: Optional[datetime] = None
    entry_point: int = 0
    image_base: int = 0
    checksum: int = 0
    calculated_checksum: int = 0

    # Sections
    sections: List[PESection] = field(default_factory=list)

    # Imports/Exports
    imports: List[PEImport] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)

    # Resources
    resources: List[Dict] = field(default_factory=list)

    # Security
    is_signed: bool = False
    signature_valid: bool = False
    signer: str = ""

    # Anomalies and indicators
    anomalies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Hashes
    imphash: str = ""
    rich_hash: str = ""

    # Debug info
    debug_info: Dict = field(default_factory=dict)
    pdb_path: str = ""

    def to_dict(self) -> Dict:
        return {
            "is_pe": self.is_pe,
            "is_dll": self.is_dll,
            "is_driver": self.is_driver,
            "is_dotnet": self.is_dotnet,
            "architecture": self.architecture,
            "subsystem": self.subsystem,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "entry_point": format_hex(self.entry_point),
            "image_base": format_hex(self.image_base),
            "sections": [s.to_dict() for s in self.sections],
            "imports": [i.to_dict() for i in self.imports],
            "exports": self.exports[:100],
            "is_signed": self.is_signed,
            "signature_valid": self.signature_valid,
            "anomalies": self.anomalies,
            "warnings": self.warnings,
            "imphash": self.imphash,
            "pdb_path": self.pdb_path,
        }


class PEAnalyzer(BaseAnalyzer):
    """
    Comprehensive PE file analyzer.

    Extracts detailed information from Windows executables:
    - DOS/PE/Optional headers
    - Section analysis with entropy
    - Import/Export tables
    - Resources
    - Digital signatures
    - Anomaly detection
    """

    MACHINE_TYPES = {
        0x0: "Unknown",
        0x14c: "i386",
        0x8664: "AMD64",
        0x1c0: "ARM",
        0xaa64: "ARM64",
        0x1c4: "ARMv7",
    }

    SUBSYSTEMS = {
        0: "Unknown",
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console",
        5: "OS/2 Console",
        7: "POSIX Console",
        9: "Windows CE",
        10: "EFI Application",
        11: "EFI Boot Driver",
        12: "EFI Runtime Driver",
        14: "Xbox",
    }

    @property
    def name(self) -> str:
        return "PE Analyzer"

    @property
    def supported_formats(self) -> list:
        return ["PE32", "PE32+", "executable", "DLL", "EXE"]

    def __init__(self):
        super().__init__()
        self._entropy_analyzer = EntropyAnalyzer(block_size=256)

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> PEInfo:
        """
        Perform comprehensive PE analysis.

        Args:
            file_path: Path to PE file
            data: Optional pre-loaded data

        Returns:
            PEInfo with complete analysis
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        result = PEInfo()

        try:
            import pefile

            pe = pefile.PE(data=data, fast_load=False)

            # Basic info
            result.machine = pe.FILE_HEADER.Machine
            result.architecture = self.MACHINE_TYPES.get(
                pe.FILE_HEADER.Machine, "Unknown"
            )

            result.subsystem_id = pe.OPTIONAL_HEADER.Subsystem
            result.subsystem = self.SUBSYSTEMS.get(
                pe.OPTIONAL_HEADER.Subsystem, "Unknown"
            )

            # Timestamp
            try:
                ts = pe.FILE_HEADER.TimeDateStamp
                # Validate timestamp range (1970 to 2100)
                if 0 < ts < 4102444800:
                    result.timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
                else:
                    result.anomalies.append(f"Suspicious timestamp value: {ts}")
            except (OSError, ValueError, OverflowError):
                result.anomalies.append("Invalid timestamp")

            # Entry point and image base
            result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            result.image_base = pe.OPTIONAL_HEADER.ImageBase
            result.checksum = pe.OPTIONAL_HEADER.CheckSum
            result.calculated_checksum = pe.generate_checksum()

            # Check for DLL/Driver
            result.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            result.is_driver = result.subsystem_id == 1

            # Checksum validation
            if result.checksum != result.calculated_checksum:
                result.warnings.append("Checksum mismatch")

            # Sections
            result.sections = self._analyze_sections(pe, data)

            # Imports
            result.imports = self._analyze_imports(pe)

            # Exports
            result.exports = self._analyze_exports(pe)

            # Import hash
            try:
                result.imphash = pe.get_imphash()
            except Exception:
                pass

            # Check for .NET
            result.is_dotnet = self._check_dotnet(pe)

            # Debug info
            result.debug_info, result.pdb_path = self._analyze_debug(pe)

            # Resources
            result.resources = self._analyze_resources(pe)

            # Digital signature
            result.is_signed, result.signature_valid, result.signer = \
                self._analyze_signature(pe)

            # Detect anomalies
            result.anomalies.extend(self._detect_anomalies(pe, result))

            pe.close()

        except ImportError:
            logger.error("pefile library not available")
            result.is_pe = False
            result.anomalies.append("pefile library not installed")
        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            result.is_pe = False
            result.anomalies.append(f"Parse error: {str(e)}")

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return result

    def _analyze_sections(self, pe, data: bytes) -> List[PESection]:
        """Analyze PE sections."""
        sections = []

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")

            # Get section data for entropy/hash
            try:
                sec_data = section.get_data()
            except Exception:
                sec_data = b""

            # Calculate entropy
            if sec_data:
                entropy = self._entropy_analyzer._calculate_entropy(sec_data)
            else:
                entropy = 0.0

            # Calculate MD5 (usedforsecurity=False for FIPS compliance)
            md5 = hashlib.md5(sec_data, usedforsecurity=False).hexdigest() if sec_data else ""

            sections.append(PESection(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                raw_offset=section.PointerToRawData,
                characteristics=section.Characteristics,
                entropy=entropy,
                md5=md5,
            ))

        return sections

    def _analyze_imports(self, pe) -> List[PEImport]:
        """Analyze import table."""
        imports = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                functions = []

                for imp in entry.imports[:100]:  # Limit functions
                    if imp.name:
                        functions.append(
                            imp.name.decode("utf-8", errors="ignore")
                        )
                    elif imp.ordinal:
                        functions.append(f"Ordinal_{imp.ordinal}")

                imports.append(PEImport(
                    dll=dll,
                    functions=functions,
                    is_delayed=False,
                ))

        # Delayed imports
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                functions = []

                for imp in entry.imports[:100]:
                    if imp.name:
                        functions.append(
                            imp.name.decode("utf-8", errors="ignore")
                        )

                imports.append(PEImport(
                    dll=dll,
                    functions=functions,
                    is_delayed=True,
                ))

        return imports

    def _analyze_exports(self, pe) -> List[str]:
        """Analyze export table."""
        exports = []

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:500]:
                if exp.name:
                    exports.append(exp.name.decode("utf-8", errors="ignore"))
                elif exp.ordinal:
                    exports.append(f"Ordinal_{exp.ordinal}")

        return exports

    def _check_dotnet(self, pe) -> bool:
        """Check if PE is a .NET assembly."""
        try:
            return hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
        except Exception:
            return False

    def _analyze_debug(self, pe) -> tuple:
        """Analyze debug information."""
        debug_info = {}
        pdb_path = ""

        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(entry, "entry"):
                    debug_entry = entry.entry
                    if hasattr(debug_entry, "PdbFileName"):
                        pdb_path = debug_entry.PdbFileName.decode(
                            "utf-8", errors="ignore"
                        ).strip("\x00")

                debug_info["type"] = entry.struct.Type
                debug_info["timestamp"] = entry.struct.TimeDateStamp

        return debug_info, pdb_path

    def _analyze_resources(self, pe) -> List[Dict]:
        """Analyze PE resources."""
        resources = []

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries[:20]:
                type_name = str(res_type.name) if res_type.name else \
                    str(res_type.struct.Id)

                if hasattr(res_type, "directory"):
                    for res_id in res_type.directory.entries[:10]:
                        if hasattr(res_id, "directory"):
                            for res_lang in res_id.directory.entries[:5]:
                                data_entry = res_lang.data
                                resources.append({
                                    "type": type_name,
                                    "id": str(res_id.struct.Id),
                                    "size": data_entry.struct.Size,
                                    "offset": data_entry.struct.OffsetToData,
                                })

        return resources

    def _analyze_signature(self, pe) -> tuple:
        """Check digital signature."""
        is_signed = False
        valid = False
        signer = ""

        # Check for security directory
        if hasattr(pe, "OPTIONAL_HEADER"):
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if security_dir.VirtualAddress != 0:
                is_signed = True
                # Full validation would require additional libraries

        return is_signed, valid, signer

    def _detect_anomalies(self, pe, result: PEInfo) -> List[str]:
        """Detect PE anomalies and suspicious characteristics."""
        anomalies = []

        # Entry point outside sections
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_in_section = False
        for sec in pe.sections:
            if sec.VirtualAddress <= ep < sec.VirtualAddress + sec.Misc_VirtualSize:
                ep_in_section = True
                break
        if not ep_in_section and ep != 0:
            anomalies.append("Entry point outside of sections")

        # Too many sections
        if len(pe.sections) > 20:
            anomalies.append(f"Unusual number of sections: {len(pe.sections)}")

        # Suspicious section names
        for sec in result.sections:
            if sec.is_suspicious:
                anomalies.append(f"Suspicious section: {sec.name}")

        # Header size anomaly
        if pe.OPTIONAL_HEADER.SizeOfHeaders > 0x2000:
            anomalies.append("Unusually large headers")

        # TLS callbacks (common in malware)
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            if pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
                anomalies.append("TLS callbacks present")

        return anomalies
