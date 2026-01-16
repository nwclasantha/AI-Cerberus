"""
Linux ELF (Executable and Linkable Format) file analyzer.

Comprehensive analysis of ELF files including:
- Headers, sections, segments
- Symbol tables
- Dynamic linking info
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import time

from .base_analyzer import BaseAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from ..utils.logger import get_logger
from ..utils.helpers import format_hex

logger = get_logger("elf_analyzer")


@dataclass
class ELFSection:
    """ELF section information."""

    name: str
    type_name: str
    address: int
    offset: int
    size: int
    flags: str
    entropy: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "type": self.type_name,
            "address": format_hex(self.address),
            "offset": format_hex(self.offset),
            "size": self.size,
            "flags": self.flags,
            "entropy": round(self.entropy, 4),
        }


@dataclass
class ELFSegment:
    """ELF program header (segment) information."""

    type_name: str
    flags: str
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int

    def to_dict(self) -> Dict:
        return {
            "type": self.type_name,
            "flags": self.flags,
            "offset": format_hex(self.offset),
            "vaddr": format_hex(self.vaddr),
            "paddr": format_hex(self.paddr),
            "filesz": self.filesz,
            "memsz": self.memsz,
        }


@dataclass
class ELFInfo:
    """Complete ELF analysis result."""

    is_elf: bool = True
    is_pe: bool = False

    # Basic info
    bits: int = 64
    endian: str = "little"
    elf_type: str = ""
    machine: str = ""
    entry_point: int = 0

    # OS/ABI
    os_abi: str = ""
    abi_version: int = 0

    # Sections and Segments
    sections: List[ELFSection] = field(default_factory=list)
    segments: List[ELFSegment] = field(default_factory=list)

    # Symbols
    symbols: List[str] = field(default_factory=list)
    dynamic_symbols: List[str] = field(default_factory=list)

    # Libraries
    needed_libraries: List[str] = field(default_factory=list)
    rpath: str = ""
    runpath: str = ""

    # Security features
    has_nx: bool = False
    has_pie: bool = False
    has_relro: str = ""  # none, partial, full
    has_canary: bool = False
    has_fortify: bool = False

    # Interpreter
    interpreter: str = ""

    # Anomalies
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "is_elf": self.is_elf,
            "bits": self.bits,
            "endian": self.endian,
            "type": self.elf_type,
            "machine": self.machine,
            "entry_point": format_hex(self.entry_point),
            "os_abi": self.os_abi,
            "sections": [s.to_dict() for s in self.sections],
            "segments": [s.to_dict() for s in self.segments],
            "needed_libraries": self.needed_libraries,
            "interpreter": self.interpreter,
            "security": {
                "nx": self.has_nx,
                "pie": self.has_pie,
                "relro": self.has_relro,
                "canary": self.has_canary,
                "fortify": self.has_fortify,
            },
            "anomalies": self.anomalies,
        }


class ELFAnalyzer(BaseAnalyzer):
    """
    Comprehensive ELF file analyzer.

    Extracts detailed information from Linux executables:
    - ELF headers
    - Section headers
    - Program headers (segments)
    - Symbol tables
    - Dynamic linking info
    - Security features (NX, PIE, RELRO)
    """

    # ELF constants
    ELF_MAGIC = b"\x7fELF"

    MACHINE_TYPES = {
        0x00: "None",
        0x02: "SPARC",
        0x03: "x86",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x28: "ARM",
        0x2A: "SuperH",
        0x32: "IA-64",
        0x3E: "x86-64",
        0xB7: "AArch64",
        0xF3: "RISC-V",
    }

    ELF_TYPES = {
        0: "None",
        1: "Relocatable",
        2: "Executable",
        3: "Shared Object",
        4: "Core Dump",
    }

    OS_ABI = {
        0x00: "System V",
        0x01: "HP-UX",
        0x02: "NetBSD",
        0x03: "Linux",
        0x06: "Solaris",
        0x07: "AIX",
        0x08: "IRIX",
        0x09: "FreeBSD",
        0x0C: "OpenBSD",
    }

    SEGMENT_TYPES = {
        0: "NULL",
        1: "LOAD",
        2: "DYNAMIC",
        3: "INTERP",
        4: "NOTE",
        5: "SHLIB",
        6: "PHDR",
        7: "TLS",
        0x6474e550: "GNU_EH_FRAME",
        0x6474e551: "GNU_STACK",
        0x6474e552: "GNU_RELRO",
    }

    SECTION_TYPES = {
        0: "NULL",
        1: "PROGBITS",
        2: "SYMTAB",
        3: "STRTAB",
        4: "RELA",
        5: "HASH",
        6: "DYNAMIC",
        7: "NOTE",
        8: "NOBITS",
        9: "REL",
        11: "DYNSYM",
        14: "INIT_ARRAY",
        15: "FINI_ARRAY",
    }

    @property
    def name(self) -> str:
        return "ELF Analyzer"

    @property
    def supported_formats(self) -> list:
        return ["ELF", "executable", "shared object"]

    def __init__(self):
        super().__init__()
        self._entropy_analyzer = EntropyAnalyzer(block_size=256)

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> ELFInfo:
        """
        Perform comprehensive ELF analysis.

        Args:
            file_path: Path to ELF file
            data: Optional pre-loaded data

        Returns:
            ELFInfo with complete analysis
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        result = ELFInfo()

        # Verify ELF magic
        if data[:4] != self.ELF_MAGIC:
            result.is_elf = False
            result.anomalies.append("Invalid ELF magic bytes")
            return result

        try:
            # Parse ELF header
            self._parse_header(data, result)

            # Parse program headers
            self._parse_program_headers(data, result)

            # Parse section headers
            self._parse_section_headers(data, result)

            # Check security features
            self._check_security(result)

            # Detect anomalies
            self._detect_anomalies(data, result)

        except Exception as e:
            logger.error(f"ELF analysis failed: {e}")
            result.anomalies.append(f"Parse error: {str(e)}")

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return result

    def _parse_header(self, data: bytes, result: ELFInfo) -> None:
        """Parse ELF header."""
        # ELF class (32/64 bit)
        ei_class = data[4]
        result.bits = 64 if ei_class == 2 else 32

        # Endianness
        ei_data = data[5]
        result.endian = "little" if ei_data == 1 else "big"
        endian = "<" if ei_data == 1 else ">"

        # OS/ABI
        result.os_abi = self.OS_ABI.get(data[7], f"Unknown ({data[7]})")
        result.abi_version = data[8]

        # ELF type
        e_type = struct.unpack(f"{endian}H", data[16:18])[0]
        result.elf_type = self.ELF_TYPES.get(e_type, f"Unknown ({e_type})")

        # Machine
        e_machine = struct.unpack(f"{endian}H", data[18:20])[0]
        result.machine = self.MACHINE_TYPES.get(
            e_machine, f"Unknown ({e_machine:#x})"
        )

        # Entry point
        if result.bits == 64:
            result.entry_point = struct.unpack(f"{endian}Q", data[24:32])[0]
        else:
            result.entry_point = struct.unpack(f"{endian}I", data[24:28])[0]

        # Check for PIE
        if e_type == 3:  # Shared object
            result.has_pie = True

    def _parse_program_headers(self, data: bytes, result: ELFInfo) -> None:
        """Parse program headers (segments)."""
        endian = "<" if result.endian == "little" else ">"
        is_64 = result.bits == 64

        # Get program header offset and count
        if is_64:
            e_phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
            e_phentsize = struct.unpack(f"{endian}H", data[54:56])[0]
            e_phnum = struct.unpack(f"{endian}H", data[56:58])[0]
        else:
            e_phoff = struct.unpack(f"{endian}I", data[28:32])[0]
            e_phentsize = struct.unpack(f"{endian}H", data[42:44])[0]
            e_phnum = struct.unpack(f"{endian}H", data[44:46])[0]

        for i in range(min(e_phnum, 50)):
            offset = e_phoff + i * e_phentsize
            if offset + e_phentsize > len(data):
                break

            ph_data = data[offset:offset + e_phentsize]

            if is_64:
                p_type = struct.unpack(f"{endian}I", ph_data[0:4])[0]
                p_flags = struct.unpack(f"{endian}I", ph_data[4:8])[0]
                p_offset = struct.unpack(f"{endian}Q", ph_data[8:16])[0]
                p_vaddr = struct.unpack(f"{endian}Q", ph_data[16:24])[0]
                p_paddr = struct.unpack(f"{endian}Q", ph_data[24:32])[0]
                p_filesz = struct.unpack(f"{endian}Q", ph_data[32:40])[0]
                p_memsz = struct.unpack(f"{endian}Q", ph_data[40:48])[0]
            else:
                p_type = struct.unpack(f"{endian}I", ph_data[0:4])[0]
                p_offset = struct.unpack(f"{endian}I", ph_data[4:8])[0]
                p_vaddr = struct.unpack(f"{endian}I", ph_data[8:12])[0]
                p_paddr = struct.unpack(f"{endian}I", ph_data[12:16])[0]
                p_filesz = struct.unpack(f"{endian}I", ph_data[16:20])[0]
                p_memsz = struct.unpack(f"{endian}I", ph_data[20:24])[0]
                p_flags = struct.unpack(f"{endian}I", ph_data[24:28])[0]

            # Flags string
            flags = ""
            flags += "R" if p_flags & 4 else "-"
            flags += "W" if p_flags & 2 else "-"
            flags += "X" if p_flags & 1 else "-"

            type_name = self.SEGMENT_TYPES.get(p_type, f"0x{p_type:x}")

            result.segments.append(ELFSegment(
                type_name=type_name,
                flags=flags,
                offset=p_offset,
                vaddr=p_vaddr,
                paddr=p_paddr,
                filesz=p_filesz,
                memsz=p_memsz,
            ))

            # Check for interpreter (PT_INTERP)
            if p_type == 3 and p_filesz > 0:
                interp_data = data[p_offset:p_offset + p_filesz]
                result.interpreter = interp_data.decode(
                    "utf-8", errors="ignore"
                ).strip("\x00")

            # Check NX (GNU_STACK without execute)
            if p_type == 0x6474e551:  # GNU_STACK
                result.has_nx = not (p_flags & 1)  # No execute

            # Check RELRO
            if p_type == 0x6474e552:  # GNU_RELRO
                result.has_relro = "partial"

    def _parse_section_headers(self, data: bytes, result: ELFInfo) -> None:
        """Parse section headers."""
        endian = "<" if result.endian == "little" else ">"
        is_64 = result.bits == 64

        # Get section header info
        if is_64:
            e_shoff = struct.unpack(f"{endian}Q", data[40:48])[0]
            e_shentsize = struct.unpack(f"{endian}H", data[58:60])[0]
            e_shnum = struct.unpack(f"{endian}H", data[60:62])[0]
            e_shstrndx = struct.unpack(f"{endian}H", data[62:64])[0]
        else:
            e_shoff = struct.unpack(f"{endian}I", data[32:36])[0]
            e_shentsize = struct.unpack(f"{endian}H", data[46:48])[0]
            e_shnum = struct.unpack(f"{endian}H", data[48:50])[0]
            e_shstrndx = struct.unpack(f"{endian}H", data[50:52])[0]

        if e_shoff == 0 or e_shnum == 0:
            return

        # Get string table for section names
        strtab_offset = 0
        if e_shstrndx < e_shnum:
            strtab_sh_offset = e_shoff + e_shstrndx * e_shentsize
            if strtab_sh_offset + e_shentsize <= len(data):
                sh_data = data[strtab_sh_offset:strtab_sh_offset + e_shentsize]
                if is_64:
                    strtab_offset = struct.unpack(f"{endian}Q", sh_data[24:32])[0]
                else:
                    strtab_offset = struct.unpack(f"{endian}I", sh_data[16:20])[0]

        for i in range(min(e_shnum, 100)):
            offset = e_shoff + i * e_shentsize
            if offset + e_shentsize > len(data):
                break

            sh_data = data[offset:offset + e_shentsize]

            if is_64:
                sh_name_idx = struct.unpack(f"{endian}I", sh_data[0:4])[0]
                sh_type = struct.unpack(f"{endian}I", sh_data[4:8])[0]
                sh_flags = struct.unpack(f"{endian}Q", sh_data[8:16])[0]
                sh_addr = struct.unpack(f"{endian}Q", sh_data[16:24])[0]
                sh_offset = struct.unpack(f"{endian}Q", sh_data[24:32])[0]
                sh_size = struct.unpack(f"{endian}Q", sh_data[32:40])[0]
            else:
                sh_name_idx = struct.unpack(f"{endian}I", sh_data[0:4])[0]
                sh_type = struct.unpack(f"{endian}I", sh_data[4:8])[0]
                sh_flags = struct.unpack(f"{endian}I", sh_data[8:12])[0]
                sh_addr = struct.unpack(f"{endian}I", sh_data[12:16])[0]
                sh_offset = struct.unpack(f"{endian}I", sh_data[16:20])[0]
                sh_size = struct.unpack(f"{endian}I", sh_data[20:24])[0]

            # Get section name
            name = ""
            if strtab_offset and sh_name_idx:
                name_start = strtab_offset + sh_name_idx
                name_end = data.find(b"\x00", name_start)
                if name_end > name_start:
                    name = data[name_start:name_end].decode(
                        "utf-8", errors="ignore"
                    )

            # Flags string
            flags = ""
            flags += "W" if sh_flags & 1 else "-"
            flags += "A" if sh_flags & 2 else "-"
            flags += "X" if sh_flags & 4 else "-"

            type_name = self.SECTION_TYPES.get(sh_type, f"0x{sh_type:x}")

            # Calculate entropy if section has data
            entropy = 0.0
            if sh_size > 0 and sh_type in [1, 14, 15]:  # PROGBITS, arrays
                sec_data = data[sh_offset:sh_offset + sh_size]
                if sec_data:
                    entropy = self._entropy_analyzer._calculate_entropy(sec_data)

            result.sections.append(ELFSection(
                name=name or f"section_{i}",
                type_name=type_name,
                address=sh_addr,
                offset=sh_offset,
                size=sh_size,
                flags=flags,
                entropy=entropy,
            ))

    def _check_security(self, result: ELFInfo) -> None:
        """Check security features."""
        # Full RELRO check
        has_bind_now = False
        for seg in result.segments:
            if seg.type_name == "DYNAMIC":
                # Would need to parse DYNAMIC segment for DT_BIND_NOW
                pass

        if result.has_relro == "partial" and has_bind_now:
            result.has_relro = "full"
        elif not result.has_relro:
            result.has_relro = "none"

    def _detect_anomalies(self, data: bytes, result: ELFInfo) -> None:
        """Detect ELF anomalies."""
        # Zero entry point
        if result.entry_point == 0 and result.elf_type == "Executable":
            result.anomalies.append("Zero entry point")

        # No program headers
        if not result.segments:
            result.anomalies.append("No program headers")

        # Entry point outside LOAD segments
        if result.entry_point:
            ep_in_segment = False
            for seg in result.segments:
                if seg.type_name == "LOAD":
                    if seg.vaddr <= result.entry_point < seg.vaddr + seg.memsz:
                        ep_in_segment = True
                        break
            if not ep_in_segment and result.segments:
                result.anomalies.append("Entry point outside LOAD segments")
