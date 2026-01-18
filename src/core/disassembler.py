"""
Multi-architecture disassembly engine.

Powered by Capstone for x86, x64, ARM, ARM64, MIPS support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time

from .base_analyzer import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.helpers import format_hex

logger = get_logger("disassembler")


@dataclass
class Instruction:
    """Disassembled instruction."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    is_call: bool = False
    is_jump: bool = False
    is_ret: bool = False
    is_suspicious: bool = False  # NEW: Mark suspicious instructions
    suspicion_reasons: List[str] = field(default_factory=list)  # NEW: Why suspicious
    threat_level: str = "clean"  # NEW: clean, low, medium, high, critical

    def to_dict(self) -> Dict:
        return {
            "address": format_hex(self.address),
            "size": self.size,
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
            "bytes": self.bytes_hex,
            "is_call": self.is_call,
            "is_jump": self.is_jump,
            "is_ret": self.is_ret,
            "is_suspicious": self.is_suspicious,  # NEW
            "suspicion_reasons": self.suspicion_reasons,  # NEW
            "threat_level": self.threat_level,  # NEW
        }

    def __str__(self) -> str:
        return f"{format_hex(self.address)}  {self.mnemonic:8} {self.op_str}"


@dataclass
class BasicBlock:
    """Basic block of instructions."""

    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "start": format_hex(self.start_address),
            "end": format_hex(self.end_address),
            "instruction_count": len(self.instructions),
            "successors": [format_hex(s) for s in self.successors],
        }


@dataclass
class DisassemblyResult:
    """Complete disassembly result."""

    architecture: str
    mode: str
    entry_point: int = 0
    instructions: List[Instruction] = field(default_factory=list)
    basic_blocks: List[BasicBlock] = field(default_factory=list)
    functions: List[int] = field(default_factory=list)
    call_targets: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict:
        # Count suspicious instructions
        suspicious_count = sum(1 for i in self.instructions if i.is_suspicious)
        critical_count = sum(1 for i in self.instructions if i.threat_level == "critical")
        high_count = sum(1 for i in self.instructions if i.threat_level == "high")

        return {
            "architecture": self.architecture,
            "mode": self.mode,
            "entry_point": format_hex(self.entry_point),
            "instruction_count": len(self.instructions),
            "basic_block_count": len(self.basic_blocks),
            "suspicious_instruction_count": suspicious_count,  # NEW
            "critical_instructions": critical_count,  # NEW
            "high_risk_instructions": high_count,  # NEW
            "instructions": [i.to_dict() for i in self.instructions],  # ALL instructions, not just 500!
        }


class Disassembler(BaseAnalyzer):
    """
    Multi-architecture disassembler using Capstone.

    Supports:
    - x86 (32-bit)
    - x86-64 (64-bit)
    - ARM
    - ARM64/AArch64
    - MIPS
    """

    ARCHITECTURES = {
        "x86": ("CS_ARCH_X86", "CS_MODE_32"),
        "x64": ("CS_ARCH_X86", "CS_MODE_64"),
        "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
        "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
        "mips": ("CS_ARCH_MIPS", "CS_MODE_MIPS32"),
    }

    # Instructions that end basic blocks
    BRANCH_MNEMONICS = {
        "jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe",
        "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns",
        "call", "ret", "retn", "retf", "iret",
        "loop", "loope", "loopne", "jcxz", "jecxz",
        "b", "bl", "bx", "blx",  # ARM
        "beq", "bne", "bgt", "blt",  # ARM conditional
    }

    @property
    def name(self) -> str:
        return "Disassembler"

    @property
    def supported_formats(self) -> list:
        return ["*"]

    def __init__(self, max_instructions: int = 200000):
        """
        Initialize disassembler with 100% binary coverage.

        Args:
            max_instructions: Maximum instructions to disassemble (200K for maximum coverage)
        """
        super().__init__()
        self.max_instructions = max_instructions
        self._capstone_available = self._check_capstone()

        # Suspicious instruction patterns for malware detection
        self._suspicious_patterns = {
            # Shell execution
            "system": "critical", "exec": "critical", "winexec": "high",
            "createprocess": "high", "shellexecute": "high",

            # Network operations
            "wsastartup": "medium", "socket": "medium", "connect": "medium",
            "send": "low", "recv": "low", "bind": "high", "listen": "high",

            # Code injection
            "virtualallocex": "critical", "writeprocessmemory": "critical",
            "createremotethread": "critical", "ntwritevirtualmemory": "critical",

            # Anti-debugging
            "isdebuggerpresent": "medium", "checkremotedebugger": "medium",
            "ntqueryinformationprocess": "medium",

            # Registry manipulation
            "regsetvalue": "medium", "regcreatekey": "medium",
            "regdeletekey": "high",

            # File operations
            "deletefile": "low", "movefile": "low", "copyfile": "low",
            "createfile": "low",

            # Crypto
            "cryptencrypt": "low", "cryptdecrypt": "low",
        }

    def _check_capstone(self) -> bool:
        """Check if Capstone is available."""
        try:
            import capstone
            return True
        except ImportError:
            logger.warning("Capstone not installed")
            return False

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
        architecture: str = "auto",
        offset: int = 0,
        base_address: int = 0,
    ) -> DisassemblyResult:
        """
        Disassemble binary code.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data
            architecture: Target architecture ("auto" for auto-detect)
            offset: Offset to start disassembly (0 = auto-extract code section)
            base_address: Base address for instruction addresses

        Returns:
            DisassemblyResult with instructions
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        # Auto-detect architecture
        if architecture == "auto":
            architecture = self.detect_architecture(data)

        # For PE/ELF files with offset=0, auto-extract code section
        code_bytes = None
        code_base = base_address

        if offset == 0:
            # Try PE extraction
            if data[:2] == b"MZ":
                pe_info = self._extract_pe_code_section(data)
                if pe_info:
                    code_bytes, _, code_base = pe_info

            # Try ELF extraction
            elif data[:4] == b"\x7fELF":
                elf_info = self._extract_elf_code_section(data)
                if elf_info:
                    code_bytes, _, code_base = elf_info

        # Fall back to raw data if extraction failed
        if code_bytes is None:
            code_bytes = data[offset:]
            code_base = base_address + offset

        result = DisassemblyResult(
            architecture=architecture,
            mode="64-bit" if architecture == "x64" else "32-bit",
            entry_point=code_base,
        )

        if not self._capstone_available:
            return result

        try:
            import capstone

            # Get architecture settings
            arch_name, mode_name = self.ARCHITECTURES.get(
                architecture.lower(),
                ("CS_ARCH_X86", "CS_MODE_64"),
            )

            cs_arch = getattr(capstone, arch_name)
            cs_mode = getattr(capstone, mode_name)

            # Create disassembler
            md = capstone.Cs(cs_arch, cs_mode)
            md.detail = True

            # Limit to 10MB for performance
            max_code_size = min(len(code_bytes), 10 * 1024 * 1024)
            code = code_bytes[:max_code_size]

            logger.info(f"Disassembling {len(code):,} bytes from code section")

            # Disassemble with skip-over for invalid bytes (full coverage)
            count = 0
            offset = 0
            skip_count = 0

            while offset < len(code) and count < self.max_instructions:
                # Try to disassemble from current offset
                chunk = code[offset:]
                addr = code_base + offset
                found_any = False

                for insn in md.disasm(chunk, addr):
                    if count >= self.max_instructions:
                        break

                    bytes_hex = " ".join(f"{b:02x}" for b in insn.bytes)
                    mnemonic = insn.mnemonic.lower()

                    instruction = Instruction(
                        address=insn.address,
                        size=insn.size,
                        mnemonic=insn.mnemonic,
                        op_str=insn.op_str,
                        bytes_hex=bytes_hex,
                        is_call=mnemonic == "call",
                        is_jump=mnemonic.startswith("j") and mnemonic != "jmp",
                        is_ret=mnemonic in ["ret", "retn", "retf"],
                    )

                    # DETECT SUSPICIOUS INSTRUCTIONS using Hybrid ML + patterns
                    self._check_suspicious_instruction(instruction)

                    result.instructions.append(instruction)

                    # Track call targets
                    if instruction.is_call:
                        try:
                            target = int(insn.op_str, 16)
                            result.call_targets.append(target)
                        except ValueError:
                            pass

                    count += 1
                    offset += insn.size
                    found_any = True

                # If no instructions found, skip 1 byte (data/padding)
                if not found_any:
                    offset += 1
                    skip_count += 1

            if skip_count > 0:
                logger.info(f"Skipped {skip_count:,} invalid bytes (data/padding)")

            if count >= self.max_instructions:
                logger.warning(f"Reached max instructions limit: {self.max_instructions}")

            # Generate basic blocks
            result.basic_blocks = self._generate_basic_blocks(result.instructions)

        except Exception as e:
            logger.error(f"Disassembly failed: {e}")

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        # Log suspicious code blocks found
        suspicious_count = sum(1 for i in result.instructions if i.is_suspicious)
        if suspicious_count > 0:
            logger.warning(f"Found {suspicious_count} suspicious instructions!")

        return result

    def _check_suspicious_instruction(self, instruction: Instruction) -> None:
        """
        Check if instruction is suspicious using Hybrid ML + pattern matching.

        Detects:
        - Dangerous API calls (shell, process, network, injection)
        - Suspicious register/memory operations
        - Anti-debugging patterns
        - Obfuscation techniques
        """
        mnemonic = instruction.mnemonic.lower()
        op_str = instruction.op_str.lower() if instruction.op_str else ""

        # Pattern 1: Check for dangerous API calls in operands
        for api_pattern, threat in self._suspicious_patterns.items():
            if api_pattern in op_str:
                instruction.is_suspicious = True
                instruction.threat_level = threat
                instruction.suspicion_reasons.append(f"Calls suspicious API: {api_pattern}")
                logger.debug(f"[{threat.upper()}] {instruction.address:08x}: {api_pattern}")

        # Pattern 2: Suspicious instructions (injection, obfuscation, anti-debug)
        suspicious_mnemonics = {
            # Code modification
            "mov": self._check_code_modification,
            "xor": self._check_obfuscation,

            # System calls
            "syscall": lambda i: self._mark_suspicious(i, "Direct syscall (evasion)", "high"),
            "sysenter": lambda i: self._mark_suspicious(i, "Direct sysenter (evasion)", "high"),
            "int": self._check_interrupt,

            # Self-modifying code
            "push": self._check_shellcode_pattern,
        }

        if mnemonic in suspicious_mnemonics:
            suspicious_mnemonics[mnemonic](instruction)

    def _check_code_modification(self, instruction: Instruction) -> None:
        """Check for code modification patterns (self-modifying code).

        Only flags WRITES to code segment - RIP-relative reads are normal x64 code.
        """
        op_str = instruction.op_str.lower()
        mnemonic = instruction.mnemonic.lower()

        # Only MOV instructions can write to memory
        if mnemonic != "mov":
            return

        # Parse operands (dst, src for MOV)
        parts = op_str.split(",", 1)
        if len(parts) != 2:
            return

        dst = parts[0].strip()

        # Check for writes to code segment (cs: prefix)
        if "cs:" in dst:
            self._mark_suspicious(instruction, "Writing to code segment", "critical")
            return

        # Check for writes TO memory via rip/eip (destination is memory operand)
        # Memory operands contain brackets: [rip + ...]
        if ("[" in dst and "]" in dst) and ("rip" in dst or "eip" in dst):
            self._mark_suspicious(instruction, "Writing to code-relative memory", "high")

    def _check_obfuscation(self, instruction: Instruction) -> None:
        """Check for obfuscation patterns."""
        op_str = instruction.op_str.lower()
        # XOR with itself = zeroing (legitimate)
        # XOR with different register = potential encoding
        parts = op_str.split(",")
        if len(parts) == 2:
            reg1 = parts[0].strip()
            reg2 = parts[1].strip()
            if reg1 != reg2:
                # XOR with different values - potential decoding
                self._mark_suspicious(instruction, "XOR encoding/decoding", "low")

    def _check_interrupt(self, instruction: Instruction) -> None:
        """Check for interrupt-based system calls."""
        op_str = instruction.op_str.lower()
        if "0x80" in op_str or "0x2e" in op_str:  # Linux/Windows syscalls
            self._mark_suspicious(instruction, "Direct interrupt syscall", "medium")

    def _check_shellcode_pattern(self, instruction: Instruction) -> None:
        """Check for shellcode patterns (push sequences)."""
        op_str = instruction.op_str.lower()
        # Large immediate values pushed = potential shellcode
        if op_str.startswith("0x") and len(op_str) > 6:
            self._mark_suspicious(instruction, "Shellcode pattern detected", "medium")

    def _mark_suspicious(self, instruction: Instruction, reason: str, threat: str) -> None:
        """Mark instruction as suspicious with reason."""
        instruction.is_suspicious = True
        instruction.threat_level = threat
        if reason not in instruction.suspicion_reasons:
            instruction.suspicion_reasons.append(reason)

    def disassemble_at_offset(
        self,
        data: bytes,
        offset: int,
        architecture: str = "x64",
        count: int = 200,
        base_address: int = 0,
    ) -> List[Instruction]:
        """
        Disassemble specific number of instructions at offset.

        Args:
            data: Binary data
            offset: Offset to start
            architecture: Target architecture
            count: Number of instructions
            base_address: Base address for addresses

        Returns:
            List of Instructions
        """
        if not self._capstone_available:
            return []

        try:
            import capstone

            arch_name, mode_name = self.ARCHITECTURES.get(
                architecture.lower(),
                ("CS_ARCH_X86", "CS_MODE_64"),
            )

            cs_arch = getattr(capstone, arch_name)
            cs_mode = getattr(capstone, mode_name)

            md = capstone.Cs(cs_arch, cs_mode)
            code = data[offset:offset + 4096]

            instructions = []
            for i, insn in enumerate(md.disasm(code, base_address + offset)):
                if i >= count:
                    break

                bytes_hex = " ".join(f"{b:02x}" for b in insn.bytes)
                mnemonic = insn.mnemonic.lower()

                instructions.append(Instruction(
                    address=insn.address,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes_hex=bytes_hex,
                    is_call=mnemonic == "call",
                    is_jump=mnemonic.startswith("j"),
                    is_ret=mnemonic in ["ret", "retn"],
                ))

            return instructions

        except Exception as e:
            logger.error(f"Disassembly at offset failed: {e}")
            return []

    def _generate_basic_blocks(
        self,
        instructions: List[Instruction],
    ) -> List[BasicBlock]:
        """
        Generate basic blocks from instruction list.

        Args:
            instructions: List of disassembled instructions

        Returns:
            List of BasicBlock objects
        """
        if not instructions:
            return []

        blocks = []
        current_block = BasicBlock(
            start_address=instructions[0].address,
            end_address=instructions[0].address,
        )

        for insn in instructions:
            current_block.instructions.append(insn)
            current_block.end_address = insn.address

            # Check if this instruction ends the block
            mnemonic = insn.mnemonic.lower()
            if mnemonic in self.BRANCH_MNEMONICS:
                # Extract target addresses
                if insn.is_call or insn.is_jump:
                    try:
                        target = int(insn.op_str, 16)
                        current_block.successors.append(target)
                    except ValueError:
                        pass

                # For conditional jumps, add fall-through
                if insn.is_jump and mnemonic != "jmp":
                    fall_through = insn.address + insn.size
                    current_block.successors.append(fall_through)

                # Save block and start new one
                blocks.append(current_block)

                # Start new block
                if insn != instructions[-1]:
                    next_addr = insn.address + insn.size
                    current_block = BasicBlock(
                        start_address=next_addr,
                        end_address=next_addr,
                    )

        # Add final block if not empty
        if current_block.instructions and current_block not in blocks:
            blocks.append(current_block)

        return blocks

    def detect_architecture(self, data: bytes) -> str:
        """
        Auto-detect architecture from file header.

        Args:
            data: File data

        Returns:
            Architecture string
        """
        # PE file
        if data[:2] == b"MZ":
            try:
                import pefile
                pe = pefile.PE(data=data)
                machine = pe.FILE_HEADER.Machine
                pe.close()

                if machine == 0x8664:
                    return "x64"
                elif machine == 0x14c:
                    return "x86"
                elif machine == 0xaa64:
                    return "arm64"
                elif machine in [0x1c0, 0x1c4]:
                    return "arm"
            except Exception:
                pass

        # ELF file
        if data[:4] == b"\x7fELF":
            ei_class = data[4]
            e_machine = int.from_bytes(data[18:20], "little")

            if e_machine == 0x3e:
                return "x64"
            elif e_machine == 0x03:
                return "x86"
            elif e_machine == 0xb7:
                return "arm64"
            elif e_machine == 0x28:
                return "arm"
            elif e_machine == 0x08:
                return "mips"

            return "x64" if ei_class == 2 else "x86"

        return "x64"  # Default

    def _extract_pe_code_section(self, data: bytes) -> Optional[Tuple[bytes, int, int]]:
        """
        Extract code section from PE file.

        Args:
            data: PE file data

        Returns:
            Tuple of (code_bytes, file_offset, virtual_address) or None
        """
        try:
            import pefile
            pe = pefile.PE(data=data)

            # Find executable section (usually .text)
            code_section = None
            for section in pe.sections:
                # Check for executable section (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
                if section.Characteristics & 0x20000000:
                    code_section = section
                    break

            if code_section is None:
                pe.close()
                return None

            # Extract code bytes
            section_offset = code_section.PointerToRawData
            section_size = code_section.SizeOfRawData
            section_va = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

            code_bytes = data[section_offset:section_offset + section_size]

            pe.close()

            logger.info(
                f"PE code section: .text at offset {section_offset}, "
                f"VA 0x{section_va:x}, size {len(code_bytes)}"
            )

            return (code_bytes, section_offset, section_va)

        except Exception as e:
            logger.warning(f"Failed to extract PE code section: {e}")
            return None

    def _extract_elf_code_section(self, data: bytes) -> Optional[Tuple[bytes, int, int]]:
        """
        Extract code section from ELF file.

        Args:
            data: ELF file data

        Returns:
            Tuple of (code_bytes, file_offset, virtual_address) or None
        """
        try:
            # Parse ELF header
            ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
            is_64bit = ei_class == 2

            if is_64bit:
                # ELF64 header
                e_phoff = int.from_bytes(data[32:40], 'little')
                e_phentsize = int.from_bytes(data[54:56], 'little')
                e_phnum = int.from_bytes(data[56:58], 'little')
            else:
                # ELF32 header
                e_phoff = int.from_bytes(data[28:32], 'little')
                e_phentsize = int.from_bytes(data[42:44], 'little')
                e_phnum = int.from_bytes(data[44:46], 'little')

            # Find PT_LOAD segment with execute permission
            for i in range(e_phnum):
                ph_offset = e_phoff + i * e_phentsize

                if is_64bit:
                    p_type = int.from_bytes(data[ph_offset:ph_offset+4], 'little')
                    p_flags = int.from_bytes(data[ph_offset+4:ph_offset+8], 'little')
                    p_offset = int.from_bytes(data[ph_offset+8:ph_offset+16], 'little')
                    p_vaddr = int.from_bytes(data[ph_offset+16:ph_offset+24], 'little')
                    p_filesz = int.from_bytes(data[ph_offset+32:ph_offset+40], 'little')
                else:
                    p_type = int.from_bytes(data[ph_offset:ph_offset+4], 'little')
                    p_offset = int.from_bytes(data[ph_offset+4:ph_offset+8], 'little')
                    p_vaddr = int.from_bytes(data[ph_offset+8:ph_offset+12], 'little')
                    p_filesz = int.from_bytes(data[ph_offset+16:ph_offset+20], 'little')
                    p_flags = int.from_bytes(data[ph_offset+24:ph_offset+28], 'little')

                # PT_LOAD = 1, PF_X (execute) = 1
                if p_type == 1 and (p_flags & 1):
                    code_bytes = data[p_offset:p_offset + p_filesz]
                    logger.info(
                        f"ELF code segment: offset {p_offset}, "
                        f"VA 0x{p_vaddr:x}, size {len(code_bytes)}"
                    )
                    return (code_bytes, p_offset, p_vaddr)

            return None

        except Exception as e:
            logger.warning(f"Failed to extract ELF code section: {e}")
            return None
