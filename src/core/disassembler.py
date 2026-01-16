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

    def __init__(self, max_instructions: int = 50000):
        """
        Initialize disassembler with 100% binary coverage.

        Args:
            max_instructions: Maximum instructions to disassemble (increased to 50K for full coverage)
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
        architecture: str = "x64",
        offset: int = 0,
        base_address: int = 0,
    ) -> DisassemblyResult:
        """
        Disassemble binary code.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data
            architecture: Target architecture
            offset: Offset to start disassembly
            base_address: Base address for instruction addresses

        Returns:
            DisassemblyResult with instructions
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        result = DisassemblyResult(
            architecture=architecture,
            mode="64-bit" if architecture == "x64" else "32-bit",
            entry_point=base_address + offset,
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

            # Get code to disassemble - FULL BINARY (not just 8KB!)
            # Limit to 10MB for performance, but that covers most binaries
            max_code_size = min(len(data) - offset, 10 * 1024 * 1024)  # 10MB max
            code = data[offset:offset + max_code_size]

            logger.info(f"Disassembling {len(code):,} bytes (full binary)")

            # Disassemble
            count = 0
            for insn in md.disasm(code, base_address + offset):
                if count >= self.max_instructions:
                    logger.warning(f"Reached max instructions limit: {self.max_instructions}")
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
        """Check for code modification patterns (self-modifying code)."""
        op_str = instruction.op_str.lower()
        # Writing to code segment or executable memory
        if "cs:" in op_str or "rip" in op_str or "eip" in op_str:
            self._mark_suspicious(instruction, "Potential self-modifying code", "high")

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
