"""
YARA rule scanning engine.

Provides comprehensive YARA scanning with:
- Built-in malware detection rules
- Custom rule management
- Match result formatting
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_analyzer import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.exceptions import YaraError

logger = get_logger("yara_engine")


@dataclass
class YaraMatch:
    """YARA rule match result."""

    rule: str
    namespace: str = ""
    description: str = ""
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    strings: List[Tuple[int, str, str]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "description": self.description,
            "severity": self.severity,
            "tags": self.tags,
            "strings": [
                {"offset": s[0], "identifier": s[1], "data": str(s[2])[:100]}
                for s in self.strings[:20]
            ],
            "meta": self.meta,
        }


class YaraEngine(BaseAnalyzer):
    """
    YARA scanning engine with built-in malware rules.

    Features:
    - Comprehensive built-in rule set
    - Custom rule file loading
    - Timeout protection
    - Detailed match reporting
    """

    @property
    def name(self) -> str:
        return "YARA Engine"

    @property
    def supported_formats(self) -> list:
        return ["*"]

    def __init__(self, timeout: int = 60, rules_dir: Optional[Path] = None):
        """
        Initialize YARA engine.

        Args:
            timeout: Scan timeout in seconds
            rules_dir: Directory containing .yar rule files (default: resources/yara_rules)
        """
        super().__init__()
        self.timeout = timeout
        self._rules = None
        self._rules_dir = rules_dir
        self._rule_count = 0
        self._compile_all_rules()

    def _compile_all_rules(self) -> None:
        """Compile all YARA rules from built-in and rule files."""
        try:
            import yara

            # Find rules directory
            if self._rules_dir:
                rules_dir = self._rules_dir
            else:
                # Default: resources/yara_rules relative to project root
                project_root = Path(__file__).parent.parent.parent
                rules_dir = project_root / "resources" / "yara_rules"

            # Collect all rule sources
            rule_sources: Dict[str, str] = {}

            # Add built-in rules
            rule_sources["builtin"] = self._get_builtin_rules()

            # Load all .yar and .yara files from directory
            if rules_dir.exists():
                for rule_file in rules_dir.glob("*.yar"):
                    try:
                        content = rule_file.read_text(encoding="utf-8")
                        namespace = rule_file.stem
                        rule_sources[namespace] = content
                        logger.debug(f"Loaded rule file: {rule_file.name}")
                    except Exception as e:
                        logger.warning(f"Failed to load {rule_file.name}: {e}")

                for rule_file in rules_dir.glob("*.yara"):
                    try:
                        content = rule_file.read_text(encoding="utf-8")
                        namespace = rule_file.stem
                        rule_sources[namespace] = content
                        logger.debug(f"Loaded rule file: {rule_file.name}")
                    except Exception as e:
                        logger.warning(f"Failed to load {rule_file.name}: {e}")

            # Compile all rules together
            if rule_sources:
                self._rules = yara.compile(sources=rule_sources)
                self._rule_count = len(rule_sources)
                logger.info(f"YARA rules compiled: {self._rule_count} rule files loaded")
            else:
                logger.warning("No YARA rules found")

        except ImportError:
            logger.warning("yara-python not installed")
        except yara.SyntaxError as e:
            logger.error(f"YARA rule syntax error: {e}")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")

    def _compile_builtin_rules(self) -> None:
        """Compile built-in YARA rules only (legacy method)."""
        try:
            import yara

            rules_source = self._get_builtin_rules()
            self._rules = yara.compile(source=rules_source)
            logger.info("YARA rules compiled successfully")

        except ImportError:
            logger.warning("yara-python not installed")
        except yara.SyntaxError as e:
            logger.error(f"YARA rule syntax error: {e}")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")

    def get_rule_count(self) -> int:
        """Get the number of loaded rule files."""
        return self._rule_count

    def reload_rules(self) -> bool:
        """Reload all YARA rules from disk."""
        try:
            self._compile_all_rules()
            return self._rules is not None
        except Exception as e:
            logger.error(f"Failed to reload rules: {e}")
            return False

    def add_rules_directory(self, directory: Path) -> int:
        """
        Add rules from an additional directory.

        Args:
            directory: Path to directory containing .yar files

        Returns:
            Number of rule files loaded
        """
        if not directory.exists():
            logger.error(f"Rules directory not found: {directory}")
            return 0

        try:
            import yara

            count = 0
            rule_sources: Dict[str, str] = {}

            # Load existing rules
            rule_sources["_current"] = self._get_builtin_rules()

            # Load from new directory
            for rule_file in directory.glob("*.yar"):
                try:
                    content = rule_file.read_text(encoding="utf-8")
                    namespace = f"{directory.name}_{rule_file.stem}"
                    rule_sources[namespace] = content
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to load {rule_file}: {e}")

            for rule_file in directory.glob("*.yara"):
                try:
                    content = rule_file.read_text(encoding="utf-8")
                    namespace = f"{directory.name}_{rule_file.stem}"
                    rule_sources[namespace] = content
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to load {rule_file}: {e}")

            if count > 0:
                self._rules = yara.compile(sources=rule_sources)
                self._rule_count += count
                logger.info(f"Added {count} rule files from {directory}")

            return count

        except Exception as e:
            logger.error(f"Failed to add rules directory: {e}")
            return 0

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> List[YaraMatch]:
        """
        Scan file with YARA rules.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data

        Returns:
            List of YaraMatch objects
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        matches = []

        if self._rules is None:
            logger.warning("YARA rules not available")
            return matches

        try:
            import yara

            yara_matches = self._rules.match(
                data=data,
                timeout=self.timeout,
            )

            for match in yara_matches:
                # Extract match strings
                matched_strings = []
                try:
                    for string_match in match.strings[:20]:
                        for instance in string_match.instances[:5]:
                            matched_strings.append((
                                instance.offset,
                                string_match.identifier,
                                instance.matched_data.decode(
                                    "latin-1", errors="ignore"
                                )[:100],
                            ))
                except AttributeError:
                    # Old yara-python API
                    for s in match.strings[:20]:
                        if len(s) >= 3:
                            data_str = s[2] if isinstance(s[2], str) else \
                                s[2].decode("latin-1", errors="ignore")
                            matched_strings.append((s[0], s[1], data_str[:100]))

                # Get metadata
                meta = {}
                if hasattr(match, "meta"):
                    meta = dict(match.meta)

                matches.append(YaraMatch(
                    rule=match.rule,
                    namespace=match.namespace if hasattr(match, "namespace") else "",
                    description=meta.get("description", ""),
                    severity=meta.get("severity", "medium"),
                    tags=list(match.tags) if hasattr(match, "tags") else [],
                    strings=matched_strings,
                    meta=meta,
                ))

        except Exception as e:
            logger.error(f"YARA scan failed: {e}")

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return matches

    def load_rules_file(self, rule_path: Path) -> bool:
        """Load additional YARA rules from file."""
        try:
            import yara

            if self._rules:
                # Combine with existing rules
                new_rules = yara.compile(filepath=str(rule_path))
                # Note: yara-python doesn't support rule combination
                # So we just replace for now
                self._rules = new_rules
            else:
                self._rules = yara.compile(filepath=str(rule_path))

            logger.info(f"Loaded YARA rules from {rule_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return False

    def _get_builtin_rules(self) -> str:
        """Get comprehensive built-in YARA rules."""
        return r'''
rule Malware_Indicators {
    meta:
        description = "Generic malware indicators"
        severity = "high"
    strings:
        $inject1 = "VirtualAllocEx" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "CreateRemoteThread" nocase
        $inject4 = "NtWriteVirtualMemory" nocase
        $persist1 = "CurrentVersion\\Run" nocase
        $persist2 = "CurrentVersion\\RunOnce" nocase
        $net1 = "URLDownloadToFile" nocase
        $net2 = "InternetOpen" nocase
        $anti1 = "IsDebuggerPresent" nocase
        $anti2 = "CheckRemoteDebuggerPresent" nocase
    condition:
        2 of ($inject*) or any of ($persist*) or
        (any of ($net*) and any of ($anti*))
}

rule Trojan_Generic {
    meta:
        description = "Generic Trojan indicators"
        severity = "high"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "wscript" nocase
        $api1 = "ShellExecute" nocase
        $api2 = "WinExec" nocase
        $hide1 = "SW_HIDE"
    condition:
        (any of ($s*) and any of ($api*)) or
        (any of ($api*) and any of ($hide*))
}

rule RAT_Indicators {
    meta:
        description = "Remote Access Trojan"
        severity = "critical"
    strings:
        $cmd1 = "shell" nocase
        $cmd2 = "execute" nocase
        $cmd3 = "download" nocase
        $cmd4 = "upload" nocase
        $cmd5 = "screenshot" nocase
        $cmd6 = "keylog" nocase
        $net1 = "socket" nocase
        $net2 = "connect" nocase
        $net3 = "send" nocase
        $net4 = "recv" nocase
    condition:
        3 of ($cmd*) and 2 of ($net*)
}

rule Ransomware_Indicators {
    meta:
        description = "Ransomware indicators"
        severity = "critical"
    strings:
        $crypt1 = "CryptEncrypt" nocase
        $crypt2 = "CryptGenKey" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".enc"
        $note1 = "ransom" nocase
        $note2 = "bitcoin" nocase
        $note3 = "decrypt" nocase
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        (any of ($crypt*) and any of ($ext*)) or
        2 of ($note*) or $btc
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger detection"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState" nocase
        $api2 = "GetKeyboardState" nocase
        $api3 = "SetWindowsHookEx" nocase
        $api4 = "GetKeyState" nocase
        $log1 = "keylog" nocase
        $log2 = "keystroke" nocase
    condition:
        2 of ($api*) or any of ($log*)
}

rule Infostealer_Indicators {
    meta:
        description = "Information stealer"
        severity = "high"
    strings:
        $browser1 = "chrome" nocase
        $browser2 = "firefox" nocase
        $browser3 = "Login Data"
        $browser4 = "cookies.sqlite"
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $path1 = "AppData\\Local" nocase
        $path2 = "AppData\\Roaming" nocase
    condition:
        (2 of ($browser*) and any of ($cred*)) or
        (any of ($path*) and 2 of ($cred*))
}

rule Shellcode_Patterns {
    meta:
        description = "Shellcode patterns"
        severity = "critical"
    strings:
        $nop = { 90 90 90 90 90 }
        $getpc1 = { E8 00 00 00 00 }
        $getpc2 = { D9 EE D9 74 24 F4 }
        $api_hash = { 60 89 E5 31 C0 64 8B 50 30 }
    condition:
        any of them
}

rule Packer_UPX {
    meta:
        description = "UPX packed executable"
        severity = "medium"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        any of them
}

rule Packer_Generic {
    meta:
        description = "Packed/obfuscated executable"
        severity = "medium"
    strings:
        $p1 = ".themida"
        $p2 = ".vmp0"
        $p3 = "PECompact"
        $p4 = "ASPack"
        $p5 = "MPRESS"
    condition:
        any of them
}

rule Network_C2 {
    meta:
        description = "C2 communication indicators"
        severity = "high"
    strings:
        $http1 = "User-Agent:" nocase
        $http2 = "POST" nocase
        $socket1 = "WSAStartup" nocase
        $socket2 = "socket" nocase
        $socket3 = "connect" nocase
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        (any of ($http*) and $ip) or
        (2 of ($socket*) and $ip)
}

rule Evasion_AntiDebug {
    meta:
        description = "Anti-debugging techniques"
        severity = "high"
    strings:
        $s1 = "IsDebuggerPresent" nocase
        $s2 = "NtQueryInformationProcess" nocase
        $s3 = "GetTickCount" nocase
        $s4 = "QueryPerformanceCounter" nocase
        $s5 = "OutputDebugString" nocase
    condition:
        2 of them
}

rule Evasion_AntiVM {
    meta:
        description = "Anti-VM techniques"
        severity = "high"
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "QEMU" nocase
        $vm4 = "Xen" nocase
        $vm5 = "Hyper-V" nocase
    condition:
        2 of them
}

rule Backdoor_Generic {
    meta:
        description = "Generic backdoor indicators"
        severity = "critical"
    strings:
        // Network operations
        $net1 = "bind" nocase
        $net2 = "listen" nocase
        $net3 = "accept" nocase
        $net4 = "socket" nocase
        $net5 = "connect" nocase
        $net6 = "send" nocase
        $net7 = "recv" nocase

        // Command execution
        $cmd1 = "system" nocase
        $cmd2 = "exec" nocase
        $cmd3 = "shell" nocase
        $cmd4 = "cmd" nocase
        $cmd5 = "/bin/sh"
        $cmd6 = "/bin/bash"
        $cmd7 = "cmd.exe"
        $cmd8 = "powershell"

        // Backdoor-specific strings
        $bd1 = "backdoor" nocase
        $bd2 = "reverse" nocase
        $bd3 = "bind shell" nocase
        $bd4 = "reverse shell" nocase
        $bd5 = "remote shell" nocase
        $bd6 = "command shell" nocase

        // Common backdoor ports (as strings)
        $port1 = "4444"
        $port2 = "31337"
        $port3 = "1337"
        $port4 = "8080"

        // Remote control
        $remote1 = "remote" nocase
        $remote2 = "control" nocase
        $remote3 = "access" nocase

    condition:
        // Any backdoor-specific string
        any of ($bd*) or
        // Network + command execution
        (2 of ($net*) and 2 of ($cmd*)) or
        // Remote control indicators
        (any of ($remote*) and (any of ($cmd*) or any of ($net*))) or
        // Port + network + command
        (any of ($port*) and any of ($net*) and any of ($cmd*))
}

rule Suspicious_Strings {
    meta:
        description = "Suspicious strings - lowered threshold"
        severity = "medium"
    strings:
        $s1 = "hack" nocase
        $s2 = "exploit" nocase
        $s3 = "payload" nocase
        $s4 = "inject" nocase
        $s5 = "backdoor" nocase
        $s6 = "rootkit" nocase
        $s7 = "malware" nocase
        $s8 = "virus" nocase
        $s9 = "trojan" nocase
    condition:
        any of them
}
'''
