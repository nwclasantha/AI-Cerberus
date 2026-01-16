"""
Behavioral indicator analyzer.

Detects suspicious behaviors based on:
- API imports
- String patterns
- Code patterns
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
import time

from .base_analyzer import BaseAnalyzer
from ..utils.logger import get_logger

logger = get_logger("behavior_analyzer")


@dataclass
class BehavioralIndicators:
    """Collection of behavioral indicators."""

    # Capabilities
    has_injection: bool = False
    has_persistence: bool = False
    has_network: bool = False
    has_anti_debug: bool = False
    has_anti_vm: bool = False
    has_crypto: bool = False
    has_keylogging: bool = False
    has_screen_capture: bool = False
    has_file_ops: bool = False
    has_registry_ops: bool = False
    has_process_ops: bool = False
    has_service_ops: bool = False
    has_privilege_escalation: bool = False
    has_backdoor: bool = False  # NEW: Backdoor detection

    # Detailed findings
    injection_techniques: List[str] = field(default_factory=list)
    persistence_mechanisms: List[str] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    suspicious_apis: List[str] = field(default_factory=list)
    backdoor_indicators: List[str] = field(default_factory=list)  # NEW

    # Risk assessment
    risk_score: float = 0.0
    risk_level: str = "low"

    def to_dict(self) -> Dict:
        return {
            "capabilities": {
                "injection": self.has_injection,
                "persistence": self.has_persistence,
                "network": self.has_network,
                "anti_debug": self.has_anti_debug,
                "anti_vm": self.has_anti_vm,
                "crypto": self.has_crypto,
                "keylogging": self.has_keylogging,
                "screen_capture": self.has_screen_capture,
                "file_operations": self.has_file_ops,
                "registry_operations": self.has_registry_ops,
                "process_operations": self.has_process_ops,
                "service_operations": self.has_service_ops,
                "privilege_escalation": self.has_privilege_escalation,
                "backdoor": self.has_backdoor,
            },
            "details": {
                "injection_techniques": self.injection_techniques,
                "persistence_mechanisms": self.persistence_mechanisms,
                "network_indicators": self.network_indicators,
                "evasion_techniques": self.evasion_techniques,
                "suspicious_apis": self.suspicious_apis[:50],
                "backdoor_indicators": self.backdoor_indicators,
            },
            "risk": {
                "score": round(self.risk_score, 2),
                "level": self.risk_level,
            },
        }

    def capability_count(self) -> int:
        """Count active capabilities."""
        return sum([
            self.has_injection, self.has_persistence, self.has_network,
            self.has_anti_debug, self.has_anti_vm, self.has_crypto,
            self.has_keylogging, self.has_screen_capture, self.has_file_ops,
            self.has_registry_ops, self.has_process_ops, self.has_service_ops,
            self.has_privilege_escalation, self.has_backdoor,
        ])


class BehaviorAnalyzer(BaseAnalyzer):
    """
    Analyze behavioral indicators from imports and strings.

    Detects:
    - Process injection techniques
    - Persistence mechanisms
    - Network communication
    - Anti-analysis techniques
    - Credential theft
    - Keylogging
    """

    # API categories for behavioral detection
    INJECTION_APIS = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory", "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "NtSetContextThread", "RtlCreateUserThread",
        "NtUnmapViewOfSection", "NtMapViewOfSection",
    }

    PERSISTENCE_APIS = {
        "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
        "CreateService", "OpenSCManager", "StartService",
        "SetWindowsHookEx", "CoCreateInstance",
    }

    PERSISTENCE_STRINGS = {
        "currentversion\\run", "currentversion\\runonce",
        "software\\microsoft\\windows\\currentversion\\run",
        "schtasks", "taskschd", "startup", "appinit_dlls",
    }

    NETWORK_APIS = {
        "WSAStartup", "WSASocket", "socket", "connect", "send", "recv",
        "bind", "listen", "accept", "InternetOpen", "InternetOpenUrl",
        "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "URLDownloadToFile", "URLDownloadToCacheFile",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "sendto", "recvfrom", "gethostbyname", "inet_addr", "htons",
    }

    # Backdoor and shell execution APIs (CRITICAL for backdoor detection)
    SHELL_EXECUTION_APIS = {
        "system", "exec", "ShellExecute", "ShellExecuteA", "ShellExecuteEx",
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "WinExec", "popen", "_popen", "_wsystem",
    }

    # Backdoor-specific string patterns
    BACKDOOR_STRINGS = {
        "backdoor", "reverse shell", "bind shell", "remote shell",
        "command shell", "/bin/sh", "/bin/bash", "cmd.exe",
    }

    ANTI_DEBUG_APIS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "GetTickCount", "QueryPerformanceCounter",
        "NtSetInformationThread", "CloseHandle",
    }

    ANTI_VM_STRINGS = {
        "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
        "virtual", "sandboxie", "wine", "bochs",
    }

    CRYPTO_APIS = {
        "CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
        "CryptDeriveKey", "CryptImportKey", "CryptExportKey",
        "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
    }

    KEYLOG_APIS = {
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "SetWindowsHookEx", "GetForegroundWindow", "GetWindowText",
    }

    SCREEN_APIS = {
        "GetDC", "GetWindowDC", "BitBlt", "CreateCompatibleDC",
        "CreateCompatibleBitmap", "capCreateCaptureWindow",
    }

    PRIVILEGE_APIS = {
        "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
        "DuplicateToken", "ImpersonateLoggedOnUser", "SetThreadToken",
    }

    @property
    def name(self) -> str:
        return "Behavior Analyzer"

    @property
    def supported_formats(self) -> list:
        return ["*"]

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
        imports: Optional[List[str]] = None,
        strings: Optional[List[str]] = None,
    ) -> BehavioralIndicators:
        """
        Analyze file for behavioral indicators.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data
            imports: Optional list of imported functions
            strings: Optional list of extracted strings

        Returns:
            BehavioralIndicators object
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        result = BehavioralIndicators()

        # Convert data to string for pattern matching
        data_str = data.decode("latin-1", errors="ignore").lower()

        # Get imports set
        imports_set: Set[str] = set()
        if imports:
            imports_set = set(imports)
        else:
            # Extract from data
            imports_set = self._extract_api_names(data)

        # Get strings set
        strings_set: Set[str] = set()
        if strings:
            strings_set = {s.lower() for s in strings}

        # Analyze each capability
        self._check_injection(result, imports_set, data_str)
        self._check_persistence(result, imports_set, data_str)
        self._check_network(result, imports_set, data_str)
        self._check_anti_debug(result, imports_set, data_str)
        self._check_anti_vm(result, data_str)
        self._check_crypto(result, imports_set)
        self._check_keylogging(result, imports_set)
        self._check_screen_capture(result, imports_set)
        self._check_privilege_escalation(result, imports_set)
        self._check_backdoor(result, imports_set, data_str)  # NEW: Backdoor detection

        # Check file/registry/process operations
        self._check_system_ops(result, imports_set, data_str)

        # Calculate risk score
        self._calculate_risk(result)

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return result

    def _extract_api_names(self, data: bytes) -> Set[str]:
        """Extract potential API names from binary data."""
        apis = set()

        # Simple pattern: PascalCase strings that look like API names
        import re
        text = data.decode("latin-1", errors="ignore")
        matches = re.findall(r"\b[A-Z][a-z]+(?:[A-Z][a-z]+)+[A-Z]?\b", text)
        apis.update(matches)

        return apis

    def _check_injection(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
        data_str: str,
    ) -> None:
        """Check for process injection capabilities."""
        found = imports.intersection(self.INJECTION_APIS)

        if found:
            result.has_injection = True
            result.suspicious_apis.extend(found)

            # Identify specific techniques
            if {"WriteProcessMemory", "CreateRemoteThread"}.issubset(found):
                result.injection_techniques.append("Classic DLL injection")

            if "NtUnmapViewOfSection" in found:
                result.injection_techniques.append("Process hollowing")

            if "QueueUserAPC" in found or "NtQueueApcThread" in found:
                result.injection_techniques.append("APC injection")

            if "SetThreadContext" in found:
                result.injection_techniques.append("Thread hijacking")

    def _check_persistence(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
        data_str: str,
    ) -> None:
        """Check for persistence mechanisms."""
        found_apis = imports.intersection(self.PERSISTENCE_APIS)

        if found_apis:
            result.has_persistence = True
            result.suspicious_apis.extend(found_apis)

        # Check for persistence strings
        for pattern in self.PERSISTENCE_STRINGS:
            if pattern in data_str:
                result.has_persistence = True
                result.persistence_mechanisms.append(f"Registry: {pattern}")

        if "CreateService" in imports:
            result.persistence_mechanisms.append("Service creation")

        if "schtasks" in data_str or "taskschd" in data_str:
            result.persistence_mechanisms.append("Scheduled task")

    def _check_network(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
        data_str: str,
    ) -> None:
        """Check for network capabilities."""
        found = imports.intersection(self.NETWORK_APIS)

        if found:
            result.has_network = True
            result.suspicious_apis.extend(found)

            if "URLDownloadToFile" in found:
                result.network_indicators.append("File download capability")

            if {"socket", "connect", "send"}.issubset(found):
                result.network_indicators.append("Raw socket communication")

            if any("Http" in api for api in found):
                result.network_indicators.append("HTTP communication")

    def _check_anti_debug(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
        data_str: str,
    ) -> None:
        """Check for anti-debugging techniques."""
        found = imports.intersection(self.ANTI_DEBUG_APIS)

        if found:
            result.has_anti_debug = True
            result.suspicious_apis.extend(found)

            if "IsDebuggerPresent" in found:
                result.evasion_techniques.append("IsDebuggerPresent check")

            if "NtQueryInformationProcess" in found:
                result.evasion_techniques.append("Process debug port check")

            if {"GetTickCount", "QueryPerformanceCounter"}.intersection(found):
                result.evasion_techniques.append("Timing-based detection")

    def _check_anti_vm(
        self,
        result: BehavioralIndicators,
        data_str: str,
    ) -> None:
        """Check for anti-VM techniques."""
        found = []
        for pattern in self.ANTI_VM_STRINGS:
            if pattern in data_str:
                found.append(pattern)

        if len(found) >= 2:
            result.has_anti_vm = True
            result.evasion_techniques.extend(
                [f"VM detection: {v}" for v in found[:5]]
            )

    def _check_crypto(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
    ) -> None:
        """Check for cryptographic capabilities."""
        found = imports.intersection(self.CRYPTO_APIS)

        if found:
            result.has_crypto = True
            result.suspicious_apis.extend(found)

    def _check_keylogging(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
    ) -> None:
        """Check for keylogging capabilities."""
        found = imports.intersection(self.KEYLOG_APIS)

        if len(found) >= 2:
            result.has_keylogging = True
            result.suspicious_apis.extend(found)

    def _check_screen_capture(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
    ) -> None:
        """Check for screen capture capabilities."""
        found = imports.intersection(self.SCREEN_APIS)

        if len(found) >= 3:
            result.has_screen_capture = True
            result.suspicious_apis.extend(found)

    def _check_privilege_escalation(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
    ) -> None:
        """Check for privilege escalation capabilities."""
        found = imports.intersection(self.PRIVILEGE_APIS)

        if found:
            result.has_privilege_escalation = True
            result.suspicious_apis.extend(found)

    def _check_backdoor(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
        data_str: str,
    ) -> None:
        """
        Check for backdoor indicators (CRITICAL for backdoor detection).

        Detects:
        - Shell execution + network communication (reverse shells)
        - Network listening + command execution (bind shells)
        - Backdoor-specific strings in binary
        """
        # Check for shell execution APIs
        shell_apis = imports.intersection(self.SHELL_EXECUTION_APIS)

        # Check for network APIs
        network_apis = imports.intersection(self.NETWORK_APIS)

        # Check for backdoor strings in data
        backdoor_strings_found = []
        for pattern in self.BACKDOOR_STRINGS:
            if pattern in data_str:
                backdoor_strings_found.append(pattern)

        # Detection logic: Backdoor if any of these conditions:
        # 1. Backdoor-specific strings found
        # 2. Network + shell execution combo (classic backdoor pattern)
        # 3. Listen/bind/accept + command execution (bind shell)

        if backdoor_strings_found:
            result.has_backdoor = True
            result.backdoor_indicators.extend(
                [f"Backdoor string: {s}" for s in backdoor_strings_found[:5]]
            )
            result.suspicious_apis.extend(backdoor_strings_found)

        # Network + shell execution = likely backdoor
        if shell_apis and network_apis:
            result.has_backdoor = True
            result.backdoor_indicators.append(
                f"Network + shell execution: {len(shell_apis)} shell APIs, {len(network_apis)} network APIs"
            )
            result.suspicious_apis.extend(shell_apis)
            result.suspicious_apis.extend(network_apis)

            # Identify specific backdoor types
            if {"bind", "listen", "accept"}.intersection(network_apis):
                result.backdoor_indicators.append("Bind shell pattern detected")

            if {"connect", "send", "recv"}.intersection(network_apis):
                result.backdoor_indicators.append("Reverse shell pattern detected")

        # Even just shell execution APIs can be suspicious
        elif len(shell_apis) >= 2:
            result.backdoor_indicators.append(
                f"Multiple shell execution APIs: {', '.join(list(shell_apis)[:3])}"
            )

    def _check_system_ops(
        self,
        result: BehavioralIndicators,
        imports: Set[str],
        data_str: str,
    ) -> None:
        """Check for file/registry/process operations."""
        file_apis = {"CreateFile", "WriteFile", "DeleteFile", "CopyFile"}
        registry_apis = {"RegOpenKey", "RegQueryValue", "RegEnumKey"}
        process_apis = {"CreateProcess", "OpenProcess", "TerminateProcess"}
        service_apis = {"OpenSCManager", "CreateService", "StartService"}

        result.has_file_ops = bool(imports.intersection(file_apis))
        result.has_registry_ops = bool(imports.intersection(registry_apis))
        result.has_process_ops = bool(imports.intersection(process_apis))
        result.has_service_ops = bool(imports.intersection(service_apis))

    def _calculate_risk(self, result: BehavioralIndicators) -> None:
        """Calculate overall risk score."""
        score = 0.0

        # Critical-risk capabilities (UPDATED: added backdoor)
        if result.has_backdoor:
            score += 30  # Backdoors are CRITICAL threats
        if result.has_injection:
            score += 25
        if result.has_keylogging:
            score += 20
        if result.has_privilege_escalation:
            score += 15

        # Medium-risk capabilities
        if result.has_persistence:
            score += 15
        if result.has_network:
            score += 10
        if result.has_crypto:
            score += 10
        if result.has_screen_capture:
            score += 10

        # Evasion techniques
        if result.has_anti_debug:
            score += 10
        if result.has_anti_vm:
            score += 10

        # Additional details
        score += len(result.injection_techniques) * 5
        score += len(result.evasion_techniques) * 3
        score += len(result.backdoor_indicators) * 5  # NEW: Backdoor details

        result.risk_score = min(100.0, score)

        # Determine risk level
        if result.risk_score >= 70:
            result.risk_level = "critical"
        elif result.risk_score >= 50:
            result.risk_level = "high"
        elif result.risk_score >= 30:
            result.risk_level = "medium"
        elif result.risk_score >= 10:
            result.risk_level = "low"
        else:
            result.risk_level = "info"
