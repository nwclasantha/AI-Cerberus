"""
Advanced string extraction and categorization.

Extracts ASCII and Unicode strings from binary files
and categorizes them by type (URLs, IPs, paths, etc.).
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import time

from .base_analyzer import BaseAnalyzer
from ..utils.logger import get_logger

logger = get_logger("string_extractor")


@dataclass
class ExtractedString:
    """A single extracted string with metadata."""

    value: str
    offset: int
    encoding: str  # ascii, utf-16-le, utf-16-be
    category: str  # url, ip, email, path, api, registry, generic
    is_suspicious: bool = False

    def to_dict(self) -> Dict:
        return {
            "value": self.value,
            "offset": self.offset,
            "encoding": self.encoding,
            "category": self.category,
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class StringsResult:
    """Complete string extraction result."""

    total_count: int = 0
    strings: List[ExtractedString] = field(default_factory=list)

    # Categorized strings
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    api_functions: List[str] = field(default_factory=list)
    suspicious: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "total_count": self.total_count,
            "categories": {
                "urls": self.urls[:100],
                "ips": self.ips[:100],
                "emails": self.emails[:50],
                "domains": self.domains[:100],
                "file_paths": self.file_paths[:100],
                "registry_keys": self.registry_keys[:100],
                "api_functions": self.api_functions[:200],
                "suspicious": self.suspicious[:100],
            },
        }


class StringExtractor(BaseAnalyzer):
    """
    Extract and categorize strings from binary files.

    Features:
    - ASCII and Unicode (UTF-16) string extraction
    - Automatic categorization (URLs, IPs, APIs, etc.)
    - Suspicious string detection
    - Configurable minimum length
    """

    # Suspicious strings indicating malicious behavior
    SUSPICIOUS_KEYWORDS = {
        # Malware terms
        "password", "credential", "bitcoin", "ransom", "decrypt",
        "encrypt", "payload", "shellcode", "inject", "hook",
        "keylog", "backdoor", "trojan", "botnet", "c2", "cnc",

        # System tools often abused
        "cmd.exe", "powershell", "wscript", "cscript", "mshta",
        "certutil", "bitsadmin", "regsvr32", "rundll32",

        # Anti-analysis
        "vmware", "virtualbox", "sandboxie", "wireshark", "procmon",
        "ollydbg", "x64dbg", "ida", "debugger",
    }

    # Suspicious API functions
    SUSPICIOUS_APIS = {
        # Injection
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory",
        "QueueUserAPC", "SetThreadContext",

        # Process/Thread
        "CreateProcess", "ShellExecute", "WinExec", "CreateThread",

        # Hooking
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState",

        # Network
        "WSAStartup", "socket", "connect", "send", "recv",
        "InternetOpen", "HttpOpenRequest", "URLDownloadToFile",

        # Registry
        "RegSetValue", "RegCreateKey", "RegDeleteKey",

        # Crypto
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",

        # Anti-debug
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount",
    }

    # Regex patterns
    PATTERNS = {
        "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
        "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "domain": re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b"),
        "windows_path": re.compile(r"[A-Za-z]:\\[^\s<>\"'|*?]+"),
        "unix_path": re.compile(r"/(?:usr|etc|var|tmp|home|bin|opt)/[^\s<>\"']+"),
        "registry": re.compile(r"HKEY_[A-Z_]+\\[^\s<>\"']+", re.IGNORECASE),
        "guid": re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"),
    }

    @property
    def name(self) -> str:
        return "String Extractor"

    @property
    def supported_formats(self) -> list:
        return ["*"]

    def __init__(
        self,
        min_length: int = 4,
        max_strings: int = 10000,
        extract_unicode: bool = True,
    ):
        """
        Initialize string extractor.

        Args:
            min_length: Minimum string length
            max_strings: Maximum strings to extract
            extract_unicode: Also extract Unicode strings
        """
        super().__init__()
        self.min_length = min_length
        self.max_strings = max_strings
        self.extract_unicode = extract_unicode

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> StringsResult:
        """
        Extract and categorize strings from file.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data

        Returns:
            StringsResult with categorized strings
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        result = StringsResult()

        # Extract ASCII strings (respects max_strings limit internally)
        ascii_strings = self._extract_ascii(data)
        result.strings.extend(ascii_strings)

        # Extract Unicode strings (pass remaining limit)
        if self.extract_unicode and len(result.strings) < self.max_strings:
            remaining = self.max_strings - len(result.strings)
            unicode_strings = self._extract_unicode(data, remaining)
            result.strings.extend(unicode_strings)

        # Total count (no need for redundant truncation - limits enforced during extraction)
        result.total_count = len(result.strings)

        # Categorize strings
        self._categorize_strings(result)

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return result

    def _extract_ascii(self, data: bytes) -> List[ExtractedString]:
        """Extract ASCII strings (with early termination at max_strings limit)."""
        strings = []
        current = b""
        start_offset = 0

        for i, byte in enumerate(data):
            # Early exit if max strings reached (prevent memory exhaustion)
            if len(strings) >= self.max_strings:
                logger.debug(f"Reached max_strings limit ({self.max_strings}), stopping ASCII extraction")
                break

            if 32 <= byte < 127:  # Printable ASCII
                if not current:
                    start_offset = i
                current += bytes([byte])
            else:
                if len(current) >= self.min_length:
                    try:
                        value = current.decode("ascii")
                        category, suspicious = self._categorize_string(value)
                        strings.append(ExtractedString(
                            value=value,
                            offset=start_offset,
                            encoding="ascii",
                            category=category,
                            is_suspicious=suspicious,
                        ))
                    except UnicodeDecodeError:
                        pass
                current = b""

        # Handle string at end (only if under limit)
        if len(current) >= self.min_length and len(strings) < self.max_strings:
            try:
                value = current.decode("ascii")
                category, suspicious = self._categorize_string(value)
                strings.append(ExtractedString(
                    value=value,
                    offset=start_offset,
                    encoding="ascii",
                    category=category,
                    is_suspicious=suspicious,
                ))
            except UnicodeDecodeError:
                pass

        return strings

    def _extract_unicode(self, data: bytes, remaining_limit: int) -> List[ExtractedString]:
        """
        Extract UTF-16LE Unicode strings (with early termination at limit).

        Args:
            data: Binary data to extract from
            remaining_limit: How many more strings can be extracted
        """
        strings = []
        current = b""
        start_offset = 0

        for i in range(0, len(data) - 1, 2):
            # Early exit if limit reached (prevent memory exhaustion)
            if len(strings) >= remaining_limit:
                logger.debug(f"Reached remaining limit ({remaining_limit}), stopping Unicode extraction")
                break

            char = data[i:i + 2]

            # Check for printable ASCII as UTF-16LE (char, 0x00)
            if char[1] == 0 and 32 <= char[0] < 127:
                if not current:
                    start_offset = i
                current += char
            else:
                if len(current) >= self.min_length * 2:
                    try:
                        value = current.decode("utf-16-le")
                        # Skip if same as ASCII (already extracted)
                        if not all(c.isascii() for c in value):
                            category, suspicious = self._categorize_string(value)
                            strings.append(ExtractedString(
                                value=value,
                                offset=start_offset,
                                encoding="utf-16-le",
                                category=category,
                                is_suspicious=suspicious,
                            ))
                    except UnicodeDecodeError:
                        pass
                current = b""

        return strings

    def _categorize_string(self, value: str) -> Tuple[str, bool]:
        """
        Categorize a single string.

        Returns:
            Tuple of (category, is_suspicious)
        """
        value_lower = value.lower()

        # Check for suspicious keywords
        is_suspicious = any(kw in value_lower for kw in self.SUSPICIOUS_KEYWORDS)

        # Check for suspicious APIs
        if value in self.SUSPICIOUS_APIS:
            return "api", True

        # Check patterns
        if self.PATTERNS["url"].search(value):
            return "url", is_suspicious
        if self.PATTERNS["ip"].match(value):
            return "ip", is_suspicious
        if self.PATTERNS["email"].search(value):
            return "email", is_suspicious
        if self.PATTERNS["registry"].search(value):
            return "registry", is_suspicious
        if self.PATTERNS["windows_path"].search(value):
            return "path", is_suspicious
        if self.PATTERNS["unix_path"].search(value):
            return "path", is_suspicious
        if self.PATTERNS["domain"].search(value) and len(value) > 5:
            return "domain", is_suspicious

        # Check for API function names (PascalCase)
        if re.match(r"^[A-Z][a-z]+(?:[A-Z][a-z]+)+[A-Z]?$", value):
            return "api", is_suspicious

        return "generic", is_suspicious

    def _categorize_strings(self, result: StringsResult) -> None:
        """Populate categorized string lists."""
        seen_urls: Set[str] = set()
        seen_ips: Set[str] = set()
        seen_emails: Set[str] = set()
        seen_domains: Set[str] = set()
        seen_paths: Set[str] = set()
        seen_registry: Set[str] = set()
        seen_apis: Set[str] = set()

        for s in result.strings:
            value = s.value

            if s.category == "url" and value not in seen_urls:
                result.urls.append(value)
                seen_urls.add(value)
            elif s.category == "ip" and value not in seen_ips:
                result.ips.append(value)
                seen_ips.add(value)
            elif s.category == "email" and value not in seen_emails:
                result.emails.append(value)
                seen_emails.add(value)
            elif s.category == "domain" and value not in seen_domains:
                result.domains.append(value)
                seen_domains.add(value)
            elif s.category == "path" and value not in seen_paths:
                result.file_paths.append(value)
                seen_paths.add(value)
            elif s.category == "registry" and value not in seen_registry:
                result.registry_keys.append(value)
                seen_registry.add(value)
            elif s.category == "api" and value not in seen_apis:
                result.api_functions.append(value)
                seen_apis.add(value)

            if s.is_suspicious:
                result.suspicious.append(value)
