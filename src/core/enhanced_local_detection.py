"""
Enhanced Local Detection System - NO EXTERNAL API REQUIRED.

This module provides accurate malware detection using ONLY local analysis.
No VirusTotal, no cloud APIs - everything runs locally.

Key Principles:
1. VALID CRYPTOGRAPHIC SIGNATURES = VERY HIGH TRUST (legitimate software is signed)
2. Context-aware analysis (SSH client SHOULD have network/crypto code)
3. Professional software characteristics (version info, resources, manifests)
4. Smart heuristics that understand software categories

Author: AI-Cerberus
Version: 1.0.0
"""

from __future__ import annotations

import ctypes
import hashlib
import math
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime

from ..utils.logger import get_logger

logger = get_logger("enhanced_local_detection")


@dataclass
class LocalDetectionResult:
    """Result from enhanced local detection."""
    is_legitimate: bool
    is_malicious: bool
    confidence: float
    threat_score: float  # 0-100

    # Detection details
    reasons: List[str] = field(default_factory=list)

    # Signature info
    has_valid_signature: bool = False
    signature_trusted: bool = False
    publisher: str = ""

    # PE characteristics
    pe_score: float = 0.0
    has_version_info: bool = False
    has_manifest: bool = False
    has_resources: bool = False

    # Category detection
    detected_category: str = ""  # "ssh_client", "browser", "utility", etc.
    category_explains_behavior: bool = False

    # Final decision
    override_malicious: bool = False
    override_reason: str = ""


class WindowsSignatureVerifier:
    """
    Cryptographic signature verification using Windows APIs.

    A VALID SIGNATURE means:
    - The file hasn't been tampered with
    - A trusted CA vouched for the publisher
    - This is STRONG evidence of legitimacy
    """

    def __init__(self):
        self._available = os.name == 'nt'

    def verify(self, file_path: Path) -> Tuple[bool, bool, str, Dict]:
        """
        Verify file signature cryptographically.

        Returns:
            (is_signed, is_valid, publisher, details)
        """
        if not self._available:
            return False, False, "", {"error": "Windows only"}

        try:
            return self._verify_with_wintrust(file_path)
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False, False, "", {"error": str(e)}

    def _verify_with_wintrust(self, file_path: Path) -> Tuple[bool, bool, str, Dict]:
        """Use WinVerifyTrust API for cryptographic verification."""
        try:
            # WinTrust structures
            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", ctypes.c_uint32),
                    ("pcwszFilePath", ctypes.c_wchar_p),
                    ("hFile", ctypes.c_void_p),
                    ("pgKnownSubject", ctypes.c_void_p),
                ]

            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", ctypes.c_uint32),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", ctypes.c_uint32),
                    ("fdwRevocationChecks", ctypes.c_uint32),
                    ("dwUnionChoice", ctypes.c_uint32),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", ctypes.c_uint32),
                    ("hWVTStateData", ctypes.c_void_p),
                    ("pwszURLReference", ctypes.c_wchar_p),
                    ("dwProvFlags", ctypes.c_uint32),
                    ("dwUIContext", ctypes.c_uint32),
                ]

            # Constants
            WTD_UI_NONE = 2
            WTD_CHOICE_FILE = 1
            WTD_STATEACTION_VERIFY = 1
            WTD_STATEACTION_CLOSE = 2
            WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

            # Create GUID
            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", ctypes.c_uint32),
                    ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_uint8 * 8),
                ]

            guid = GUID()
            guid.Data1 = 0x00AAC56B
            guid.Data2 = 0xCD44
            guid.Data3 = 0x11d0
            guid.Data4 = (ctypes.c_uint8 * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)

            # Set up file info
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = str(file_path)
            file_info.hFile = None
            file_info.pgKnownSubject = None

            # Set up trust data
            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            trust_data.dwUIChoice = WTD_UI_NONE
            trust_data.fdwRevocationChecks = 0
            trust_data.dwUnionChoice = WTD_CHOICE_FILE
            trust_data.pFile = ctypes.pointer(file_info)
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY

            # Call WinVerifyTrust
            wintrust = ctypes.windll.wintrust
            result = wintrust.WinVerifyTrust(
                None,
                ctypes.byref(guid),
                ctypes.byref(trust_data)
            )

            # Clean up
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(trust_data))

            # Interpret result
            is_signed = result != 0x800B0100  # TRUST_E_NOSIGNATURE
            is_valid = result == 0  # Success

            # Get publisher name
            publisher = self._get_publisher(file_path) if is_signed else ""

            return is_signed, is_valid, publisher, {
                "wintrust_result": result,
                "is_signed": is_signed,
                "is_valid": is_valid,
            }

        except Exception as e:
            return False, False, "", {"error": str(e)}

    def _get_publisher(self, file_path: Path) -> str:
        """Extract publisher name from certificate using Windows Crypt32."""
        try:
            # Try using Crypt32 API for proper certificate extraction
            crypt32 = ctypes.windll.crypt32

            # Get message from file
            CERT_QUERY_OBJECT_FILE = 0x01
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
            CERT_QUERY_FORMAT_FLAG_BINARY = 0x02

            content_type = ctypes.c_uint32()
            format_type = ctypes.c_uint32()
            cert_store = ctypes.c_void_p()
            msg = ctypes.c_void_p()
            context = ctypes.c_void_p()

            result = crypt32.CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                ctypes.c_wchar_p(str(file_path)),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                None,
                ctypes.byref(content_type),
                ctypes.byref(format_type),
                ctypes.byref(cert_store),
                ctypes.byref(msg),
                ctypes.byref(context)
            )

            if result and cert_store:
                # Get certificate from store
                cert_context = crypt32.CertEnumCertificatesInStore(cert_store, None)
                if cert_context:
                    # Get subject name
                    name_size = crypt32.CertGetNameStringW(
                        cert_context,
                        4,  # CERT_NAME_SIMPLE_DISPLAY_TYPE
                        0,
                        None,
                        None,
                        0
                    )

                    if name_size > 0:
                        name_buf = ctypes.create_unicode_buffer(name_size)
                        crypt32.CertGetNameStringW(
                            cert_context,
                            4,
                            0,
                            None,
                            name_buf,
                            name_size
                        )
                        publisher = name_buf.value

                        # Cleanup
                        crypt32.CertFreeCertificateContext(cert_context)
                        crypt32.CertCloseStore(cert_store, 0)

                        if publisher and len(publisher) > 2:
                            return publisher

                if cert_store:
                    crypt32.CertCloseStore(cert_store, 0)

        except Exception as e:
            logger.debug(f"Crypt32 publisher extraction failed: {e}")

        # DO NOT use fallback pattern matching - it causes false positives!
        # Malware can easily contain strings like "Intel", "AMD", etc.
        # Only trust publishers extracted from actual certificates.
        return ""


class SoftwareCategoryDetector:
    """
    Detects what category of software a file is.

    Key insight: An SSH client SHOULD have network and crypto code.
    That's not suspicious - it's EXPECTED.
    """

    # Category signatures - what we expect to find
    CATEGORIES = {
        'ssh_client': {
            'strings': [b'SSH', b'ssh-', b'PuTTY', b'putty', b'OpenSSH', b'terminal',
                       b'session', b'connection', b'host', b'port 22'],
            'imports': ['ws2_32.dll', 'crypt32.dll', 'bcrypt.dll'],
            'expected_behaviors': ['network', 'crypto', 'terminal'],
        },
        'browser': {
            'strings': [b'Mozilla', b'Chrome', b'Firefox', b'http://', b'https://',
                       b'WebKit', b'Gecko', b'HTML', b'JavaScript'],
            'imports': ['wininet.dll', 'urlmon.dll', 'winhttp.dll'],
            'expected_behaviors': ['network', 'crypto', 'file_access'],
        },
        'archive_tool': {
            'strings': [b'ZIP', b'RAR', b'7z', b'archive', b'compress', b'extract',
                       b'PKZIP', b'WinRAR', b'7-Zip'],
            'imports': [],
            'expected_behaviors': ['file_access', 'compression'],
        },
        'media_player': {
            'strings': [b'codec', b'audio', b'video', b'mp3', b'mp4', b'avi',
                       b'DirectShow', b'Media', b'Player'],
            'imports': ['dsound.dll', 'mf.dll', 'mfplat.dll'],
            'expected_behaviors': ['media', 'file_access'],
        },
        'development_tool': {
            'strings': [b'compiler', b'debugger', b'IDE', b'Visual Studio',
                       b'debug', b'breakpoint', b'symbol'],
            'imports': ['dbghelp.dll', 'dbgcore.dll'],
            'expected_behaviors': ['process_access', 'debug', 'file_access'],
        },
        'system_utility': {
            'strings': [b'Microsoft', b'Windows', b'System', b'utility', b'tool',
                       b'administrator', b'service'],
            'imports': ['advapi32.dll', 'kernel32.dll'],
            'expected_behaviors': ['system', 'registry', 'service'],
        },
        'installer': {
            'strings': [b'Setup', b'Install', b'Installer', b'Uninstall',
                       b'InstallShield', b'NSIS', b'Inno Setup'],
            'imports': ['msi.dll', 'cabinet.dll'],
            'expected_behaviors': ['file_access', 'registry', 'service'],
        },
    }

    def detect_category(self, data: bytes, imports: List[str]) -> Tuple[str, float, List[str]]:
        """
        Detect software category.

        Returns:
            (category, confidence, expected_behaviors)
        """
        best_category = ""
        best_score = 0.0
        best_behaviors = []

        data_lower = data.lower()
        imports_lower = [i.lower() for i in imports]

        for category, signatures in self.CATEGORIES.items():
            score = 0.0

            # Check strings
            string_matches = sum(1 for s in signatures['strings'] if s.lower() in data_lower)
            if signatures['strings']:
                score += (string_matches / len(signatures['strings'])) * 0.6

            # Check imports
            if signatures['imports']:
                import_matches = sum(1 for i in signatures['imports'] if i.lower() in imports_lower)
                score += (import_matches / len(signatures['imports'])) * 0.4

            if score > best_score:
                best_score = score
                best_category = category
                best_behaviors = signatures['expected_behaviors']

        return best_category, best_score, best_behaviors


class PECharacteristicsAnalyzer:
    """
    Analyzes PE characteristics to determine legitimacy.

    Professional software has:
    - Version information
    - Resources (icons, dialogs)
    - Manifest (DPI awareness, UAC settings)
    - Standard section names
    - Reasonable timestamps
    - Known compiler signatures
    """

    def analyze(self, file_path: Path, data: bytes) -> Dict[str, Any]:
        """Analyze PE characteristics."""
        result = {
            'is_pe': False,
            'has_version_info': False,
            'has_manifest': False,
            'has_resources': False,
            'has_icon': False,
            'standard_sections': False,
            'reasonable_timestamp': False,
            'known_compiler': None,
            'company': '',
            'product': '',
            'description': '',
            'version': '',
            'imports': [],
            'legitimacy_score': 0.0,
        }

        # Check PE signature
        if len(data) < 64 or data[:2] != b'MZ':
            return result

        try:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return result
            result['is_pe'] = True
        except:
            return result

        score = 0.0

        # Check version info
        if b'VS_VERSION_INFO' in data:
            result['has_version_info'] = True
            score += 0.2

            # Extract version details
            version_info = self._extract_version_info(data)
            result.update(version_info)

            if version_info.get('company'):
                score += 0.1
            if version_info.get('product'):
                score += 0.1

        # Check manifest
        if b'<assembly' in data or b'manifest' in data.lower():
            result['has_manifest'] = True
            score += 0.15

        # Check resources
        if b'.rsrc' in data:
            result['has_resources'] = True
            score += 0.1

        # Check icon
        if b'icon' in data.lower() or b'\x00\x00\x01\x00' in data[:1000]:
            result['has_icon'] = True
            score += 0.05

        # Check sections
        sections = self._get_sections(data, pe_offset)
        standard = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata'}
        section_names = {s.lower() for s in sections}
        if len(section_names & standard) >= 2:
            result['standard_sections'] = True
            score += 0.1

        # Check timestamp
        try:
            timestamp = struct.unpack('<I', data[pe_offset+8:pe_offset+12])[0]
            # Between 2000 and now+1year
            if 946684800 < timestamp < (datetime.now().timestamp() + 31536000):
                result['reasonable_timestamp'] = True
                score += 0.1
        except:
            pass

        # Check compiler
        compiler = self._detect_compiler(data)
        if compiler:
            result['known_compiler'] = compiler
            score += 0.1

        # Extract imports
        result['imports'] = self._extract_imports(data)

        result['legitimacy_score'] = min(1.0, score)
        return result

    def _extract_version_info(self, data: bytes) -> Dict[str, str]:
        """Extract version info from PE."""
        info = {}
        patterns = [
            (b'CompanyName\x00', 'company'),
            (b'ProductName\x00', 'product'),
            (b'FileDescription\x00', 'description'),
            (b'FileVersion\x00', 'version'),
            (b'OriginalFilename\x00', 'original_filename'),
        ]

        for pattern, key in patterns:
            idx = data.find(pattern)
            if idx != -1:
                start = idx + len(pattern)
                value = self._extract_unicode_string(data[start:start+500])
                if value:
                    info[key] = value

        return info

    def _extract_unicode_string(self, data: bytes) -> str:
        """Extract null-terminated unicode string."""
        result = ""
        for i in range(0, min(len(data)-1, 400), 2):
            if data[i:i+2] == b'\x00\x00':
                break
            if 32 <= data[i] < 127:
                result += chr(data[i])
        return result.strip()

    def _get_sections(self, data: bytes, pe_offset: int) -> List[str]:
        """Get section names."""
        sections = []
        try:
            # Number of sections
            num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
            optional_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
            section_offset = pe_offset + 24 + optional_header_size

            for i in range(min(num_sections, 20)):
                name_bytes = data[section_offset + i*40:section_offset + i*40 + 8]
                name = name_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')
                sections.append(name)
        except:
            pass
        return sections

    def _detect_compiler(self, data: bytes) -> Optional[str]:
        """Detect compiler used."""
        data_start = data[:100000]
        compilers = [
            (b'Rich', 'MSVC'),
            (b'GCC:', 'GCC'),
            (b'mingw', 'MinGW'),
            (b'Go build', 'Go'),
            (b'rustc', 'Rust'),
            (b'Delphi', 'Delphi'),
            (b'.NET', '.NET'),
            (b'mscoree.dll', '.NET'),
        ]
        for pattern, name in compilers:
            if pattern in data_start:
                return name
        return None

    def _extract_imports(self, data: bytes) -> List[str]:
        """Extract imported DLLs."""
        imports = []
        common_dlls = [
            b'kernel32.dll', b'user32.dll', b'advapi32.dll', b'shell32.dll',
            b'gdi32.dll', b'ole32.dll', b'ws2_32.dll', b'crypt32.dll',
            b'ntdll.dll', b'msvcrt.dll', b'comctl32.dll', b'comdlg32.dll',
        ]

        data_lower = data.lower()
        for dll in common_dlls:
            if dll in data_lower:
                imports.append(dll.decode())

        return imports


class EnhancedLocalDetector:
    """
    Main enhanced local detection engine.

    NO EXTERNAL APIs - Everything runs locally.

    Decision logic:
    1. Valid cryptographic signature = HIGH TRUST (0.9+ legitimacy)
    2. Professional PE characteristics = MEDIUM TRUST
    3. Category explains behavior = REDUCES suspicion
    4. Only flag as malicious with MULTIPLE strong indicators
    """

    # Weights for decision making
    WEIGHTS = {
        'valid_signature': 0.45,      # VERY HIGH - signatures are hard to fake
        'pe_characteristics': 0.25,   # Professional software characteristics
        'category_match': 0.15,       # Software category explains behavior
        'no_suspicious_only': 0.15,   # No ONLY suspicious indicators
    }

    # Threshold for legitimate
    LEGITIMATE_THRESHOLD = 0.65

    def __init__(self):
        self._signature_verifier = WindowsSignatureVerifier()
        self._category_detector = SoftwareCategoryDetector()
        self._pe_analyzer = PECharacteristicsAnalyzer()

    def analyze(self, file_path: Path, data: Optional[bytes] = None) -> LocalDetectionResult:
        """
        Perform enhanced local detection.

        Args:
            file_path: Path to file
            data: File contents (will read if not provided)

        Returns:
            LocalDetectionResult with detection decision
        """
        if data is None:
            with open(file_path, 'rb') as f:
                data = f.read()

        result = LocalDetectionResult(
            is_legitimate=False,
            is_malicious=False,
            confidence=0.5,
            threat_score=50.0,
        )

        score = 0.0

        # 1. SIGNATURE VERIFICATION (Most important!)
        is_signed, is_valid, publisher, sig_details = self._signature_verifier.verify(file_path)

        result.has_valid_signature = is_valid
        result.signature_trusted = is_valid
        result.publisher = publisher

        if is_valid:
            score += self.WEIGHTS['valid_signature']
            result.reasons.append(f"Valid cryptographic signature from: {publisher or 'Unknown'}")
        elif is_signed:
            # Signed but not fully verified - still trustworthy
            # (may be due to missing intermediate certs, offline, etc.)
            score += self.WEIGHTS['valid_signature'] * 0.7
            result.reasons.append(f"Digitally signed by: {publisher or 'Unknown'}")
            # If we found a known good publisher, trust it more
            if publisher and any(p in publisher for p in ['Microsoft', 'Simon Tatham', 'Google', 'Mozilla', 'Adobe', 'Intel', 'NVIDIA']):
                score += 0.15
                result.signature_trusted = True
                result.reasons.append(f"Known trusted publisher: {publisher}")

        # 2. PE CHARACTERISTICS
        pe_result = self._pe_analyzer.analyze(file_path, data)
        result.pe_score = pe_result['legitimacy_score']
        result.has_version_info = pe_result['has_version_info']
        result.has_manifest = pe_result['has_manifest']
        result.has_resources = pe_result['has_resources']

        score += pe_result['legitimacy_score'] * self.WEIGHTS['pe_characteristics']

        if pe_result['has_version_info']:
            result.reasons.append(f"Has version info: {pe_result.get('product', pe_result.get('description', 'Unknown'))}")
        if pe_result['known_compiler']:
            result.reasons.append(f"Built with: {pe_result['known_compiler']}")

        # 3. CATEGORY DETECTION
        category, cat_confidence, expected_behaviors = self._category_detector.detect_category(
            data, pe_result['imports']
        )

        if category and cat_confidence > 0.3:
            result.detected_category = category
            result.category_explains_behavior = True
            score += cat_confidence * self.WEIGHTS['category_match']
            result.reasons.append(f"Detected category: {category} (explains network/crypto behavior)")

        # 4. CHECK FOR PURELY SUSPICIOUS INDICATORS (without legitimate context)
        suspicious_only = self._check_suspicious_only(data, pe_result, category)
        if not suspicious_only:
            score += self.WEIGHTS['no_suspicious_only']
        else:
            result.reasons.append(f"Suspicious indicators: {', '.join(suspicious_only)}")

        # FINAL DECISION
        result.confidence = score

        if score >= self.LEGITIMATE_THRESHOLD:
            result.is_legitimate = True
            result.is_malicious = False
            result.threat_score = max(0, (1 - score) * 30)  # Low threat score

            if is_valid:  # Valid signature = very confident
                result.override_malicious = True
                result.override_reason = f"Valid signature from {publisher}" if publisher else "Valid cryptographic signature"
        else:
            # Check for malicious indicators
            num_suspicious = len(suspicious_only)
            has_multiple_backdoor = 'multiple_linux_backdoor_patterns' in suspicious_only
            has_no_metadata = 'no_executable_metadata' in suspicious_only

            # MALICIOUS if:
            # 1. Score < 0.4 AND has 3+ suspicious indicators
            # 2. Has multiple backdoor patterns (definitely malware)
            # 3. Score < 0.3 AND has any suspicious indicators
            if has_multiple_backdoor:
                # Multiple Linux backdoor patterns = definitely malicious
                result.is_malicious = True
                result.threat_score = min(100, 70 + num_suspicious * 5)
                result.reasons.append(f"Multiple backdoor patterns detected ({num_suspicious} indicators)")
            elif score < 0.4 and num_suspicious >= 3:
                # Low legitimacy score + multiple suspicious = malicious
                result.is_malicious = True
                result.threat_score = min(100, 60 + num_suspicious * 5)
            elif score < 0.3 and suspicious_only:
                # Very low score + any suspicious = malicious
                result.is_malicious = True
                result.threat_score = min(100, (1 - score) * 100)
            elif has_no_metadata and num_suspicious >= 2:
                # No metadata + suspicious patterns = likely malicious
                result.is_malicious = True
                result.threat_score = min(100, 50 + num_suspicious * 10)
            elif suspicious_only:
                # Has suspicious indicators but not enough to confirm malicious
                result.is_malicious = False
                result.threat_score = min(60, 30 + num_suspicious * 10)
            else:
                # Uncertain - not enough evidence either way
                result.threat_score = 50

        return result

    def _check_suspicious_only(
        self,
        data: bytes,
        pe_result: Dict,
        category: str
    ) -> List[str]:
        """
        Check for suspicious indicators that aren't explained by category.

        Returns list of unexplained suspicious indicators.
        """
        suspicious = []

        # ================================================================
        # WINDOWS PE SUSPICIOUS INDICATORS
        # ================================================================
        win_checks = [
            (b'CreateRemoteThread', 'process_injection', ['development_tool']),
            (b'VirtualAllocEx', 'memory_manipulation', ['development_tool']),
            (b'WriteProcessMemory', 'process_manipulation', ['development_tool']),
            (b'SetWindowsHookEx', 'hooking', ['development_tool', 'system_utility']),
            (b'IsDebuggerPresent', 'anti_debug', ['development_tool']),
            (b'NtUnmapViewOfSection', 'process_hollowing', []),
            (b'RegSetValue', 'registry_modification', ['installer', 'system_utility']),
            (b'ShellExecute', 'shell_execution', ['browser', 'system_utility']),
        ]

        for pattern, indicator, allowed_categories in win_checks:
            if pattern in data:
                if category not in allowed_categories:
                    suspicious.append(indicator)

        # ================================================================
        # LINUX/UNIX MALWARE INDICATORS
        # ================================================================
        linux_indicators = [
            # Backdoor/RAT indicators
            (b'/bin/sh', 'shell_access'),
            (b'/bin/bash', 'shell_access'),
            (b'/dev/null', 'output_hiding'),
            (b'socket', 'network_socket'),
            (b'connect', 'network_connect'),
            (b'bind', 'network_bind'),
            (b'listen', 'network_listen'),
            (b'accept', 'network_accept'),
            (b'fork', 'process_fork'),
            (b'execve', 'process_exec'),
            (b'system', 'shell_command'),
            (b'popen', 'shell_command'),
            # Crypto mining indicators
            (b'stratum', 'crypto_mining'),
            (b'mining', 'crypto_mining'),
            (b'hashrate', 'crypto_mining'),
            # Persistence indicators
            (b'/etc/cron', 'persistence'),
            (b'/etc/init', 'persistence'),
            (b'systemctl', 'persistence'),
            (b'.bashrc', 'persistence'),
            (b'/tmp/', 'temp_file_usage'),
            # Data exfiltration
            (b'curl', 'http_client'),
            (b'wget', 'http_client'),
            (b'POST', 'http_post'),
            (b'GET', 'http_get'),
            # Evasion
            (b'LD_PRELOAD', 'library_injection'),
            (b'ptrace', 'anti_debug'),
            (b'/proc/', 'proc_access'),
        ]

        linux_count = 0
        for pattern, indicator in linux_indicators:
            if pattern in data:
                linux_count += 1
                if linux_count <= 5:  # Only add first 5
                    suspicious.append(f'linux_{indicator}')

        # If many Linux indicators, definitely suspicious
        if linux_count >= 5:
            suspicious.append('multiple_linux_backdoor_patterns')

        # ================================================================
        # GENERAL SUSPICIOUS PATTERNS
        # ================================================================

        # Check for packed/encrypted (suspicious if no valid signature)
        if not pe_result.get('has_version_info') and not pe_result.get('has_resources'):
            entropy = self._calculate_entropy(data[:10000])
            if entropy > 7.5:
                suspicious.append('high_entropy_no_resources')

        # Executable without metadata = suspicious
        # Professional software ALWAYS has version info and resources
        has_no_metadata = (
            not pe_result.get('has_version_info') and
            not pe_result.get('has_manifest') and
            not pe_result.get('has_resources')
        )
        if has_no_metadata:
            suspicious.append('no_executable_metadata')

        return suspicious

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = 0.0
        length = len(data)
        for f in freq:
            if f > 0:
                p = f / length
                entropy -= p * math.log2(p)

        return entropy

    def should_override_malicious_detection(
        self,
        file_path: Path,
        data: bytes,
        current_threat_score: float
    ) -> Tuple[bool, str, float]:
        """
        Check if a malicious detection should be overridden.

        Called when other detectors flag file as malicious.

        Returns:
            (should_override, reason, new_threat_score)
        """
        result = self.analyze(file_path, data)

        # If we're confident it's legitimate, override
        if result.override_malicious:
            new_score = min(15.0, current_threat_score * 0.15)
            return True, result.override_reason, new_score

        # If it's in a known category that explains behavior
        if result.category_explains_behavior and result.confidence > 0.5:
            new_score = min(25.0, current_threat_score * 0.3)
            return True, f"Behavior explained by category: {result.detected_category}", new_score

        return False, "", current_threat_score


# Global instance
_enhanced_detector: Optional[EnhancedLocalDetector] = None


def get_enhanced_local_detector() -> EnhancedLocalDetector:
    """Get global enhanced local detector instance."""
    global _enhanced_detector
    if _enhanced_detector is None:
        _enhanced_detector = EnhancedLocalDetector()
    return _enhanced_detector
