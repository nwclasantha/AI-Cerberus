"""
Multi-algorithm hash calculator for malware samples.

Supports standard cryptographic hashes (MD5, SHA family)
and fuzzy hashes (SSDeep, TLSH) for similarity analysis.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional
import time

from .base_analyzer import BaseAnalyzer
from ..utils.logger import get_logger

logger = get_logger("hash_calculator")


@dataclass
class HashCollection:
    """Collection of file hashes."""

    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    sha512: str = ""
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    imphash: Optional[str] = None
    rich_hash: Optional[str] = None
    authentihash: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert to dictionary."""
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "sha512": self.sha512,
            "ssdeep": self.ssdeep,
            "tlsh": self.tlsh,
            "imphash": self.imphash,
            "rich_hash": self.rich_hash,
            "authentihash": self.authentihash,
        }

    @property
    def primary(self) -> str:
        """Return primary identifier (SHA256)."""
        return self.sha256


class HashCalculator(BaseAnalyzer):
    """
    Calculate multiple hashes for file identification and similarity.

    Supports:
    - MD5, SHA1, SHA256, SHA512 (cryptographic)
    - SSDeep (fuzzy hash for similarity)
    - TLSH (locality sensitive hash)
    - ImpHash (import hash for PE files)
    """

    @property
    def name(self) -> str:
        return "Hash Calculator"

    @property
    def supported_formats(self) -> list:
        return ["*"]  # Supports all file types

    def __init__(self):
        super().__init__()
        self._ssdeep_available = self._check_ssdeep()
        self._tlsh_available = self._check_tlsh()

    def _check_ssdeep(self) -> bool:
        """Check if ssdeep library is available."""
        try:
            import ssdeep
            return True
        except ImportError:
            logger.warning("SSDeep library not available, fuzzy hashing disabled")
            return False

    def _check_tlsh(self) -> bool:
        """Check if TLSH library is available."""
        try:
            import tlsh
            return True
        except ImportError:
            logger.warning("TLSH library not available")
            return False

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> HashCollection:
        """
        Calculate all available hashes for a file.

        Args:
            file_path: Path to file
            data: Optional pre-loaded file data

        Returns:
            HashCollection with all calculated hashes
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        # Calculate cryptographic hashes
        hashes = HashCollection(
            md5=self._calculate_md5(data),
            sha1=self._calculate_sha1(data),
            sha256=self._calculate_sha256(data),
            sha512=self._calculate_sha512(data),
        )

        # Calculate fuzzy hashes if available
        if self._ssdeep_available:
            hashes.ssdeep = self._calculate_ssdeep(data)

        if self._tlsh_available:
            hashes.tlsh = self._calculate_tlsh(data)

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return hashes

    def _calculate_md5(self, data: bytes) -> str:
        """Calculate MD5 hash."""
        return hashlib.md5(data).hexdigest()

    def _calculate_sha1(self, data: bytes) -> str:
        """Calculate SHA1 hash."""
        return hashlib.sha1(data).hexdigest()

    def _calculate_sha256(self, data: bytes) -> str:
        """Calculate SHA256 hash."""
        return hashlib.sha256(data).hexdigest()

    def _calculate_sha512(self, data: bytes) -> str:
        """Calculate SHA512 hash."""
        return hashlib.sha512(data).hexdigest()

    def _calculate_ssdeep(self, data: bytes) -> Optional[str]:
        """Calculate SSDeep fuzzy hash."""
        try:
            import ssdeep
            return ssdeep.hash(data)
        except Exception as e:
            logger.warning(f"SSDeep calculation failed: {e}")
            return None

    def _calculate_tlsh(self, data: bytes) -> Optional[str]:
        """Calculate TLSH locality sensitive hash."""
        try:
            import tlsh
            # TLSH requires minimum 50 bytes
            if len(data) < 50:
                return None
            h = tlsh.hash(data)
            return h if h else None
        except Exception as e:
            logger.warning(f"TLSH calculation failed: {e}")
            return None

    def calculate_imphash(self, pe_obj) -> Optional[str]:
        """
        Calculate import hash from PE object.

        Args:
            pe_obj: pefile.PE object

        Returns:
            Import hash string or None
        """
        try:
            return pe_obj.get_imphash()
        except Exception as e:
            logger.warning(f"ImpHash calculation failed: {e}")
            return None

    def calculate_rich_hash(self, data: bytes) -> Optional[str]:
        """
        Calculate Rich header hash for PE files.

        Args:
            data: File data

        Returns:
            Rich header MD5 hash or None
        """
        try:
            # Find Rich header marker "DanS"
            rich_marker = b"DanS"
            idx = data.find(rich_marker)
            if idx == -1:
                return None

            # Find "Rich" marker to get end of header
            rich_end = data.find(b"Rich", idx)
            if rich_end == -1:
                return None

            # Extract and hash Rich header
            rich_data = data[idx:rich_end + 4]
            return hashlib.md5(rich_data).hexdigest()
        except Exception as e:
            logger.warning(f"Rich hash calculation failed: {e}")
            return None

    def compare_ssdeep(self, hash1: str, hash2: str) -> int:
        """
        Compare two SSDeep hashes for similarity.

        Args:
            hash1: First SSDeep hash
            hash2: Second SSDeep hash

        Returns:
            Similarity score (0-100)
        """
        try:
            import ssdeep
            return ssdeep.compare(hash1, hash2)
        except Exception:
            return 0

    def compare_tlsh(self, hash1: str, hash2: str) -> int:
        """
        Compare two TLSH hashes.

        Args:
            hash1: First TLSH hash
            hash2: Second TLSH hash

        Returns:
            Distance score (0 = identical, higher = more different)
        """
        try:
            import tlsh
            return tlsh.diff(hash1, hash2)
        except Exception:
            return -1
