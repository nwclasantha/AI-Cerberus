"""
Entropy analysis for detecting packed/encrypted content.

Calculates Shannon entropy for overall file and block-level
analysis to identify suspicious high-entropy regions.
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time

from .base_analyzer import BaseAnalyzer
from ..utils.logger import get_logger

logger = get_logger("entropy_analyzer")


@dataclass
class EntropyBlock:
    """Entropy data for a single block."""

    offset: int
    size: int
    entropy: float
    is_suspicious: bool = False

    def to_dict(self) -> Dict:
        return {
            "offset": self.offset,
            "size": self.size,
            "entropy": round(self.entropy, 4),
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class EntropyResult:
    """Complete entropy analysis result."""

    overall: float  # 0-1 normalized
    raw: float      # 0-8 bits
    blocks: List[EntropyBlock] = field(default_factory=list)
    histogram: List[int] = field(default_factory=list)
    assessment: str = "normal"
    suspicious_regions: List[Tuple[int, int]] = field(default_factory=list)

    # Statistics
    min_block_entropy: float = 0.0
    max_block_entropy: float = 0.0
    mean_block_entropy: float = 0.0
    std_block_entropy: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "overall": round(self.overall, 4),
            "raw": round(self.raw, 4),
            "assessment": self.assessment,
            "statistics": {
                "min": round(self.min_block_entropy, 4),
                "max": round(self.max_block_entropy, 4),
                "mean": round(self.mean_block_entropy, 4),
                "std": round(self.std_block_entropy, 4),
            },
            "suspicious_regions": self.suspicious_regions,
            "block_count": len(self.blocks),
            "histogram": self.histogram,
        }

    @property
    def is_packed(self) -> bool:
        """Check if file appears to be packed/encrypted."""
        return self.overall > 0.9 or self.assessment in ["packed", "encrypted"]

    @property
    def is_suspicious(self) -> bool:
        """Check if entropy is suspiciously high."""
        return self.overall > 0.85 or len(self.suspicious_regions) > 3


class EntropyAnalyzer(BaseAnalyzer):
    """
    Analyze file entropy to detect packing/encryption.

    High entropy (close to 1.0 or 8 bits) indicates:
    - Encrypted content
    - Compressed/packed code
    - Random data

    Normal executables typically have entropy 0.5-0.7.
    """

    # Entropy thresholds
    THRESHOLD_ENCRYPTED = 0.95  # > 95% likely encrypted
    THRESHOLD_PACKED = 0.85     # > 85% likely packed/compressed
    THRESHOLD_SUSPICIOUS = 0.75 # > 75% suspicious
    THRESHOLD_NORMAL = 0.60     # < 60% normal

    @property
    def name(self) -> str:
        return "Entropy Analyzer"

    @property
    def supported_formats(self) -> list:
        return ["*"]

    def __init__(self, block_size: int = 256):
        """
        Initialize entropy analyzer.

        Args:
            block_size: Size of blocks for granular analysis
        """
        super().__init__()
        self.block_size = block_size

    def analyze(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> EntropyResult:
        """
        Perform complete entropy analysis.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data

        Returns:
            EntropyResult with overall and block-level entropy
        """
        self._log_start(file_path)
        start_time = time.time()

        if data is None:
            data = self._load_file(file_path)

        # Calculate overall entropy
        overall_raw = self._calculate_entropy(data)
        overall_normalized = overall_raw / 8.0

        # Calculate byte histogram
        histogram = self._calculate_histogram(data)

        # Calculate block-level entropy
        blocks = self._analyze_blocks(data)

        # Find suspicious regions
        suspicious_regions = self._find_suspicious_regions(blocks)

        # Calculate block statistics
        block_entropies = [b.entropy for b in blocks]
        if block_entropies:
            min_entropy = min(block_entropies)
            max_entropy = max(block_entropies)
            mean_entropy = sum(block_entropies) / len(block_entropies)
            variance = sum((e - mean_entropy) ** 2 for e in block_entropies) / len(block_entropies)
            std_entropy = math.sqrt(variance)
        else:
            min_entropy = max_entropy = mean_entropy = std_entropy = 0.0

        # Assess entropy level
        assessment = self._assess_entropy(overall_normalized, blocks)

        result = EntropyResult(
            overall=overall_normalized,
            raw=overall_raw,
            blocks=blocks,
            histogram=histogram,
            assessment=assessment,
            suspicious_regions=suspicious_regions,
            min_block_entropy=min_entropy,
            max_block_entropy=max_entropy,
            mean_block_entropy=mean_entropy,
            std_block_entropy=std_entropy,
        )

        duration = time.time() - start_time
        self._log_complete(file_path, duration)

        return result

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        Args:
            data: Byte data

        Returns:
            Entropy in bits (0-8)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        counter = Counter(data)
        length = len(data)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_histogram(self, data: bytes) -> List[int]:
        """
        Calculate byte value histogram.

        Args:
            data: Byte data

        Returns:
            List of 256 counts, one per byte value
        """
        histogram = [0] * 256
        for byte in data:
            histogram[byte] += 1
        return histogram

    def _analyze_blocks(self, data: bytes) -> List[EntropyBlock]:
        """
        Calculate entropy for each block.

        Args:
            data: File data

        Returns:
            List of EntropyBlock objects
        """
        blocks = []
        offset = 0

        while offset < len(data):
            block_data = data[offset:offset + self.block_size]
            if len(block_data) < self.block_size // 2:
                break  # Skip very small trailing blocks

            entropy = self._calculate_entropy(block_data) / 8.0
            is_suspicious = entropy > self.THRESHOLD_SUSPICIOUS

            blocks.append(EntropyBlock(
                offset=offset,
                size=len(block_data),
                entropy=entropy,
                is_suspicious=is_suspicious,
            ))

            offset += self.block_size

        return blocks

    def _find_suspicious_regions(
        self,
        blocks: List[EntropyBlock],
    ) -> List[Tuple[int, int]]:
        """
        Find contiguous suspicious high-entropy regions.

        Args:
            blocks: List of entropy blocks

        Returns:
            List of (start_offset, end_offset) tuples
        """
        regions = []
        in_region = False
        region_start = 0

        for block in blocks:
            if block.is_suspicious:
                if not in_region:
                    in_region = True
                    region_start = block.offset
            else:
                if in_region:
                    in_region = False
                    region_end = block.offset
                    # Only track regions larger than a few blocks
                    if region_end - region_start >= self.block_size * 3:
                        regions.append((region_start, region_end))

        # Handle region extending to end of file
        if in_region and blocks:
            last_block = blocks[-1]
            region_end = last_block.offset + last_block.size
            if region_end - region_start >= self.block_size * 3:
                regions.append((region_start, region_end))

        return regions

    def _assess_entropy(
        self,
        overall: float,
        blocks: List[EntropyBlock],
    ) -> str:
        """
        Assess overall entropy level.

        Args:
            overall: Normalized overall entropy (0-1)
            blocks: List of entropy blocks

        Returns:
            Assessment string
        """
        # Check for encrypted content
        if overall >= self.THRESHOLD_ENCRYPTED:
            return "encrypted"

        # Check for packed/compressed
        if overall >= self.THRESHOLD_PACKED:
            # Additional check: uniform high entropy across file
            high_entropy_blocks = sum(1 for b in blocks if b.entropy > 0.9)
            if blocks and high_entropy_blocks / len(blocks) > 0.8:
                return "encrypted"
            return "packed"

        # Check for suspicious patterns
        if overall >= self.THRESHOLD_SUSPICIOUS:
            return "suspicious"

        # Check for mixed content (some high entropy regions)
        suspicious_blocks = sum(1 for b in blocks if b.is_suspicious)
        if blocks and suspicious_blocks / len(blocks) > 0.3:
            return "mixed"

        return "normal"

    def get_entropy_color(self, entropy: float) -> str:
        """
        Get color for entropy visualization.

        Args:
            entropy: Normalized entropy (0-1)

        Returns:
            Hex color string
        """
        if entropy >= self.THRESHOLD_ENCRYPTED:
            return "#ff0000"  # Red - encrypted
        elif entropy >= self.THRESHOLD_PACKED:
            return "#ff6600"  # Orange - packed
        elif entropy >= self.THRESHOLD_SUSPICIOUS:
            return "#ffcc00"  # Yellow - suspicious
        elif entropy >= self.THRESHOLD_NORMAL:
            return "#00cc00"  # Green - normal
        else:
            return "#0066ff"  # Blue - low entropy
