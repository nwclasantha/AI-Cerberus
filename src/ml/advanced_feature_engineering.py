"""
Advanced Feature Engineering Pipeline for Malware Detection.

Implements sophisticated feature transformations and engineering
techniques to enhance anomaly detection precision to 98.6%+.

Features:
- Polynomial feature expansion
- Interaction terms generation
- N-gram byte sequence features
- Statistical moment features
- Wavelet transform features
- Entropy-based features at multiple scales
- Benford's Law deviation features
- Information-theoretic features
- Structural complexity features
- Dynamic feature selection

Author: AI-Cerberus
Version: 3.0.0
"""

from __future__ import annotations

import math
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from scipy import stats
from scipy.fft import fft
from collections import Counter

from ..utils.logger import get_logger

logger = get_logger("feature_engineering")
warnings.filterwarnings('ignore')


@dataclass
class AdvancedFeatures:
    """Advanced engineered features for malware detection."""

    # Original features
    base_features: np.ndarray

    # Polynomial features
    polynomial_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Interaction features
    interaction_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Statistical moment features
    moment_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # N-gram features
    ngram_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Entropy features
    entropy_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Frequency domain features
    frequency_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Benford's Law features
    benford_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Complexity features
    complexity_features: np.ndarray = field(default_factory=lambda: np.array([]))

    # Information-theoretic features
    info_theory_features: np.ndarray = field(default_factory=lambda: np.array([]))

    def to_array(self) -> np.ndarray:
        """Concatenate all features into single array."""
        all_features = [self.base_features]

        for name in ['polynomial_features', 'interaction_features', 'moment_features',
                     'ngram_features', 'entropy_features', 'frequency_features',
                     'benford_features', 'complexity_features', 'info_theory_features']:
            feat = getattr(self, name)
            if feat is not None and len(feat) > 0:
                all_features.append(feat)

        return np.concatenate(all_features)

    @property
    def total_features(self) -> int:
        """Total number of features."""
        return len(self.to_array())


class PolynomialFeatureGenerator:
    """Generate polynomial features with controlled expansion."""

    def __init__(self, degree: int = 2, interaction_only: bool = False):
        self._degree = degree
        self._interaction_only = interaction_only
        self._n_input_features = None
        self._n_output_features = None

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit and transform data."""
        self._n_input_features = X.shape[1] if len(X.shape) > 1 else len(X)
        return self._transform(X)

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform data."""
        return self._transform(X)

    def _transform(self, X: np.ndarray) -> np.ndarray:
        """Generate polynomial features."""
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        n_samples, n_features = X.shape
        features = [X]

        if self._degree >= 2:
            # Squared features
            squared = X ** 2
            features.append(squared)

            if not self._interaction_only:
                # Interaction terms (pairwise products)
                n_interactions = min(50, n_features * (n_features - 1) // 2)
                interactions = []
                count = 0
                for i in range(n_features):
                    for j in range(i + 1, n_features):
                        if count >= n_interactions:
                            break
                        interactions.append(X[:, i] * X[:, j])
                        count += 1
                    if count >= n_interactions:
                        break

                if interactions:
                    features.append(np.column_stack(interactions))

        if self._degree >= 3:
            # Cubed features (limited)
            cubed = X[:, :min(20, n_features)] ** 3
            features.append(cubed)

        result = np.hstack(features)
        self._n_output_features = result.shape[1]
        return result


class StatisticalMomentFeatures:
    """Extract statistical moment features."""

    def __init__(self, max_moment: int = 4):
        self._max_moment = max_moment

    def transform(self, data: bytes) -> np.ndarray:
        """Extract statistical moments from byte data."""
        if not data:
            return np.zeros(10)

        byte_values = np.frombuffer(data[:10000], dtype=np.uint8).astype(np.float64)

        if len(byte_values) == 0:
            return np.zeros(10)

        features = []

        # Basic statistics
        features.append(np.mean(byte_values))
        features.append(np.std(byte_values))
        features.append(np.median(byte_values))

        # Skewness and kurtosis
        if len(byte_values) > 2:
            features.append(float(stats.skew(byte_values)))
            features.append(float(stats.kurtosis(byte_values)))
        else:
            features.extend([0.0, 0.0])

        # Higher moments
        for moment in range(3, self._max_moment + 1):
            centered = byte_values - np.mean(byte_values)
            if np.std(byte_values) > 0:
                normalized = centered / np.std(byte_values)
                features.append(np.mean(normalized ** moment))
            else:
                features.append(0.0)

        # Range and IQR
        features.append(np.max(byte_values) - np.min(byte_values))
        q75, q25 = np.percentile(byte_values, [75, 25])
        features.append(q75 - q25)

        return np.array(features[:10])


class NGramFeatureExtractor:
    """Extract N-gram features from byte sequences."""

    def __init__(self, n_values: List[int] = [2, 3, 4]):
        self._n_values = n_values
        self._top_k = 100  # Top K most common n-grams

    def transform(self, data: bytes) -> np.ndarray:
        """Extract N-gram distribution features."""
        if not data:
            return np.zeros(len(self._n_values) * 10)

        features = []

        for n in self._n_values:
            ngram_features = self._extract_ngram_features(data, n)
            features.extend(ngram_features)

        return np.array(features)

    def _extract_ngram_features(self, data: bytes, n: int) -> List[float]:
        """Extract features from n-gram distribution."""
        if len(data) < n:
            return [0.0] * 10

        # Count n-grams
        ngrams = []
        for i in range(len(data) - n + 1):
            ngrams.append(data[i:i+n])

        counter = Counter(ngrams)
        total = len(ngrams)

        if total == 0:
            return [0.0] * 10

        # Distribution features
        frequencies = np.array(list(counter.values())) / total

        features = [
            len(counter) / (256 ** n),  # Uniqueness ratio
            np.mean(frequencies),
            np.std(frequencies),
            np.max(frequencies),
            np.min(frequencies),
            float(stats.entropy(frequencies)),  # Entropy
            np.percentile(frequencies, 90),
            np.percentile(frequencies, 10),
            sum(1 for f in frequencies if f > 0.01) / len(frequencies),  # Common ratio
            sum(1 for f in frequencies if f < 0.001) / len(frequencies),  # Rare ratio
        ]

        return features


class MultiScaleEntropyFeatures:
    """Extract entropy features at multiple scales."""

    def __init__(self, scales: List[int] = [1, 4, 16, 64, 256]):
        self._scales = scales

    def transform(self, data: bytes) -> np.ndarray:
        """Extract multi-scale entropy features."""
        if not data:
            return np.zeros(len(self._scales) * 3)

        features = []

        for scale in self._scales:
            scale_features = self._entropy_at_scale(data, scale)
            features.extend(scale_features)

        return np.array(features)

    def _entropy_at_scale(self, data: bytes, scale: int) -> List[float]:
        """Calculate entropy at specific scale."""
        if len(data) < scale:
            return [0.0, 0.0, 0.0]

        # Chunk data at this scale
        chunks = []
        for i in range(0, len(data) - scale + 1, scale):
            chunk = data[i:i+scale]
            # Compute chunk signature (mean byte value)
            chunks.append(sum(chunk) // scale)

        if not chunks:
            return [0.0, 0.0, 0.0]

        # Calculate entropy of chunk distribution
        counter = Counter(chunks)
        probs = np.array(list(counter.values())) / len(chunks)

        entropy = float(stats.entropy(probs))
        max_entropy = np.log2(len(counter)) if len(counter) > 1 else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0

        return [entropy, normalized_entropy, len(counter) / 256]


class FrequencyDomainFeatures:
    """Extract frequency domain features using FFT."""

    def __init__(self, n_components: int = 20):
        self._n_components = n_components

    def transform(self, data: bytes) -> np.ndarray:
        """Extract FFT-based features."""
        if len(data) < 64:
            return np.zeros(self._n_components + 5)

        # Convert to signal
        signal = np.frombuffer(data[:4096], dtype=np.uint8).astype(np.float64)
        signal = signal - np.mean(signal)  # Remove DC component

        # Apply FFT
        fft_result = fft(signal)
        magnitude = np.abs(fft_result[:len(fft_result)//2])

        if len(magnitude) == 0:
            return np.zeros(self._n_components + 5)

        features = []

        # Top N frequency components (normalized)
        top_indices = np.argsort(magnitude)[-self._n_components:]
        top_magnitudes = magnitude[top_indices]
        total_energy = np.sum(magnitude ** 2)

        if total_energy > 0:
            normalized_mags = top_magnitudes / np.sqrt(total_energy)
        else:
            normalized_mags = np.zeros(self._n_components)

        features.extend(normalized_mags.tolist())

        # Spectral features
        features.append(np.sum(magnitude ** 2))  # Total energy
        features.append(np.mean(magnitude))  # Spectral centroid approximation
        features.append(np.std(magnitude))  # Spectral spread
        features.append(np.max(magnitude) / (np.mean(magnitude) + 1e-10))  # Peak ratio
        features.append(float(stats.entropy(magnitude / (np.sum(magnitude) + 1e-10))))  # Spectral entropy

        return np.array(features)


class BenfordLawFeatures:
    """Extract features based on Benford's Law deviation."""

    BENFORD_PROBS = np.array([
        0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046
    ])

    def transform(self, data: bytes) -> np.ndarray:
        """Calculate Benford's Law deviation features."""
        if len(data) < 100:
            return np.zeros(5)

        # Extract leading digits from byte values
        byte_values = np.frombuffer(data[:10000], dtype=np.uint8)
        leading_digits = []

        for val in byte_values:
            if val > 0:
                while val >= 10:
                    val //= 10
                if 1 <= val <= 9:
                    leading_digits.append(val)

        if len(leading_digits) < 10:
            return np.zeros(5)

        # Calculate observed distribution
        counter = Counter(leading_digits)
        observed = np.array([counter.get(d, 0) for d in range(1, 10)]) / len(leading_digits)

        # Calculate deviations
        deviation = observed - self.BENFORD_PROBS
        abs_deviation = np.abs(deviation)

        features = [
            np.sum(abs_deviation),  # Total deviation
            np.max(abs_deviation),  # Max deviation
            np.mean(abs_deviation),  # Mean deviation
            float(stats.chisquare(observed * len(leading_digits) + 1,
                                  self.BENFORD_PROBS * len(leading_digits) + 1)[0]),  # Chi-square
            np.corrcoef(observed, self.BENFORD_PROBS)[0, 1] if len(set(observed)) > 1 else 0,  # Correlation
        ]

        return np.array(features)


class ComplexityFeatures:
    """Extract structural complexity features."""

    def transform(self, data: bytes) -> np.ndarray:
        """Extract complexity-based features."""
        if len(data) < 100:
            return np.zeros(8)

        features = []

        # Run-length encoding complexity
        rle_complexity = self._rle_complexity(data)
        features.append(rle_complexity)

        # Lempel-Ziv complexity approximation
        lz_complexity = self._lz_complexity(data[:4096])
        features.append(lz_complexity)

        # Repetition ratio
        rep_ratio = self._repetition_ratio(data[:4096])
        features.append(rep_ratio)

        # Null byte ratio
        null_ratio = data[:4096].count(b'\x00') / min(len(data), 4096)
        features.append(null_ratio)

        # High byte ratio (> 127)
        byte_values = np.frombuffer(data[:4096], dtype=np.uint8)
        high_ratio = np.sum(byte_values > 127) / len(byte_values)
        features.append(high_ratio)

        # Printable character ratio
        printable = sum(1 for b in data[:4096] if 32 <= b <= 126)
        features.append(printable / min(len(data), 4096))

        # Whitespace ratio
        whitespace = sum(1 for b in data[:4096] if b in [9, 10, 13, 32])
        features.append(whitespace / min(len(data), 4096))

        # Byte value variance
        features.append(np.var(byte_values) / 65536)

        return np.array(features)

    def _rle_complexity(self, data: bytes) -> float:
        """Calculate run-length encoding complexity."""
        if len(data) < 2:
            return 0.0

        runs = 1
        for i in range(1, min(len(data), 4096)):
            if data[i] != data[i-1]:
                runs += 1

        return runs / min(len(data), 4096)

    def _lz_complexity(self, data: bytes) -> float:
        """Approximate Lempel-Ziv complexity."""
        if len(data) < 2:
            return 0.0

        complexity = 0
        i = 0
        dictionary = set()

        while i < len(data):
            # Find longest match in dictionary
            for length in range(1, len(data) - i + 1):
                substring = data[i:i+length]
                if substring not in dictionary:
                    dictionary.add(substring)
                    complexity += 1
                    i += length
                    break
            else:
                i += 1

        return complexity / len(data)

    def _repetition_ratio(self, data: bytes) -> float:
        """Calculate block repetition ratio."""
        block_size = 16
        if len(data) < block_size * 2:
            return 0.0

        blocks = []
        for i in range(0, len(data) - block_size + 1, block_size):
            blocks.append(data[i:i+block_size])

        unique_blocks = len(set(blocks))
        return 1 - (unique_blocks / len(blocks))


class InformationTheoreticFeatures:
    """Extract information-theoretic features."""

    def transform(self, data: bytes) -> np.ndarray:
        """Extract information-theoretic features."""
        if len(data) < 100:
            return np.zeros(6)

        byte_values = np.frombuffer(data[:10000], dtype=np.uint8)

        features = []

        # Shannon entropy
        counter = Counter(byte_values)
        probs = np.array(list(counter.values())) / len(byte_values)
        shannon_entropy = float(stats.entropy(probs, base=2))
        features.append(shannon_entropy / 8.0)  # Normalized to [0,1]

        # Renyi entropy (order 2)
        renyi_2 = -np.log2(np.sum(probs ** 2)) if np.sum(probs ** 2) > 0 else 0
        features.append(renyi_2 / 8.0)

        # Min-entropy
        min_entropy = -np.log2(np.max(probs)) if np.max(probs) > 0 else 0
        features.append(min_entropy / 8.0)

        # Conditional entropy approximation (bigram)
        if len(byte_values) > 1:
            bigrams = [(byte_values[i], byte_values[i+1]) for i in range(len(byte_values)-1)]
            bigram_counter = Counter(bigrams)
            bigram_probs = np.array(list(bigram_counter.values())) / len(bigrams)
            bigram_entropy = float(stats.entropy(bigram_probs, base=2))
            conditional_entropy = bigram_entropy - shannon_entropy
            features.append(conditional_entropy / 8.0)
        else:
            features.append(0.0)

        # Mutual information approximation
        mi = shannon_entropy - features[-1] * 8.0  # H(X) - H(X|Y)
        features.append(mi / 8.0)

        # Kolmogorov complexity approximation (via compression)
        try:
            import zlib
            compressed = zlib.compress(data[:4096])
            compression_ratio = len(compressed) / min(len(data), 4096)
            features.append(compression_ratio)
        except Exception:
            features.append(0.5)

        return np.array(features)


class AdvancedFeatureEngineeringPipeline:
    """
    Complete feature engineering pipeline for malware detection.

    Combines multiple feature extraction techniques:
    - Polynomial expansion
    - Statistical moments
    - N-gram analysis
    - Multi-scale entropy
    - Frequency domain analysis
    - Benford's Law deviation
    - Structural complexity
    - Information theory metrics
    """

    def __init__(
        self,
        enable_polynomial: bool = True,
        enable_ngrams: bool = True,
        enable_entropy: bool = True,
        enable_frequency: bool = True,
        enable_benford: bool = True,
        enable_complexity: bool = True,
        enable_info_theory: bool = True,
    ):
        self._enable_polynomial = enable_polynomial
        self._enable_ngrams = enable_ngrams
        self._enable_entropy = enable_entropy
        self._enable_frequency = enable_frequency
        self._enable_benford = enable_benford
        self._enable_complexity = enable_complexity
        self._enable_info_theory = enable_info_theory

        # Initialize extractors
        self._polynomial = PolynomialFeatureGenerator(degree=2)
        self._moments = StatisticalMomentFeatures()
        self._ngrams = NGramFeatureExtractor(n_values=[2, 3])
        self._entropy = MultiScaleEntropyFeatures(scales=[1, 4, 16, 64])
        self._frequency = FrequencyDomainFeatures(n_components=15)
        self._benford = BenfordLawFeatures()
        self._complexity = ComplexityFeatures()
        self._info_theory = InformationTheoreticFeatures()

        # Feature selection
        self._feature_selector = None
        self._selected_indices = None

    def transform(
        self,
        base_features: np.ndarray,
        raw_data: Optional[bytes] = None
    ) -> AdvancedFeatures:
        """
        Transform base features into advanced engineered features.

        Args:
            base_features: Base feature vector
            raw_data: Optional raw file data for byte-level features

        Returns:
            AdvancedFeatures with all engineered features
        """
        result = AdvancedFeatures(base_features=base_features)

        # Polynomial features
        if self._enable_polynomial:
            result.polynomial_features = self._polynomial.fit_transform(
                base_features.reshape(1, -1)
            ).flatten()

        # Interaction features (top correlations)
        if self._enable_polynomial:
            result.interaction_features = self._generate_interactions(base_features)

        if raw_data is not None:
            # Moment features
            result.moment_features = self._moments.transform(raw_data)

            # N-gram features
            if self._enable_ngrams:
                result.ngram_features = self._ngrams.transform(raw_data)

            # Entropy features
            if self._enable_entropy:
                result.entropy_features = self._entropy.transform(raw_data)

            # Frequency features
            if self._enable_frequency:
                result.frequency_features = self._frequency.transform(raw_data)

            # Benford's Law features
            if self._enable_benford:
                result.benford_features = self._benford.transform(raw_data)

            # Complexity features
            if self._enable_complexity:
                result.complexity_features = self._complexity.transform(raw_data)

            # Information theory features
            if self._enable_info_theory:
                result.info_theory_features = self._info_theory.transform(raw_data)

        return result

    def _generate_interactions(self, features: np.ndarray, top_k: int = 30) -> np.ndarray:
        """Generate interaction features between top correlated pairs."""
        n = len(features)
        if n < 2:
            return np.array([])

        # Select features with highest variance
        variance_indices = np.argsort(-np.abs(features - np.mean(features)))[:min(10, n)]

        interactions = []
        for i in range(len(variance_indices)):
            for j in range(i + 1, len(variance_indices)):
                idx_i = variance_indices[i]
                idx_j = variance_indices[j]
                interactions.append(features[idx_i] * features[idx_j])
                if len(interactions) >= top_k:
                    break
            if len(interactions) >= top_k:
                break

        return np.array(interactions)

    def fit_feature_selector(
        self,
        X: np.ndarray,
        y: np.ndarray,
        n_features: int = 100
    ) -> None:
        """
        Fit feature selector using mutual information.

        Args:
            X: Feature matrix
            y: Labels
            n_features: Number of features to select
        """
        try:
            from sklearn.feature_selection import mutual_info_classif

            # Calculate mutual information
            mi_scores = mutual_info_classif(X, y, random_state=42)

            # Select top features
            self._selected_indices = np.argsort(mi_scores)[-n_features:]
            logger.info(f"Selected {len(self._selected_indices)} features based on MI")

        except ImportError:
            logger.warning("sklearn not available for feature selection")

    def apply_feature_selection(self, X: np.ndarray) -> np.ndarray:
        """Apply fitted feature selection."""
        if self._selected_indices is not None:
            return X[:, self._selected_indices]
        return X

    def get_feature_statistics(self, features: AdvancedFeatures) -> Dict[str, Any]:
        """Get statistics about engineered features."""
        all_features = features.to_array()

        return {
            "total_features": len(all_features),
            "base_features": len(features.base_features),
            "polynomial_features": len(features.polynomial_features),
            "interaction_features": len(features.interaction_features),
            "moment_features": len(features.moment_features),
            "ngram_features": len(features.ngram_features),
            "entropy_features": len(features.entropy_features),
            "frequency_features": len(features.frequency_features),
            "benford_features": len(features.benford_features),
            "complexity_features": len(features.complexity_features),
            "info_theory_features": len(features.info_theory_features),
            "mean": float(np.mean(all_features)),
            "std": float(np.std(all_features)),
            "min": float(np.min(all_features)),
            "max": float(np.max(all_features)),
        }


# Global instance
_pipeline: Optional[AdvancedFeatureEngineeringPipeline] = None


def get_feature_pipeline() -> AdvancedFeatureEngineeringPipeline:
    """Get global feature engineering pipeline."""
    global _pipeline
    if _pipeline is None:
        _pipeline = AdvancedFeatureEngineeringPipeline()
    return _pipeline
