"""
Automatic ML model training system with Incremental Learning.

Features:
- Automatically trains models when they don't exist
- Incremental learning: updates model with new samples
- Model persistence: saves and loads trained models
- On first scan: trains if no model, else uses trained model
- Continuous learning: improves with each labeled sample
- Version tracking for model updates

Author: AI-Cerberus
Version: 2.0.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import time
import threading
import pickle
import hashlib
import numpy as np
from datetime import datetime, timezone
from collections import deque

from .classifier import MalwareClassifier
from .feature_extractor import FeatureExtractor, FeatureVector
from ..utils.logger import get_logger
from ..database import get_repository

logger = get_logger("auto_trainer")


class IncrementalLearningBuffer:
    """
    Buffer for incremental learning samples.

    Stores recently seen samples for periodic model updates.
    Uses reservoir sampling for memory efficiency.
    """

    def __init__(self, max_size: int = 1000):
        self._max_size = max_size
        self._buffer: deque = deque(maxlen=max_size)
        self._label_counts = {'benign': 0, 'suspicious': 0, 'malicious': 0}
        self._total_seen = 0

    def add(self, features: np.ndarray, label: str, file_hash: str) -> None:
        """Add a sample to the buffer."""
        self._buffer.append({
            'features': features,
            'label': label,
            'hash': file_hash,
            'timestamp': time.time()
        })
        self._label_counts[label] = self._label_counts.get(label, 0) + 1
        self._total_seen += 1

    def get_samples(self, min_samples: int = 50) -> Tuple[np.ndarray, np.ndarray]:
        """Get samples for training."""
        if len(self._buffer) < min_samples:
            return np.array([]), np.array([])

        X = np.array([s['features'] for s in self._buffer])
        y = np.array([s['label'] for s in self._buffer])
        return X, y

    def clear(self) -> None:
        """Clear the buffer."""
        self._buffer.clear()

    @property
    def size(self) -> int:
        return len(self._buffer)

    @property
    def label_distribution(self) -> Dict[str, int]:
        return dict(self._label_counts)


class AutoTrainer:
    """
    Automatic model training system with Incremental Learning.

    Features:
    - Checks if models exist on startup
    - Trains models if needed
    - Uses database samples for training
    - Generates synthetic samples if needed
    - Incremental learning: continuously improves with new samples
    - Model versioning and persistence
    - Automatic retraining when enough new samples collected
    """

    VERSION = "2.0.0"
    MINIMUM_SAMPLES = 100  # Minimum samples needed for training
    SAMPLES_PER_CLASS = 50  # Minimum per class
    INCREMENTAL_THRESHOLD = 50  # Samples before incremental update
    FULL_RETRAIN_THRESHOLD = 500  # Samples before full retrain

    def __init__(self, model_dir: Optional[Path] = None):
        """
        Initialize auto-trainer.

        Args:
            model_dir: Directory for model storage
        """
        if model_dir is None:
            model_dir = Path.home() / ".malware_analyzer" / "models"
        self._model_dir = model_dir
        self._model_dir.mkdir(parents=True, exist_ok=True)

        self._classifier = MalwareClassifier(model_dir=model_dir)
        self._feature_extractor = FeatureExtractor()

        # Initialize repository with error handling
        try:
            self._repository = get_repository()
        except Exception as e:
            logger.warning(f"Failed to initialize database repository: {e}")
            self._repository = None

        # Training status
        self._training_info_file = model_dir / "training_info.json"
        self._training_info = self._load_training_info()

        # Incremental learning components
        self._learning_buffer = IncrementalLearningBuffer(max_size=1000)
        self._samples_since_update = 0
        self._model_version = self._training_info.get('model_version', 0)

        # Feature cache for faster incremental updates
        self._feature_cache_file = model_dir / "feature_cache.pkl"
        self._feature_cache = self._load_feature_cache()

    def add_sample_for_learning(
        self,
        file_path: Path,
        label: str,
        features: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Add a labeled sample for incremental learning.

        This is called after each scan when the user confirms or corrects the label.
        The sample is added to the learning buffer for future model updates.

        Args:
            file_path: Path to the analyzed file
            label: Confirmed label ('benign', 'suspicious', 'malicious')
            features: Pre-extracted features (optional)

        Returns:
            Status dictionary
        """
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Extract features if not provided
            if features is None:
                feat_vector = self._feature_extractor.extract(file_path)
                features = feat_vector.to_array()

            # Add to learning buffer
            self._learning_buffer.add(features, label, file_hash)
            self._samples_since_update += 1

            # Cache features for future use
            self._feature_cache[file_hash] = {
                'features': features,
                'label': label,
                'path': str(file_path),
                'timestamp': time.time()
            }

            # Check if we should trigger incremental update
            should_update = self._samples_since_update >= self.INCREMENTAL_THRESHOLD
            should_retrain = self._samples_since_update >= self.FULL_RETRAIN_THRESHOLD

            status = {
                'added': True,
                'buffer_size': self._learning_buffer.size,
                'samples_since_update': self._samples_since_update,
                'should_update': should_update,
                'should_retrain': should_retrain,
            }

            # Auto-trigger incremental update if threshold reached
            if should_update and not should_retrain:
                logger.info("Triggering incremental model update...")
                update_result = self.incremental_update()
                status['incremental_update'] = update_result

            elif should_retrain:
                logger.info("Triggering full model retrain...")
                retrain_result = self.retrain_models(force=True)
                status['retrain'] = retrain_result

            # Save feature cache periodically
            if self._samples_since_update % 10 == 0:
                self._save_feature_cache()

            return status

        except Exception as e:
            logger.error(f"Failed to add sample for learning: {e}")
            return {'added': False, 'error': str(e)}

    def incremental_update(self) -> Dict[str, Any]:
        """
        Perform incremental model update with buffered samples.

        Uses partial_fit where available, otherwise performs weighted
        combination of old and new model.

        Returns:
            Update metrics
        """
        X, y = self._learning_buffer.get_samples(min_samples=self.INCREMENTAL_THRESHOLD)

        if len(X) == 0:
            return {'status': 'skipped', 'reason': 'insufficient_samples'}

        start_time = time.time()

        try:
            # Try incremental update on classifier
            if hasattr(self._classifier, 'partial_fit'):
                metrics = self._classifier.partial_fit(X, y)
            else:
                # Fallback: combine with cached features for full retrain
                cached_X, cached_y = self._get_cached_samples()
                if len(cached_X) > 0:
                    X = np.vstack([cached_X, X])
                    y = np.concatenate([cached_y, y])

                metrics = self._classifier.train_from_features(X, y)

            # Update training info
            self._model_version += 1
            self._samples_since_update = 0

            self._training_info.update({
                'last_incremental_update': datetime.now(timezone.utc).isoformat(),
                'model_version': self._model_version,
                'incremental_samples': len(X),
            })
            self._save_training_info()

            logger.info(f"Incremental update complete (v{self._model_version})")

            return {
                'status': 'success',
                'samples_used': len(X),
                'model_version': self._model_version,
                'update_time': time.time() - start_time,
                'metrics': metrics
            }

        except Exception as e:
            logger.error(f"Incremental update failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def _get_cached_samples(self, max_samples: int = 500) -> Tuple[np.ndarray, np.ndarray]:
        """Get samples from feature cache."""
        if not self._feature_cache:
            return np.array([]), np.array([])

        # Get most recent samples
        samples = sorted(
            self._feature_cache.values(),
            key=lambda x: x.get('timestamp', 0),
            reverse=True
        )[:max_samples]

        if not samples:
            return np.array([]), np.array([])

        X = np.array([s['features'] for s in samples])
        y = np.array([s['label'] for s in samples])

        return X, y

    def _save_feature_cache(self) -> None:
        """Save feature cache to disk."""
        try:
            # Keep only recent entries (last 1000)
            if len(self._feature_cache) > 1000:
                sorted_items = sorted(
                    self._feature_cache.items(),
                    key=lambda x: x[1].get('timestamp', 0),
                    reverse=True
                )[:1000]
                self._feature_cache = dict(sorted_items)

            with open(self._feature_cache_file, 'wb') as f:
                pickle.dump(self._feature_cache, f)
        except Exception as e:
            logger.warning(f"Failed to save feature cache: {e}")

    def _load_feature_cache(self) -> Dict:
        """Load feature cache from disk."""
        try:
            if self._feature_cache_file.exists():
                with open(self._feature_cache_file, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.warning(f"Failed to load feature cache: {e}")
        return {}

    def get_learning_status(self) -> Dict[str, Any]:
        """Get current incremental learning status."""
        return {
            'buffer_size': self._learning_buffer.size,
            'samples_since_update': self._samples_since_update,
            'model_version': self._model_version,
            'label_distribution': self._learning_buffer.label_distribution,
            'cached_samples': len(self._feature_cache),
            'incremental_threshold': self.INCREMENTAL_THRESHOLD,
            'retrain_threshold': self.FULL_RETRAIN_THRESHOLD,
            'next_update_in': max(0, self.INCREMENTAL_THRESHOLD - self._samples_since_update),
        }

    def check_and_train(self) -> Dict[str, any]:
        """
        Check if models exist and train if needed.

        Returns:
            Status dictionary with training information
        """
        status = {
            "models_exist": self._classifier.is_trained,
            "training_needed": False,
            "training_performed": False,
            "samples_available": 0,
            "last_trained": self._training_info.get("last_trained"),
        }

        # Check if models exist
        if self._classifier.is_trained:
            logger.info("ML models already trained and loaded")
            status["message"] = "Models already trained"
            return status

        logger.info("ML models not found - checking for training data")

        # Check available samples
        samples = self._get_training_samples()
        status["samples_available"] = len(samples)

        if len(samples) < self.MINIMUM_SAMPLES:
            logger.warning(
                f"Insufficient samples for training: {len(samples)} < {self.MINIMUM_SAMPLES}"
            )
            status["training_needed"] = True
            status["message"] = f"Need {self.MINIMUM_SAMPLES - len(samples)} more samples"

            # Generate synthetic samples if none exist
            if len(samples) == 0:
                logger.info("No samples found - generating synthetic training data")
                samples = self._generate_synthetic_samples()
                status["samples_available"] = len(samples)
                status["synthetic_generated"] = True

        if len(samples) >= self.MINIMUM_SAMPLES:
            logger.info(f"Training models with {len(samples)} samples")
            status["training_needed"] = True
            status["training_performed"] = True

            try:
                metrics = self.train_models(samples)
                status["training_metrics"] = metrics
                status["message"] = "Models trained successfully"
            except Exception as e:
                logger.error(f"Training failed: {e}")
                status["error"] = str(e)
                status["message"] = f"Training failed: {e}"

        return status

    def train_models(self, samples: List[Tuple[Path, str]]) -> Dict:
        """
        Train ML models with provided samples.

        Args:
            samples: List of (file_path, label) tuples

        Returns:
            Training metrics

        Raises:
            ValueError: If samples list is empty or too small
        """
        if not samples:
            raise ValueError("Cannot train models: No training samples provided")

        if len(samples) < 10:
            raise ValueError(f"Insufficient samples for training: {len(samples)} < 10 minimum")

        start_time = time.time()

        logger.info(f"Starting model training with {len(samples)} samples")

        # Train classifier
        metrics = self._classifier.train(samples, validation_split=0.2)

        # Update training info
        training_time = time.time() - start_time
        self._training_info = {
            "last_trained": datetime.now(timezone.utc).isoformat(),
            "samples_used": len(samples),
            "training_time_seconds": training_time,
            "metrics": metrics,
        }
        self._save_training_info()

        logger.info(f"Model training complete in {training_time:.2f}s")

        return metrics

    def retrain_models(self, force: bool = False) -> Dict:
        """
        Retrain models with latest data.

        Args:
            force: Force retraining even if models exist

        Returns:
            Training status and metrics
        """
        if not force and self._classifier.is_trained:
            logger.info("Models already trained - use force=True to retrain")
            return {"status": "skipped", "message": "Models already trained"}

        logger.info("Retraining models...")

        samples = self._get_training_samples()
        if len(samples) < self.MINIMUM_SAMPLES:
            return {
                "status": "insufficient_data",
                "message": f"Need at least {self.MINIMUM_SAMPLES} samples",
                "samples_available": len(samples),
            }

        metrics = self.train_models(samples)

        return {
            "status": "success",
            "message": "Models retrained successfully",
            "metrics": metrics,
        }

    def _get_training_samples(self) -> List[Tuple[Path, str]]:
        """
        Get training samples from database.

        Returns:
            List of (file_path, label) tuples
        """
        samples = []

        # Check if repository is available
        if self._repository is None:
            logger.warning("Database repository not available, cannot get training samples")
            return samples

        try:
            # Get samples from database
            db_samples = self._repository.get_all_samples(limit=1000)

            for sample in db_samples:
                if sample.file_path and sample.classification:
                    file_path = Path(sample.file_path)
                    if file_path.exists():
                        samples.append((file_path, sample.classification))

            logger.info(f"Found {len(samples)} training samples in database")

        except AttributeError as e:
            logger.warning(f"Repository method not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to get samples from database: {e}")

        return samples

    def _generate_synthetic_samples(self) -> List[Tuple[Path, str]]:
        """
        Generate synthetic training samples.

        This creates minimal synthetic samples for initial training.
        Real samples should be added for production use.

        Returns:
            List of (file_path, label) tuples
        """
        logger.info("Generating synthetic training samples")

        synthetic_dir = self._model_dir / "synthetic_samples"
        synthetic_dir.mkdir(exist_ok=True)

        samples = []

        # Generate benign samples (low entropy, normal structure)
        for i in range(self.SAMPLES_PER_CLASS):
            sample_path = synthetic_dir / f"benign_{i}.bin"
            if not sample_path.exists():
                # Create benign-looking data
                data = self._create_synthetic_benign(i)
                sample_path.write_bytes(data)
            samples.append((sample_path, "benign"))

        # Generate suspicious samples (medium entropy, some indicators)
        for i in range(self.SAMPLES_PER_CLASS):
            sample_path = synthetic_dir / f"suspicious_{i}.bin"
            if not sample_path.exists():
                data = self._create_synthetic_suspicious(i)
                sample_path.write_bytes(data)
            samples.append((sample_path, "suspicious"))

        # Generate malicious samples (high entropy, many indicators)
        for i in range(self.SAMPLES_PER_CLASS):
            sample_path = synthetic_dir / f"malicious_{i}.bin"
            if not sample_path.exists():
                data = self._create_synthetic_malicious(i)
                sample_path.write_bytes(data)
            samples.append((sample_path, "malicious"))

        logger.info(f"Generated {len(samples)} synthetic samples")

        return samples

    def _create_synthetic_benign(self, seed: int) -> bytes:
        """Create synthetic benign sample."""
        import random
        random.seed(seed)

        # Low entropy data
        size = random.randint(1024, 4096)
        data = bytearray()

        # Add mostly printable ASCII
        for _ in range(size):
            if random.random() < 0.8:
                # Printable ASCII
                data.append(random.randint(32, 126))
            else:
                # Some zeros and low bytes
                data.append(random.randint(0, 31))

        return bytes(data)

    def _create_synthetic_suspicious(self, seed: int) -> bytes:
        """Create synthetic suspicious sample."""
        import random
        random.seed(seed + 1000)

        size = random.randint(2048, 8192)
        data = bytearray()

        # Medium entropy - mixed data
        for _ in range(size):
            if random.random() < 0.5:
                # Random bytes
                data.append(random.randint(0, 255))
            else:
                # Structured data
                data.append(random.randint(32, 126))

        # Add suspicious strings
        suspicious_strings = [
            b"WriteProcessMemory",
            b"VirtualAlloc",
            b"LoadLibrary",
            b"GetProcAddress",
        ]

        for s in suspicious_strings:
            if random.random() < 0.7:
                pos = random.randint(0, len(data) - len(s))
                data[pos:pos+len(s)] = s

        return bytes(data)

    def _create_synthetic_malicious(self, seed: int) -> bytes:
        """Create synthetic malicious sample."""
        import random
        random.seed(seed + 2000)

        size = random.randint(4096, 16384)
        data = bytearray()

        # High entropy - mostly random
        for _ in range(size):
            data.append(random.randint(0, 255))

        # Add multiple suspicious indicators
        malicious_strings = [
            b"inject",
            b"shellcode",
            b"payload",
            b"CreateRemoteThread",
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"IsDebuggerPresent",
            b"keylog",
            b"backdoor",
        ]

        for s in malicious_strings:
            if random.random() < 0.8:
                pos = random.randint(0, len(data) - len(s))
                data[pos:pos+len(s)] = s

        return bytes(data)

    def _save_training_info(self) -> None:
        """Save training information to disk."""
        try:
            with open(self._training_info_file, "w") as f:
                json.dump(self._training_info, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save training info: {e}")

    def _load_training_info(self) -> Dict:
        """Load training information from disk."""
        try:
            if self._training_info_file.exists():
                with open(self._training_info_file, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load training info: {e}")
        return {}

    def get_training_status(self) -> Dict:
        """Get current training status."""
        return {
            "models_trained": self._classifier.is_trained,
            "last_trained": self._training_info.get("last_trained"),
            "samples_used": self._training_info.get("samples_used"),
            "training_time": self._training_info.get("training_time_seconds"),
            "metrics": self._training_info.get("metrics"),
        }


# Global instance
_auto_trainer: Optional[AutoTrainer] = None
_auto_trainer_lock = threading.Lock()


def get_auto_trainer() -> AutoTrainer:
    """Get global auto-trainer instance (thread-safe)."""
    global _auto_trainer
    if _auto_trainer is None:
        with _auto_trainer_lock:
            # Double-check locking pattern
            if _auto_trainer is None:
                _auto_trainer = AutoTrainer()
    return _auto_trainer
