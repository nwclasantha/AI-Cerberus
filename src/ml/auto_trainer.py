"""
Automatic ML model training system.

Automatically trains models when they don't exist using built-in or collected samples.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import time
import threading
from datetime import datetime, timezone

from .classifier import MalwareClassifier
from .feature_extractor import FeatureExtractor
from ..utils.logger import get_logger
from ..database import get_repository

logger = get_logger("auto_trainer")


class AutoTrainer:
    """
    Automatic model training system.

    Features:
    - Checks if models exist on startup
    - Trains models if needed
    - Uses database samples for training
    - Generates synthetic samples if needed
    - Scheduled retraining
    """

    MINIMUM_SAMPLES = 100  # Minimum samples needed for training
    SAMPLES_PER_CLASS = 50  # Minimum per class

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
