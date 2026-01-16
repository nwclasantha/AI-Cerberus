"""
Neural network classifier for malware detection.

Implements deep learning-based classification using TensorFlow/Keras.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import json
import time

from .feature_extractor import FeatureVector
from ..utils.logger import get_logger

logger = get_logger("neural_classifier")


class NeuralClassifier:
    """
    Deep neural network classifier for malware detection.

    Architecture:
    - Input layer: Feature vector (75+ features)
    - Hidden layers: 3 dense layers with dropout
    - Output layer: 3 classes (benign, suspicious, malicious)

    Features:
    - Model persistence
    - Early stopping during training
    - Batch normalization
    - Dropout for regularization
    """

    MODEL_VERSION = "1.0.0"  # Semantic versioning for model compatibility
    LABELS = ["benign", "suspicious", "malicious"]
    _tf_warning_logged = False  # Class variable to log warning only once

    def __init__(self, model_dir: Optional[Path] = None):
        """
        Initialize neural network classifier.

        Args:
            model_dir: Directory for model storage
        """
        if model_dir is None:
            model_dir = Path.home() / ".malware_analyzer" / "models"
        self._model_dir = model_dir
        self._model_dir.mkdir(parents=True, exist_ok=True)

        self._model = None
        self._is_trained = False

        # Determine input dimension dynamically from FeatureVector
        try:
            from .feature_extractor import FeatureVector
            dummy_features = FeatureVector()
            self._input_dim = len(dummy_features.to_array())
        except Exception:
            self._input_dim = 75  # Fallback to safe default

        # Check if TensorFlow/Keras is available
        self._keras_available = self._check_keras()

        if self._keras_available:
            # Try to load existing model
            self._load_model()

    def _check_keras(self) -> bool:
        """Check if TensorFlow/Keras is available."""
        try:
            import tensorflow as tf
            # Suppress TF warnings
            import os
            os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
            tf.get_logger().setLevel('ERROR')
            return True
        except ImportError:
            # Only log warning once to avoid spam
            if not NeuralClassifier._tf_warning_logged:
                logger.warning(
                    "TensorFlow not installed - neural network classifier unavailable. "
                    "Install with: pip install tensorflow>=2.13.0"
                )
                NeuralClassifier._tf_warning_logged = True
            return False

    def _build_model(self, input_dim: int) -> Any:
        """
        Build neural network model.

        Args:
            input_dim: Number of input features

        Returns:
            Compiled Keras model
        """
        try:
            from tensorflow import keras
            from tensorflow.keras import layers, regularizers

            model = keras.Sequential([
                # Input layer
                layers.Input(shape=(input_dim,)),
                layers.BatchNormalization(),

                # First hidden layer
                layers.Dense(
                    256,
                    activation='relu',
                    kernel_regularizer=regularizers.l2(0.001),
                ),
                layers.Dropout(0.3),
                layers.BatchNormalization(),

                # Second hidden layer
                layers.Dense(
                    128,
                    activation='relu',
                    kernel_regularizer=regularizers.l2(0.001),
                ),
                layers.Dropout(0.3),
                layers.BatchNormalization(),

                # Third hidden layer
                layers.Dense(
                    64,
                    activation='relu',
                    kernel_regularizer=regularizers.l2(0.001),
                ),
                layers.Dropout(0.2),

                # Output layer
                layers.Dense(len(self.LABELS), activation='softmax'),
            ])

            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy'],
            )

            logger.info(f"Neural network model built: {input_dim} inputs, {len(self.LABELS)} outputs")
            return model

        except Exception as e:
            logger.error(f"Failed to build model: {e}")
            return None

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        epochs: int = 50,
        batch_size: int = 32,
    ) -> Dict[str, Any]:
        """
        Train the neural network.

        Args:
            X_train: Training features
            y_train: Training labels (0, 1, 2)
            X_val: Validation features
            y_val: Validation labels
            epochs: Number of training epochs
            batch_size: Batch size for training

        Returns:
            Training history and metrics
        """
        if not self._keras_available:
            raise RuntimeError("TensorFlow/Keras required for neural network training")

        from tensorflow import keras

        start_time = time.time()

        # Build model if not exists
        if self._model is None:
            self._input_dim = X_train.shape[1]
            self._model = self._build_model(self._input_dim)

        # Early stopping callback
        early_stop = keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True,
        )

        # Train model
        logger.info(f"Training neural network: {len(X_train)} samples, {epochs} epochs")

        history = self._model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stop],
            verbose=0,
        )

        # Evaluate model
        train_loss, train_acc = self._model.evaluate(X_train, y_train, verbose=0)
        val_loss, val_acc = self._model.evaluate(X_val, y_val, verbose=0)

        self._is_trained = True

        # Save model
        self._save_model()

        training_time = time.time() - start_time

        metrics = {
            "train_accuracy": float(train_acc),
            "val_accuracy": float(val_acc),
            "train_loss": float(train_loss),
            "val_loss": float(val_loss),
            "epochs_trained": len(history.history['loss']),
            "training_time_seconds": training_time,
        }

        logger.info(
            "Neural network training complete",
            extra_data={
                "train_acc": f"{train_acc:.4f}",
                "val_acc": f"{val_acc:.4f}",
                "time": f"{training_time:.2f}s",
            },
        )

        return metrics

    def predict(self, features: FeatureVector) -> Tuple[str, float, Dict[str, float]]:
        """
        Predict class for a feature vector.

        Args:
            features: Extracted feature vector

        Returns:
            Tuple of (prediction, confidence, probabilities)
        """
        if not self._is_trained or self._model is None:
            return "unknown", 0.0, {}

        try:
            # Convert features to array and ensure correct dimension
            feature_array = features.to_array()

            # Handle dimension mismatch
            if len(feature_array) > self._input_dim:
                # Truncate to model's expected dimension
                feature_array = feature_array[:self._input_dim]
            elif len(feature_array) < self._input_dim:
                # Pad with zeros if somehow shorter
                padding = [0.0] * (self._input_dim - len(feature_array))
                feature_array = feature_array + padding

            X = np.array([feature_array]).astype(np.float32)

            # Predict
            proba = self._model.predict(X, verbose=0)[0]

            # Get prediction
            pred_idx = np.argmax(proba)
            prediction = self.LABELS[pred_idx]
            confidence = float(proba[pred_idx])

            # Build probability dict
            probabilities = {
                label: float(prob)
                for label, prob in zip(self.LABELS, proba)
            }

            return prediction, confidence, probabilities

        except Exception as e:
            logger.error(f"Neural network prediction failed: {e}")
            return "unknown", 0.0, {}

    def predict_batch(self, features_list: List[FeatureVector]) -> List[Tuple[str, float, Dict]]:
        """
        Predict classes for multiple samples.

        Args:
            features_list: List of feature vectors

        Returns:
            List of (prediction, confidence, probabilities) tuples
        """
        # Input validation
        if not features_list:
            logger.warning("Empty features list provided for batch prediction")
            return []

        if not self._is_trained or self._model is None:
            logger.warning("Model not trained, returning unknown predictions")
            return [("unknown", 0.0, {}) for _ in features_list]

        try:
            # Convert to batch array with dimension handling
            feature_arrays = []
            for f in features_list:
                arr = f.to_array()
                if len(arr) > self._input_dim:
                    arr = arr[:self._input_dim]
                elif len(arr) < self._input_dim:
                    arr = arr + [0.0] * (self._input_dim - len(arr))
                feature_arrays.append(arr)

            X = np.array(feature_arrays).astype(np.float32)

            # Batch predict
            probas = self._model.predict(X, verbose=0)

            results = []
            for proba in probas:
                pred_idx = np.argmax(proba)
                prediction = self.LABELS[pred_idx]
                confidence = float(proba[pred_idx])
                probabilities = {
                    label: float(prob)
                    for label, prob in zip(self.LABELS, proba)
                }
                results.append((prediction, confidence, probabilities))

            return results

        except Exception as e:
            logger.error(f"Batch prediction failed: {e}")
            return [("unknown", 0.0, {}) for _ in features_list]

    def _save_model(self) -> None:
        """Save trained model to disk."""
        if self._model is None:
            return

        try:
            model_path = self._model_dir / "neural_network.h5"
            self._model.save(str(model_path))

            # Save metadata
            metadata = {
                "version": self.MODEL_VERSION,
                "input_dim": self._input_dim,
                "labels": self.LABELS,
                "is_trained": self._is_trained,
            }
            meta_path = self._model_dir / "neural_network_meta.json"
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Neural network model saved to {model_path}")

        except Exception as e:
            logger.error(f"Failed to save neural network model: {e}")

    def _load_model(self) -> None:
        """Load trained model from disk."""
        try:
            from tensorflow import keras

            model_path = self._model_dir / "neural_network.h5"
            meta_path = self._model_dir / "neural_network_meta.json"

            if not model_path.exists() or not meta_path.exists():
                return

            # Load metadata
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            # Check version compatibility
            saved_version = metadata.get("version", "0.0.0")
            if saved_version != self.MODEL_VERSION:
                logger.warning(
                    f"Neural network version mismatch: saved={saved_version}, current={self.MODEL_VERSION}. "
                    "Model may be incompatible. Consider retraining."
                )
                # For now, we'll still try to load, but warn the user

            self._input_dim = metadata.get("input_dim", 75)
            self._is_trained = metadata.get("is_trained", False)

            # Load model
            self._model = keras.models.load_model(str(model_path))

            logger.info("Neural network model loaded successfully")

        except Exception as e:
            logger.warning(f"Failed to load neural network model: {e}")

    @property
    def is_trained(self) -> bool:
        """Check if model is trained."""
        return self._is_trained and self._model is not None

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        if not self._model:
            return {"status": "not_loaded"}

        info = {
            "status": "trained" if self._is_trained else "untrained",
            "input_dim": self._input_dim,
            "labels": self.LABELS,
            "num_classes": len(self.LABELS),
        }

        if self._model:
            try:
                info["total_params"] = self._model.count_params()
                info["layers"] = len(self._model.layers)
            except Exception:
                pass

        return info
