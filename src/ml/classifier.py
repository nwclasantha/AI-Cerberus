"""
Machine Learning classifier for malware detection.

Implements ensemble classification using:
- Random Forest
- Gradient Boosting
- Optional Neural Network
"""

from __future__ import annotations

import json
import pickle
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .feature_extractor import FeatureExtractor, FeatureVector
from .neural_classifier import NeuralClassifier
from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger("ml_classifier")


@dataclass
class ClassificationResult:
    """ML classification result."""

    prediction: str  # "malicious", "suspicious", "benign"
    confidence: float  # 0.0 - 1.0
    probabilities: Dict[str, float] = field(default_factory=dict)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    model_used: str = "ensemble"
    analysis_time: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "prediction": self.prediction,
            "confidence": round(self.confidence, 4),
            "probabilities": {
                k: round(v, 4) for k, v in self.probabilities.items()
            },
            "top_features": dict(
                sorted(
                    self.feature_importance.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]
            ),
            "model": self.model_used,
            "analysis_time_ms": round(self.analysis_time * 1000, 2),
        }


class MalwareClassifier:
    """
    Ensemble ML classifier for malware detection.

    Uses multiple models for robust classification:
    - Random Forest: Good for feature importance
    - Gradient Boosting: High accuracy
    - Voting ensemble for final prediction

    Features:
    - 100+ extracted features
    - Model persistence
    - Confidence scoring
    - Feature importance ranking
    """

    MODEL_VERSION = "1.0.0"  # Semantic versioning for model compatibility
    LABELS = ["benign", "suspicious", "malicious"]

    def __init__(self, model_dir: Optional[Path] = None):
        """
        Initialize classifier.

        Args:
            model_dir: Directory for model storage
        """
        self._config = get_config()
        self._feature_extractor = FeatureExtractor()

        if model_dir is None:
            model_dir = Path.home() / ".malware_analyzer" / "models"
        self._model_dir = model_dir
        self._model_dir.mkdir(parents=True, exist_ok=True)

        # Model components
        self._rf_model = None
        self._gb_model = None
        self._nn_model = None  # Neural network
        self._scaler = None
        self._is_trained = False

        # Check ML libraries
        self._sklearn_available = self._check_sklearn()
        self._xgboost_available = self._check_xgboost()

        # Initialize neural network
        self._nn_classifier = NeuralClassifier(model_dir=model_dir)

        # Try to load existing models
        self._load_models()

    def _check_sklearn(self) -> bool:
        """Check if scikit-learn is available."""
        try:
            import sklearn
            return True
        except ImportError:
            logger.warning("scikit-learn not installed")
            return False

    def _check_xgboost(self) -> bool:
        """Check if XGBoost is available."""
        try:
            import xgboost
            return True
        except ImportError:
            logger.warning("XGBoost not installed")
            return False

    def classify(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
    ) -> ClassificationResult:
        """
        Classify a file as malicious, suspicious, or benign.

        Args:
            file_path: Path to file
            data: Optional pre-loaded data

        Returns:
            ClassificationResult with prediction and confidence
        """
        start_time = time.time()

        # Extract features
        features = self._feature_extractor.extract(file_path, data)

        # If no trained model, use heuristic classification
        if not self._is_trained or not self._sklearn_available:
            result = self._heuristic_classify(features)
            result.analysis_time = time.time() - start_time
            return result

        # ML-based classification
        result = self._ml_classify(features)
        result.analysis_time = time.time() - start_time

        return result

    def _heuristic_classify(self, features: FeatureVector) -> ClassificationResult:
        """
        Classify using heuristic rules when ML models not available.

        Args:
            features: Extracted feature vector

        Returns:
            ClassificationResult based on heuristics
        """
        score = 0.0
        weights = {
            "high_entropy": 0.15,
            "packed": 0.20,
            "injection_imports": 0.25,
            "anti_debug": 0.15,
            "suspicious_sections": 0.10,
            "no_imports": 0.05,
            "suspicious_strings": 0.10,
        }

        # High entropy
        if features.overall_entropy > 7.0:
            score += weights["high_entropy"]
        elif features.overall_entropy > 6.5:
            score += weights["high_entropy"] * 0.5

        # Packed indicators
        if features.packed_indicator:
            score += weights["packed"]

        # Injection capability
        if features.injection_imports >= 2:
            score += weights["injection_imports"]
        elif features.injection_imports >= 1:
            score += weights["injection_imports"] * 0.5

        # Anti-debugging
        if features.anti_debug_imports >= 2:
            score += weights["anti_debug"]
        elif features.anti_debug_imports >= 1:
            score += weights["anti_debug"] * 0.5

        # Suspicious sections
        if features.suspicious_section_names > 0:
            score += weights["suspicious_sections"]

        # No imports (unusual)
        if features.no_imports:
            score += weights["no_imports"]

        # Suspicious strings
        if features.suspicious_strings >= 3:
            score += weights["suspicious_strings"]
        elif features.suspicious_strings >= 1:
            score += weights["suspicious_strings"] * 0.5

        # Determine classification
        if score >= 0.6:
            prediction = "malicious"
            confidence = min(0.95, 0.6 + score * 0.3)
        elif score >= 0.3:
            prediction = "suspicious"
            confidence = 0.5 + score * 0.3
        else:
            prediction = "benign"
            confidence = max(0.5, 0.9 - score)

        probabilities = {
            "malicious": score,
            "suspicious": max(0, 0.5 - abs(score - 0.45)),
            "benign": max(0, 1.0 - score),
        }

        # Normalize probabilities
        total = sum(probabilities.values())
        if total > 0:
            probabilities = {k: v / total for k, v in probabilities.items()}

        # Feature importance (based on heuristic weights)
        importance = {}
        if features.injection_imports > 0:
            importance["injection_imports"] = features.injection_imports * 0.3
        if features.overall_entropy > 6.0:
            importance["overall_entropy"] = (features.overall_entropy - 6.0) * 0.2
        if features.packed_indicator:
            importance["packed_indicator"] = 0.25
        if features.anti_debug_imports > 0:
            importance["anti_debug_imports"] = features.anti_debug_imports * 0.15
        if features.suspicious_strings > 0:
            importance["suspicious_strings"] = features.suspicious_strings * 0.1

        return ClassificationResult(
            prediction=prediction,
            confidence=confidence,
            probabilities=probabilities,
            feature_importance=importance,
            model_used="heuristic",
        )

    def _ml_classify(self, features: FeatureVector) -> ClassificationResult:
        """
        Classify using trained ML models.

        Args:
            features: Extracted feature vector

        Returns:
            ClassificationResult from ensemble
        """
        # Prepare feature array
        X = np.array([features.to_array()])

        # Scale features
        if self._scaler is not None:
            X = self._scaler.transform(X)

        predictions = []
        probabilities_list = []

        # Random Forest prediction
        if self._rf_model is not None:
            rf_pred = self._rf_model.predict(X)[0]
            rf_proba = self._rf_model.predict_proba(X)[0]
            predictions.append(rf_pred)
            probabilities_list.append(rf_proba)

        # Gradient Boosting prediction
        if self._gb_model is not None:
            gb_pred = self._gb_model.predict(X)[0]
            gb_proba = self._gb_model.predict_proba(X)[0]
            predictions.append(gb_pred)
            probabilities_list.append(gb_proba)

        # Neural Network prediction
        if self._nn_classifier and self._nn_classifier.is_trained:
            nn_pred_str, nn_conf, nn_proba_dict = self._nn_classifier.predict(features)
            nn_pred_idx = self.LABELS.index(nn_pred_str)
            nn_proba = np.array([nn_proba_dict.get(label, 0.0) for label in self.LABELS])
            predictions.append(nn_pred_idx)
            probabilities_list.append(nn_proba)

        if not predictions:
            return self._heuristic_classify(features)

        # Ensemble voting (average probabilities)
        avg_proba = np.mean(probabilities_list, axis=0)
        final_pred_idx = np.argmax(avg_proba)
        final_pred = self.LABELS[final_pred_idx]
        confidence = float(avg_proba[final_pred_idx])

        # Build probability dict
        probabilities = {
            label: float(prob)
            for label, prob in zip(self.LABELS, avg_proba)
        }

        # Get feature importance from Random Forest
        importance = {}
        if self._rf_model is not None:
            feature_names = FeatureVector.feature_names()
            importances = self._rf_model.feature_importances_
            for name, imp in zip(feature_names, importances):
                if imp > 0.01:  # Only significant features
                    importance[name] = float(imp)

        return ClassificationResult(
            prediction=final_pred,
            confidence=confidence,
            probabilities=probabilities,
            feature_importance=importance,
            model_used="ensemble",
        )

    def train(
        self,
        training_data: List[Tuple[Path, str]],
        validation_split: float = 0.2,
    ) -> Dict[str, Any]:
        """
        Train the ensemble classifier.

        Args:
            training_data: List of (file_path, label) tuples
            validation_split: Fraction for validation

        Returns:
            Training metrics
        """
        if not self._sklearn_available:
            raise RuntimeError("scikit-learn required for training")

        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.metrics import classification_report, accuracy_score

        logger.info(f"Training on {len(training_data)} samples")

        # Extract features
        X = []
        y = []
        for file_path, label in training_data:
            try:
                features = self._feature_extractor.extract(file_path)
                X.append(features.to_array())
                y.append(self.LABELS.index(label))
            except Exception as e:
                logger.warning(f"Failed to extract features from {file_path}: {e}")

        X = np.array(X)
        y = np.array(y)

        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42, stratify=y
        )

        # Scale features
        self._scaler = StandardScaler()
        X_train_scaled = self._scaler.fit_transform(X_train)
        X_val_scaled = self._scaler.transform(X_val)

        # Train Random Forest
        logger.info("Training Random Forest...")
        self._rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=42,
        )
        self._rf_model.fit(X_train_scaled, y_train)
        rf_accuracy = accuracy_score(y_val, self._rf_model.predict(X_val_scaled))

        # Train Gradient Boosting
        logger.info("Training Gradient Boosting...")
        self._gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
        )
        self._gb_model.fit(X_train_scaled, y_train)
        gb_accuracy = accuracy_score(y_val, self._gb_model.predict(X_val_scaled))

        # Train Neural Network
        logger.info("Training Neural Network...")
        nn_metrics = {}
        nn_accuracy = 0.0
        if self._nn_classifier:
            try:
                nn_metrics = self._nn_classifier.train(
                    X_train_scaled, y_train,
                    X_val_scaled, y_val,
                    epochs=50,
                    batch_size=32,
                )
                nn_accuracy = nn_metrics.get("val_accuracy", 0.0)
                logger.info(f"Neural Network trained: accuracy={nn_accuracy:.4f}")
            except Exception as e:
                logger.warning(f"Neural network training failed: {e}")

        # Ensemble accuracy (including NN if available)
        rf_proba = self._rf_model.predict_proba(X_val_scaled)
        gb_proba = self._gb_model.predict_proba(X_val_scaled)

        # Add NN predictions if available
        if self._nn_classifier and self._nn_classifier.is_trained:
            try:
                # Get NN predictions directly from scaled features
                # Create dummy FeatureVector just for the interface
                nn_proba_list = []
                for x_val in X_val_scaled:
                    # Create FeatureVector from scaled array
                    features_obj = self._create_feature_vector_from_array(x_val)
                    _, _, proba_dict = self._nn_classifier.predict(features_obj)
                    nn_proba_row = [proba_dict.get(label, 0.0) for label in self.LABELS]
                    nn_proba_list.append(nn_proba_row)
                nn_proba = np.array(nn_proba_list)

                ensemble_proba = (rf_proba + gb_proba + nn_proba) / 3
                logger.debug("Ensemble includes Neural Network predictions")
            except Exception as e:
                logger.warning(f"NN ensemble prediction failed: {e}, using RF+GB only")
                ensemble_proba = (rf_proba + gb_proba) / 2
        else:
            ensemble_proba = (rf_proba + gb_proba) / 2

        ensemble_pred = np.argmax(ensemble_proba, axis=1)
        ensemble_accuracy = accuracy_score(y_val, ensemble_pred)

        self._is_trained = True

        # Save models
        self._save_models()

        metrics = {
            "rf_accuracy": rf_accuracy,
            "gb_accuracy": gb_accuracy,
            "nn_accuracy": nn_accuracy,
            "ensemble_accuracy": ensemble_accuracy,
            "samples_trained": len(X_train),
            "samples_validated": len(X_val),
            "classification_report": classification_report(
                y_val, ensemble_pred, target_names=self.LABELS, output_dict=True
            ),
            "nn_metrics": nn_metrics,
        }

        logger.info(
            "Training complete",
            extra_data={
                "rf_accuracy": f"{rf_accuracy:.4f}",
                "gb_accuracy": f"{gb_accuracy:.4f}",
                "nn_accuracy": f"{nn_accuracy:.4f}",
                "ensemble_accuracy": f"{ensemble_accuracy:.4f}",
            },
        )

        return metrics

    def _save_models(self) -> None:
        """Save trained models to disk."""
        try:
            if self._rf_model is not None:
                rf_path = self._model_dir / "random_forest.pkl"
                with open(rf_path, "wb") as f:
                    pickle.dump(self._rf_model, f)

            if self._gb_model is not None:
                gb_path = self._model_dir / "gradient_boosting.pkl"
                with open(gb_path, "wb") as f:
                    pickle.dump(self._gb_model, f)

            if self._scaler is not None:
                scaler_path = self._model_dir / "scaler.pkl"
                with open(scaler_path, "wb") as f:
                    pickle.dump(self._scaler, f)

            # Save metadata
            metadata = {
                "version": self.MODEL_VERSION,
                "labels": self.LABELS,
                "feature_names": FeatureVector.feature_names(),
                "feature_count": len(FeatureVector.feature_names()),
            }
            meta_path = self._model_dir / "metadata.json"
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Models saved to {self._model_dir}")

        except Exception as e:
            logger.error(f"Failed to save models: {e}")

    def _load_models(self) -> None:
        """Load trained models from disk."""
        try:
            # Check version compatibility first
            meta_path = self._model_dir / "metadata.json"
            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)

                saved_version = metadata.get("version", "0.0.0")
                if saved_version != self.MODEL_VERSION:
                    logger.warning(
                        f"Model version mismatch: saved={saved_version}, current={self.MODEL_VERSION}. "
                        "Models may be incompatible. Consider retraining."
                    )
                    # For now, we'll still try to load, but warn the user
                    # In production, you might want to reject incompatible versions

            rf_path = self._model_dir / "random_forest.pkl"
            gb_path = self._model_dir / "gradient_boosting.pkl"
            scaler_path = self._model_dir / "scaler.pkl"

            if rf_path.exists():
                with open(rf_path, "rb") as f:
                    self._rf_model = pickle.load(f)

            if gb_path.exists():
                with open(gb_path, "rb") as f:
                    self._gb_model = pickle.load(f)

            if scaler_path.exists():
                with open(scaler_path, "rb") as f:
                    self._scaler = pickle.load(f)

            # Check if any model is trained
            models_loaded = []
            if self._rf_model is not None:
                models_loaded.append("RF")
            if self._gb_model is not None:
                models_loaded.append("GB")
            if self._nn_classifier and self._nn_classifier.is_trained:
                models_loaded.append("NN")

            if models_loaded:
                self._is_trained = True
                logger.info(f"ML models loaded successfully: {', '.join(models_loaded)}")

        except Exception as e:
            logger.warning(f"Failed to load models: {e}")

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model."""
        if not self._is_trained or self._rf_model is None:
            return {}

        feature_names = FeatureVector.feature_names()
        importances = self._rf_model.feature_importances_

        return {
            name: float(imp)
            for name, imp in sorted(
                zip(feature_names, importances),
                key=lambda x: x[1],
                reverse=True,
            )
            if imp > 0.001
        }

    def _create_feature_vector_from_array(self, array: np.ndarray) -> FeatureVector:
        """
        Create a FeatureVector object from a numpy array.

        This is a helper method for converting scaled feature arrays
        back into FeatureVector objects for the neural network interface.

        Args:
            array: Numpy array of features

        Returns:
            FeatureVector object with features populated
        """
        features = FeatureVector()
        feature_names = FeatureVector.feature_names()

        # Map array values to FeatureVector attributes
        for i, name in enumerate(feature_names):
            if i < len(array):
                # Set attribute dynamically
                if hasattr(features, name):
                    try:
                        # Convert back to appropriate type
                        value = float(array[i])
                        # Integer fields should be cast to int
                        if any(keyword in name for keyword in ['num_', 'count', 'sections', 'imports', 'exports']):
                            value = int(value) if value >= 0 else 0
                        setattr(features, name, value)
                    except (ValueError, TypeError):
                        pass  # Keep default value

        return features

    @property
    def is_trained(self) -> bool:
        """Check if model is trained."""
        return self._is_trained
