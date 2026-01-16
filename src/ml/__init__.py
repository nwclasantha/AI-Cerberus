"""Machine Learning module for malware classification."""

from .feature_extractor import FeatureExtractor, FeatureVector
from .classifier import MalwareClassifier, ClassificationResult
from .neural_classifier import NeuralClassifier
from .auto_trainer import AutoTrainer, get_auto_trainer

__all__ = [
    "FeatureExtractor",
    "FeatureVector",
    "MalwareClassifier",
    "ClassificationResult",
    "NeuralClassifier",
    "AutoTrainer",
    "get_auto_trainer",
]
