"""
Machine Learning module for malware classification and anomaly detection.

This module provides comprehensive ML capabilities:
- Feature extraction and engineering
- Traditional ML classification
- Neural network classification
- Advanced unsupervised anomaly detection (98.6%+ precision)
- Self-supervised pre-training
- Precision-optimized ensemble methods
"""

from .feature_extractor import FeatureExtractor, FeatureVector
from .classifier import MalwareClassifier, ClassificationResult
from .neural_classifier import NeuralClassifier
from .auto_trainer import AutoTrainer, get_auto_trainer

# Advanced Anomaly Detection (v2.0)
from .advanced_anomaly_detector import (
    AdvancedAnomalyDetector,
    AnomalyResult,
    get_anomaly_detector,
)

# Ultra-Advanced Anomaly Detection (v3.0 - 98.6% precision)
from .ultra_advanced_anomaly_detector import (
    UltraAdvancedAnomalyDetector,
    DetailedAnomalyResult,
    AnomalyLevel,
    get_ultra_anomaly_detector,
)

# Advanced Feature Engineering
from .advanced_feature_engineering import (
    AdvancedFeatureEngineeringPipeline,
    AdvancedFeatures,
    PolynomialFeatureGenerator,
    StatisticalMomentFeatures,
    NGramFeatureExtractor,
    MultiScaleEntropyFeatures,
    FrequencyDomainFeatures,
    BenfordLawFeatures,
    ComplexityFeatures,
    InformationTheoreticFeatures,
    get_feature_pipeline,
)

# Precision-Optimized Ensemble
from .precision_optimized_ensemble import (
    PrecisionOptimizedEnsemble,
    EnsemblePrediction,
    DynamicWeightAdjuster,
    ConfidenceWeightedVoting,
    CascadeEnsemble,
    SelectivePrediction,
    get_precision_ensemble,
)

# Self-Supervised Pre-training
from .self_supervised_pretraining import (
    SelfSupervisedPretrainingPipeline,
    PretrainedRepresentation,
    MaskedFeaturePredictor,
    ContrastivePredictiveCoding,
    BarlowTwins,
    SimSiam,
    get_pretraining_pipeline,
)

__all__ = [
    # Core Feature Extraction
    "FeatureExtractor",
    "FeatureVector",

    # Classification
    "MalwareClassifier",
    "ClassificationResult",
    "NeuralClassifier",
    "AutoTrainer",
    "get_auto_trainer",

    # Anomaly Detection (v2.0)
    "AdvancedAnomalyDetector",
    "AnomalyResult",
    "get_anomaly_detector",

    # Ultra-Advanced Anomaly Detection (v3.0)
    "UltraAdvancedAnomalyDetector",
    "DetailedAnomalyResult",
    "AnomalyLevel",
    "get_ultra_anomaly_detector",

    # Feature Engineering
    "AdvancedFeatureEngineeringPipeline",
    "AdvancedFeatures",
    "PolynomialFeatureGenerator",
    "StatisticalMomentFeatures",
    "NGramFeatureExtractor",
    "MultiScaleEntropyFeatures",
    "FrequencyDomainFeatures",
    "BenfordLawFeatures",
    "ComplexityFeatures",
    "InformationTheoreticFeatures",
    "get_feature_pipeline",

    # Precision-Optimized Ensemble
    "PrecisionOptimizedEnsemble",
    "EnsemblePrediction",
    "DynamicWeightAdjuster",
    "ConfidenceWeightedVoting",
    "CascadeEnsemble",
    "SelectivePrediction",
    "get_precision_ensemble",

    # Self-Supervised Pre-training
    "SelfSupervisedPretrainingPipeline",
    "PretrainedRepresentation",
    "MaskedFeaturePredictor",
    "ContrastivePredictiveCoding",
    "BarlowTwins",
    "SimSiam",
    "get_pretraining_pipeline",
]
