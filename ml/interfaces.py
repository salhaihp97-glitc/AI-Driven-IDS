"""
Machine Learning Layer Interfaces Module.

Establishes foundational core interface definitions for predictive workflows, adhering to the
Dependency Inversion Principle. Decouples prediction engines and ingestion wrappers from specific
third-party libraries (e.g., scikit-learn, XGBoost) and arbitrary network capture tools.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from capture.flow_models import FlowFeatures


class IModelAdapter(ABC):
    """
    Unified Abstract Machine Learning Model Predictor Contract.
    
    Provides a standardized analytical boundary wrapper to execute multi-framework classification
    and inference probability queries uniformly across downstream system detection layers.
    """

    @abstractmethod
    def predict(self, feature_vector: np.ndarray) -> int:
        """
        Executes binary categorization over an ordered numerical matrix input sample.

        Args:
            feature_vector: A single-row numerical NumPy matrix matching expected dimensions.

        Returns:
            The predicted target execution state identifier (e.g., 0 = Normal, 1 = Attack).
        """

    @abstractmethod
    def predict_confidence(self, feature_vector: np.ndarray) -> float:
        """
        Evaluates prediction probability arrays to derive classification precision scores.

        Args:
            feature_vector: A single-row numerical NumPy matrix matching expected dimensions.

        Returns:
            A floating-point confidence coefficient score bounded between 0.0 and 1.0.
        """

    @property
    @abstractmethod
    def required_features(self) -> list[str]:
        """
        Exposes the exact, ordered sequence of structural feature tags expected by this model.
        """


class IFlowExtractor(ABC):
    """
    Unified Abstract Network Flow Feature Extraction Contract.
    
    Establishes the structural packet inspection blueprint required to translate unstructured 
    network data captures into structured behavioral telemetry row sets.
    """

    @abstractmethod
    def extract_from_pcap(self, pcap_path: str) -> list[FlowFeatures]:
        """
        Parses a target physical PCAP format recording asset into tabular flow feature maps.

        Args:
            pcap_path: The filesystem path string targeting the historical capture asset.

        Returns:
            A list of FlowFeatures dataclass instances representing distinct network flows.
        """