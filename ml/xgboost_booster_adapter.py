"""
Native XGBoost Booster Adapter Module.

Implements the structural IModelAdapter interface wrapper for native XGBoost Booster instances
serialized directly via JSON or Universal Binary JSON (.ubj) configurations. Isolates native DMatrix
generation logic safely away from high-level prediction brokers.
"""

from __future__ import annotations

from typing import Any, Final

import numpy as np

from ml.feature_schema import FeatureSchema
from ml.interfaces import IModelAdapter


class XGBoostBoosterAdapter(IModelAdapter):
    """
    Adapter component mapping native low-level gradient booster execution arrays.
    
    Translates raw linear numerical entry matrices dynamically into namespaced validation 
    DMatrix evaluation blocks to achieve high-frequency classification operations.
    """

    def __init__(self, booster: Any, schema: FeatureSchema, decision_threshold: float = 0.5) -> None:
        """
        Initializes the native gradient booster adapter with an active booster core and schema mapping.

        Args:
            booster: The hydrated native XGBoost Booster core.
            schema: Contractual metadata outlining the ordered input feature footprint.
            decision_threshold: Attack probability above which a sample is classified as
                malicious. Defaults to 0.5 (the standard binary decision boundary); raising
                it reduces false positives at the cost of more missed detections.
        """
        self._booster: Final[Any] = booster
        self._schema: Final[FeatureSchema] = schema
        self._decision_threshold: Final[float] = decision_threshold

    @property
    def required_features(self) -> list[str]:
        """
        Exposes the exact, ordered sequence of structural feature tags expected by this model.
        """
        return self._schema.feature_names

    def _predict_proba_positive(self, feature_vector: np.ndarray) -> float:
        """
        Generates raw execution arrays to evaluate single-row continuous probability states.
        
        Performs localized dynamic lazy imports of the 'xgboost' core driver to allow modular 
        system configurations when the library is not installed globally.
        """
        import xgboost as xgb

        # Restructure flat row layouts explicitly into standard 2D evaluation states
        two_dimensional_vector: Final[np.ndarray] = feature_vector.reshape(1, -1)
        
        dmatrix: Final[xgb.DMatrix] = xgb.DMatrix(
            two_dimensional_vector,
            feature_names=self._schema.feature_names,
        )
        return float(self._booster.predict(dmatrix)[0])

    def predict(self, feature_vector: np.ndarray) -> int:
        """
        Executes binary categorization over an ordered numerical matrix input sample.

        Args:
            feature_vector: A single-row numerical NumPy matrix matching expected dimensions.

        Returns:
            The predicted target execution state identifier (0 = Normal, 1 = Attack).
        """
        proba_attack: Final[float] = self._predict_proba_positive(feature_vector)
        return int(proba_attack >= self._decision_threshold)

    def predict_confidence(self, feature_vector: np.ndarray) -> float:
        """
        Evaluates decision probability spaces to extract absolute evaluation confidence scores.

        Args:
            feature_vector: A single-row numerical NumPy matrix matching expected dimensions.

        Returns:
            A floating-point confidence coefficient score bounded between 0.5 and 1.0.
        """
        proba_attack: Final[float] = self._predict_proba_positive(feature_vector)
        return float(max(proba_attack, 1.0 - proba_attack))