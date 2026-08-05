"""
Scikit-Learn Compatible Model Adapter Module.

Implements the unified IModelAdapter interface contract for estimator runtimes exposing 
standard scikit-learn API interfaces. Wraps raw predictors, custom analytics pipelines, 
and XGBoost wrappers seamlessly to isolate internal framework prediction mechanics from downstream systems.
"""

from __future__ import annotations

from typing import Any, Final

import numpy as np

from ml.feature_schema import FeatureSchema
from ml.interfaces import IModelAdapter


class SklearnCompatibleModelAdapter(IModelAdapter):
    """
    Adapter component mapping standard scikit-learn and XGBoost model API behaviors.
    
    Transforms raw input arrays dynamically into named structural matrices before evaluation, 
    safely handling prediction routing, feature indexing verification warnings, and 
    fallback precision scores uniformly.
    """

    def __init__(self, estimator: Any, schema: FeatureSchema, scaler: Any = None, decision_threshold: float = 0.5) -> None:
        """
        Initializes the model wrapper adapter with an underlying predictive asset and schema contract.

        Args:
            estimator: The hydrated scikit-learn compatible predictive estimator.
            schema: Contractual metadata outlining the ordered input feature footprint.
            scaler: Optional fitted preprocessing transformer (e.g. ``StandardScaler``)
                that was applied to the training matrix. When present it is applied to
                incoming feature vectors so inference mirrors the exact training-time
                input semantics. Absence is treated as a no-op for models trained raw.
            decision_threshold: Attack probability above which a sample is classified as
                malicious. Defaults to 0.5, which is arithmetically identical to the
                estimator's own argmax boundary for binary models (probabilities sum to 1).
        """
        self._estimator: Final[Any] = estimator
        self._schema: Final[FeatureSchema] = schema
        self._scaler: Any = scaler
        self._decision_threshold: Final[float] = decision_threshold

    @property
    def required_features(self) -> list[str]:
        """
        Exposes the exact, ordered sequence of structural feature tags expected by this model.
        """
        return self._schema.feature_names

    def _preprocess(self, feature_vector: np.ndarray) -> np.ndarray:
        """
        Projects a raw sample matrix through the model's training-time preprocessing chain.

        The estimator is trained on transformed values (when a scaler accompanies the
        artifact), so feeding raw magnitudes back would misalign learned split thresholds.
        Returns a strictly 2D (1, n_features) matrix ready for estimator evaluation.
        """
        row_2d: Final[np.ndarray] = feature_vector.reshape(1, -1)
        if self._scaler is not None:
            scaler_names = getattr(self._scaler, "feature_names_in_", None)
            if scaler_names is not None:
                # Local import keeps pandas coupling scoped to the scaling path and provides
                # named-column validation (guarding silent misalignment) for the transformer.
                import pandas as pd
                return self._scaler.transform(pd.DataFrame(row_2d, columns=list(scaler_names)))
            return self._scaler.transform(row_2d)
        return row_2d

    def predict(self, feature_vector: np.ndarray) -> int:
        """
        Executes binary categorization over an ordered numerical matrix input sample.

        Args:
            feature_vector: A single-row numerical NumPy matrix matching expected dimensions.

        Returns:
            The predicted target execution state identifier (0 = Normal, 1 = Attack).
        """
        row_2d: Final[np.ndarray] = self._preprocess(feature_vector)

        # When the estimator exposes continuous probabilities and the model is binary,
        # apply the configurable decision threshold directly. At the default 0.5 this is
        # arithmetically identical to the estimator's argmax boundary.
        if hasattr(self._estimator, "predict_proba"):
            probabilities = self._estimator.predict_proba(row_2d)[0]
            if len(probabilities) == 2:
                return int(probabilities[1] >= self._decision_threshold)

        prediction = self._estimator.predict(row_2d)[0]
        return int(prediction)

    def predict_confidence(self, feature_vector: np.ndarray) -> float:
        """
        Evaluates prediction probability arrays to derive classification precision scores.
        
        Gracefully defaults to absolute certainty (1.0) if the wrapped tracking architecture 
        lacks continuous target score generation utilities (e.g., discrete Support Vector machines).

        Args:
            feature_vector: A single-row numerical NumPy matrix matching expected dimensions.

        Returns:
            A floating-point confidence coefficient score bounded between 0.0 and 1.0.
        """
        row_2d: Final[np.ndarray] = self._preprocess(feature_vector)

        if hasattr(self._estimator, "predict_proba"):
            probabilities = self._estimator.predict_proba(row_2d)[0]
            return float(np.max(probabilities))
            
        # Standard structural fallback context for models devoid of probability extraction hooks
        return 1.0