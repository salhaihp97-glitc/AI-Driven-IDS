"""
Machine Learning Model Performance Evaluation and Benchmark Service Module.

Computes descriptive classification statistical metrics (including Accuracy, Precision, 
Recall, F1-Score, False Positive/Negative Rates, Matthews Correlation Coefficients, and 
Confusion Matrix profiles) across registered models against verification datasets.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)

from config.settings import Settings
from core.entities.model_record import ModelRecord
from infrastructure.logging.logger_factory import get_logger
from ml.feature_mapper import FeatureMapper
from ml.model_loader import ModelLoader
from services.model_service import ModelService

logger = get_logger("services.model_evaluation_service")


@dataclass(frozen=True)
class EvaluationResult:
    """
    Immutable structured metrics data transfer object housing complete validation run information.
    """
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    fpr: float
    fnr: float
    mcc: float
    tn: int
    fp: int
    fn: int
    tp: int
    prediction_time_ms: float
    loading_time_ms: float
    features_count: int
    model_size_kb: float
    is_active: bool


class ModelEvaluationService:
    """
    Application core analytics engine running automated model validation suites and diagnostic loops.
    """

    def __init__(self, model_service: ModelService, loader: ModelLoader | None = None) -> None:
        """
        Initializes the evaluation suite with mandatory model registry and artifact loader utilities.
        """
        self._models: Final[ModelService] = model_service
        self._loader: Final[ModelLoader] = loader or ModelLoader()
        self._mapper: Final[FeatureMapper] = FeatureMapper()

    def evaluate(self, model_record: ModelRecord, test_csv_path: str, label_column: str = "Label") -> EvaluationResult:
        """
        Performs thorough vectorized evaluation against a verification dataset to map classification errors.

        Args:
            model_record: The persistent database entity profile tracking the targeted artifact metadata.
            test_csv_path: Physical file system path locating the baseline evaluation records.
            label_column: The target field name referencing ground-truth validation criteria labels.

        Returns:
            A detailed EvaluationResult matrix profile object capturing precision and runtime behavior.

        Raises:
            ValueError: If the target label validation column is missing from the provided frame.
        """
        # 1. Profile computational overhead linked to artifact binary loading sequences
        resolved_model_path: Final[str] = str(Settings.resolve_model_path(model_record.file_path))
        load_start: Final[float] = time.perf_counter()
        adapter = self._loader.load(resolved_model_path, model_record.model_type)
        loading_time_ms: Final[float] = (time.perf_counter() - load_start) * 1000.0

        df = pd.read_csv(test_csv_path)
        if label_column not in df.columns:
            raise ValueError(f"Evaluation Context Fault: Ground truth key label '{label_column}' missing from input dataset columns.")

        y_true: Final[np.ndarray] = df[label_column].astype(int).to_numpy()
        X_raw: Final[pd.DataFrame] = df.drop(columns=[label_column])

        # 2. Dynamic Batch Alignment & Vectorized Inference
        predict_start: Final[float] = time.perf_counter()
        
        # Batch align features (resizes columns, handles missing features, enforces strict 2D output)
        X_aligned, _ = self._mapper.map_dataframe_with_report(
            X_raw, adapter.required_features, as_numpy=True
        )

        # Explicit Structural Defensive Guard: Force strict 2D input (n_samples, n_features)
        if isinstance(X_aligned, np.ndarray):
            if X_aligned.ndim == 3 and X_aligned.shape[0] == 1:
                X_aligned = X_aligned.squeeze(axis=0)
            elif X_aligned.ndim > 2:
                X_aligned = X_aligned.reshape(-1, len(adapter.required_features))

        # Batch prediction using the underlying estimator directly for performance
        n_samples: Final[int] = X_aligned.shape[0]
        predictions = np.empty(n_samples, dtype=int)
        confidences: np.ndarray | None = None
        has_confidence = hasattr(adapter, "predict_confidence")

        if has_confidence:
            confidences = np.empty(n_samples, dtype=float)

        for i in range(n_samples):
            row = X_aligned[i]
            predictions[i] = int(adapter.predict(row))
            if confidences is not None:
                confidences[i] = float(adapter.predict_confidence(row))

        prediction_time_ms: Final[float] = (time.perf_counter() - predict_start) * 1000.0

        # 3. Derive a consistent binary attack-vs-benign axis.
        #
        # Deployed CICIDS2017 adapters emit multiclass indices (0 = BENIGN,
        # 1..14 = specific attack families). Collapsing every non-benign class
        # to 1 keeps detection-oriented metrics (accuracy, precision, recall,
        # F1, MCC, and the confusion-matrix quadrants) truthful and crash-free
        # regardless of the evaluation dataset's label cardinality, instead of
        # silently discarding attack classes 2-14 in a truncated 2x2 matrix.
        y_true_binary: Final[np.ndarray] = (y_true != 0).astype(int)
        predictions_binary: Final[np.ndarray] = (predictions != 0).astype(int)

        cm: Final[np.ndarray] = confusion_matrix(y_true_binary, predictions_binary, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        # 4. Compute specialized security performance rates (False Positive & False Negative Rates)
        fpr: Final[float] = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
        fnr: Final[float] = float(fn / (tp + fn)) if (tp + fn) > 0 else 0.0

        # 5. Calculate Matthews Correlation Coefficient indicators (robust to class imbalances)
        mcc: Final[float] = float(matthews_corrcoef(y_true_binary, predictions_binary))

        # 6. Evaluate Area Under ROC Curve safely ignoring single-class or missing probability layouts
        roc_auc: float | None = None
        if len(np.unique(y_true_binary)) > 1 and confidences is not None:
            try:
                if confidences.ndim == 1:
                    roc_auc = float(roc_auc_score(y_true_binary, confidences))
                elif confidences.ndim == 2:
                    roc_auc = float(roc_auc_score(y_true_binary, confidences, multi_class='ovr', average='weighted'))
            except Exception:
                roc_auc = None

        # 7. Map physical space requirements on the host infrastructure drive
        artifact_path = Path(resolved_model_path)
        model_size_kb: Final[float] = artifact_path.stat().st_size / 1024.0 if artifact_path.exists() else 0.0

        return EvaluationResult(
            model_name=model_record.name,
            accuracy=float(accuracy_score(y_true_binary, predictions_binary)),
            precision=float(precision_score(y_true_binary, predictions_binary, zero_division=0)),
            recall=float(recall_score(y_true_binary, predictions_binary, zero_division=0)),
            f1=float(f1_score(y_true_binary, predictions_binary, zero_division=0)),
            roc_auc=roc_auc,
            fpr=fpr,
            fnr=fnr,
            mcc=mcc,
            tn=int(tn),
            fp=int(fp),
            fn=int(fn),
            tp=int(tp),
            prediction_time_ms=prediction_time_ms,
            loading_time_ms=loading_time_ms,
            features_count=len(adapter.required_features),
            model_size_kb=model_size_kb,
            is_active=model_record.is_active,
        )