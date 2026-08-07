"""
Model Metadata Resolution and Caching Service.

Loads, validates, and caches model metadata from JSON sidecar files,
evaluation results, and feature schemas. Provides a unified query interface
for the evaluation dashboard to consume without touching raw files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from config.settings import get_settings
from infrastructure.logging.logger_factory import get_logger

logger = get_logger("services.model_metadata_service")

# ── Data Transfer Objects ───────────────────────────────────────────────


@dataclass(frozen=True)
class PerClassMetrics:
    """Metrics for a single attack class."""
    class_name: str
    precision: float
    recall: float
    f1_score: float
    support: float


@dataclass(frozen=True)
class ConfusionMatrixData:
    """Full confusion matrix with labels."""
    labels: list[str]
    matrix: list[list[int]]


@dataclass(frozen=True)
class ModelProfile:
    """Complete evaluation profile for a single model."""
    key: str                          # "random_forest" | "xgboost"
    display_name: str                 # "Random Forest V3"
    version: str                      # "3.0.0"
    model_type: str                   # "random_forest"
    accuracy: float
    mcc: float
    feature_names: list[str]
    features_count: int
    per_class: list[PerClassMetrics]
    weighted_avg: dict[str, float]
    macro_avg: dict[str, float]
    confusion_matrix: ConfusionMatrixData
    total_samples: int
    # Derived safety metrics
    false_positive_rate: float        # Overall FPR
    false_negative_rate: float        # Overall FNR
    attack_detection_rate: float      # Recall across all attack classes
    benign_detection_rate: float      # Recall for BENIGN class

    @property
    def f1(self) -> float:
        """Weighted average F1 score across all classes."""
        return float(self.weighted_avg.get("f1_score", 0.0))


@dataclass(frozen=True)
class ComparisonResult:
    """Head-to-head comparison between two models."""
    rf_profile: ModelProfile
    xgb_profile: ModelProfile
    winner_accuracy: str
    winner_f1: str
    winner_mcc: str
    winner_attack_detection: str
    winner_false_negative: str
    rf_better_classes: list[str]
    xgb_better_classes: list[str]
    tied_classes: list[str]


# ── Service ─────────────────────────────────────────────────────────────


class ModelMetadataService:
    """
    Resolves and caches all model evaluation metadata from disk.
    Thread-safe, lazy-loading, idempotent.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._models_dir: Final[Path] = self._settings.models_dir
        self._eval_cache: dict[str, Any] | None = None
        self._rf_meta_cache: dict[str, Any] | None = None
        self._xgb_meta_cache: dict[str, Any] | None = None

    # ── Raw Loaders ─────────────────────────────────────────────────────

    def _load_eval_results(self) -> dict[str, Any]:
        if self._eval_cache is None:
            path = self._models_dir / "models_evaluation_results.json"
            if not path.exists():
                logger.error("Evaluation results file not found: %s", path)
                self._eval_cache = {}
            else:
                with open(path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                # Normalize class names: replace Unicode replacement chars
                self._eval_cache = self._normalize(raw)
                logger.info("Loaded evaluation results from %s", path)
        return self._eval_cache

    @staticmethod
    def _normalize(data: dict[str, Any]) -> dict[str, Any]:
        """Replace Unicode replacement chars (\ufffd) with '/' in class names."""
        result = dict(data)
        if "classes" in result:
            result["classes"] = [
                c.replace("\ufffd", "/") for c in result["classes"]
            ]
        # Normalize report keys too
        for model_key in ("random_forest", "xgboost"):
            if model_key in result and "report" in result[model_key]:
                old_report = result[model_key]["report"]
                new_report = {}
                for k, v in old_report.items():
                    new_report[k.replace("\ufffd", "/")] = v
                result[model_key]["report"] = new_report
        return result

    def _load_meta_json(self, filename: str) -> dict[str, Any]:
        path = self._models_dir / filename
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _load_scaler_feature_names(self) -> list[str]:
        """
        Reads the fitted feature footprint from the co-located ``scaler.joblib``.

        Mirrors the runtime inference precedence in ``ml.model_loader``, where the
        scaler's ``feature_names_in_`` is the ground-truth training-time column order.
        Cached at instance level so the dashboard never reparses the artifact on
        every render.
        """
        scaler_cache: list[str] | None = self.__dict__.get("_scaler_features")
        if scaler_cache is not None:
            return scaler_cache

        names: list[str] = []
        scaler_path: Final[Path] = self._models_dir / "scaler.joblib"
        if scaler_path.exists():
            try:
                import joblib
                scaler = joblib.load(scaler_path)
                fitted: Any = getattr(scaler, "feature_names_in_", None)
                if fitted is not None:
                    names = list(fitted)
            except Exception:  # noqa: BLE001 - best-effort fallback; never break the dashboard
                logger.warning("Failed to read feature footprint from %s", scaler_path)
        self.__dict__["_scaler_features"] = names
        return names

    def _resolve_feature_names(self, meta: dict[str, Any]) -> list[str]:
        """
        Resolves the model feature footprint with the same precedence as inference:
        sidecar ``meta.json`` first, then the co-located scaler artifact.
        """
        feature_names: list[str] = meta.get("feature_names", [])
        if feature_names:
            return feature_names
        scaler_names: list[str] = self._load_scaler_feature_names()
        if scaler_names:
            logger.warning(
                "meta.json lacks feature_names — falling back to scaler.joblib footprint (%d features).",
                len(scaler_names),
            )
            return scaler_names
        return []

    # ── Public API ──────────────────────────────────────────────────────

    def get_classes(self) -> list[str]:
        """Return the ordered list of attack class labels."""
        data = self._load_eval_results()
        return data.get("classes", [])

    def has_evaluation_data(self) -> bool:
        """``True`` when a populated evaluation-results artifact exists on disk."""
        data = self._load_eval_results()
        return bool(data.get("classes")) or bool(data.get("random_forest")) or bool(data.get("xgboost"))

    def get_rf_profile(self) -> ModelProfile:
        """Build a complete Random Forest evaluation profile."""
        return self._build_profile("random_forest", "Random Forest V3", "3.0.0")

    def get_xgb_profile(self) -> ModelProfile:
        """Build a complete XGBoost evaluation profile."""
        return self._build_profile("xgboost", "XGBoost Pipeline V2", "2.0.0")

    def get_all_profiles(self) -> list[ModelProfile]:
        return [self.get_rf_profile(), self.get_xgb_profile()]

    def get_comparison(self) -> ComparisonResult:
        """Build a head-to-head comparison between both models."""
        rf = self.get_rf_profile()
        xgb = self.get_xgb_profile()

        # Determine winners per metric
        def pick(a: ModelProfile, b: ModelProfile, metric: str) -> str:
            va = getattr(a, metric)
            vb = getattr(b, metric)
            if va > vb:
                return a.display_name
            elif vb > va:
                return b.display_name
            return "Tied"

        # Per-class winner determination
        rf_better, xgb_better, tied = [], [], []
        rf_map = {pc.class_name: pc for pc in rf.per_class}
        xgb_map = {pc.class_name: pc for pc in xgb.per_class}
        for cls_name in rf_map:
            if cls_name in xgb_map:
                rf_f1 = rf_map[cls_name].f1_score
                xgb_f1 = xgb_map[cls_name].f1_score
                if abs(rf_f1 - xgb_f1) < 0.001:
                    tied.append(cls_name)
                elif rf_f1 > xgb_f1:
                    rf_better.append(cls_name)
                else:
                    xgb_better.append(cls_name)

        return ComparisonResult(
            rf_profile=rf,
            xgb_profile=xgb,
            winner_accuracy=pick(rf, xgb, "accuracy"),
            winner_f1=pick(rf, xgb, "f1"),
            winner_mcc=pick(rf, xgb, "mcc"),
            winner_attack_detection=pick(rf, xgb, "attack_detection_rate"),
            winner_false_negative=pick(rf, xgb, "false_negative_rate"),
            rf_better_classes=rf_better,
            xgb_better_classes=xgb_better,
            tied_classes=tied,
        )

    # ── Internal Builder ────────────────────────────────────────────────

    def _build_profile(self, key: str, display_name: str, version: str) -> ModelProfile:
        data = self._load_eval_results()
        model_data = data.get(key, {})
        classes = data.get("classes", [])

        # Load feature names from meta.json (falling back to the scaler footprint)
        meta_file = f"{'random_forest_v3' if key == 'random_forest' else 'xgboost_pipeline_v2'}.joblib.meta.json"
        meta = self._load_meta_json(meta_file)
        feature_names = self._resolve_feature_names(meta)

        # Parse per-class metrics
        report = model_data.get("report", {})
        per_class = []
        for cls_name in classes:
            cls_data = report.get(cls_name, {})
            per_class.append(PerClassMetrics(
                class_name=cls_name,
                precision=float(cls_data.get("precision", 0)),
                recall=float(cls_data.get("recall", 0)),
                f1_score=float(cls_data.get("f1-score", 0)),
                support=float(cls_data.get("support", 0)),
            ))

        # Weighted and macro averages
        weighted = report.get("weighted avg", {})
        macro = report.get("macro avg", {})

        # Confusion matrix
        cm_raw = model_data.get("confusion_matrix", [])
        cm = ConfusionMatrixData(labels=classes, matrix=cm_raw)

        # Derived metrics
        total_samples = int(weighted.get("support", 0))
        accuracy = float(model_data.get("accuracy", 0))
        mcc = float(model_data.get("mcc", 0))

        # BENIGN recall = true negative rate (benign correctly identified)
        benign_recall = report.get("BENIGN", {}).get("recall", 0)

        # Attack detection rate = average recall across all attack classes
        attack_recalls = [
            report.get(c, {}).get("recall", 0)
            for c in classes if c != "BENIGN"
        ]
        attack_detection = sum(attack_recalls) / len(attack_recalls) if attack_recalls else 0

        # FPR = 1 - benign_recall, FNR = 1 - attack_detection
        fpr = 1.0 - benign_recall
        fnr = 1.0 - attack_detection

        return ModelProfile(
            key=key,
            display_name=display_name,
            version=version,
            model_type=key,
            accuracy=accuracy,
            mcc=mcc,
            feature_names=feature_names,
            features_count=len(feature_names),
            per_class=per_class,
            weighted_avg={
                "precision": float(weighted.get("precision", 0)),
                "recall": float(weighted.get("recall", 0)),
                "f1_score": float(weighted.get("f1-score", 0)),
            },
            macro_avg={
                "precision": float(macro.get("precision", 0)),
                "recall": float(macro.get("recall", 0)),
                "f1_score": float(macro.get("f1-score", 0)),
            },
            confusion_matrix=cm,
            total_samples=total_samples,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            attack_detection_rate=attack_detection,
            benign_detection_rate=float(benign_recall),
        )
