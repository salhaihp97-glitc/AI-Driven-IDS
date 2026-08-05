"""
Model Metadata Service — Test Suite.

Verifies profile building, comparison logic, and the correctness of each
"winner by metric" field. In particular it guards the regression where
``ComparisonResult.winner_f1`` was computed from MCC instead of the weighted
average F1 score.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import pytest

from config.settings import Settings
from services import model_metadata_service as mm
from services.model_metadata_service import ModelMetadataService

EVAL_FILENAME: Final[str] = "models_evaluation_results.json"
CLASSES: Final[list[str]] = ["BENIGN", "ATTACK1", "ATTACK2"]


def _report_row(precision: float, recall: float, f1: float, support: float) -> dict[str, float]:
    return {
        "precision": precision,
        "recall": recall,
        "f1-score": f1,
        "support": support,
    }


def _model_block(accuracy: float, mcc: float, f1: float) -> dict[str, Any]:
    report: dict[str, Any] = {
        "BENIGN": _report_row(0.95, 0.90, 0.92, 100),
        "ATTACK1": _report_row(0.90, 0.85, 0.87, 60),
        "ATTACK2": _report_row(0.88, 0.80, 0.84, 40),
        "weighted avg": _report_row(0.92, 0.87, f1, 200),
        "macro avg": _report_row(0.91, 0.85, 0.88, 200),
    }
    return {
        "report": report,
        "confusion_matrix": [[90, 5, 5], [6, 51, 3], [4, 4, 32]],
        "accuracy": accuracy,
        "mcc": mcc,
    }


def _write_eval_results(models_dir: Path) -> None:
    data = {
        "classes": CLASSES,
        "random_forest": _model_block(accuracy=0.89, mcc=0.55, f1=0.90),
        "xgboost": _model_block(accuracy=0.87, mcc=0.70, f1=0.80),
    }
    (models_dir / EVAL_FILENAME).write_text(
        json.dumps(data), encoding="utf-8"
    )


def _write_meta(models_dir: Path, filename: str, features: list[str]) -> None:
    (models_dir / filename).write_text(
        json.dumps({"feature_names": features}), encoding="utf-8"
    )


@pytest.fixture()
def meta_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModelMetadataService:
    """ModelMetadataService pointed at an isolated, pre-seeded models directory."""
    _write_eval_results(tmp_path)
    _write_meta(tmp_path, "random_forest_v3.joblib.meta.json", ["a", "b", "c"])
    _write_meta(tmp_path, "xgboost_pipeline_v2.joblib.meta.json", ["a", "b", "c"])
    monkeypatch.setattr(mm, "get_settings", lambda: Settings(models_dir=tmp_path))
    return ModelMetadataService()


def test_rf_profile_exposes_weighted_f1(meta_service: ModelMetadataService) -> None:
    profile = meta_service.get_rf_profile()
    assert profile.f1 == pytest.approx(0.90)


def test_xgb_profile_exposes_weighted_f1(meta_service: ModelMetadataService) -> None:
    profile = meta_service.get_xgb_profile()
    assert profile.f1 == pytest.approx(0.80)


def test_winner_f1_is_driven_by_f1_not_mcc(meta_service: ModelMetadataService) -> None:
    """RF has the higher F1 but the lower MCC — the F1 winner must be RF."""
    comparison = meta_service.get_comparison()
    assert comparison.rf_profile.f1 > comparison.xgb_profile.f1
    assert comparison.rf_profile.mcc < comparison.xgb_profile.mcc
    assert comparison.winner_f1 == "Random Forest V3"
    assert comparison.winner_mcc == "XGBoost Pipeline V2"


def test_comparison_winners_accuracy(meta_service: ModelMetadataService) -> None:
    comparison = meta_service.get_comparison()
    assert comparison.rf_profile.accuracy > comparison.xgb_profile.accuracy
    assert comparison.winner_accuracy == "Random Forest V3"


def test_per_class_breakdown_populated(meta_service: ModelMetadataService) -> None:
    profile = meta_service.get_rf_profile()
    assert [pc.class_name for pc in profile.per_class] == CLASSES
    assert all(pc.f1_score > 0 for pc in profile.per_class)
    assert profile.total_samples == 200
    assert profile.features_count == 3
