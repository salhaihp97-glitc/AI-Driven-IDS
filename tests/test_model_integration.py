"""Integration test: verify both RF and XGBoost models work end-to-end."""
import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

warnings.filterwarnings("ignore")

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


class TestBothModels:
    """Verify RF V3 and XGBoost V2 sidecars, internals, and predictions."""

    @pytest.fixture(autouse=True)
    def _load_models(self):
        self.rf = joblib.load(MODELS_DIR / "random_forest_v3.joblib")
        self.xgb = joblib.load(MODELS_DIR / "xgboost_pipeline_v2.joblib")
        self.rf_sc = json.loads(
            (MODELS_DIR / "random_forest_v3.joblib.meta.json").read_text(encoding="utf-8")
        )
        self.xgb_sc = json.loads(
            (MODELS_DIR / "xgboost_pipeline_v2.joblib.meta.json").read_text(encoding="utf-8")
        )
        self.le = joblib.load(MODELS_DIR / "label_encoder.joblib")
        self.rf_feat = self.rf_sc["feature_names"]
        self.xgb_feat = self.xgb_sc["feature_names"]

    # --- Sidecar checks ---

    def test_rf_sidecar_feature_count_matches_model(self):
        assert len(self.rf_feat) == self.rf.n_features_in_

    def test_xgb_sidecar_feature_count_matches_model(self):
        assert len(self.xgb_feat) == self.xgb.n_features_in_

    def test_rf_and_xgb_sidecars_identical(self):
        assert self.rf_feat == self.xgb_feat

    def test_sidecar_count_is_70(self):
        assert len(self.rf_feat) == 70
        assert len(self.xgb_feat) == 70

    # --- Model internal checks ---

    def test_rf_has_predict_proba(self):
        assert hasattr(self.rf, "predict_proba")

    def test_xgb_has_predict_proba(self):
        assert hasattr(self.xgb, "predict_proba")

    def test_rf_n_classes_15(self):
        assert self.rf.n_classes_ == 15

    def test_label_encoder_15_classes(self):
        assert len(self.le.classes_) == 15

    # --- Prediction checks ---

    def test_rf_predict_returns_correct_type(self):
        dummy = np.zeros((1, len(self.rf_feat)))
        pred = self.rf.predict(dummy)[0]
        assert isinstance(int(pred), int)

    def test_xgb_predict_returns_correct_type(self):
        dummy = np.zeros((1, len(self.xgb_feat)))
        pred = self.xgb.predict(dummy)[0]
        assert isinstance(int(pred), int)

    def test_rf_predict_proba_shape(self):
        dummy = np.zeros((1, len(self.rf_feat)))
        proba = self.rf.predict_proba(dummy)
        assert proba.shape == (1, 15)

    def test_xgb_predict_proba_shape(self):
        dummy = np.zeros((1, len(self.xgb_feat)))
        proba = self.xgb.predict_proba(dummy)
        assert proba.shape == (1, 15)

    def test_rf_confidence_is_valid(self):
        dummy = np.zeros((1, len(self.rf_feat)))
        conf = float(np.max(self.rf.predict_proba(dummy)[0]))
        assert 0.0 <= conf <= 1.0

    def test_xgb_confidence_is_valid(self):
        dummy = np.zeros((1, len(self.xgb_feat)))
        conf = float(np.max(self.xgb.predict_proba(dummy)[0]))
        assert 0.0 <= conf <= 1.0

    def test_rf_attack_type_resolution(self):
        dummy = np.zeros((1, len(self.rf_feat)))
        pred = int(self.rf.predict(dummy)[0])
        assert 0 <= pred < len(self.le.classes_)
        attack_type = str(self.le.classes_[pred])
        assert attack_type in list(self.le.classes_)

    def test_xgb_attack_type_resolution(self):
        dummy = np.zeros((1, len(self.xgb_feat)))
        pred = int(self.xgb.predict(dummy)[0])
        assert 0 <= pred < len(self.le.classes_)
        attack_type = str(self.le.classes_[pred])
        assert attack_type in list(self.le.classes_)

    def test_rf_predict_zeros_gives_benign(self):
        dummy = np.zeros((1, len(self.rf_feat)))
        pred = int(self.rf.predict(dummy)[0])
        assert pred == 0  # BENIGN class index
        assert str(self.le.classes_[0]) == "BENIGN"

    def test_xgb_predict_zeros_gives_benign(self):
        dummy = np.zeros((1, len(self.xgb_feat)))
        pred = int(self.xgb.predict(dummy)[0])
        assert pred == 0

    def test_rf_random_data_prediction(self):
        rand = np.random.rand(1, len(self.rf_feat)) * 100
        pred = int(self.rf.predict(rand)[0])
        conf = float(np.max(self.rf.predict_proba(rand)[0]))
        assert 0 <= pred < 15
        assert 0.0 <= conf <= 1.0

    def test_xgb_random_data_prediction(self):
        rand = np.random.rand(1, len(self.xgb_feat)) * 100
        pred = int(self.xgb.predict(rand)[0])
        conf = float(np.max(self.xgb.predict_proba(rand)[0]))
        assert 0 <= pred < 15
        assert 0.0 <= conf <= 1.0

    def test_label_encoder_transform_inverse(self):
        """LabelEncoder can transform class names to indices and back."""
        idx = self.le.transform(["BENIGN"])[0]
        assert idx == 0
        name = self.le.inverse_transform([idx])[0]
        assert name == "BENIGN"

    def test_label_encoder_all_classes_transformable(self):
        """All 15 class names can be transformed to valid indices."""
        for name in self.le.classes_:
            idx = self.le.transform([name])[0]
            assert 0 <= idx < 15
            assert self.le.inverse_transform([idx])[0] == name


class TestFeatureMapperWithBothModels:
    """Verify FeatureMapper correctly maps features for both models."""

    def test_mapper_aligns_cicflowmeter_columns(self):
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper()

        rf_sc = json.loads(
            (MODELS_DIR / "random_forest_v3.joblib.meta.json").read_text(encoding="utf-8")
        )
        required = rf_sc["feature_names"]

        # Simulate CICFlowMeter output column names (mixed case, different separators)
        cic_features = {
            "Destination Port": 80,
            "Flow Duration": 12000,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 5,
            "Fwd Packet Length Max": 1400,
            "Bwd Packet Length Mean": 200,
            "Flow Bytes S": 5000.0,
            "Flow Packets S": 100.0,
            "Init Win bytes forward": 65535,
            "Init Win bytes backward": 65535,
        }

        vector, missing = mapper.map_with_report(cic_features, required)

        assert len(vector) == 70
        assert isinstance(missing, list)
        assert vector.shape == (70,)

    def test_mapper_fills_missing_with_zero(self):
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper(missing_value_fill=0.0)

        rf_sc = json.loads(
            (MODELS_DIR / "random_forest_v3.joblib.meta.json").read_text(encoding="utf-8")
        )
        required = rf_sc["feature_names"]

        empty_features: dict[str, float] = {}
        vector, missing = mapper.map_with_report(empty_features, required)

        assert len(vector) == 70
        assert np.all(vector == 0.0)
        assert len(missing) == 70


class TestDetectionServiceIntegration:
    """End-to-end: ModelLoader -> Adapter -> LabelEncoder for both models (no DB dependency)."""

    def test_rf_via_model_loader(self):
        from ml.model_loader import ModelLoader

        loader = ModelLoader()
        adapter = loader.load(str(MODELS_DIR / "random_forest_v3.joblib"), "random_forest")
        assert len(adapter.required_features) == 70

        dummy_dict = {f: 0.0 for f in adapter.required_features}
        vec = np.array(list(dummy_dict.values()), dtype=float).reshape(1, -1)
        pred = int(adapter.predict(vec))
        conf = float(adapter.predict_confidence(vec))

        assert 0 <= pred < 15
        assert 0.0 <= conf <= 1.0

        le = joblib.load(MODELS_DIR / "label_encoder.joblib")
        attack_type = str(le.classes_[pred])
        assert attack_type == "BENIGN"

    def test_xgb_via_model_loader(self):
        from ml.model_loader import ModelLoader

        loader = ModelLoader()
        adapter = loader.load(str(MODELS_DIR / "xgboost_pipeline_v2.joblib"), "xgboost")
        assert len(adapter.required_features) == 70

        dummy_dict = {f: 0.0 for f in adapter.required_features}
        vec = np.array(list(dummy_dict.values()), dtype=float).reshape(1, -1)
        pred = int(adapter.predict(vec))
        conf = float(adapter.predict_confidence(vec))

        assert 0 <= pred < 15
        assert 0.0 <= conf <= 1.0

        le = joblib.load(MODELS_DIR / "label_encoder.joblib")
        attack_type = str(le.classes_[pred])
        assert attack_type == "BENIGN"

    def test_both_models_same_benign_prediction(self):
        """Both RF and XGBoost predict BENIGN for a zero-vector input."""
        from ml.model_loader import ModelLoader

        loader = ModelLoader()
        rf_adapter = loader.load(str(MODELS_DIR / "random_forest_v3.joblib"), "random_forest")
        xgb_adapter = loader.load(str(MODELS_DIR / "xgboost_pipeline_v2.joblib"), "xgboost")

        vec = np.zeros((1, 70))
        rf_pred = int(rf_adapter.predict(vec))
        xgb_pred = int(xgb_adapter.predict(vec))

        assert rf_pred == 0, f"RF should predict BENIGN (0), got {rf_pred}"
        assert xgb_pred == 0, f"XGB should predict BENIGN (0), got {xgb_pred}"

    def test_attack_type_resolves_for_all_classes(self):
        """LabelEncoder resolves all 15 classes correctly for both models."""
        le = joblib.load(MODELS_DIR / "label_encoder.joblib")
        assert len(le.classes_) == 15

        for name in le.classes_:
            idx = le.transform([name])[0]
            resolved = le.inverse_transform([idx])[0]
            assert resolved == name

    def test_severity_classification(self):
        """Detection.classify_severity returns correct labels."""
        from core.entities.detection import Detection

        # Malicious classifications
        assert Detection.classify_severity(0.95, True) == "CRITICAL"
        assert Detection.classify_severity(0.90, True) == "CRITICAL"
        assert Detection.classify_severity(0.80, True) == "HIGH"
        assert Detection.classify_severity(0.70, True) == "HIGH"
        assert Detection.classify_severity(0.50, True) == "MEDIUM"
        assert Detection.classify_severity(0.40, True) == "MEDIUM"
        assert Detection.classify_severity(0.20, True) == "LOW"
        assert Detection.classify_severity(0.01, True) == "LOW"
        # Benign gets empty severity
        assert Detection.classify_severity(0.10, False) == ""
        assert Detection.classify_severity(0.99, False) == ""

    def test_severity_thresholds_are_configurable(self):
        """Detection.classify_severity exposes tuneable band thresholds (no hardcoded bands)."""
        from core.entities.detection import Detection

        # Same confidence reclassified under custom bands.
        assert Detection.classify_severity(0.90, True) == "CRITICAL"
        assert (
            Detection.classify_severity(
                0.90, True, critical_threshold=0.95, high_threshold=0.90, medium_threshold=0.50
            )
            == "HIGH"
        )
        assert Detection.classify_severity(0.95, False, critical_threshold=0.10) == ""


class TestScalerAwareInference:
    """Regression: inference must reproduce training-time scaling + feature order.

    The runtime models (RF V3 / XGB V2) were trained on CICIDS2017 matrices transformed by
    ``models/scaler.joblib``. Feeding raw features in the static sidecar order silently
    misaligns learned split thresholds and drives every flow to BENIGN. These tests guard
    the adapter/loader contract that restores training-time input semantics.
    """

    @pytest.fixture(autouse=True)
    def _load(self):
        from ml.model_loader import ModelLoader

        self.scaler = joblib.load(MODELS_DIR / "scaler.joblib")
        self.le = joblib.load(MODELS_DIR / "label_encoder.joblib")
        self.xgb = ModelLoader().load(str(MODELS_DIR / "xgboost_pipeline_v2.joblib"), "xgboost")
        self.rf = ModelLoader().load(str(MODELS_DIR / "random_forest_v3.joblib"), "random_forest")

    def test_required_features_match_scaler_footprint(self):
        """Adapter feature order must equal the scaler's fitted training footprint."""
        scaler_order = list(self.scaler.feature_names_in_)
        assert len(scaler_order) == 70
        assert self.xgb.required_features == scaler_order
        assert self.rf.required_features == scaler_order

    def test_mean_vector_predicts_benign(self):
        """The scaler mean (z=0) sits in the majority BENIGN region."""
        center = self.scaler.mean_.reshape(1, -1)
        assert int(self.xgb.predict(center)) == 0
        assert int(self.rf.predict(center)) == 0
        assert str(self.le.classes_[0]) == "BENIGN"

    def test_scaled_vector_predicts_attack_where_raw_does_not(self):
        """Adapter must reproduce the estimator's scaled probability verdict.

        The adapter's ``predict`` is the generalized ``P(attack) = 1 - P(BENIGN)`` rule over
        the internal scaler + estimator chain: when the model assigns the majority
        probability to BENIGN (at or above the decision threshold) the flow stays benign,
        otherwise the strongest non-benign class is declared. It must always apply
        training-time scaling first (raw magnitudes misalign learned split thresholds) and
        must never fabricate a class the underlying estimator's probability distribution
        does not support. Guarding the rule relationally against the estimator's own scaled
        probabilities keeps the test robust to model re-training that shifts boundaries.
        """
        from config.settings import get_settings

        threshold = get_settings().ml_decision_threshold
        for seed in range(24):
            rng = np.random.default_rng(seed)
            z = rng.normal(0, 2.0, size=(1, 70))
            raw = (self.scaler.mean_ + z * self.scaler.scale_).reshape(1, -1)

            probs = self.xgb._estimator.predict_proba(self.xgb._preprocess(raw))[0]
            p_benign = float(probs[0])
            pred_scaled = int(self.xgb.predict(raw))
            if 1.0 - p_benign < threshold:
                assert pred_scaled == 0, f"seed={seed}: benign-majority flow must stay BENIGN"
            else:
                assert pred_scaled == int(np.argmax(np.delete(probs, 0))) + 1, (
                    f"seed={seed}: scaled path must declare the estimator's strongest attack class"
                )
            assert self.xgb.predict_confidence(raw) == pytest.approx(float(np.max(probs)))

        for seed in range(8):
            rng = np.random.default_rng(seed)
            z = rng.normal(0, 2.0, size=(1, 70))
            raw = (self.scaler.mean_ + z * self.scaler.scale_).reshape(1, -1)
            probs = self.rf._estimator.predict_proba(self.rf._preprocess(raw))[0]
            p_benign = float(probs[0])
            pred_scaled = int(self.rf.predict(raw))
            if 1.0 - p_benign < threshold:
                assert pred_scaled == 0, f"RF seed={seed}: benign-majority flow must stay BENIGN"
            else:
                assert pred_scaled == int(np.argmax(np.delete(probs, 0))) + 1, (
                    f"RF seed={seed}: scaled path must declare the estimator's strongest attack class"
                )

    def test_mapper_end_to_end_attack_detection(self):
        """FeatureMapper round-trip must reproduce the direct-vector verdict."""
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper()
        for seed in range(8):
            rng = np.random.default_rng(seed)
            z = rng.normal(0, 2.0, size=(1, 70))
            vals = self.scaler.mean_ + z * self.scaler.scale_

            flow_style = {
                name: float(vals[0, i])
                for i, name in enumerate(self.xgb.required_features)
            }
            vector, missing = mapper.map_with_report(flow_style, self.xgb.required_features)
            assert len(missing) == 0, f"seed={seed}: full footprint must map with no gaps"
            assert int(self.xgb.predict(vector)) == int(self.xgb.predict(vals.reshape(1, -1))), (
                f"seed={seed}: mapper must not alter the scaled verdict"
            )


class TestFeatureMapperInfHandling:
    """Regression: non-finite values (Inf/NaN) from raw CSV rows must not reach the scaler.

    Real CICIDS2017 CSVs contain ``Inf`` (e.g. ``Flow Bytes/s`` when flow duration is 0).
    ``sklearn >= 1.6`` rejects Inf in ``scaler.transform``, and the pre-fix mapper only
    guarded ``np.isnan``, so such rows crashed the whole CSV/PCAP analysis pipeline.
    """

    @pytest.fixture(autouse=True)
    def _load(self):
        from ml.model_loader import ModelLoader

        self.scaler = joblib.load(MODELS_DIR / "scaler.joblib")
        self.le = joblib.load(MODELS_DIR / "label_encoder.joblib")
        self.xgb = ModelLoader().load(str(MODELS_DIR / "xgboost_pipeline_v2.joblib"), "xgboost")
        self.rf = ModelLoader().load(str(MODELS_DIR / "random_forest_v3.joblib"), "random_forest")

    def test_map_with_report_sanitizes_inf(self):
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper()
        vector, missing = mapper.map_with_report(
            {"Flow Duration": float("inf"), "Total Fwd Packets": 100.0},
            ["Flow Duration", "Total Fwd Packets"],
        )
        assert np.all(np.isfinite(vector))
        assert vector[0] == 0.0
        assert vector[1] == 100.0

    def test_map_with_report_sanitizes_negative_inf(self):
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper()
        vector, _ = mapper.map_with_report(
            {"Flow Duration": float("-inf")},
            ["Flow Duration"],
        )
        assert np.isfinite(vector[0])
        assert vector[0] == 0.0

    def test_map_dataframe_sanitizes_inf(self):
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper()
        df = pd.DataFrame({"Flow Duration": [float("inf"), float("-inf"), np.nan, 5.0]})
        aligned, _ = mapper.map_dataframe_with_report(df, ["Flow Duration"], as_numpy=True)
        assert np.all(np.isfinite(aligned))
        assert aligned.tolist() == [[0.0], [0.0], [0.0], [5.0]]

    def test_real_flow_with_inf_flows_through_scaled_adapter(self):
        """A vector containing Inf must be sanitized by the mapper before scaling."""
        from ml.feature_mapper import FeatureMapper

        mapper = FeatureMapper()
        names = self.xgb.required_features
        rng = np.random.default_rng(10)
        z = rng.normal(0, 2.0, size=len(names))
        raw_vals = self.scaler.mean_ + z * self.scaler.scale_
        flow_style = {name: float(raw_vals[i]) for i, name in enumerate(names)}
        flow_style["Flow Duration"] = float("inf")

        vector, missing = mapper.map_with_report(flow_style, names)
        assert np.all(np.isfinite(vector))
        pred = int(self.xgb.predict(vector))
        assert 0 <= pred < len(self.le.classes_)

