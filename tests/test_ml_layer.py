"""
================================================================================
 وحدة اختبار طبقة التعلم الآلي
 Machine Learning Layer — Test Suite
================================================================================

الوصف:
    تتحقق هذه الاختبارات من سلامة مكونات التعلم الآلي في النظام، بما في ذلك
    تحميل النماذج، التنبؤ، تشفير التصنيفات (LabelEncoder)، مقياس Scaler،
    وراسم الخصائص (FeatureMapper) وآلية Sidecar.

الهدف:
    ضمان أن النظام قادر على:
    - تحميل نماذج RandomForest و XGBoost من ملفات joblib
    - تنفيذ التنبؤات وحساب درجات الثقة
    - فك تشفير تسميات الهجمات عبر LabelEncoder
    - التعامل الآمن مع البيانات غير الصالحة أو المفقودة

المتطلبات المرتبطة:
    FR-ML-01: تحميل نماذج التعلم الآلي
    FR-ML-02: تنفيذ التنبؤات وحساب الثقة
    FR-ML-03: تشفير وفك تشفير تسميات الهجمات
    NFR-ML-01: التعامل مع البيانات غير الصالحة دون تعطل

================================================================================
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

from core.exceptions import ConfigurationError, ValidationError
from ml.feature_mapper import FeatureMapper
from ml.feature_schema import FeatureSchema, resolve_feature_schema, write_sidecar
from ml.model_adapter import SklearnCompatibleModelAdapter
from ml.model_loader import ModelLoader


# ================================================================================
# القسم 1: تركيب (Fixtures) مشتركة
# ================================================================================

@pytest.fixture()
def rf_model_with_names(tmp_path: Path) -> Path:
    """نموذج RandomForest بأسماء خصائص واضحة — يستخدم DataFrame مع column names."""
    feature_names = [
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "SYN Flag Count", "Flow Bytes/s",
    ]
    x_matrix = pd.DataFrame(np.random.rand(60, 5), columns=feature_names)
    y_vector = (x_matrix["Flow Bytes/s"] > 0.5).astype(int)
    clf = RandomForestClassifier(n_estimators=5, random_state=0).fit(x_matrix, y_vector)
    path = tmp_path / "rf_named.joblib"
    joblib.dump(clf, path)
    return path


@pytest.fixture()
def rf_model_without_names(tmp_path: Path) -> Path:
    """نموذج RandomForest بدون أسماء خصائص — يستخدم ndarray."""
    x_matrix = np.random.rand(60, 4)
    y_vector = (x_matrix[:, 0] > 0.5).astype(int)
    clf = RandomForestClassifier(n_estimators=5, random_state=0).fit(x_matrix, y_vector)
    path = tmp_path / "rf_unnamed.joblib"
    joblib.dump(clf, path)
    return path


@pytest.fixture()
def sample_label_encoder(tmp_path: Path) -> Path:
    """مشفّر تسميات (LabelEncoder) وهمي بحجوم فعلية."""
    encoder = LabelEncoder()
    encoder.fit(["BENIGN", "Bot", "DDoS", "PortScan", "Heartbleed"])
    path = tmp_path / "label_encoder.joblib"
    joblib.dump(encoder, path)
    return path


@pytest.fixture()
def sample_scaler(tmp_path: Path) -> Path:
    """StandardScaler وهمي."""
    scaler = StandardScaler()
    scaler.fit(np.random.rand(100, 5))
    path = tmp_path / "scaler.joblib"
    joblib.dump(scaler, path)
    return path


# ================================================================================
# القسم 2: اختبارات ModelLoader — تحميل النماذج
# ================================================================================

class TestModelLoader:
    """
    FR-ML-01: التحقق من تحميل النماذج من ملفات joblib.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_load_rf_with_names(self, rf_model_with_names: Path) -> None:
        """FR-ML-01: تحميل نموذج RandomForest مع أسماء خصائص — يجب استخراج feature names."""
        adapter = ModelLoader().load(str(rf_model_with_names), "random_forest")
        assert adapter.required_features == [
            "Destination Port", "Flow Duration", "Total Fwd Packets",
            "SYN Flag Count", "Flow Bytes/s",
        ]

    def test_load_rf_predict_and_confidence(self, rf_model_with_names: Path) -> None:
        """
        FR-ML-02: التحقق من أن adapter.predict و adapter.predict_confidence
        يعيدان قيمًا صالحة.
        """
        adapter = ModelLoader().load(str(rf_model_with_names), "random_forest")
        vector = np.array([80, 100, 2, 0, 0.3])
        prediction = adapter.predict(vector)
        confidence = adapter.predict_confidence(vector)
        assert prediction in (0, 1)
        assert 0.0 <= confidence <= 1.0

    def test_load_predict_batch(self, rf_model_with_names: Path) -> None:
        """FR-ML-02: التنبؤ على مجموعة من المتجهات (batch prediction)."""
        adapter = ModelLoader().load(str(rf_model_with_names), "random_forest")
        batch = np.array([
            [80, 100, 2, 0, 0.3],
            [443, 50, 5, 1, 0.8],
            [22, 200, 1, 0, 0.1],
        ])
        predictions = [adapter.predict(row) for row in batch]
        assert len(predictions) == 3
        for p in predictions:
            assert p in (0, 1)

    def test_raises_without_feature_names(self, rf_model_without_names: Path) -> None:
        """
        NFR-ML-01: نموذج بدون أسماء خصائص — يجب رفع ConfigurationError
        لعدم توفر sidecar.
        """
        with pytest.raises(ConfigurationError):
            ModelLoader().load(str(rf_model_without_names), "random_forest")

    def test_missing_file_raises(self) -> None:
        """NFR-ML-01: ملف غير موجود — يجب رفع ConfigurationError."""
        with pytest.raises(ConfigurationError):
            ModelLoader().load("/nonexistent/path/model.joblib")

    def test_unsupported_extension_raises(self, tmp_path: Path) -> None:
        """NFR-ML-01: امتداد غير مدعوم — يجب رفضه."""
        bad = tmp_path / "model.txt"
        bad.write_text("not a model")
        with pytest.raises(ConfigurationError):
            ModelLoader().load(str(bad))

    def test_sidecar_metadata_unblocks_unnamed_model(self, rf_model_without_names: Path) -> None:
        """
        FR-ML-01: وجود ملف sidecar .meta.json يجب أن يسمح بتحميل
        النموذج حتى بدون feature names داخل النموذج.
        """
        expected = ["a", "b", "c", "d"]
        write_sidecar(rf_model_without_names, expected, "random_forest")
        adapter = ModelLoader().load(str(rf_model_without_names), "random_forest")
        assert adapter.required_features == expected

    def test_load_dict_wrapped_model(self, tmp_path: Path) -> None:
        """
        FR-ML-01: تحميل نموذج مغلّف داخل dict (مثل pipeline مع ميتاداتا).
        """
        feature_names = ["Dest Port", "Duration", "Flags"]
        x = pd.DataFrame(np.random.rand(30, 3), columns=feature_names)
        y = (x["Dest Port"] > 0.5).astype(int)
        clf = RandomForestClassifier(n_estimators=3, random_state=0).fit(x, y)
        wrapped = {"pipeline": clf, "model_type": "random_forest", "version": "2.0"}
        path = tmp_path / "wrapped.joblib"
        joblib.dump(wrapped, path)
        adapter = ModelLoader().load(str(path), "random_forest")
        assert len(adapter.required_features) == 3

    def test_sklearn_adapter_applies_configurable_decision_threshold(self) -> None:
        """
        NFR-ML-03: عتبة القرار الافتراضية (0.5) قابلة للتكوين — عند رفعها لا
        تُصنَّف العينة ذات الاحتمال المنخفض كحالة هجوم، بدون أي تصلب (hardcode).
        """
        class DummyProbaModel:
            # احتمال الهجوم (الفئة 1) ثابت عند 0.6
            def predict_proba(self, X):
                return np.array([[0.4, 0.6]])

            def predict(self, X):
                return np.array([1])

        schema = FeatureSchema(feature_names=["A", "B"], model_type="random_forest")
        vector = np.array([1.0, 2.0])

        default_adapter = SklearnCompatibleModelAdapter(DummyProbaModel(), schema)
        strict_adapter = SklearnCompatibleModelAdapter(DummyProbaModel(), schema, decision_threshold=0.9)

        # العتبة الافتراضية 0.5 < 0.6 → يُصنّف كهجوم
        assert default_adapter.predict(vector) == 1
        # العتبة المرتفعة 0.9 > 0.6 → لا يُصنّف كهجوم
        assert strict_adapter.predict(vector) == 0

    def test_sklearn_adapter_multiclass_threshold_is_real(self) -> None:
        """
        NFR-ML-03: على النماذج متعددة الفئات (15 فئة CICIDS2017) تعمل عتبة القرار
        فعليًا كبوابة على P(attack)=1-P(BENIGN): عند 0.5 مطابقة لـ argmax، وعند رفعها
        تُنزَّل العينات قليلة الثقة إلى BENIGN.
        """
        class PAttack060:
            # argmax هو فئة الهجوم 1 باحتمال 0.60 (P_attack = 1 - 0.40 = 0.60)
            def predict_proba(self, X):
                return np.array([[0.40, 0.60]])

            def predict(self, X):
                return np.array([1])

        class PAttack045:
            # BENIGN 0.55 هو الأرجح (argmax)، وP_attack = 1 - 0.55 = 0.45 < 0.5
            def predict_proba(self, X):
                return np.array([[0.55, 0.10, 0.35]])

            def predict(self, X):
                return np.array([2])

        class PAttack085:
            # argmax هو فئة الهجوم 3 باحتمال 0.85 (P_attack = 0.90)
            def predict_proba(self, X):
                return np.array([[0.10, 0.05, 0.05, 0.80]])

            def predict(self, X):
                return np.array([3])

        schema = FeatureSchema(feature_names=["A", "B"], model_type="random_forest")
        vector = np.array([1.0, 2.0])

        # P_attack 0.45 < عتبة 0.5 → تُنزل إلى الفئة الحميدة (0)
        low = SklearnCompatibleModelAdapter(PAttack045(), schema, decision_threshold=0.5)
        assert low.predict(vector) == 0

        # P_attack 0.60 >= 0.5 → تُعلن أقوى فئة هجوم (1)
        std = SklearnCompatibleModelAdapter(PAttack060(), schema, decision_threshold=0.5)
        assert std.predict(vector) == 1

        # P_attack 0.90 >= 0.5 → تُعلن فئة الهجوم القصوى (3)
        high = SklearnCompatibleModelAdapter(PAttack085(), schema, decision_threshold=0.5)
        assert high.predict(vector) == 3

        # عتبة مرتفعة 0.95 > P_attack 0.90 → تنزيل إلى BENIGN رغم أن predict() يرجّع 3
        strict = SklearnCompatibleModelAdapter(PAttack085(), schema, decision_threshold=0.95)
        assert strict.predict(vector) == 0


# ================================================================================
# القسم 3: اختبارات FeatureMapper — راسم الخصائص
# ================================================================================

class TestFeatureMapper:
    """
    FR-ML-02: التحقق من تعيين الخصائص (Feature Mapping) ومعالجة البيانات المفقودة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_case_and_separator_insensitive(self) -> None:
        """FR-ML-02: تعيين الخصائص يجب أن يكون غير حساس لحالة الأحرف وفواصل الأسماء."""
        mapper = FeatureMapper()
        available = {"flow_duration": 100.0, "SYN Flag Count": 1.0, "destination-port": 80.0}
        required = ["Destination Port", "Flow Duration", "SYN Flag Count"]
        vector = mapper.map(available, required)
        assert list(vector) == [80.0, 100.0, 1.0]

    def test_reports_missing_features(self) -> None:
        """FR-ML-02: الخصائص المفقودة يجب أن تُبلغ وتُملأ بصفر."""
        mapper = FeatureMapper()
        available = {"Flow Duration": 50.0}
        required = ["Flow Duration", "Missing A", "Missing B"]
        vector, missing = mapper.map_with_report(available, required)
        assert missing == ["Missing A", "Missing B"]
        assert vector[0] == 50.0
        assert vector[1] == 0.0
        assert vector[2] == 0.0

    def test_minimum_coverage_raises(self) -> None:
        """
        NFR-ML-01: إذا قلت نسبة التغطية عن الحد الأدنى — يجب رفع ValidationError.
        """
        mapper = FeatureMapper()
        available = {"Flow Duration": 50.0}
        required = ["Flow Duration", "A", "B", "C", "D"]
        with pytest.raises(ValidationError):
            mapper.validate_minimum_coverage(available, required, min_coverage=0.6)

    def test_minimum_coverage_passes(self) -> None:
        """FR-ML-02: نسبة تغطية كافية — يجب أن تمر بدون خطأ."""
        mapper = FeatureMapper()
        available = {"Flow Duration": 50.0, "A": 1.0, "B": 2.0, "C": 3.0}
        required = ["Flow Duration", "A", "B", "C", "D"]
        mapper.validate_minimum_coverage(available, required, min_coverage=0.6)

    def test_map_with_no_missing_features(self) -> None:
        """جميع الخصائص موجودة — missing_features يجب أن يكون قائمة فارغة."""
        mapper = FeatureMapper()
        available = {"A": 1.0, "B": 2.0, "C": 3.0}
        required = ["A", "B", "C"]
        vector, missing = mapper.map_with_report(available, required)
        assert missing == []
        assert list(vector) == [1.0, 2.0, 3.0]

    def test_map_empty_available(self) -> None:
        """FR-ML-02: بيانات فارغة — جميع الخصائص مفقودة."""
        mapper = FeatureMapper()
        required = ["A", "B"]
        vector, missing = mapper.map_with_report({}, required)
        assert missing == ["A", "B"]
        assert list(vector) == [0.0, 0.0]

    def test_validate_100_percent_coverage(self) -> None:
        """تغطية 100% — يجب أن تمر بدون خطأ."""
        mapper = FeatureMapper()
        available = {"A": 1.0, "B": 2.0}
        required = ["A", "B"]
        mapper.validate_minimum_coverage(available, required, min_coverage=1.0)

    def test_validate_zero_percent_coverage(self) -> None:
        """تغطية 0% — يجب أن ترفع خطأ عند أي min_coverage > 0."""
        mapper = FeatureMapper()
        with pytest.raises(ValidationError):
            mapper.validate_minimum_coverage({}, ["A", "B"], min_coverage=0.1)

    def test_dynamic_snake_case_expansion_maps_cicflowmeter_columns(self) -> None:
        """
        FR-ML-02: توجيه البرمجة — أسماء أعمدة CICFlowMeter بصيغة snake_case
        (الاختصارات) يجب أن تُعيّن ديناميكيًا إلى أسماء النماذج الأكاديمية بدون
        تصفير (zero-fill) للحقول الصحيحة.
        """
        mapper = FeatureMapper()
        available = {
            "Flow Duration": 12000.0,
            "Tot Fwd Pkts": 10.0,
            "Fwd Pkt Len Max": 1400.0,
            "Fwd Pkt Len Mean": 400.0,
            "Fwd Seg Size Avg": 512.0,
            "Bwd Seg Size Avg": 256.0,
            "Tot Len Fwd Pkts": 14000.0,
            "Flow Byts/s": 5000.0,
            "Flow Pkts/s": 100.0,
            "SYN Flag Count": 3.0,
        }
        required = [
            "Total Fwd Packets",
            "Fwd Packet Length Max",
            "Fwd Packet Length Mean",
            "Avg Fwd Segment Size",
            "Avg Bwd Segment Size",
            "Total Length of Fwd Packets",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
        ]
        vector, missing = mapper.map_with_report(available, required)
        assert missing == []
        expected = [10.0, 1400.0, 400.0, 512.0, 256.0, 14000.0, 5000.0, 100.0, 3.0]
        for got, want in zip(vector, expected):
            assert got == want, f"expected {want} but got {got}"

    def test_dynamic_expansion_prevents_zero_fill_for_unlisted_alias(self) -> None:
        """
        FR-ML-02: اختصار snake_case غير مُدرج في جدول _aliases الثابت يجب أن
        يُعيّن عبر طبقة التوسع البرمجية بدلاً من التصفير الصامت.
        """
        mapper = FeatureMapper()
        available = {"Fwd Seg Size Avg": 1024.0}
        required = ["Avg Fwd Segment Size"]
        vector, missing = mapper.map_with_report(available, required)
        assert missing == []
        assert vector[0] == 1024.0

    def test_dynamic_expansion_dataframe_no_missing(self) -> None:
        """
        FR-ML-02: نفس الضمان لمُعيّن DataFrame — لا يجب أن تظهر أعمدة snake_case
        صحيحة كمفقودة ولا أن تُصفّر قيمها.
        """
        import pandas as pd

        mapper = FeatureMapper()
        df = pd.DataFrame(
            [{"flow_duration": 100.0, "tot_fwd_pkts": 7.0, "flow_byts_s": 3000.0}]
        )
        required = ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s"]
        result, missing = mapper.map_dataframe_with_report(df, required)
        assert missing == []
        row = result.iloc[0]
        assert row["Flow Duration"] == 100.0
        assert row["Total Fwd Packets"] == 7.0
        assert row["Flow Bytes/s"] == 3000.0


# ================================================================================
# القسم 4: اختبارات FeatureSchema و Sidecar
# ================================================================================

class TestFeatureSchemaAndSidecar:
    """
    FR-ML-01: التحقق من كتابة وقراءة FeatureSchema و Sidecar.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_write_sidecar_creates_json(self, tmp_path: Path) -> None:
        """write_sidecar يجب أن ينشئ ملف JSON بالمحتوى الصحيح."""
        model_path = tmp_path / "model.joblib"
        model_path.write_text("dummy")
        sidecar_path = write_sidecar(model_path, ["a", "b", "c"], "random_forest", version="2.0")
        assert sidecar_path.exists()
        with open(sidecar_path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["feature_names"] == ["a", "b", "c"]
        assert data["model_type"] == "random_forest"
        assert data["version"] == "2.0"

    def test_resolve_from_estimator_attribute(self, tmp_path: Path) -> None:
        """resolve_feature_schema يجب أن يقرأ feature_names_in_ من متعلم sklearn."""
        feature_names = ["X1", "X2", "X3"]
        x = pd.DataFrame(np.random.rand(20, 3), columns=feature_names)
        y = (x["X1"] > 0.5).astype(int)
        clf = RandomForestClassifier(n_estimators=3, random_state=0).fit(x, y)
        path = tmp_path / "sk_model.joblib"
        joblib.dump(clf, path)
        schema = resolve_feature_schema(path, clf, "random_forest")
        assert schema.feature_names == feature_names
        assert schema.model_type == "random_forest"
        assert schema.count == 3

    def test_resolve_from_dict_wrapper(self, tmp_path: Path) -> None:
        """resolve_feature_schema يجب أن يقرأ feature_names من dict."""
        loaded = {"feature_names": ["a", "b"], "model_type": "xgboost"}
        path = tmp_path / "dict_model.joblib"
        joblib.dump({}, path)
        schema = resolve_feature_schema(path, loaded, "xgboost")
        assert schema.feature_names == ["a", "b"]
        assert schema.count == 2

    def test_resolve_from_sidecar(self, tmp_path: Path) -> None:
        """resolve_feature_schema يجب أن يقرأ من sidecar كحل أخير."""
        model_path = tmp_path / "fallback.joblib"
        model_path.write_text("dummy")
        write_sidecar(model_path, ["alpha", "beta"], "random_forest", "1.5")
        loaded = np.array([1, 2, 3])
        schema = resolve_feature_schema(model_path, loaded, "random_forest")
        assert schema.feature_names == ["alpha", "beta"]
        assert schema.version == "1.5"

    def test_resolve_all_fail_raises(self, tmp_path: Path) -> None:
        """
        NFR-ML-01: عندما تفشل جميع طرق استخراج feature names —
        يجب رفع ConfigurationError.
        """
        model_path = tmp_path / "bad.joblib"
        model_path.write_text("dummy")
        loaded = 42  # int has no feature_names_in_
        with pytest.raises(ConfigurationError):
            resolve_feature_schema(model_path, loaded, "random_forest")

    def test_feature_schema_count_property(self) -> None:
        """FeatureSchema.count يجب أن يعيد طول feature_names."""
        schema = FeatureSchema(feature_names=["a", "b", "c"], model_type="rf")
        assert schema.count == 3


# ================================================================================
# القسم 5: اختبارات LabelEncoder
# ================================================================================

class TestLabelEncoder:
    """
    FR-ML-03: التحقق من تشفير وفك تشفير تسميات الهجمات.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_load_label_encoder(self, sample_label_encoder: Path) -> None:
        """FR-ML-03: تحميل LabelEncoder من ملف joblib — يجب أن يعمل بدون خطأ."""
        encoder = joblib.load(sample_label_encoder)
        assert isinstance(encoder, LabelEncoder)
        assert len(encoder.classes_) == 5

    def test_label_encoder_classes(self, sample_label_encoder: Path) -> None:
        """FR-ML-03: التحقق من قائمة التصنيفات في LabelEncoder."""
        encoder = joblib.load(sample_label_encoder)
        # LabelEncoder.fit() sorts classes alphabetically
        assert list(encoder.classes_) == ["BENIGN", "Bot", "DDoS", "Heartbleed", "PortScan"]

    def test_label_encoder_transform_and_inverse(self) -> None:
        """
        FR-ML-03: تحويل التسميات إلى أرقام والعكس — يجب أن يكون متسقًا.
        """
        encoder = LabelEncoder()
        encoder.fit(["BENIGN", "Bot", "DDoS", "PortScan", "Heartbleed"])
        assert encoder.transform(["BENIGN"])[0] == 0
        assert encoder.transform(["DDoS"])[0] == 2
        # LabelEncoder sorts alphabetically: Heartbleed=3, PortScan=4
        assert encoder.inverse_transform([3])[0] == "Heartbleed"
        assert encoder.inverse_transform([4])[0] == "PortScan"

    def test_label_encoder_multiclass_support(self) -> None:
        """
        FR-ML-03: التحقق من أن التصنيف متعدد الفئات (15 فئة) يعمل بشكل صحيح.
        هذا يضمن عدم افتراض أن النموذج ثنائي التصنيف فقط (0/1).
        """
        attack_types = [
            "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk",
            "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed",
            "Infiltration", "PortScan", "SSH-Patator",
            "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS",
        ]
        encoder = LabelEncoder()
        encoder.fit(attack_types)
        assert len(encoder.classes_) == 15
        assert encoder.transform(["DDoS"])[0] == 2
        assert encoder.transform(["Heartbleed"])[0] == 8
        assert encoder.transform(["PortScan"])[0] == 10
        # BENIGN يجب أن يكون دائمًا الفئة 0
        assert encoder.transform(["BENIGN"])[0] == 0


# ================================================================================
# القسم 6: اختبارات Scaler
# ================================================================================

class TestScaler:
    """
    FR-ML-01: التحقق من تحميل وتطبيق StandardScaler.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_load_scaler(self, sample_scaler: Path) -> None:
        """تحميل StandardScaler من ملف joblib — يجب أن يعمل."""
        scaler = joblib.load(sample_scaler)
        assert isinstance(scaler, StandardScaler)

    def test_scaler_transform(self, sample_scaler: Path) -> None:
        """تطبيق StandardScaler على متجه — يجب أن يُعيد قياسها (scale)."""
        scaler = joblib.load(sample_scaler)
        data = np.array([[80, 100, 2, 0, 0.3]])
        transformed = scaler.transform(data)
        assert transformed.shape == (1, 5)
        assert isinstance(transformed, np.ndarray)

    def test_scaler_inverse_transform(self, sample_scaler: Path) -> None:
        """FR-ML-01: inverse_transform يجب أن يعيد البيانات إلى مقياسها الأصلي."""
        scaler = joblib.load(sample_scaler)
        original = np.array([[80.0, 100.0, 2.0, 0.0, 0.3]])
        transformed = scaler.transform(original)
        recovered = scaler.inverse_transform(transformed)
        np.testing.assert_array_almost_equal(original, recovered, decimal=10)


# ================================================================================
# القسم 7: اختبارات البيانات غير الصالحة
# ================================================================================

class TestInvalidData:
    """
    NFR-ML-01: التحقق من التعامل الآمن مع البيانات غير الصالحة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_nan_values_in_features(self) -> None:
        """القيم NaN في الخصائص — يجب تعبئتها بصفر."""
        mapper = FeatureMapper()
        available = {"A": float("nan"), "B": 5.0}
        required = ["A", "B"]
        vector = mapper.map(available, required)
        assert vector[0] == 0.0
        assert vector[1] == 5.0

    def test_none_values_in_features(self) -> None:
        """القيم None في الخصائص — يجب معالجتها بدون خطأ."""
        mapper = FeatureMapper()
        available = {"A": None, "B": 5.0}
        required = ["A", "B"]
        vector = mapper.map(available, required)
        assert vector[0] == 0.0

    def test_predict_with_empty_vector(self, rf_model_with_names: Path) -> None:
        """
        NFR-ML-01: التنبؤ بمتجه فارغ الطول — يعتمد على النموذج ولكن يجب
        ألا يسبب تعطل النظام.
        """
        adapter = ModelLoader().load(str(rf_model_with_names), "random_forest")
        with pytest.raises(Exception):
            adapter.predict(np.array([]))

    def test_validate_coverage_empty_required(self) -> None:
        """قائمة خصائص مطلوبة فارغة — تغطية 100%."""
        mapper = FeatureMapper()
        mapper.validate_minimum_coverage({}, [], min_coverage=0.5)  # should pass
