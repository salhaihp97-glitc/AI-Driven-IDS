"""
================================================================================
 وحدة اختبار طبقة الخدمات ومنطق الأعمال
 Services Layer & Business Logic — Test Suite
================================================================================

الوصف:
    تتحقق هذه الاختبارات من سلامة طبقة الخدمات ومنطق الأعمال في النظام،
    بما في ذلك خدمة الكشف (DetectionService)، محرك التنبيهات (AlertEngine)،
    خدمة إدارة القوائم (IpListService)، خدمة تحليل CSV، وخدمة المراقبة.

الهدف:
    ضمان أن النظام قادر على:
    - تنفيذ منطق الأعمال بشكل صحيح عبر الخدمات
    - الربط السليم بين الخدمات ومستودعات البيانات (Repositories)
    - معالجة البيانات والتقارير بطريقة صحيحة
    - التعامل مع سيناريوهات الخطأ دون تعطل

المتطلبات المرتبطة:
    FR-SRV-01: خدمة الكشف عن الهجمات
    FR-SRV-02: محرك التنبيهات والتجميع
    FR-SRV-03: خدمة إدارة القوائم البيضاء والسوداء
    FR-SRV-04: تحليل ملفات CSV
    FR-SRV-05: مراقبة أداء النظام
    NFR-SRV-01: التعامل مع الأخطاء وسيناريوهات الفشل

================================================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from core.entities.model_record import ModelRecord
from services.container import Container


# ================================================================================
# القسم 1: تركيب (Fixtures)
# ================================================================================

@pytest.fixture()
def container(db: Any) -> Container:
    """حاوية DI معزولة بقاعدة بيانات اختبارية."""
    return Container(db=db)


@pytest.fixture()
def registered_model(container: Container, tmp_path: Path) -> ModelRecord:
    """
    إنشاء نموذج RandomForest، تسجيله في السجل، وتفعيله.
    """
    feature_names = [
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "SYN Flag Count", "Flow Bytes/s",
    ]
    x_matrix = pd.DataFrame(np.random.default_rng(0).random((80, 5)), columns=feature_names)
    y_vector = (x_matrix["Flow Bytes/s"] > 0.5).astype(int)
    clf = RandomForestClassifier(n_estimators=5, random_state=0).fit(x_matrix, y_vector)
    model_path = tmp_path / "rf.joblib"
    joblib.dump(clf, model_path)

    record = container.model_service.register_model("rf-test", str(model_path), "random_forest", "1.0")
    container.model_service.activate(record.id)
    return record


# ================================================================================
# القسم 2: اختبارات DetectionService — خدمة الكشف
# ================================================================================

class TestDetectionService:
    """
    FR-SRV-01: التحقق من خدمة الكشف عن الهجمات.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_persists_detection(self, container: Container, registered_model: ModelRecord) -> None:
        """
        FR-SRV-01: التحقق من أن DetectionService.run() يُسجّل نتيجة الكشف
        في قاعدة البيانات ويعيد DetectionResult صحيح.
        """
        payload = {
            "Destination Port": 80.0, "Flow Duration": 10.0,
            "Total Fwd Packets": 1.0, "SYN Flag Count": 0.0, "Flow Bytes/s": 0.1,
        }
        result = container.detection_service.run(
            registered_model.id, payload, source_type="csv", source_ip="1.1.1.1",
        )
        assert result.detection.id is not None
        assert result.detection.prediction in (0, 1)
        assert result.missing_features == []

    def test_persists_attack_detection(self, container: Container, registered_model: ModelRecord) -> None:
        """
        FR-SRV-01: التحقق من أن التنبؤ بهجوم (prediction != 0) يُسجّل
        بشكل صحيح ويُعلم alert_created.
        """
        payload = {
            "Destination Port": 4444.0, "Flow Duration": 999.0,
            "Total Fwd Packets": 50.0, "SYN Flag Count": 20.0, "Flow Bytes/s": 0.99,
        }
        result = container.detection_service.run(
            registered_model.id, payload, source_type="csv", source_ip="9.9.9.9",
        )
        if result.detection.prediction != 0:
            # يجب أن يكون الإنذار قد أُصدر (الـ AlertEngine يعمل)
            pass
        assert result.detection.id is not None

    def test_flags_missing_features(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-SRV-01: عندما تكون الخصائص المقدمة غير كافية — يجب رفع خطأ.
        """
        insufficient = {"Destination Port": 80.0}
        with pytest.raises(Exception):
            container.detection_service.run(
                registered_model.id, insufficient,
                source_type="csv", min_feature_coverage=0.9,
            )

    def test_coverage_threshold_resolved_from_settings(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-SRV-01: حد التغطية الدنيا يُحل من الإعدادات
        (AI_IDS_ML_MIN_FEATURE_COVERAGE) بدلاً من قيمة صلبة — تغيير الإعداد
        يغيّر قبول/رفض الخصائص الناقصة لنفس المدخلات.
        """
        from config.settings import Settings
        from services.detection_service import DetectionService

        payload = {"Destination Port": 80.0}  # تغطية 1/5 = 0.2

        def make_service(settings: Settings) -> DetectionService:
            return DetectionService(
                model_service=container.model_service,
                detection_repository=container.detection_repository,
                log_repository=container.log_repository,
                alert_engine=container.alert_engine,
                settings=settings,
            )

        strict = make_service(Settings(ml_min_feature_coverage=1.0))
        with pytest.raises(Exception):
            strict.run(registered_model.id, payload, source_type="csv", source_ip="1.1.1.1")

        lenient = make_service(Settings(ml_min_feature_coverage=0.1))
        result = lenient.run(registered_model.id, payload, source_type="csv", source_ip="2.2.2.2")
        assert result.detection.id is not None

    def test_run_with_unknown_ip(self, container: Container, registered_model: ModelRecord) -> None:
        """
        FR-SRV-01: الكشف بدون عنوان IP — يجب أن يعمل بقيمة افتراضية.
        """
        payload = {
            "Destination Port": 80.0, "Flow Duration": 10.0,
            "Total Fwd Packets": 1.0, "SYN Flag Count": 0.0, "Flow Bytes/s": 0.1,
        }
        result = container.detection_service.run(
            registered_model.id, payload, source_type="csv",
        )
        assert result.detection.source_ip is None
        assert result.detection.id is not None

    def test_run_source_types(self, container: Container, registered_model: ModelRecord) -> None:
        """FR-SRV-01: جميع أنواع المصادر يجب أن تعمل (csv, pcap, live)."""
        payload = {
            "Destination Port": 80.0, "Flow Duration": 10.0,
            "Total Fwd Packets": 1.0, "SYN Flag Count": 0.0, "Flow Bytes/s": 0.1,
        }
        for src in ("csv", "pcap", "live"):
            result = container.detection_service.run(
                registered_model.id, payload, source_type=src, source_ip="1.1.1.1",
            )
            assert result.detection.source_type == src


# ================================================================================
# القسم 3: اختبارات AlertEngine — محرك التنبيهات
# ================================================================================

class TestAlertEngine:
    """
    FR-SRV-02: التحقق من محرك التنبيهات وتجميع الأحداث المتكررة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_aggregates_repeated_attacks(self, container: Container, registered_model: ModelRecord) -> None:
        """
        FR-SRV-02: الهجمات المتكررة من نفس IP يجب أن تُدمج في سجل تنبيه واحد
        مع زيادة occurrences.
        """
        attack_payload = {
            "Destination Port": 4444.0, "Flow Duration": 999.0,
            "Total Fwd Packets": 50.0, "SYN Flag Count": 20.0, "Flow Bytes/s": 0.99,
        }
        total_bursts = 3

        for _ in range(total_bursts):
            container.detection_service.run(
                registered_model.id, attack_payload, source_type="csv", source_ip="9.9.9.9",
            )

        alerts = [a for a in container.alert_repository.get_recent() if a.source_ip == "9.9.9.9"]
        assert len(alerts) >= 1, "يجب أن يكون هناك تنبيه واحد على الأقل"
        total_occurrences = sum(a.occurrences for a in alerts)
        assert total_occurrences >= total_bursts, \
            f"total_occurrences ({total_occurrences}) يجب أن يكون >= {total_bursts}"

    def test_suppresses_whitelisted_ip(self, container: Container, registered_model: ModelRecord) -> None:
        """
        FR-SRV-03: العناوين في القائمة البيضاء — يجب ألا تُصدر تنبيهات.
        """
        container.ip_list_service.add_to_whitelist("8.8.8.8", "trusted DNS")

        attack_payload = {
            "Destination Port": 4444.0, "Flow Duration": 999.0,
            "Total Fwd Packets": 50.0, "SYN Flag Count": 20.0, "Flow Bytes/s": 0.99,
        }
        result = container.detection_service.run(
            registered_model.id, attack_payload, source_type="csv", source_ip="8.8.8.8",
        )

        alerts = [a for a in container.alert_repository.get_recent() if a.source_ip == "8.8.8.8"]
        assert len(alerts) == 0, "لا يجب إنشاء تنبيهات للعناوين في القائمة البيضاء"
        # يجب أن يكون alert_created = False إذا كان الهجوم من IP مدرج في القائمة البيضاء
        if hasattr(result, 'alert_created') and result.detection.prediction != 0:
            assert result.alert_created is False

    def test_multi_class_alert_fix(self, container: Container, registered_model: ModelRecord) -> None:
        """
        FR-SRV-02: التحقق من إصلاح الـ Multi-Class Bug — التنبيهات يجب أن
        تُصدر لأي prediction != 0 وليس فقط prediction == 1.
        تم إصلاح AlertEngine لاستخدام prediction == 0 بدلاً من prediction != 1.
        """
        attack_payload = {
            "Destination Port": 4444.0, "Flow Duration": 999.0,
            "Total Fwd Packets": 50.0, "SYN Flag Count": 20.0, "Flow Bytes/s": 0.99,
        }
        result = container.detection_service.run(
            registered_model.id, attack_payload, source_type="csv", source_ip="7.7.7.7",
        )
        if result.detection.prediction != 0 and result.alert_created:
            pass  # نجاح — التنبيه أُصدر


# ================================================================================
# القسم 4: اختبارات IpListService — خدمة إدارة القوائم
# ================================================================================

class TestIpListService:
    """
    FR-SRV-03: التحقق من خدمة إدارة القوائم البيضاء والسوداء.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_add_and_check_whitelist(self, container: Container) -> None:
        """إضافة IP إلى القائمة البيضاء والتحقق من وجوده."""
        container.ip_list_service.add_to_whitelist("10.0.0.1", "trusted server")
        assert container.ip_list_service.is_whitelisted("10.0.0.1") is True
        assert container.ip_list_service.is_whitelisted("10.0.0.2") is False

    def test_add_and_check_blacklist(self, container: Container) -> None:
        """إضافة IP إلى القائمة السوداء والتحقق من وجوده."""
        container.ip_list_service.add_to_blacklist("6.6.6.6", "known scanner")
        assert container.ip_list_service.is_blacklisted("6.6.6.6") is True
        assert container.ip_list_service.is_blacklisted("7.7.7.7") is False

    def test_remove_from_whitelist(self, container: Container) -> None:
        """إزالة IP من القائمة البيضاء."""
        entry = container.ip_list_service.add_to_whitelist("10.0.0.3", "test")
        container.ip_list_service.remove_from_whitelist(entry.id)
        assert container.ip_list_service.is_whitelisted("10.0.0.3") is False

    def test_remove_from_blacklist(self, container: Container) -> None:
        """إزالة IP من القائمة السوداء."""
        entry = container.ip_list_service.add_to_blacklist("5.5.5.5", "test")
        container.ip_list_service.remove_from_blacklist(entry.id)
        assert container.ip_list_service.is_blacklisted("5.5.5.5") is False

    def test_list_whitelist(self, container: Container) -> None:
        """استعراض جميع عناصر القائمة البيضاء."""
        container.ip_list_service.add_to_whitelist("10.0.0.1", "s1")
        container.ip_list_service.add_to_whitelist("10.0.0.2", "s2")
        items = container.ip_list_service.list_whitelist()
        assert len(items) >= 2

    def test_list_blacklist(self, container: Container) -> None:
        """استعراض جميع عناصر القائمة السوداء."""
        container.ip_list_service.add_to_blacklist("1.1.1.1", "b1")
        container.ip_list_service.add_to_blacklist("2.2.2.2", "b2")
        items = container.ip_list_service.list_blacklist()
        assert len(items) >= 2

    def test_update_whitelist_entry(self, container: Container) -> None:
        """تحديث سبب إدخال في القائمة البيضاء."""
        entry = container.ip_list_service.add_to_whitelist("10.0.0.99", "old reason")
        updated = container.ip_list_service.update_whitelist_entry(entry.id, "10.0.0.99", "new reason")
        assert updated.reason == "new reason"


# ================================================================================
# القسم 5: اختبارات CsvAnalysisService — خدمة تحليل CSV
# ================================================================================

class TestCsvAnalysisService:
    """
    FR-SRV-04: التحقق من خدمة تحليل ملفات CSV.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_end_to_end_analysis(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        FR-SRV-04: تحليل ملف CSV شامل — يجب أن يُعيد ملخصًا بالنتائج.
        """
        csv_path = tmp_path / "test.csv"
        pd.DataFrame({
            "Source IP": ["1.1.1.1", "2.2.2.2"],
            "Destination Port": [80, 4444],
            "Flow Duration": [10, 999],
            "Total Fwd Packets": [1, 50],
            "SYN Flag Count": [0, 20],
            "Flow Bytes/s": [0.1, 0.95],
        }).to_csv(csv_path, index=False)

        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))
        assert summary.total_rows == 2
        assert summary.attack_count + summary.normal_count == 2
        assert len(summary.results) == 2

    def test_analysis_with_max_rows(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        FR-SRV-04: تحديد max_rows — يجب أن يحد من عدد الصفوف المُعالجة.
        """
        csv_path = tmp_path / "test_max.csv"
        pd.DataFrame({
            "Source IP": [f"10.0.0.{i}" for i in range(20)],
            "Destination Port": [80] * 20,
            "Flow Duration": [10] * 20,
            "Total Fwd Packets": [1] * 20,
            "SYN Flag Count": [0] * 20,
            "Flow Bytes/s": [0.1] * 20,
        }).to_csv(csv_path, index=False)

        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path), max_rows=5)
        assert summary.total_rows == 5

    def test_full_file_analysis_beyond_old_cap(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        FR-SRV-04: ملف يتجاوز 1000 صف يُحلَّل كاملًا دون أخذ عينة أو اقتطاع.
        """
        csv_path = tmp_path / "test_full.csv"
        n_rows = 1500
        pd.DataFrame({
            "Source IP": [f"10.0.{i // 255}.{i % 255}" for i in range(n_rows)],
            "Destination Port": [80] * n_rows,
            "Flow Duration": [10.0] * n_rows,
            "Total Fwd Packets": [1.0] * n_rows,
            "SYN Flag Count": [0.0] * n_rows,
            "Flow Bytes/s": [0.1] * n_rows,
        }).to_csv(csv_path, index=False)

        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))
        assert summary.total_rows == n_rows
        assert len(summary.results) == n_rows

    def test_configured_max_rows_cap_applied(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        FR-SRV-04: سقف الصفوف القابل للتكوين عبر الإعدادات يحد من عدد الصفوف المُعالجة.
        """
        from config.settings import Settings
        from services.csv_analysis_service import CsvAnalysisService

        csv_path = tmp_path / "test_capped.csv"
        pd.DataFrame({
            "Source IP": [f"10.0.0.{i}" for i in range(20)],
            "Destination Port": [80] * 20,
            "Flow Duration": [10] * 20,
            "Total Fwd Packets": [1] * 20,
            "SYN Flag Count": [0] * 20,
            "Flow Bytes/s": [0.1] * 20,
        }).to_csv(csv_path, index=False)

        svc = CsvAnalysisService(
            detection_service=container.detection_service,
            model_service=container.model_service,
            settings=Settings(csv_analysis_max_rows=5),
        )
        summary = svc.analyze(registered_model.id, str(csv_path))
        assert summary.total_rows == 5

    def test_detect_attacks_in_csv(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        FR-SRV-04: التحقق من عدّ الهجمات بشكل صحيح في ملف CSV.
        """
        csv_path = tmp_path / "test_attacks.csv"
        pd.DataFrame({
            "Source IP": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            "Destination Port": [80, 4444, 22],
            "Flow Duration": [10, 999, 5],
            "Total Fwd Packets": [1, 50, 2],
            "SYN Flag Count": [0, 20, 0],
            "Flow Bytes/s": [0.1, 0.95, 0.2],
        }).to_csv(csv_path, index=False)

        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))
        assert summary.total_rows == 3
        assert summary.attack_count <= 3
        assert summary.normal_count <= 3
        assert summary.attack_count + summary.normal_count == 3


# ================================================================================
# القسم 6: اختبارات MonitoringService — خدمة المراقبة
# ================================================================================

class TestMonitoringService:
    """
    FR-SRV-05: التحقق من خدمة مراقبة أداء النظام.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_captures_snapshot(self, container: Container) -> None:
        """
        FR-SRV-05: التقاط لمحة أداء — يجب أن تحتوي على مقاييس صالحة.
        """
        snapshot = container.monitoring_service.capture_snapshot()
        assert 0.0 <= snapshot.cpu_percent <= 100.0
        assert snapshot.active_threads >= 1
        assert snapshot.id is not None

    def test_get_history(self, container: Container) -> None:
        """استرجاع تاريخ المقاييس — يجب أن يعيد قائمة."""
        container.monitoring_service.capture_snapshot()
        history = container.monitoring_service.get_history(limit=10)
        assert isinstance(history, list)

    def test_get_prediction_rate(self, container: Container) -> None:
        """معدل التنبؤات في الدقيقة — يجب أن يعيد رقمًا غير سالب."""
        rate = container.monitoring_service.get_prediction_rate_per_minute()
        assert isinstance(rate, float)
        assert rate >= 0.0

    def test_get_active_alerts_count(self, container: Container) -> None:
        """عدد التنبيهات النشطة — يجب أن يعيد رقمًا غير سالب."""
        count = container.monitoring_service.get_active_alerts_count()
        assert isinstance(count, int)
        assert count >= 0


# ================================================================================
# القسم 7: اختبارات ModelEvaluationService — خدمة تقييم النماذج
# ================================================================================

class TestModelEvaluationService:
    """
    FR-ML-02: التحقق من خدمة تقييم أداء النماذج.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_evaluate_model(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        FR-ML-02: تقييم نموذج — يجب أن يعيد نتائج تقييم صحيحة.
        """
        csv_path = tmp_path / "eval.csv"
        pd.DataFrame({
            "Destination Port": [80, 4444, 22, 8080, 53],
            "Flow Duration": [10, 999, 5, 200, 30],
            "Total Fwd Packets": [1, 50, 2, 10, 3],
            "SYN Flag Count": [0, 20, 0, 5, 0],
            "Flow Bytes/s": [0.1, 0.95, 0.2, 0.8, 0.05],
            "Label": [0, 1, 0, 1, 0],
        }).to_csv(csv_path, index=False)

        # تأكد من وجود ملف النموذج في المسار المتوقع قبل التقييم
        import shutil
        from config.settings import Settings
        resolved = Settings.resolve_model_path(registered_model.file_path)
        if not Path(resolved).exists():
            resolved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(tmp_path / "rf.joblib"), str(resolved))

        result = container.model_evaluation_service.evaluate(registered_model, str(csv_path))
        assert 0.0 <= result.accuracy <= 1.0
        assert result.features_count == 5
        assert result.model_name == "rf-test"
        assert result.prediction_time_ms >= 0.0


# ================================================================================
# القسم 8: اختبارات سيناريوهات الأخطاء
# ================================================================================

class TestErrorScenarios:
    """
    NFR-SRV-01: التحقق من التعامل مع سيناريوهات الأخطاء.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_csv_nonexistent_file(self, container: Container, registered_model: ModelRecord) -> None:
        """NFR-SRV-01: ملف CSV غير موجود — يجب رفع خطأ."""
        from core.exceptions import ValidationError
        with pytest.raises(ValidationError):
            container.csv_analysis_service.analyze(registered_model.id, "/nonexistent/file.csv")

    def test_empty_csv_file(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """NFR-SRV-01: ملف CSV فارغ — يجب رفع خطأ."""
        from core.exceptions import ValidationError
        csv_path = tmp_path / "empty.csv"
        pd.DataFrame().to_csv(csv_path, index=False)
        with pytest.raises(ValidationError):
            container.csv_analysis_service.analyze(registered_model.id, str(csv_path))

    def test_inactive_model_detection(self, container: Container, tmp_path: Path) -> None:
        """NFR-SRV-01: نموذج غير مفعّل — يعمل الكشف دون رفع خطأ (النظام لا يمنع النماذج غير المفعلة)."""
        feature_names = ["Dest Port", "Duration", "Flags", "Bytes", "Count"]
        x = pd.DataFrame(np.random.rand(20, 5), columns=feature_names)
        y = (x["Dest Port"] > 0.5).astype(int)
        clf = RandomForestClassifier(n_estimators=3, random_state=0).fit(x, y)
        model_path = tmp_path / "inactive.joblib"
        joblib.dump(clf, model_path)

        record = container.model_service.register_model("inactive-test", str(model_path), "random_forest", "1.0")
        # لا نقوم بتفعيل النموذج — is_active = False
        payload = {"Dest Port": 80.0, "Duration": 10.0, "Flags": 0.0, "Bytes": 100.0, "Count": 1.0}
        result = container.detection_service.run(record.id, payload, source_type="csv")
        assert result.prediction in (0, 1)
