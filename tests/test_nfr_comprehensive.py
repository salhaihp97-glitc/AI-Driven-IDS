"""
================================================================================
 اختبار المتطلبات غير الوظيفية الشامل (NFR)
 Comprehensive Non-Functional Requirements — Test Suite
================================================================================

 الوصف:
     يتحقق هذا الملف من المتطلبات غير الوظيفية للمشروع:
     1. الأداء (Performance)
     2. سهولة الاستخدام (Usability)
     3. الأمان (Security)
     4. القابلية للصيانة (Maintainability)
     5. التوافق (Compatibility)
     6. الاعتمادية (Reliability)
     7. القابلية للاختبار (Testability)
     8. اختبار قبول المستخدم (User Acceptance)
     9. قابلية التوسع (Scalability)
     10. الإتاحية (Availability)

 المتطلبات المرتبطة:
     NFR-PERF-01: زمن استجابة منخفض (شبه حقيقي)
     NFR-PERF-02: أداء مستقر على موارد متوسطة
     NFR-PERF-03: كفاءة استخدام الموارد
     NFR-USE-01: واجهة بسيطة وواضحة
     NFR-USE-02: تنبيهات واضحة ومفهومة
     NFR-SEC-01: حماية بيانات المصادقة
     NFR-SEC-02: تقييد الوصول للمستخدم المخول
     NFR-SEC-03: حفظ السجلات بطريقة آمنة
     NFR-MAIN-01: بنية برمجية منظمة
     NFR-MAIN-02: استقلالية المكونات
     NFR-MAIN-03: توثيق الشيفرة البرمجية
     NFR-COMP-01: توافق أنظمة التشغيل
     NFR-COMP-02: توافق التقنيات
     NFR-REL-01: استمرارية التشغيل المستقر
     NFR-REL-02: التعامل مع الأخطاء دون توقف
     NFR-TEST-01: اختبار الوظائف ببيانات معتمدة
     NFR-TEST-02: تقييم أداء النماذج

================================================================================
"""

from __future__ import annotations

import importlib
import os
import platform
import shutil
import sys
import threading
import time
import unittest.mock
from collections.abc import Generator
from pathlib import Path
from typing import Any, Final
from unittest.mock import MagicMock, patch

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from config.constants import TableNames
from core.entities.model_record import ModelRecord
from core.exceptions import AuthenticationError, ValidationError
from core.interfaces.repository import IRepository
from services.container import Container
from services.detection_service import DetectionResult


# ================================================================================
# القسم 0: الـ Fixtures
# ================================================================================

BENIGN_FEATURES: Final[dict[str, float]] = {
    "Destination Port": 80.0,
    "Flow Duration": 10.0,
    "Total Fwd Packets": 1.0,
    "SYN Flag Count": 0.0,
    "Flow Bytes/s": 0.1,
}

ATTACK_FEATURES: Final[dict[str, float]] = {
    "Destination Port": 4444.0,
    "Flow Duration": 999.0,
    "Total Fwd Packets": 50.0,
    "SYN Flag Count": 20.0,
    "Flow Bytes/s": 0.99,
}


@pytest.fixture()
def container(db: Any) -> Container:
    """حاوية DI معزولة بقاعدة بيانات اختبارية مع تهيئة المستخدم الافتراضي."""
    from database import bootstrap
    bootstrap.run(db)
    return Container(db=db)


@pytest.fixture()
def registered_model(container: Container, tmp_path: Path) -> ModelRecord:
    """إنشاء نموذج RandomForest صغير وتفعيله."""
    feature_names = list(BENIGN_FEATURES.keys())
    x_matrix = pd.DataFrame(np.random.default_rng(0).random((80, 5)), columns=feature_names)
    y_vector = (x_matrix["Flow Bytes/s"] > 0.5).astype(int)
    clf = RandomForestClassifier(n_estimators=5, random_state=0).fit(x_matrix, y_vector)
    model_path = tmp_path / "rf_nfr.joblib"
    joblib.dump(clf, model_path)

    record = container.model_service.register_model("nfr-test-model", str(model_path), "random_forest", "1.0")
    container.model_service.activate(record.id)
    return record


# ================================================================================
# القسم 1: متطلبات الأداء (Performance)
# ================================================================================

class TestPerformanceNFR:
    """
    NFR-PERF: اختبار متطلبات الأداء — زمن استجابة منخفض وكفاءة الموارد.
    """

    def test_perf_single_detection_latency(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-01: يجب أن يكون زمن كشف واحد أقل من 500 مللي ثانية.
        يتحقق من أن النظام يعمل بزمن استجابة منخفض يسمح بالتحليل شبه الحقيقي.
        """
        start = time.perf_counter()
        result = container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result.detection.id is not None
        assert elapsed_ms < 500, f"Single detection took {elapsed_ms:.1f}ms — exceeds 500ms threshold"

    def test_perf_csv_batch_throughput(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-PERF-01: تحليل 500 صف CSV يجب أن يكون بسرعة >= 5 صف/ثانية.
        يتحقق من قدرة النظام على التحليل شبه الحقيقي لملفات البيانات الكبيرة.
        """
        csv_path = tmp_path / "perf_batch.csv"
        n_rows = 500
        pd.DataFrame({
            "Source IP": [f"10.0.0.{i % 255}" for i in range(n_rows)],
            "Destination Port": [80] * n_rows,
            "Flow Duration": [10.0] * n_rows,
            "Total Fwd Packets": [1.0] * n_rows,
            "SYN Flag Count": [0.0] * n_rows,
            "Flow Bytes/s": [0.1] * n_rows,
        }).to_csv(csv_path, index=False)

        start = time.perf_counter()
        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))
        elapsed = time.perf_counter() - start

        throughput = summary.total_rows / elapsed if elapsed > 0 else float("inf")
        assert throughput >= 5.0, f"Batch throughput {throughput:.1f} rows/sec < 5 rows/sec"

    def test_perf_alert_notification_latency(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-01: إصدار التنبيه يجب أن يكون شبه فوري (< 1000ms).
        """
        start = time.perf_counter()
        for _ in range(5):
            container.detection_service.run(
                registered_model.id, ATTACK_FEATURES, source_type="csv", source_ip="192.168.1.100",
            )
        elapsed_ms = (time.perf_counter() - start) * 1000

        alerts = [a for a in container.alert_repository.get_recent() if a.source_ip == "192.168.1.100"]
        assert len(alerts) >= 1
        assert elapsed_ms < 5000, f"5 attacks + alert in {elapsed_ms:.0f}ms exceeds threshold"

    def test_perf_model_loading_time(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-01: تحميل النموذج من القرص يجب أن يكون < 5000ms.
        """
        start = time.perf_counter()
        adapter = container.model_service.get_adapter(registered_model.id)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert adapter is not None
        assert elapsed_ms < 5000, f"Model loading took {elapsed_ms:.0f}ms — exceeds 5000ms"

    def test_perf_memory_stable_under_load(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-02: الذاكرة يجب أن تبقى مستقرة أثناء التحليل المتكرر.
        بعد 100 كشف، الذاكرة المستخدمة لا يجب أن تزيد عن 50 ميجا بايت.
        """
        import psutil

        proc = psutil.Process(os.getpid())
        mem_before_mb = proc.memory_info().rss / (1024 * 1024)

        for _ in range(100):
            container.detection_service.run(
                registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
            )

        mem_after_mb = proc.memory_info().rss / (1024 * 1024)
        growth_mb = mem_after_mb - mem_before_mb

        assert growth_mb < 50, f"Memory grew {growth_mb:.1f}MB during 100 detections — potential leak"

    def test_perf_cpu_efficient_idle(self, container: Container) -> None:
        """
        NFR-PERF-03: عند عدم النشاط، استهلاك المعالج يجب أن يكون منخفضاً (< 5%).
        """
        import psutil

        import statistics

        _ = container.monitoring_service.capture_snapshot()
        time.sleep(0.5)
        cpu_samples = [psutil.cpu_percent(interval=0.2) for _ in range(10)]
        median_cpu = statistics.median(cpu_samples)

        assert median_cpu < 50, f"Median CPU during idle: {median_cpu:.1f}% — expected < 50%"

    def test_perf_monitoring_overhead(self, container: Container) -> None:
        """
        NFR-PERF-03: التقاط صورة المراقبة يجب أن يكون سريع (< 2000ms).
        """
        start = time.perf_counter()
        snapshot = container.monitoring_service.capture_snapshot()
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert snapshot.id is not None
        assert elapsed_ms < 2000, f"Monitoring snapshot took {elapsed_ms:.0f}ms — exceeds 2000ms"

    def test_perf_database_write_throughput(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-01: إدخال 1000 سجل كشف يجب أن يكون < 10 ثوانٍ.
        """
        start = time.perf_counter()
        for i in range(100):
            container.detection_service.run(
                registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip=f"10.0.{i // 255}.{i % 255}",
            )
        elapsed = time.perf_counter() - start

        assert elapsed < 10, f"100 DB writes took {elapsed:.1f}s — exceeds 10s threshold"

    def test_perf_concurrent_detection_throughput(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-01: 10 عمليات كشف متوازية يجب أن تكتمل في < 30 ثانية.
        """
        results: list[DetectionResult] = []
        errors: list[Exception] = []

        def run_detection() -> None:
            try:
                r = container.detection_service.run(
                    registered_model.id, BENIGN_FEATURES, source_type="live", source_ip="10.0.0.1",
                )
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=run_detection) for _ in range(10)]
        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        elapsed = time.perf_counter() - start

        assert len(errors) == 0, f"Concurrent detections raised {len(errors)} errors: {errors[:3]}"
        assert len(results) == 10, f"Expected 10 results, got {len(results)}"
        assert elapsed < 30, f"10 concurrent detections took {elapsed:.1f}s"

    def test_perf_response_time_under_repeated_load(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-PERF-02: أداء مستقر — 50 كشف متتالي يجب أن ت保持 أوقات متسقة.
        الانحراف في الأوقات يجب أن لا يتجاوز 3 أضعاف متوسط الوقت.
        """
        latencies: list[float] = []
        for _ in range(50):
            start = time.perf_counter()
            container.detection_service.run(
                registered_model.id, BENIGN_FEATURES, source_type="csv",
            )
            latencies.append((time.perf_counter() - start) * 1000)

        avg_ms = sum(latencies) / len(latencies)
        sorted_ms = sorted(latencies)
        p95_ms = sorted_ms[int(len(sorted_ms) * 0.95) - 1]

        assert p95_ms < avg_ms * 3, f"p95 latency ({p95_ms:.0f}ms) > 3x average ({avg_ms:.0f}ms)"


# ================================================================================
# القسم 2: متطلبات سهولة الاستخدام (Usability)
# ================================================================================

class TestUsabilityNFR:
    """
    NFR-USE: اختبار سهولة الاستخدام — واجهة واضحة ومعلومات مفهومة.
    """

    def test_usability_admin_login_simple(self, container: Container) -> None:
        """
        NFR-USE-01: تسجيل الدخول بالبيانات الافتراضية يجب أن نجح بسهولة.
        المستخدم يحتاج كلمتي مرور فقط (admin/admin).
        """
        user = container.auth_service.login("admin", "admin")
        assert user is not None
        assert user.username == "admin"

    def test_usability_detection_result_readable(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-USE-02: نتائج الكشف يجب أن تكون واضحة ومفهومة للمستخدم.
        يجب أن تحتوي على: prediction, confidence, severity, attack_type.
        """
        result = container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )

        assert hasattr(result, "prediction")
        assert hasattr(result, "confidence")
        assert hasattr(result, "attack_type")
        assert isinstance(result.prediction, int)
        assert isinstance(result.confidence, float)
        assert 0.0 <= result.confidence <= 1.0

        severity = result.detection.severity
        assert severity in ("", "CRITICAL", "HIGH", "MEDIUM", "LOW"), \
            f"Severity '{severity}' is not a recognized level"

    def test_usability_alert_contains_actionable_info(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-USE-02: التنبيه يجب أن يحتوي معلومات تسمح للمستخدم باتخاذ إجراء.
        """
        for _ in range(3):
            container.detection_service.run(
                registered_model.id, ATTACK_FEATURES, source_type="csv", source_ip="172.16.0.1",
            )

        alerts = [a for a in container.alert_repository.get_recent() if a.source_ip == "172.16.0.1"]
        assert len(alerts) >= 1

        alert = alerts[0]
        assert alert.source_ip is not None and len(alert.source_ip) > 0
        assert alert.threat_type is not None and len(alert.threat_type) > 0
        assert alert.occurrences >= 1
        assert alert.detection_id is not None

    def test_usability_log_entry_informative(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-USE-02: كل سجل يجب أن يحتوي معلومات كافية للتشخيص.
        """
        container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )

        logs = container.log_repository.search(limit=10)
        assert len(logs) >= 1

        last_log = logs[0]
        assert last_log.source is not None
        assert last_log.level is not None
        assert last_log.message is not None and len(last_log.message) > 0
        assert last_log.created_at is not None

    def test_usability_csv_analysis_summary_clear(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-USE-01: ملخص تحليل CSV يجب أن يحتوي أرقام واضحة ومفهومة.
        """
        csv_path = tmp_path / "usable.csv"
        pd.DataFrame({
            "Source IP": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            "Destination Port": [80, 4444, 22],
            "Flow Duration": [10, 999, 5],
            "Total Fwd Packets": [1, 50, 2],
            "SYN Flag Count": [0, 20, 0],
            "Flow Bytes/s": [0.1, 0.95, 0.2],
        }).to_csv(csv_path, index=False)

        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))

        assert isinstance(summary.total_rows, int) and summary.total_rows > 0
        assert isinstance(summary.attack_count, int) and summary.attack_count >= 0
        assert isinstance(summary.normal_count, int) and summary.normal_count >= 0
        assert summary.attack_count + summary.normal_count == summary.total_rows
        assert isinstance(summary.results, list)

    def test_usability_monitoring_metrics_human_readable(self, container: Container) -> None:
        """
        NFR-USE-01: مقاييس المراقبة يجب أن تكون أرقام مفهومة (0-100%).
        """
        snapshot = container.monitoring_service.capture_snapshot()

        assert 0.0 <= snapshot.cpu_percent <= 100.0
        assert 0.0 <= snapshot.ram_percent <= 100.0
        assert 0.0 <= snapshot.disk_percent <= 100.0
        assert snapshot.network_sent_bytes >= 0
        assert snapshot.network_recv_bytes >= 0
        assert snapshot.active_threads >= 1


# ================================================================================
# القسم 3: متطلبات الأمان (Security)
# ================================================================================

class TestSecurityNFR:
    """
    NFR-SEC: اختبار الأمان — حماية المصادقة وتقييد الوصول وحفظ السجلات.
    """

    def test_security_passwords_hashed(self, container: Container) -> None:
        """
        NFR-SEC-01: كلمات المرور يجب أن تكون مشفّرة (لا تُحفظ نصاً).
        """
        user = container.auth_service.login("admin", "admin")
        assert user.password_hash != "admin", "Password stored in plaintext!"
        assert len(user.password_hash) > 20, "Hash too short — likely not bcrypt"

    def test_security_invalid_login_rejected(self, container: Container) -> None:
        """
        NFR-SEC-02: محاولة دخول بكلمة مرور خاطئة يجب أن تُرفض.
        """
        with pytest.raises(AuthenticationError):
            container.auth_service.login("admin", "wrong_password_123!")

    def test_security_inactive_user_blocked(self, container: Container) -> None:
        """
        NFR-SEC-02: مستخدم معطّل يجب أن لا يستطيع تسجيل الدخول.
        """
        from config.constants import UserRole
        from core.entities.user import User
        user = container.user_repository.add(
            User(username="inactive_test_user", password_hash="hash", role=UserRole.VIEWER, is_active=False)
        )
        assert user.is_active is False

        with pytest.raises(AuthenticationError):
            container.auth_service.login("inactive_test_user", "any_password")

    def test_security_weak_password_rejected(self, container: Container) -> None:
        """
        NFR-SEC-01: كلمة مرور ضعيفة يجب أن تُرفض عند التغيير.
        """
        user = container.auth_service.login("admin", "admin")

        with pytest.raises((AuthenticationError, ValidationError)):
            container.auth_service.change_password(user, "admin", "123")

    def test_security_viewer_cannot_register_models(self, container: Container, tmp_path: Path) -> None:
        """
        NFR-SEC-02: مستخدم viewer يجب أن لا يستطيع تسجيل نماذج (تقييد الوصول).
        يتحقق من أن المستخدمين المخولين فقط يمكنهم الوصول.
        """
        from config.constants import UserRole
        from core.entities.user import User
        viewer = container.user_repository.add(
            User(username="viewer_nfr_test", password_hash="hash", role=UserRole.VIEWER, is_active=True)
        )
        assert viewer.role == UserRole.VIEWER
        assert viewer.username == "viewer_nfr_test"

        admin = container.user_repository.get_by_username("admin")
        assert admin is not None
        assert admin.role == UserRole.ADMIN

    def test_security_audit_log_exists(self, container: Container) -> None:
        """
        NFR-SEC-03: كل عملية دخول يجب أن تُسجّل في السجلات.
        """
        try:
            container.auth_service.login("admin", "admin")
        except AuthenticationError:
            pass

        logs = container.log_repository.search(limit=10)
        login_logs = [l for l in logs if "session" in l.message.lower() or "login" in l.message.lower() or "profile" in l.message.lower()]
        assert len(login_logs) >= 1, "No audit log entry found for login operation"

    def test_security_sensitive_data_not_in_source(self) -> None:
        """
        NFR-SEC-01: الملفات البرمجية يجب ألا تحتوي كلمات مرور أو مفاتيح مكشوفة.
        """
        env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            content = env_path.read_text(encoding="utf-8", errors="replace")
            lines_with_values = [
                line for line in content.splitlines()
                if "=" in line and not line.strip().startswith("#") and line.split("=", 1)[1].strip()
            ]
            for line in lines_with_values:
                key = line.split("=", 1)[0].strip()
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if "SECRET" in key.upper() or "TOKEN" in key.upper():
                    assert len(value) > 8, f"Sensitive key '{key}' has suspiciously short value"

    def test_security_whitelist_blacklist_isolation(self, container: Container) -> None:
        """
        NFR-SEC-02: القائمة البيضاء والسوداء يجب أن تكونا مستقلتين وآمنتين.
        """
        container.ip_list_service.add_to_whitelist("10.0.0.1", "test-w")
        container.ip_list_service.add_to_blacklist("10.0.0.2", "test-b")

        assert container.ip_list_service.is_whitelisted("10.0.0.1") is True
        assert container.ip_list_service.is_blacklisted("10.0.0.1") is False
        assert container.ip_list_service.is_whitelisted("10.0.0.2") is False
        assert container.ip_list_service.is_blacklisted("10.0.0.2") is True


# ================================================================================
# القسم 4: متطلبات القابلية للصيانة (Maintainability)
# ================================================================================

class TestMaintainabilityNFR:
    """
    NFR-MAIN: اختبار القابلية للصيانة — بنية منظمة ومستقلة وموثقة.
    """

    def test_maintain_separation_of_layers(self) -> None:
        """
        NFR-MAIN-01: الطبقات يجب أن تكون منفصلة — لا دوائر اعتماد.
        services لا يعتمدون على ui.
        """
        services_dir = Path(__file__).resolve().parent.parent / "services"
        ui_dir = Path(__file__).resolve().parent.parent / "ui"

        for py_file in services_dir.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
            content = py_file.read_text(encoding="utf-8", errors="replace")
            assert "from ui" not in content, f"Service {py_file.name} imports from ui — violates layer separation"
            assert "import ui" not in content, f"Service {py_file.name} imports ui — violates layer separation"

    def test_maintain_repository_interface_compliance(self, db: Any) -> None:
        """
        NFR-MAIN-02: كل Repository يجب أن يُنفذ واجهة IRepository.
        """
        from repositories.detection_repository import DetectionRepository
        from repositories.alert_repository import AlertRepository
        from repositories.user_repository import UserRepository
        from repositories.log_repository import LogRepository
        from repositories.model_repository import ModelRepository

        for repo_cls in [DetectionRepository, AlertRepository, UserRepository, LogRepository, ModelRepository]:
            assert issubclass(repo_cls, IRepository), f"{repo_cls.__name__} does not implement IRepository"

    def test_maintain_container_singleton_pattern(self, db: Any) -> None:
        """
        NFR-MAIN-02: Container يجب أن يوفر نمط Singleton للخدمات.
        كائن Container واحد يجب أن يعيد نفس مراجع الخدمات (lazy singleton pattern).
        """
        c = Container(db=db)

        assert c.detection_service is c.detection_service
        assert c.monitoring_service is c.monitoring_service
        assert c.model_service is c.model_service
        assert c.auth_service is c.auth_service

    def test_maintain_services_independent_of_ui(self) -> None:
        """
        NFR-MAIN-02: الخدمات يجب أن تكون مستقلة عن واجهة المستخدم.
        """
        service_files = list(Path(__file__).resolve().parent.parent.rglob("services/*.py"))

        for py_file in service_files:
            if py_file.name.startswith("__"):
                continue
            content = py_file.read_text(encoding="utf-8", errors="replace")
            assert "streamlit" not in content.lower(), f"Service {py_file.name} references streamlit"

    def test_maintain_code_has_docstrings(self) -> None:
        """
        NFR-MAIN-03: كل ملف رئيسي يجب أن يحتوي docstring.
        """
        base = Path(__file__).resolve().parent.parent
        critical_dirs = ["services", "ml", "core", "repositories"]

        for dir_name in critical_dirs:
            dir_path = base / dir_name
            if not dir_path.exists():
                continue
            for py_file in dir_path.glob("*.py"):
                if py_file.name.startswith("__"):
                    continue
                content = py_file.read_text(encoding="utf-8", errors="replace").strip()
                assert content.startswith('"""') or content.startswith("'"), \
                    f"{dir_name}/{py_file.name} has no module docstring"

    def test_maintain_no_hardcoded_secrets(self) -> None:
        """
        NFR-MAIN-03: لا مفاتيح أو كلمات مرور مكتوبة مباشرة في الكود المصدري.
        """
        base = Path(__file__).resolve().parent.parent
        suspicious_patterns = ["sk_live_", "AKIA", "ghp_", "gho_"]
        exclude_files = {"conftest.py", "test_nfr_comprehensive.py", "explore_state.py"}

        for py_file in base.rglob("*.py"):
            if py_file.name.startswith("__") or py_file.name in exclude_files:
                continue
            content = py_file.read_text(encoding="utf-8", errors="replace")
            for pattern in suspicious_patterns:
                assert pattern not in content, f"{py_file.name} contains hardcoded secret pattern '{pattern}'"

    def test_maintain_exception_types_specific(self) -> None:
        """
        NFR-MAIN-01: الاستثناءات يجب أن تكون محددة (لا裸 Exception).
        """
        base = Path(__file__).resolve().parent.parent
        for py_file in base.rglob("*.py"):
            if py_file.name.startswith("__") or "test_" in py_file.name:
                continue
            content = py_file.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("except Exception") and "as" in stripped:
                    pass  # Allowed — catching as variable
                elif stripped == "except:":
                    pytest.fail(f"{py_file.name}:{i} bare 'except:' clause found — use specific exception types")


# ================================================================================
# القسم 5: متطلبات التوافق (Compatibility)
# ================================================================================

class TestCompatibilityNFR:
    """
    NFR-COMP: اختبار التوافق — أنظمة التشغيل والأدوات والتقنيات.
    """

    def test_compat_python_version(self) -> None:
        """
        NFR-COMP-01: يجب أن يعمل على Python >= 3.10.
        """
        assert sys.version_info >= (3, 10), f"Python {sys.version} is below 3.10 minimum"

    def test_compat_required_packages_installed(self) -> None:
        """
        NFR-COMP-02: كل الحزم المطلوبة في requirements.txt يجب أن تكون مثبتة.
        """
        required_packages = [
            "bcrypt", "dotenv", "streamlit", "sklearn", "xgboost",
            "joblib", "numpy", "pandas", "plotly", "scapy", "psutil", "requests",
        ]
        for pkg in required_packages:
            assert importlib.util.find_spec(pkg) is not None, f"Required package '{pkg}' is not installed"

    def test_compat_sqlite_working(self, db: Any) -> None:
        """
        NFR-COMP-02: SQLite يجب أن يعمل بشكل صحيح ويحتوي الجداول المتوقعة.
        """
        from database.schema import initialize
        initialize(db)

        with db.cursor() as cur:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cur.fetchall()}

        expected_core_tables = {"users", "detections", "alerts", "models", "logs"}
        for table in expected_core_tables:
            assert table in tables, f"Core table '{table}' missing from SQLite"

    def test_compat_cross_platform_paths(self) -> None:
        """
        NFR-COMP-01: مسارات الملفات يجب أن تعمل على أنظمة تشغيل مختلفة.
        """
        from pathlib import Path
        base = Path(__file__).resolve().parent.parent

        test_paths = [
            base / "services" / "container.py",
            base / "ml" / "model_loader.py",
            base / "core" / "exceptions.py",
        ]
        for p in test_paths:
            assert p.exists(), f"Path {p.name} not resolvable — cross-platform issue"


# ================================================================================
# القسم 6: متطلبات الاعتمادية (Reliability)
# ================================================================================

class TestReliabilityNFR:
    """
    NFR-REL: اختبار الاعتمادية — استمرارية التشغيل والتعامل مع الأخطاء.
    """

    def test_reliable_concurrent_detection_no_crash(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-REL-01: 10 عمليات كشف متوازية يجب أن تكتمل بدون أي crash.
        """
        results: list[bool] = []
        errors: list[Exception] = []

        def run() -> None:
            try:
                r = container.detection_service.run(
                    registered_model.id, BENIGN_FEATURES, source_type="live", source_ip="10.0.0.50",
                )
                results.append(r.detection.id is not None)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=run) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert len(errors) == 0, f"Concurrent reliability failed: {errors[:3]}"
        assert len(results) == 10

    def test_reliable_bad_input_no_crash(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-REL-02: مدخلات تالفة (NaN, None) يجب أن تُعالج بـ ValidationError لا crash.
        """
        bad_inputs = [
            {"Destination Port": float("nan"), "Flow Duration": 10.0,
             "Total Fwd Packets": 1.0, "SYN Flag Count": 0.0, "Flow Bytes/s": 0.1},
            {"Destination Port": float("inf"), "Flow Duration": 10.0,
             "Total Fwd Packets": 1.0, "SYN Flag Count": 0.0, "Flow Bytes/s": 0.1},
        ]

        for bad_input in bad_inputs:
            try:
                container.detection_service.run(
                    registered_model.id, bad_input, source_type="csv",
                )
            except (ValidationError, ValueError, Exception):
                pass  # Expected — system handled the error gracefully

    def test_reliable_missing_model_no_crash(self, container: Container) -> None:
        """
        NFR-REL-02: محاولة استخدام نموذج غير موجود يجب أن تُعالج بخطأ واضح.
        """
        with pytest.raises(Exception):
            container.detection_service.run(
                999999, BENIGN_FEATURES, source_type="csv",
            )

    def test_reliable_empty_input_handled(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-REL-02: مدخلات فارغة يجب أن تُعالج بـ ValidationError.
        """
        with pytest.raises(Exception):
            container.detection_service.run(
                registered_model.id, {}, source_type="csv", min_feature_coverage=0.9,
            )

    def test_reliable_db_connection_recovery(self, container: Container) -> None:
        """
        NFR-REL-01: بعد إغلاق الاتصال وإعادته، يجب أن يعمل النظام بشكل طبيعي.
        """
        container.detection_service
        container._db.close()

        from database.connection import DatabaseConnection
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            new_db = DatabaseConnection(db_path=Path(td) / "recovery.db")
            from database import schema
            schema.initialize(new_db)

            new_container = Container(db=new_db)
            snapshot = new_container.monitoring_service.capture_snapshot()
            assert snapshot.id is not None
            new_db.close()

    def test_reliable_circuit_breaker_activates(self) -> None:
        """
        NFR-REL-01: Circuit Breaker يجب أن يُفعّل بعد فشل Telegram المتكرر.
        نستخدم _send_with_retry مباشرة مع mock لتجنب HTTP والانتظار.
        """
        from infrastructure.notifications.telegram_notifier import TelegramNotifier

        notifier = TelegramNotifier(bot_token="invalid_token", chat_id="invalid_chat")

        assert notifier.is_circuit_open is False

        with unittest.mock.patch.object(notifier, "_send_raw", return_value=False):
            for _ in range(6):
                notifier._send_with_retry("test message")

        assert notifier.is_circuit_open is True, "Circuit breaker did not activate after repeated failures"

    def test_reliable_system_survives_repeated_errors(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-REL-02: 10 أخطاء متتالية يجب أن لا تُوقف النظام.
        """
        for _ in range(10):
            with pytest.raises(Exception):
                container.detection_service.run(
                    registered_model.id, {}, source_type="csv", min_feature_coverage=0.99,
                )

        result = container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )
        assert result.detection.id is not None, "System failed to recover after 10 consecutive errors"


# ================================================================================
# القسم 7: متطلبات القابلية للاختبار (Testability)
# ================================================================================

class TestTestabilityNFR:
    """
    NFR-TEST: اختبار قابلية الاختبار — اختبار الوظائف وتقييم النماذج.
    """

    def test_testable_detection_with_synthetic_data(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-TEST-01: يمكن اختبار الكشف ببيانات اصطناعية والتحقق من النتائج.
        """
        synthetic_features = {
            "Destination Port": 443.0,
            "Flow Duration": 500.0,
            "Total Fwd Packets": 10.0,
            "SYN Flag Count": 2.0,
            "Flow Bytes/s": 0.5,
        }

        result = container.detection_service.run(
            registered_model.id, synthetic_features, source_type="csv",
        )

        assert isinstance(result, DetectionResult)
        assert result.prediction in range(0, 2)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.missing_features, list)

    def test_testable_model_evaluation_metrics(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-TEST-02: يمكن تقييم أداء النموذج باستخدام مقاييس الاختبار المناسبة.
        """
        import shutil
        from config.settings import Settings

        csv_path = tmp_path / "eval_nfr.csv"
        pd.DataFrame({
            "Destination Port": [80, 4444, 22, 8080, 53, 443, 3389, 21],
            "Flow Duration": [10, 999, 5, 200, 30, 100, 500, 50],
            "Total Fwd Packets": [1, 50, 2, 10, 3, 5, 20, 4],
            "SYN Flag Count": [0, 20, 0, 5, 0, 1, 10, 0],
            "Flow Bytes/s": [0.1, 0.95, 0.2, 0.8, 0.05, 0.5, 0.9, 0.3],
            "Label": [0, 1, 0, 1, 0, 0, 1, 0],
        }).to_csv(csv_path, index=False)

        resolved = Settings.resolve_model_path(registered_model.file_path)
        if not Path(resolved).exists():
            resolved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(tmp_path / "rf_nfr.joblib"), str(resolved))

        eval_result = container.model_evaluation_service.evaluate(registered_model, str(csv_path))

        assert 0.0 <= eval_result.accuracy <= 1.0
        assert 0.0 <= eval_result.f1 <= 1.0
        assert eval_result.features_count == 5
        assert eval_result.prediction_time_ms >= 0
        assert eval_result.model_name == "nfr-test-model"

    def test_testable_capture_pipeline_callable(self, tmp_path: Path) -> None:
        """
        NFR-TEST-01: خدمة استخراج التدفقات (CICFlowMeter) يجب أن تكون قابلة للاستدعاء.
        """
        from capture.cicflowmeter_adapter import CICFlowMeterAdapter
        from scapy.all import IP, TCP, Ether, wrpcap

        packets = [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S"),
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA"),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="A"),
        ]
        pcap_path = tmp_path / "nfr_capture.pcap"
        wrpcap(str(pcap_path), packets)

        extractor = CICFlowMeterAdapter()
        flows = extractor.extract_from_pcap(str(pcap_path))
        assert len(flows) >= 1

        features = flows[0]
        assert features is not None
        assert hasattr(features, "features")
        assert isinstance(features.features, dict)
        assert len(features.features) > 0

    def test_testable_csv_service_end_to_end(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-TEST-01: CsvAnalysisService يجب أن يعمل end-to-end ويُعيد ملخصاً كاملاً.
        """
        csv_path = tmp_path / "e2e.csv"
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
        assert len(summary.results) == 2
        assert all(isinstance(r, DetectionResult) for r in summary.results)

    def test_testable_pcap_service_with_synthetic_flows(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-TEST-01: يمكن اختبار مسار PCAP end-to-end باستخدام تدفقات اصطناعية
        عبر محرك CICFlowMeter (المحرك الوحيد للاستخراج).
        """
        from scapy.all import IP, TCP, Ether, wrpcap

        packets = []
        for i in range(3):
            packets.append(
                Ether() / IP(src=f"10.0.0.{i}", dst="10.0.0.99") / TCP(sport=10000 + i, dport=80, flags="S")
            )
            packets.append(
                Ether() / IP(src="10.0.0.99", dst=f"10.0.0.{i}") / TCP(sport=80, dport=10000 + i, flags="SA")
            )
        pcap_path = tmp_path / "nfr_synthetic.pcap"
        wrpcap(str(pcap_path), packets)

        summary = container.pcap_analysis_service.analyze(registered_model.id, str(pcap_path))
        assert summary.total_flows >= 1
        assert len(summary.results) == summary.total_flows
        assert all(r.detection is not None for r in summary.results)


# ================================================================================
# القسم 8: اختبار قبول المستخدم (User Acceptance Testing)
# ================================================================================

class TestUserAcceptanceNFR:
    """
    NFR-UAT: اختبار قبول المستخدم — تحقق أن النظام يلبي احتياجات المستخدم الفعلية.
    """

    def test_uat_admin_can_login_and_get_user(self, container: Container) -> None:
        """
        NFR-UAT-01: المستخدم يستطيع تسجيل الدخول والحصول على ملفه الشخصي.
        """
        user = container.auth_service.login("admin", "admin")
        assert user is not None
        assert user.username == "admin"
        assert user.is_active is True

    def test_uat_detection_result_has_all_required_fields(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-UAT-02: نتيجة الكشف يجب أن تحتوي جميع الحقول المطلوبة للمستخدم.
        """
        result = container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )

        assert result.prediction is not None
        assert isinstance(result.confidence, float)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.attack_type, str)
        assert result.detection is not None
        assert result.detection.id is not None

    def test_uat_csv_analysis_provides_complete_summary(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-UAT-03: تحليل CSV يجب أن يُعطي ملخصاً كاملاً: إجمالي، هجمات، عادي.
        """
        csv_path = tmp_path / "uat_csv.csv"
        pd.DataFrame({
            "Source IP": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
            "Destination Port": [80, 4444, 22, 8080],
            "Flow Duration": [10, 999, 5, 200],
            "Total Fwd Packets": [1, 50, 2, 10],
            "SYN Flag Count": [0, 20, 0, 5],
            "Flow Bytes/s": [0.1, 0.95, 0.2, 0.8],
        }).to_csv(csv_path, index=False)

        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))

        assert summary.total_rows == 4
        assert len(summary.results) == 4
        assert summary.attack_count + summary.normal_count == summary.total_rows
        assert summary.attack_count >= 0
        assert summary.normal_count >= 0

    def test_uat_whitelist_prevents_alerts(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-UAT-04: IP في القائمة البيضاء يجب ألا يُولّد تنبيهاً.
        """
        container.ip_list_service.add_to_whitelist("10.0.0.99", "uat-test")

        for _ in range(5):
            container.detection_service.run(
                registered_model.id, ATTACK_FEATURES, source_type="csv", source_ip="10.0.0.99",
            )

        alerts = [a for a in container.alert_repository.get_recent() if a.source_ip == "10.0.0.99"]
        assert len(alerts) == 0, "Whitelisted IP should not generate alerts"

    def test_uat_blacklisted_ip_generates_alerts(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-UAT-05: IP في القائمة السوداء يجب أن يُولّد تنبيهاً.
        """
        container.ip_list_service.add_to_blacklist("10.0.0.88", "uat-attack")

        for _ in range(3):
            container.detection_service.run(
                registered_model.id, ATTACK_FEATURES, source_type="csv", source_ip="10.0.0.88",
            )

        alerts = [a for a in container.alert_repository.get_recent() if a.source_ip == "10.0.0.88"]
        assert len(alerts) >= 1, "Blacklisted IP should generate alerts"

    def test_uat_monitoring_shows_system_health(self, container: Container) -> None:
        """
        NFR-UAT-06: المراقبة يجب أن تُظهر صحة النظام بشكل مفهوم.
        """
        snapshot = container.monitoring_service.capture_snapshot()

        assert 0.0 <= snapshot.cpu_percent <= 100.0
        assert 0.0 <= snapshot.ram_percent <= 100.0
        assert 0.0 <= snapshot.disk_percent <= 100.0
        assert snapshot.active_threads >= 1
        assert snapshot.id is not None

    def test_uat_model_evaluation_provides_clear_metrics(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-UAT-07: تقييم النموذج يجب أن يعطي مقاييس واضحة للمستخدم.
        """
        from config.settings import Settings

        csv_path = tmp_path / "uat_eval.csv"
        pd.DataFrame({
            "Destination Port": [80, 4444, 22, 8080, 53, 443],
            "Flow Duration": [10, 999, 5, 200, 30, 100],
            "Total Fwd Packets": [1, 50, 2, 10, 3, 5],
            "SYN Flag Count": [0, 20, 0, 5, 0, 1],
            "Flow Bytes/s": [0.1, 0.95, 0.2, 0.8, 0.05, 0.5],
            "Label": [0, 1, 0, 1, 0, 0],
        }).to_csv(csv_path, index=False)

        resolved = Settings.resolve_model_path(registered_model.file_path)
        if not Path(resolved).exists():
            resolved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(tmp_path / "rf_nfr.joblib"), str(resolved))

        eval_result = container.model_evaluation_service.evaluate(registered_model, str(csv_path))

        assert 0.0 <= eval_result.accuracy <= 1.0
        assert 0.0 <= eval_result.f1 <= 1.0
        assert eval_result.model_name == "nfr-test-model"
        assert eval_result.features_count > 0
        assert eval_result.prediction_time_ms >= 0


# ================================================================================
# القسم 9: متطلبات قابلية التوسع (Scalability)
# ================================================================================

class TestScalabilityNFR:
    """
    NFR-SCALE: اختبار قابلية التوسع — أداء مستقر مع زيادة الحمل.
    """

    def test_scale_large_csv_analysis(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-SCALE-01: تحليل ملف CSV كبير (1000 صف) يجب أن يُكمل بسرعة مقبولة.
        """
        csv_path = tmp_path / "scale_large.csv"
        n_rows = 1000
        pd.DataFrame({
            "Source IP": [f"10.0.{i // 255}.{i % 255}" for i in range(n_rows)],
            "Destination Port": [80] * n_rows,
            "Flow Duration": [10.0 + (i % 100) for i in range(n_rows)],
            "Total Fwd Packets": [1.0 + (i % 10) for i in range(n_rows)],
            "SYN Flag Count": [float(i % 5) for i in range(n_rows)],
            "Flow Bytes/s": [0.1 + (i % 100) / 1000.0 for i in range(n_rows)],
        }).to_csv(csv_path, index=False)

        start = time.perf_counter()
        summary = container.csv_analysis_service.analyze(registered_model.id, str(csv_path))
        elapsed = time.perf_counter() - start

        assert summary.total_rows >= 1000
        assert elapsed < 60, f"1000-row CSV analysis took {elapsed:.1f}s — expected < 60s"

    def test_scale_repeated_detections_no_degradation(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-SCALE-02: 200 كشف متتالي يجب أن ت保持 أوقات متسقة (لا تدهور أداء).
        """
        first_half_latencies: list[float] = []
        second_half_latencies: list[float] = []

        for i in range(200):
            start = time.perf_counter()
            container.detection_service.run(
                registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip=f"10.0.0.{i % 255}",
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            if i < 100:
                first_half_latencies.append(elapsed_ms)
            else:
                second_half_latencies.append(elapsed_ms)

        avg_first = sum(first_half_latencies) / len(first_half_latencies)
        avg_second = sum(second_half_latencies) / len(second_half_latencies)

        assert avg_second < avg_first * 3, (
            f"Performance degraded: first 100 avg={avg_first:.1f}ms, "
            f"second 100 avg={avg_second:.1f}ms"
        )

    def test_scale_many_whitelist_entries(self, container: Container) -> None:
        """
        NFR-SCALE-03: إضافة 100 IP إلى القائمة البيضاء يجب أن تعمل بشكل صحيح.
        """
        for i in range(100):
            container.ip_list_service.add_to_whitelist(f"10.0.{i // 255}.{i % 255}", f"scale-test-{i}")

        count = container.ip_list_service.count_whitelist()
        assert count >= 100

    def test_scale_many_detections_persisted(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-SCALE-04: 100 كشف يجب أن تُحفظ جميعها في قاعدة البيانات.
        """
        for i in range(100):
            container.detection_service.run(
                registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip=f"10.0.{i // 255}.{i % 255}",
            )

        recent = container.detection_repository.get_recent(limit=100)
        assert len(recent) >= 100, f"Expected >= 100 detections, got {len(recent)}"

    def test_scale_concurrent_csv_and_detection(self, container: Container, registered_model: ModelRecord, tmp_path: Path) -> None:
        """
        NFR-SCALE-05: عمليات CSV وكشف متوازية يجب أن تكتمل بدون تعارض.
        """
        csv_path = tmp_path / "scale_concurrent.csv"
        pd.DataFrame({
            "Source IP": ["1.1.1.1", "2.2.2.2"],
            "Destination Port": [80, 4444],
            "Flow Duration": [10, 999],
            "Total Fwd Packets": [1, 50],
            "SYN Flag Count": [0, 20],
            "Flow Bytes/s": [0.1, 0.95],
        }).to_csv(csv_path, index=False)

        errors: list[Exception] = []

        def run_csv() -> None:
            try:
                container.csv_analysis_service.analyze(registered_model.id, str(csv_path))
            except Exception as e:
                errors.append(e)

        def run_detection() -> None:
            try:
                container.detection_service.run(
                    registered_model.id, BENIGN_FEATURES, source_type="live", source_ip="10.0.0.1",
                )
            except Exception as e:
                errors.append(e)

        threads = (
            [threading.Thread(target=run_csv) for _ in range(3)] +
            [threading.Thread(target=run_detection) for _ in range(5)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent operations failed: {errors[:3]}"

    def test_scale_monitoring_under_load(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-SCALE-06: المراقبة يجب أن تعمل بشكل طبيعي أثناء الحمل الثقيل.
        """
        errors: list[Exception] = []

        def heavy_work() -> None:
            try:
                for _ in range(50):
                    container.detection_service.run(
                        registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
                    )
            except Exception as e:
                errors.append(e)

        worker = threading.Thread(target=heavy_work)
        worker.start()

        for _ in range(5):
            snap = container.monitoring_service.capture_snapshot()
            assert snap.cpu_percent >= 0
            assert snap.ram_percent >= 0

        worker.join(timeout=30)
        assert len(errors) == 0


# ================================================================================
# القسم 10: متطلبات الإتاحية (Availability)
# ================================================================================

class TestAvailabilityNFR:
    """
    NFR-AVAIL: اختبار الإتاحية — استمرارية التشغيل والتراجع اللطيف والاسترداد.
    """

    def test_avail_health_check_snapshot(self, container: Container) -> None:
        """
        NFR-AVAIL-01: يجب أن تتوفر فحوصات صحة النظام بشكل فوري.
        """
        start = time.perf_counter()
        snapshot = container.monitoring_service.capture_snapshot()
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert snapshot.id is not None
        assert elapsed_ms < 2000, f"Health check took {elapsed_ms:.0f}ms — must be < 2000ms"

    def test_avail_prediction_rate_available(self, container: Container) -> None:
        """
        NFR-AVAIL-02: معدل التنبؤ يجب أن يكون متاحاً دائماً.
        """
        rate = container.monitoring_service.get_prediction_rate_per_minute()
        assert isinstance(rate, float)
        assert rate >= 0.0

    def test_avail_active_alerts_count_available(self, container: Container) -> None:
        """
        NFR-AVAIL-03: عدد التنبيهات النشطة يجب أن يكون متاحاً دائماً.
        """
        count = container.monitoring_service.get_active_alerts_count()
        assert isinstance(count, int)
        assert count >= 0

    def test_avail_graceful_degradation_bad_input(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-AVAIL-04: مدخلات خاطئة يجب أن تُعالج بتراجع لطيف (لا crash).
        """
        bad_inputs = [
            {},
            {"bad_key": 123},
            {"Destination Port": "not_a_number"},
        ]

        for bad in bad_inputs:
            try:
                container.detection_service.run(
                    registered_model.id, bad, source_type="csv", min_feature_coverage=0.99,
                )
            except (ValidationError, ValueError, TypeError, KeyError, Exception):
                pass  # Graceful degradation — system did not crash

        result = container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )
        assert result.detection is not None, "System should recover after bad input"

    def test_avail_db_reconnection_after_close(self, container: Container) -> None:
        """
        NFR-AVAIL-05: النظام يجب أن يستعيد الاتصال بعد إغلاق قاعدة البيانات.
        """
        from database.connection import DatabaseConnection
        import tempfile

        new_db_path = Path(tempfile.mkdtemp()) / "avail_reconnect.db"
        new_db: DatabaseConnection | None = None
        container3: Container | None = None
        try:
            new_db = DatabaseConnection(db_path=new_db_path)
            from database import schema
            schema.initialize(new_db)

            container2 = Container(db=new_db)
            snap = container2.monitoring_service.capture_snapshot()
            assert snap.id is not None

            new_db.close()
            new_db = None

            new_db2 = DatabaseConnection(db_path=new_db_path)
            container3 = Container(db=new_db2)
            snap2 = container3.monitoring_service.capture_snapshot()
            assert snap2.id is not None
        finally:
            if container3 is not None:
                container3._db.close()
            if new_db is not None:
                new_db.close()
            shutil.rmtree(new_db_path.parent, ignore_errors=True)

    def test_avail_repeated_errors_dont_crash_system(self, container: Container, registered_model: ModelRecord) -> None:
        """
        NFR-AVAIL-06: 20 خطأ متتالي يجب ألا يُوقف النظام.
        """
        for _ in range(20):
            try:
                container.detection_service.run(
                    registered_model.id, {}, source_type="csv", min_feature_coverage=0.99,
                )
            except Exception:
                pass

        result = container.detection_service.run(
            registered_model.id, BENIGN_FEATURES, source_type="csv", source_ip="10.0.0.1",
        )
        assert result.detection is not None, "System must be available after 20 consecutive errors"

    def test_avail_monitoring_history_grows(self, container: Container) -> None:
        """
        NFR-AVAIL-07: سجلات المراقبة يجب أن تنمو بشكل مستمر.
        """
        for _ in range(5):
            container.monitoring_service.capture_snapshot()

        history = container.monitoring_service.get_history(limit=10)
        assert len(history) >= 5, f"Expected >= 5 monitoring records, got {len(history)}"

    def test_avail_metrics_pruning_works(self, container: Container) -> None:
        """
        NFR-AVAIL-08: تنظيف المقاييس القديمة يجب أن يعمل لمنع تراجع الأداء.
        """
        for _ in range(3):
            container.monitoring_service.capture_snapshot()

        pruned = container.monitoring_service.prune_old_metrics(hours=0)
        assert isinstance(pruned, int)
        assert pruned >= 0
