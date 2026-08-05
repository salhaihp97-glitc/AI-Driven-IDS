"""
================================================================================
 وحدة اختبار قاعدة البيانات وطبقة الثبات
 Database Layer & Persistence — Test Suite
================================================================================

الوصف:
    تتحقق هذه الاختبارات من سلامة وكفاءة طبقة قاعدة البيانات، بما في ذلك
    إنشاء الجداول، وعمليات CRUD، والتكامل مع SQLite، والتعامل مع البيانات
    غير الصالحة.

الهدف:
    ضمان أن النظام قادر على:
    - الاتصال بقاعدة البيانات وإنشاء الجداول المطلوبة
    - تنفيذ عمليات CREATE, READ, UPDATE, DELETE بشكل صحيح
    - التعامل مع الجداول الفارغة دون أخطاء
    - رفض البيانات غير الصالحة وفق قيود التكامل

المتطلبات المرتبطة:
    FR-DB-01: إنشاء جداول قاعدة البيانات
    FR-DB-02: إجراء عمليات CRUD على جميع الكيانات
    FR-DB-03: فرض قيود التكامل (مفتاح خارجي، قيم فريدة)
    NFR-DB-01: التعامل الآمن مع الجداول الفارغة والبيانات التالفة

================================================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest

from core.entities.alert import Alert
from core.entities.detection import Detection
from core.entities.model_record import ModelRecord
from core.entities.system_metric import SystemMetric
from core.entities.user import User
from core.exceptions import DatabaseError, DuplicateRecordError, RecordNotFoundError
from config.constants import UserRole
from database import schema
from database.connection import DatabaseConnection


# ================================================================================
# القسم 1: اختبارات الاتصال وإنشاء الجداول
# ================================================================================

class TestDatabaseConnection:
    """
    FR-DB-01: التحقق من إنشاء قاعدة البيانات وجداولها الأساسية.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    EXPECTED_TABLES: Final[set[str]] = {
        "users", "settings", "models", "detections",
        "alerts", "logs", "whitelist_ips", "blacklist_ips", "system_metrics",
        "telegram_subscribers",
    }

    def test_all_expected_tables_exist(self, db: DatabaseConnection) -> None:
        """FR-DB-01: جميع الجداول المتوقعة يجب أن تكون موجودة بعد initialization."""
        tables = self._get_table_names(db)
        missing = self.EXPECTED_TABLES.difference(tables)
        assert self.EXPECTED_TABLES.issubset(tables), (
            f"الجداول المفقودة: {missing}"
        )

    def test_schema_initialize_is_idempotent(self, db: DatabaseConnection) -> None:
        """FR-DB-01: استدعاء schema.initialize مرتين يجب ألا يسبب أخطاء."""
        schema.initialize(db)
        schema.initialize(db)
        tables = self._get_table_names(db)
        assert self.EXPECTED_TABLES.issubset(tables)

    def test_users_table_has_expected_columns(self, db: DatabaseConnection) -> None:
        """FR-DB-01: التحقق من وجود الأعمدة المتوقعة في جدول users."""
        expected: Final[set[str]] = {
            "id", "username", "password_hash", "role",
            "is_active", "created_at", "last_login_at",
        }
        columns = self._get_column_names(db, "users")
        assert expected == columns, (
            f"الأعمدة غير المتطابقة: {expected.symmetric_difference(columns)}"
        )

    def test_detections_table_has_expected_columns(self, db: DatabaseConnection) -> None:
        """FR-DB-01: التحقق من أعمدة جدول detections."""
        expected: Final[set[str]] = {
            "id", "model_id", "source_ip", "destination_ip",
            "prediction", "confidence", "source_type",
            "raw_features", "created_at",
        }
        columns = self._get_column_names(db, "detections")
        assert expected.issubset(columns)

    def test_alerts_table_has_expected_columns(self, db: DatabaseConnection) -> None:
        """FR-DB-01: التحقق من أعمدة جدول alerts."""
        expected: Final[set[str]] = {
            "id", "source_ip", "threat_type", "detection_id",
            "occurrences", "first_seen", "last_seen",
            "is_acknowledged", "telegram_sent",
        }
        columns = self._get_column_names(db, "alerts")
        assert expected.issubset(columns)

    def test_models_table_has_expected_columns(self, db: DatabaseConnection) -> None:
        """FR-DB-01: التحقق من أعمدة جدول models."""
        expected: Final[set[str]] = {
            "id", "name", "file_path", "model_type", "version",
            "features_count", "is_active", "created_at", "metadata",
        }
        columns = self._get_column_names(db, "models")
        assert expected.issubset(columns)

    def test_telegram_subscribers_table_has_expected_columns(self, db: DatabaseConnection) -> None:
        """FR-DB-01: التحقق من أعمدة جدول telegram_subscribers."""
        expected: Final[set[str]] = {
            "id", "chat_id", "label", "is_active", "created_at",
        }
        columns = self._get_column_names(db, "telegram_subscribers")
        assert expected.issubset(columns)

    def test_migrates_legacy_telegram_subscribers_missing_status(self, tmp_path: Path) -> None:
        """FR-DB-01: ترقية قاعدة بيانات قديمة (جدول telegram_subscribers بدون عمود status)
        يجب ألا تفشل تهيئة المخطط ولا إنشاء الفهارس."""
        legacy_path: Final[Path] = tmp_path / "legacy_ai_ids.db"
        legacy = DatabaseConnection(db_path=legacy_path)
        with legacy.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE telegram_subscribers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                """
            )
        legacy.close()

        upgraded = DatabaseConnection(db_path=legacy_path)
        try:
            schema.initialize(upgraded)
            columns = self._get_column_names(upgraded, "telegram_subscribers")
            assert "status" in columns, f"عمود status لم يُضف بعد الترقية: {columns}"
            with upgraded.cursor() as cur:
                cur.execute(
                    "INSERT INTO telegram_subscribers (chat_id, label, is_active, status) "
                    "VALUES ('123456', 'legacy user', 1, 'approved')"
                )
        finally:
            upgraded.close()

    # ── helpers ──

    @staticmethod
    def _get_table_names(db: DatabaseConnection) -> set[str]:
        with db.cursor() as cur:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            return {str(row["name"]) for row in cur.fetchall()}

    @staticmethod
    def _get_column_names(db: DatabaseConnection, table: str) -> set[str]:
        with db.cursor() as cur:
            cur.execute(f"PRAGMA table_info({table})")
            return {str(row["name"]) for row in cur.fetchall()}


# ================================================================================
# القسم 2: اختبارات CRUD — جدول users
# ================================================================================

class TestUserRepository:
    """
    FR-DB-02: التحقق من عمليات CRUD على كيان User.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_create_user(self, db: DatabaseConnection) -> None:
        """إنشاء مستخدم — يجب إرجاع الكائن مع id."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        user = repo.add(User(username="test_user", password_hash="abc123", role=UserRole.ADMIN))
        assert user.id is not None
        assert user.username == "test_user"

    def test_read_user_by_id(self, db: DatabaseConnection) -> None:
        """قراءة مستخدم بواسطة id — يجب إرجاع الكائن الصحيح."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        created = repo.add(User(username="read_test", password_hash="abc123", role=UserRole.VIEWER))
        fetched = repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.username == "read_test"
        assert fetched.role == UserRole.VIEWER

    def test_read_user_by_username(self, db: DatabaseConnection) -> None:
        """قراءة مستخدم بواسطة username — يجب إرجاع الكائن الصحيح."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        repo.add(User(username="find_me", password_hash="abc123", role=UserRole.ADMIN))
        found = repo.get_by_username("find_me")
        assert found is not None
        assert found.username == "find_me"

    def test_update_user(self, db: DatabaseConnection) -> None:
        """تحديث مستخدم — يجب حفظ التغييرات في قاعدة البيانات."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        user = repo.add(User(username="update_test", password_hash="old_hash", role=UserRole.ADMIN))
        user.role = UserRole.VIEWER
        user.is_active = False
        updated = repo.update(user)
        assert updated.role == UserRole.VIEWER
        assert updated.is_active is False
        # تحقق من القراءة مرة أخرى
        fetched = repo.get_by_id(user.id)
        assert fetched is not None
        assert fetched.role == UserRole.VIEWER

    def test_delete_user(self, db: DatabaseConnection) -> None:
        """حذف مستخدم — يجب ألا يعود موجودًا بعد الحذف."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        user = repo.add(User(username="delete_test", password_hash="abc123", role=UserRole.ADMIN))
        user_id = user.id
        repo.delete(user_id)
        assert repo.get_by_id(user_id) is None


# ================================================================================
# القسم 3: اختبارات CRUD — جداول القوائم (Whitelist / Blacklist)
# ================================================================================

class TestIPListRepositories:
    """
    FR-DB-02: التحقق من عمليات CRUD على جداول القوائم البيضاء والسوداء.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_add_to_whitelist(self, db: DatabaseConnection) -> None:
        """إضافة IP إلى القائمة البيضاء — يجب أن يُحفظ بنجاح."""
        from repositories.whitelist_repository import WhitelistRepository
        from core.entities.ip_list_entry import WhitelistIP
        repo = WhitelistRepository(db)
        entry = repo.add(WhitelistIP(ip_address="10.0.0.1", reason="trusted server"))
        assert entry.id is not None
        assert entry.ip_address == "10.0.0.1"

    def test_add_to_blacklist(self, db: DatabaseConnection) -> None:
        """إضافة IP إلى القائمة السوداء — يجب أن يُحفظ بنجاح."""
        from repositories.blacklist_repository import BlacklistRepository
        from core.entities.ip_list_entry import BlacklistIP
        repo = BlacklistRepository(db)
        entry = repo.add(BlacklistIP(ip_address="192.168.1.100", reason="malicious scanner"))
        assert entry.id is not None
        assert entry.ip_address == "192.168.1.100"

    def test_check_ip_exists(self, db: DatabaseConnection) -> None:
        """التحقق من وجود IP في القائمة السوداء."""
        from repositories.blacklist_repository import BlacklistRepository
        from core.entities.ip_list_entry import BlacklistIP
        repo = BlacklistRepository(db)
        repo.add(BlacklistIP(ip_address="5.5.5.5", reason="bad actor"))
        assert repo.exists("5.5.5.5") is True
        assert repo.exists("6.6.6.6") is False

    def test_delete_from_whitelist(self, db: DatabaseConnection) -> None:
        """حذف IP من القائمة البيضاء."""
        from repositories.whitelist_repository import WhitelistRepository
        from core.entities.ip_list_entry import WhitelistIP
        repo = WhitelistRepository(db)
        entry = repo.add(WhitelistIP(ip_address="10.0.0.2", reason="test"))
        repo.delete(entry.id)
        assert repo.exists("10.0.0.2") is False


# ================================================================================
# القسم 4: اختبارات CRUD — جدول detections
# ================================================================================

class TestDetectionRepository:
    """
    FR-DB-02: التحقق من عمليات CRUD على كيان Detection.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    @staticmethod
    def _create_test_model(db: DatabaseConnection) -> int:
        """ينشئ سجل نموذج ويعيد id لاستخدامه في اختبارات الكشف."""
        from repositories.model_repository import ModelRepository
        model_repo = ModelRepository(db)
        model = model_repo.add(ModelRecord(
            name="detection_test_model", file_path="dummy.joblib",
            model_type="test", version="1.0.0",
        ))
        assert model.id is not None
        return model.id

    def test_create_detection(self, db: DatabaseConnection) -> None:
        """إنشاء سجل كشف — يجب أن يُحفظ في قاعدة البيانات."""
        from repositories.detection_repository import DetectionRepository
        repo = DetectionRepository(db)
        model_id = self._create_test_model(db)
        det = Detection(
            model_id=model_id, source_ip="1.1.1.1", destination_ip="2.2.2.2",
            prediction=1, confidence=0.95, source_type="csv",
            raw_features='{"port": 80}',
        )
        saved = repo.add(det)
        assert saved.id is not None

    def test_get_recent_detections(self, db: DatabaseConnection) -> None:
        """استرجاع أحدث السجلات — يجب أن يعيد القائمة حسب الترتيب."""
        from repositories.detection_repository import DetectionRepository
        repo = DetectionRepository(db)
        model_id = self._create_test_model(db)
        for i in range(3):
            repo.add(Detection(
                model_id=model_id, source_ip=f"10.0.0.{i}", destination_ip="5.5.5.5",
                prediction=0, confidence=1.0, source_type="csv", raw_features="{}",
            ))
        recent = repo.get_recent(limit=2)
        assert len(recent) == 2

    def test_count_since(self, db: DatabaseConnection) -> None:
        """FR-DB-02: عدّ السجلات منذ وقت معين."""
        from repositories.detection_repository import DetectionRepository
        repo = DetectionRepository(db)
        model_id = self._create_test_model(db)
        repo.add(Detection(model_id=model_id, source_ip="5.5.5.5", destination_ip="6.6.6.6",
                           prediction=0, confidence=1.0, source_type="csv", raw_features="{}"))
        repo.add(Detection(model_id=model_id, source_ip="5.5.5.5", destination_ip="6.6.6.6",
                           prediction=1, confidence=0.9, source_type="csv", raw_features="{}"))
        from utils.time_utils import utc_hours_ago_sql
        count = repo.count_since(utc_hours_ago_sql(24))
        assert count >= 2

    def test_count_since_only_attacks(self, db: DatabaseConnection) -> None:
        """
        FR-DB-02: عدّ الهجمات فقط (prediction != 0).
        ملاحظة: تم إصلاح الخلل — الآن يستخدم != 0 بدلاً من = 1.
        """
        from repositories.detection_repository import DetectionRepository
        repo = DetectionRepository(db)
        model_id = self._create_test_model(db)
        repo.add(Detection(model_id=model_id, source_ip="5.5.5.5", destination_ip="6.6.6.6",
                           prediction=0, confidence=1.0, source_type="csv", raw_features="{}"))
        repo.add(Detection(model_id=model_id, source_ip="5.5.5.5", destination_ip="6.6.6.6",
                           prediction=1, confidence=0.9, source_type="csv", raw_features="{}"))
        repo.add(Detection(model_id=model_id, source_ip="5.5.5.5", destination_ip="6.6.6.6",
                           prediction=2, confidence=0.8, source_type="csv", raw_features="{}"))
        from utils.time_utils import utc_hours_ago_sql
        count = repo.count_since(utc_hours_ago_sql(24), only_attacks=True)
        assert count >= 2, "يجب عد prediction=1 و prediction=2 كلا الهجومين"


# ================================================================================
# القسم 5: اختبارات CRUD — جدول alerts
# ================================================================================

class TestAlertRepository:
    """
    FR-DB-02: التحقق من عمليات CRUD على كيان Alert.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    @staticmethod
    def _create_test_model(db: DatabaseConnection) -> int:
        """ينشئ سجل نموذج ويعيد id لاستخدامه في اختبارات التنبيه."""
        from repositories.model_repository import ModelRepository
        model_repo = ModelRepository(db)
        model = model_repo.add(ModelRecord(
            name="alert_test_model", file_path="dummy.joblib",
            model_type="test", version="1.0.0",
        ))
        assert model.id is not None
        return model.id

    @staticmethod
    def _create_test_detection(db: DatabaseConnection, model_id: int) -> int:
        """ينشئ سجل كشف ويعيد id لاستخدامه في اختبارات التنبيه."""
        from repositories.detection_repository import DetectionRepository
        det_repo = DetectionRepository(db)
        det = det_repo.add(Detection(
            model_id=model_id, source_ip="10.0.0.1", destination_ip="20.0.0.1",
            prediction=1, confidence=0.95, source_type="csv",
        ))
        assert det.id is not None
        return det.id

    def test_create_alert(self, db: DatabaseConnection) -> None:
        """إنشاء تنبيه — يجب أن يُحفظ مع القيم الصحيحة."""
        from repositories.alert_repository import AlertRepository
        repo = AlertRepository(db)
        model_id = self._create_test_model(db)
        det_id = self._create_test_detection(db, model_id)
        alert = Alert(source_ip="10.0.0.5", threat_type="Port Scan", detection_id=det_id)
        saved = repo.add(alert)
        assert saved.id is not None
        assert saved.threat_type == "Port Scan"

    def test_count_active_alerts(self, db: DatabaseConnection) -> None:
        """FR-DB-02: عدّ التنبيهات النشطة (غير المؤكدة)."""
        from repositories.alert_repository import AlertRepository
        repo = AlertRepository(db)
        model_id = self._create_test_model(db)
        det_id1 = self._create_test_detection(db, model_id)
        det_id2 = self._create_test_detection(db, model_id)
        det_id3 = self._create_test_detection(db, model_id)
        repo.add(Alert(source_ip="1.1.1.1", threat_type="Test", detection_id=det_id1, is_acknowledged=False))
        repo.add(Alert(source_ip="2.2.2.2", threat_type="Test", detection_id=det_id2, is_acknowledged=True))
        repo.add(Alert(source_ip="3.3.3.3", threat_type="Test", detection_id=det_id3, is_acknowledged=False))
        assert repo.count_active() == 2

    def test_find_active_window(self, db: DatabaseConnection) -> None:
        """FR-DB-02: البحث عن نافذة تنبيه نشطة لنفس IP."""
        from repositories.alert_repository import AlertRepository
        repo = AlertRepository(db)
        model_id = self._create_test_model(db)
        det_id = self._create_test_detection(db, model_id)
        alert = Alert(source_ip="10.0.0.1", threat_type="DDoS", detection_id=det_id)
        repo.add(alert)
        found = repo.find_active_window(source_ip="10.0.0.1", threat_type="DDoS", window_minutes=60)
        assert found is not None
        assert found.source_ip == "10.0.0.1"


# ================================================================================
# القسم 6: اختبارات CRUD — جداول models و system_metrics
# ================================================================================

class TestModelAndMetricsRepositories:
    """
    FR-DB-02: التحقق من عمليات CRUD على جداول models و system_metrics.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_create_model_record(self, db: DatabaseConnection) -> None:
        """إنشاء سجل نموذج — يجب أن يُحفظ مع جميع الحقول."""
        from repositories.model_repository import ModelRepository
        repo = ModelRepository(db)
        record = ModelRecord(name="test_model", file_path="model.joblib", model_type="random_forest",
                             version="1.0.0", features_count=10, is_active=True)
        saved = repo.add(record)
        assert saved.id is not None
        assert saved.name == "test_model"

    def test_get_active_models(self, db: DatabaseConnection) -> None:
        """استرجاع النماذج النشطة فقط."""
        from repositories.model_repository import ModelRepository
        repo = ModelRepository(db)
        repo.add(ModelRecord(name="m1", file_path="m1.joblib", model_type="rf",
                             version="1.0.0", features_count=5, is_active=True))
        repo.add(ModelRecord(name="m2", file_path="m2.joblib", model_type="xgb",
                             version="2.0.0", features_count=5, is_active=False))
        active = repo.get_active()
        assert len(active) == 1
        assert active[0].name == "m1"

    def test_add_system_metric(self, db: DatabaseConnection) -> None:
        """إنشاء سجل مقياس نظام — يجب أن يُحفظ بشكل صحيح."""
        from repositories.system_metric_repository import SystemMetricRepository
        repo = SystemMetricRepository(db)
        metric = SystemMetric(cpu_percent=45.2, ram_percent=62.1, disk_percent=55.0,
                              network_sent_bytes=1000, network_recv_bytes=2000, active_threads=25)
        saved = repo.add(metric)
        assert saved.id is not None
        assert saved.cpu_percent == 45.2

    def test_update_model_activation(self, db: DatabaseConnection) -> None:
        """تحديث حالة تفعيل النموذج."""
        from repositories.model_repository import ModelRepository
        repo = ModelRepository(db)
        record = repo.add(ModelRecord(name="activate_test", file_path="a.joblib", model_type="rf",
                                      version="1.0.0", features_count=3, is_active=False))
        record.is_active = True
        repo.update(record)
        fetched = repo.get_by_id(record.id)
        assert fetched is not None
        assert fetched.is_active is True


# ================================================================================
# القسم 7: اختبارات الجداول الفارغة والبيانات غير الصالحة
# ================================================================================

class TestEdgeCases:
    """
    NFR-DB-01: التحقق من التعامل مع الجداول الفارغة والبيانات غير الصالحة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_empty_table_get_all(self, db: DatabaseConnection) -> None:
        """استعلام على جدول فارغ — يجب أن يعيد قائمة فارغة لا خطأ."""
        from repositories.detection_repository import DetectionRepository
        repo = DetectionRepository(db)
        all_detections = repo.get_recent(limit=100)
        assert all_detections == []

    def test_get_nonexistent_id_returns_none(self, db: DatabaseConnection) -> None:
        """استعلام عن id غير موجود — يجب أن يعيد None."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        assert repo.get_by_id(99999) is None

    def test_delete_nonexistent_record_raises(self, db: DatabaseConnection) -> None:
        """حذف سجل غير موجود — يجب ألا يرفع خطأ (أو يعيد False)."""
        from repositories.alert_repository import AlertRepository
        repo = AlertRepository(db)
        # الحذف يجب ألا يسبب تعطل النظام
        repo.delete(99999)

    def test_create_duplicate_username(self, db: DatabaseConnection) -> None:
        """إنشاء اسم مستخدم مكرر — يجب رفضه حسب قيد UNIQUE."""
        from repositories.user_repository import UserRepository
        repo = UserRepository(db)
        repo.add(User(username="unique_user", password_hash="abc", role=UserRole.ADMIN))
        with pytest.raises(DuplicateRecordError):
            repo.add(User(username="unique_user", password_hash="xyz", role=UserRole.VIEWER))
