"""
================================================================================
 وحدة اختبار طبقة تعزيز الكشف بالتوقيعات
 Anomaly Signature Augmentation — Test Suite
================================================================================

الوصف:
    تتحقق هذه الاختبارات من محرك التوقيعات القابل للتكوين (AnomalySignatureEngine)
    وتكامله مع خدمة الكشف (DetectionService) لالتقاط أنماط الهجوم خارج توزيع
    التدريب (CICIDS2017) مثل SYN Flood، دون المساس بتصنيف الحركة السليمة.

الهدف:
    ضمان أن النظام قادر على:
    - رفع تنبؤ ML الحميد إلى هجوم عند مطابقة توقيع SYN Flood حقيقي
    - عدم إطلاق إنذارات كاذبة على الحركة السليمة أو البيانات الناقصة
    - احترام الإعدادات القابلة للتكوين (عتبات الحساسية) بدقة
    - تمرير التجاوز الناتج عن التوقيعات عبر مسار الكشف الكامل

المتطلبات المرتبطة:
    FR-SRV-01: خدمة الكشف عن الهجمات
    NFR-...: قابلية ضبط الحساسية دون تغيير الشيفرة

================================================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

from config.settings import Settings
from core.entities.model_record import ModelRecord
from ml.anomaly_signature import (
    AnomalySignatureEngine,
    LOW_CONFIDENCE_ATTACK_TYPE,
    PORT_SCAN_ATTACK_TYPE,
    SYN_FLOOD_ATTACK_TYPE,
)
from services.container import Container

# قيم تدفق SYN Flood الحقيقي الملتقط عبر حلقة الاسترجاع (Loopback)
SYN_FLOOD_PAYLOAD: Final[dict[str, float]] = {
    "Destination Port": 9999.0,
    "Flow Duration": 5985110.9981536865,
    "Total Fwd Packets": 383.0,
    "Total Backward Packets": 383.0,
    "SYN Flag Count": 383.0,
    "RST Flag Count": 383.0,
    "ACK Flag Count": 383.0,
    "Total Length of Fwd Packets": 0.0,
    "Total Length of Bwd Packets": 0.0,
}

NORMAL_FLOW_PAYLOAD: Final[dict[str, float]] = {
    "Destination Port": 443.0,
    "Flow Duration": 120000.0,
    "Total Fwd Packets": 12.0,
    "Total Backward Packets": 15.0,
    "SYN Flag Count": 1.0,
    "ACK Flag Count": 20.0,
    "Total Length of Fwd Packets": 4800.0,
    "Total Length of Bwd Packets": 9200.0,
}


# ================================================================================
# القسم 1: تركيب (Fixtures)
# ================================================================================

@pytest.fixture()
def container(db: Any) -> Container:
    """يبني حاوية DI معزولة بقاعدة بيانات مؤقتة."""
    return Container(db=db)


@pytest.fixture()
def benign_labeled_model(container: Container, tmp_path: Path) -> ModelRecord:
    """
    يسجل نموذجًا حميدًا لأغراض الاختبار.

    النموذج عبارة عن شجرة قرار عميقة واحدة تدرب بحيث يصنف أي منفذ أقل من 40000
    بأنه حميد — بما في ذلك منفذ تدفق SYN Flood (9999). وبما أن خصائص النموذج
    لا تشمل عداد SYN، فإن قرار الحميدة يأتي من المنفذ فقط بينما يلتقط محرك
    التوقيعات نمط SYN Flood بشكل مستقل.
    """
    feature_names: Final[list[str]] = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "SYN Flag Count",
    ]
    ports = np.linspace(0, 100000, 300)
    x_matrix = pd.DataFrame(
        {
            "Destination Port": ports,
            "Flow Duration": np.zeros_like(ports),
            "Total Fwd Packets": np.zeros_like(ports),
            "SYN Flag Count": np.zeros_like(ports),
        }
    )
    y_vector = (ports > 40000).astype(int)
    clf = DecisionTreeClassifier(max_depth=1, random_state=0).fit(x_matrix, y_vector)

    model_path: Final[Path] = tmp_path / "benign_labeled.joblib"
    joblib.dump(clf, model_path)

    record = container.model_service.register_model("signature-test-model", str(model_path), "random_forest", "1.0")
    container.model_service.activate(record.id)
    return record


# ================================================================================
# القسم 2: اختبارات وحدة محرك التوقيعات
# ================================================================================

class TestAnomalySignatureEngine:
    """اختبارات سلوك محرك التوقيعات في عزلة تامة."""

    def test_syn_flood_flow_is_flagged(self) -> None:
        """FR-SRV-01: تدفق SYN Flood يرفع إنذار هجوم بهوية SYN Flood."""
        hit = AnomalySignatureEngine().assess(SYN_FLOOD_PAYLOAD)
        assert hit.is_attack
        assert hit.attack_type == SYN_FLOOD_ATTACK_TYPE
        assert hit.confidence == pytest.approx(0.9)
        assert "signature override" in hit.reason

    def test_normal_flow_not_flagged(self) -> None:
        """الحركة السليمة (SYN واحد مع حمولة) لا تُطلق أي توقيع."""
        hit = AnomalySignatureEngine().assess(NORMAL_FLOW_PAYLOAD)
        assert not hit.is_attack

    def test_syn_flood_with_large_payload_not_flagged(self) -> None:
        """تدفق يحمل عدد SYNs كبيرًا لكن بحمولة حقيقية لا يُعتبر SYN Flood."""
        payload = dict(SYN_FLOOD_PAYLOAD)
        payload["Total Length of Fwd Packets"] = 20000.0
        payload["Total Length of Bwd Packets"] = 30000.0
        hit = AnomalySignatureEngine().assess(payload)
        assert not hit.is_attack

    def test_syn_count_below_threshold_not_flagged(self) -> None:
        """عدد SYNs أقل من الحد الأدنى لا يرفع إنذارًا."""
        payload = dict(SYN_FLOOD_PAYLOAD)
        payload["SYN Flag Count"] = 10.0
        hit = AnomalySignatureEngine().assess(payload)
        assert not hit.is_attack

    def test_missing_signature_features_no_false_positive(self) -> None:
        """غياب الخصائص الحرجة يمنع إطلاق التوقيع (حماية من البيانات الناقصة)."""
        payload = dict(SYN_FLOOD_PAYLOAD)
        del payload["SYN Flag Count"]
        hit = AnomalySignatureEngine().assess(payload)
        assert not hit.is_attack

    def test_disabled_engine_never_fires(self) -> None:
        """تعطيل المحرك عبر الإعدادات يمنع كل التوقيعات."""
        settings = Settings(signature_engine_enabled=False)
        hit = AnomalySignatureEngine(settings=settings).assess(SYN_FLOOD_PAYLOAD)
        assert not hit.is_attack

    def test_syn_threshold_is_configurable(self) -> None:
        """رفع حد الحساسية عبر الإعدادات يمنع إطلاق توقيع على تدفق أصغر."""
        settings = Settings(signature_syn_flood_min_syn=500)
        hit = AnomalySignatureEngine(settings=settings).assess(SYN_FLOOD_PAYLOAD)
        assert not hit.is_attack

    def test_low_confidence_override_fires_when_configured(self) -> None:
        """تفعيل عتبة المراجعة يرفع تنبؤ الحميدة منخفض الثقة إلى هجوم."""
        settings = Settings(signature_low_confidence_benign_threshold=0.95)
        hit = AnomalySignatureEngine(settings=settings).assess(
            NORMAL_FLOW_PAYLOAD, ml_benign_confidence=0.5
        )
        assert hit.is_attack
        assert hit.attack_type == LOW_CONFIDENCE_ATTACK_TYPE

    def test_low_confidence_override_respects_threshold(self) -> None:
        """ثقة الحميدة فوق العتبة لا تطلق إنذار المراجعة."""
        settings = Settings(signature_low_confidence_benign_threshold=0.95)
        hit = AnomalySignatureEngine(settings=settings).assess(
            NORMAL_FLOW_PAYLOAD, ml_benign_confidence=0.98
        )
        assert not hit.is_attack

    def test_confidence_override_disabled_by_default(self) -> None:
        """عتبة المراجعة معطلة افتراضيًا فلا يطلق إنذارًا دون تفعيل."""
        hit = AnomalySignatureEngine().assess(NORMAL_FLOW_PAYLOAD, ml_benign_confidence=0.1)
        assert not hit.is_attack

    def test_port_scan_detected_after_threshold(self) -> None:
        """
        فحص المنافذ: مسح سريع يستهدف منافذ مختلفة من نفس المصدر لنفس الوجهة
        يُكتشف عند بلوغ عدد المنافذ المميزة الحد الأدنى (محاكاة nmap -F).
        """
        engine = AnomalySignatureEngine(
            settings=Settings(
                signature_port_scan_min_dst_ports=10,
                signature_port_scan_window_seconds=60,
                signature_port_scan_cooldown_seconds=0,
            )
        )
        base = dict(NORMAL_FLOW_PAYLOAD)
        for i in range(9):
            base["Destination Port"] = float(1000 + i)
            hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=1000.0 + i)
            assert not hit.is_attack, f"فشل عند المنفذ {i}"
        base["Destination Port"] = 9999.0
        hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=1000.0 + 9)
        assert hit.is_attack
        assert hit.attack_type == PORT_SCAN_ATTACK_TYPE
        assert "distinct destination ports" in hit.reason

    def test_port_scan_requires_distinct_ports(self) -> None:
        """تكرار نفس المنفذ (نشاط عادي) لا يُحتسب كفحص منافذ."""
        engine = AnomalySignatureEngine(
            settings=Settings(
                signature_port_scan_min_dst_ports=30,
                signature_port_scan_window_seconds=60,
                signature_port_scan_cooldown_seconds=0,
            )
        )
        base = dict(NORMAL_FLOW_PAYLOAD)
        base["Destination Port"] = 443.0
        for i in range(25):
            hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=2000.0 + i)
            assert not hit.is_attack

    def test_port_scan_window_expiry_resets_count(self) -> None:
        """المنافذ المسجلة قبل النافذة الزمنية لا تُحتسب في العد."""
        engine = AnomalySignatureEngine(
            settings=Settings(
                signature_port_scan_min_dst_ports=10,
                signature_port_scan_window_seconds=60,
                signature_port_scan_cooldown_seconds=0,
            )
        )
        base = dict(NORMAL_FLOW_PAYLOAD)
        for i in range(9):
            base["Destination Port"] = float(3000 + i)
            engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=3000.0 + i)
        # انقضاء النافذة الزمنية ثم منفذ جديد واحد فقط
        hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=3100.0)
        assert not hit.is_attack

    def test_port_scan_requires_endpoints(self) -> None:
        """غياب عنواني المصدر والوجهة يمنع تفعيل تتبع الفحص (لا إنذار كاذب)."""
        engine = AnomalySignatureEngine(
            settings=Settings(
                signature_port_scan_min_dst_ports=10,
                signature_port_scan_window_seconds=60,
                signature_port_scan_cooldown_seconds=0,
            )
        )
        base = dict(NORMAL_FLOW_PAYLOAD)
        for i in range(20):
            base["Destination Port"] = float(4000 + i)
            hit = engine.assess(base, now=4000.0 + i)
            assert not hit.is_attack

    def test_port_scan_threshold_is_configurable(self) -> None:
        """رفع عتبة المنافذ عبر الإعدادات يمنع إنذار فحص أصغر."""
        settings = Settings(
            signature_port_scan_min_dst_ports=100,
            signature_port_scan_window_seconds=60,
            signature_port_scan_cooldown_seconds=0,
        )
        engine = AnomalySignatureEngine(settings=settings)
        base = dict(NORMAL_FLOW_PAYLOAD)
        for i in range(20):
            base["Destination Port"] = float(5000 + i)
            hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=5000.0 + i)
            assert not hit.is_attack

    def test_port_scan_cooldown_suppresses_repeat_fires(self) -> None:
        """
        فترة التهدئة: بعد إطلاق إنذار الفحص، تُكبَت الإطلاقات المتكررة لنفس الزوج
        حتى تمر فترة التهدئة — فيحد ذلك من سيل الإنذارات الصادر عن مسح واحد مستمر.
        """
        engine = AnomalySignatureEngine(
            settings=Settings(
                signature_port_scan_min_dst_ports=10,
                signature_port_scan_window_seconds=1000,
                signature_port_scan_cooldown_seconds=300,
            )
        )
        base = dict(NORMAL_FLOW_PAYLOAD)
        fired_on: int = -1
        for i in range(10):
            base["Destination Port"] = float(6000 + i)
            hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=6000.0 + i)
            if hit.is_attack:
                fired_on = i
        assert fired_on == 9
        # ضمن فترة التهدئة: منفذ مميز جديد لا يطلق إنذارًا ثانيًا
        base["Destination Port"] = 9999.0
        hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=6100.0)
        assert not hit.is_attack
        # بعد انقضاء فترة التهدئة: منفذ مميز جديد يطلق الإنذار مجددًا
        base["Destination Port"] = 7000.0
        hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=6400.0)
        assert hit.is_attack
        assert hit.attack_type == PORT_SCAN_ATTACK_TYPE

    def test_reset_clears_scan_tracking(self) -> None:
        """
        إعادة التعيين تمسح حالة تتبع الفحص بحيث يُكشف مسح جديد فورًا رغم فترة التهدئة
        — وهو السلوك المطلوب عند فحص كل ملف CSV/PCAP كدفعة مستقلة.
        """
        engine = AnomalySignatureEngine(
            settings=Settings(
                signature_port_scan_min_dst_ports=10,
                signature_port_scan_window_seconds=1000,
                signature_port_scan_cooldown_seconds=300,
            )
        )
        base = dict(NORMAL_FLOW_PAYLOAD)
        for i in range(10):
            base["Destination Port"] = float(8000 + i)
            engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=8000.0 + i)
        # ضمن فترة التهدئة: منفذ مميز جديد لا يطلق إنذارًا
        base["Destination Port"] = 9999.0
        hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=8010.0)
        assert not hit.is_attack
        # بعد إعادة التعيين: دفعة مسح جديدة تُكشف فورًا دون انتظار فترة التهدئة
        engine.reset()
        for i in range(9):
            base["Destination Port"] = float(9000 + i)
            engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=8020.0 + i)
        base["Destination Port"] = 9500.0
        hit = engine.assess(base, source_ip="10.0.0.1", destination_ip="192.168.126.1", now=8029.0)
        assert hit.is_attack
        assert hit.attack_type == PORT_SCAN_ATTACK_TYPE


# ================================================================================
# القسم 3: اختبارات التكامل عبر DetectionService
# ================================================================================

class TestSignatureIntegration:
    """اختبارات مرور التوقيعات عبر مسار الكشف الكامل."""

    def test_syn_flood_flow_flagged_through_detection_service(
        self, container: Container, benign_labeled_model: ModelRecord
    ) -> None:
        """
        FR-SRV-01: رغم أن النموذج يصنف التدفق حميدًا (منفذ 9999 < 40000)،
        يرفع محرك التوقيعات النتيجة إلى هجوم SYN Flood عبر المسار الكامل.
        """
        result = container.detection_service.run(
            benign_labeled_model.id,
            SYN_FLOOD_PAYLOAD,
            source_type="live",
            source_ip="127.0.0.1",
            destination_ip="127.0.0.1",
        )
        assert result.prediction != 0
        assert result.attack_type == SYN_FLOOD_ATTACK_TYPE
        assert "signature override" in result.attack_reason
        assert result.detection is not None
        assert result.detection.prediction != 0

    def test_normal_flow_stays_benign_through_detection_service(
        self, container: Container, benign_labeled_model: ModelRecord
    ) -> None:
        """الحركة السليمة تبقى حميدة ولا يتدخل أي توقيع."""
        result = container.detection_service.run(
            benign_labeled_model.id,
            NORMAL_FLOW_PAYLOAD,
            source_type="live",
            source_ip="10.0.0.5",
            destination_ip="10.0.0.9",
        )
        assert result.prediction == 0
        assert result.attack_type == ""

    def test_port_scan_flagged_through_detection_service(
        self, container: Container, benign_labeled_model: ModelRecord
    ) -> None:
        """
        FR-SRV-01: محاكاة nmap -F — مسح 40 منفذًا مختلفًا من مصدر واحد لنفس
        الوجهة عبر مسار الكشف الكامل يرفع إنذار Port Scan على التدفق الأربعين.
        """
        base = dict(NORMAL_FLOW_PAYLOAD)
        last_result = None
        for i in range(40):
            base["Destination Port"] = float(1000 + i)
            last_result = container.detection_service.run(
                benign_labeled_model.id,
                base,
                source_type="live",
                source_ip="10.0.0.50",
                destination_ip="192.168.126.1",
            )
        assert last_result is not None
        assert last_result.prediction != 0
        assert last_result.attack_type == PORT_SCAN_ATTACK_TYPE
        assert "Port scan signature override" in last_result.attack_reason
