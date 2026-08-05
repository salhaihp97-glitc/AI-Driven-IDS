"""
================================================================================
 وحدة اختبار طبقة الالتقاط ومعالجة التدفقات
 Capture Layer & Flow Processing — Test Suite
================================================================================

الوصف:
    تتحقق هذه الاختبارات من سلامة وكفاءة مكونات التقاط حزم الشبكة وتجميع
    التدفقات (Flow Assembler) وحساب الخصائص الإحصائية (Feature Calculator).

الهدف:
    ضمان أن النظام قادر على:
    - استخراج التدفقات من ملفات PCAP
    - الالتقاط الحي لحركة الشبكة
    - حساب الخصائص الإحصائية المطلوبة لنماذج ML
    - التعامل الآمن مع الملفات التالفة والمدخلات غير الصالحة

المتطلبات المرتبطة:
    FR-CAP-01: استخراج التدفقات من ملفات PCAP
    FR-CAP-02: الالتقاط الحي لحركة الشبكة
    FR-CAP-03: حساب خصائص CICFlowMeter
    NFR-CAP-01: التعامل الآمن مع الأخطاء دون تعطل النظام

================================================================================
"""

from __future__ import annotations

import dataclasses
import os
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Final
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from capture.cicflowmeter_live_capture_service import CICFlowMeterLiveCaptureService, _QueueWriter
from capture.flow import Flow, PacketObservation
from capture.flow_assembler import FlowAssembler
from capture.flow_feature_calculator import FlowFeatureCalculator, FlowFeatures
from capture.live_capture_service import LiveCaptureService
from config.settings import get_settings
from core.entities.detection import Detection
from core.exceptions import ConfigurationError
from services.detection_service import DetectionResult


# ================================================================================
# القسم 1: اختبارات PacketObservation — كائن ملاحظة الحزمة
# ================================================================================

class TestPacketObservation:
    """
    FR-CAP-01: التحقق من إنشاء كائن PacketObservation بجميع حالات الأعلام.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_create_minimal_packet(self) -> None:
        """إنشاء حزمة بأقل عدد من المعاملات — يجب أن تعمل بالقيم الافتراضية."""
        pkt = PacketObservation(timestamp=1.0, size_bytes=60, is_forward=True)
        assert pkt.timestamp == 1.0
        assert pkt.size_bytes == 60
        assert pkt.is_forward is True
        assert pkt.syn is False
        assert pkt.ack is False
        assert pkt.window_size == 0

    def test_create_full_packet(self) -> None:
        """إنشاء حزمة بجميع الأعلام — يجب أن تحتفظ بالقيم الممررة."""
        pkt = PacketObservation(
            timestamp=2.5, size_bytes=1400, is_forward=False,
            syn=True, ack=True, rst=False, fin=True,
            psh=False, urg=True, ece=False, cwr=False,
            window_size=64240, header_length=20,
        )
        assert pkt.timestamp == 2.5
        assert pkt.size_bytes == 1400
        assert pkt.is_forward is False
        assert pkt.syn is True
        assert pkt.ack is True
        assert pkt.fin is True
        assert pkt.urg is True
        assert pkt.window_size == 64240
        assert pkt.header_length == 20

    def test_packet_is_frozen(self) -> None:
        """PacketObservation يجب أن يكون كائنًا غير قابل للتعديل (immutable)."""
        pkt = PacketObservation(timestamp=1.0, size_bytes=60, is_forward=True)
        with pytest.raises(Exception):
            pkt.timestamp = 2.0  # type: ignore[misc]


# ================================================================================
# القسم 2: اختبارات Flow — كائن التدفق
# ================================================================================

class TestFlow:
    """
    FR-CAP-01: التحقق من إنشاء وإدارة كائن التدفق Flow.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_create_empty_flow(self) -> None:
        """إنشاء تدفق فارغ — يجب أن يكون خاليًا من الحزم."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        assert flow.is_empty is True
        assert flow.last_timestamp == 0.0
        assert len(flow.packets) == 0

    def test_add_packet_updates_timestamps(self) -> None:
        """إضافة حزم يجب أن يحدّث last_timestamp."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow.add_packet(PacketObservation(timestamp=10.0, size_bytes=60, is_forward=True))
        assert flow.last_timestamp == 10.0

        flow.add_packet(PacketObservation(timestamp=20.0, size_bytes=100, is_forward=True))
        assert flow.last_timestamp == 20.0

    def test_add_multiple_packets(self) -> None:
        """إضافة حزم متعددة — يجب أن تتراكم في قائمة packets."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        for i in range(5):
            flow.add_packet(PacketObservation(timestamp=float(i), size_bytes=60, is_forward=True))
        assert len(flow.packets) == 5
        assert flow.is_empty is False

    def test_flow_empty_no_packets(self) -> None:
        """تدفق بدون حزم — is_empty == True."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        assert flow.is_empty is True


# ================================================================================
# القسم 3: اختبارات FlowAssembler — مجمّع التدفقات
# ================================================================================

class TestFlowAssembler:
    """
    FR-CAP-01: التحقق من تجميع التدفقات ثنائية الاتجاه.
    FR-CAP-02: التحقق من الفصل بين التدفقات المختلفة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_groups_bidirectional_traffic(self) -> None:
        """
        FR-CAP-01: التحقق من أن المجمّع يدمج الحزم الأمامية والخلفية
        لنفس الجلسة في تدفق واحد.
        """
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6, timestamp=1.0, size_bytes=60, syn=True)
        assembler.add_packet("10.0.0.2", "10.0.0.1", 80, 1000, 6, timestamp=1.1, size_bytes=60, syn=True, ack=True)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6, timestamp=1.2, size_bytes=100, ack=True)
        assert assembler.active_flow_count == 1
        flows = assembler.flush_all()
        assert len(flows) == 1
        assert len(flows[0].packets) == 3

    def test_separates_different_flows(self) -> None:
        """
        FR-CAP-01: التحقق من أن الجلسات المختلفة تُفصل إلى تدفقات مستقلة.
        """
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6, timestamp=1.0, size_bytes=60)
        assembler.add_packet("10.0.0.5", "10.0.0.9", 2000, 443, 6, timestamp=1.0, size_bytes=60)
        assert assembler.active_flow_count == 2

    def test_idle_timeout_evicts_only_stale_flows(self) -> None:
        """
        FR-CAP-02: التحقق من أن المهلة الزمنية تطرد فقط التدفقات القديمة.
        """
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6, timestamp=0.0, size_bytes=60)
        assembler.add_packet("10.0.0.5", "10.0.0.9", 2000, 443, 6, timestamp=100.0, size_bytes=60)
        idle_flows = assembler.pop_idle_flows(now=100.5)
        assert len(idle_flows) == 1
        assert idle_flows[0].src_ip == "10.0.0.1"
        assert assembler.active_flow_count == 1

    def test_flush_all_empties_assembler(self) -> None:
        """flush_all يجب أن يفرغ جميع التدفقات من المجمّع."""
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6, timestamp=1.0, size_bytes=60)
        assembler.add_packet("10.0.0.5", "10.0.0.9", 2000, 443, 6, timestamp=1.0, size_bytes=60)
        assert assembler.active_flow_count == 2
        flows = assembler.flush_all()
        assert len(flows) == 2
        assert assembler.active_flow_count == 0

    def test_canonical_key_determinism(self) -> None:
        """
        FR-CAP-01: التحقق من أن _canonical_key يُعيد نفس المفتاح
        بغض النظر عن ترتيب IP/Port.
        """
        key1 = FlowAssembler._canonical_key("10.0.0.1", "10.0.0.2", 1000, 80, 6)
        key2 = FlowAssembler._canonical_key("10.0.0.2", "10.0.0.1", 80, 1000, 6)
        assert key1 == key2

    def test_no_idle_flows_when_all_active(self) -> None:
        """عندما تكون جميع التدفقات نشطة، لا يجب طرد أي منها."""
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6, timestamp=10.0, size_bytes=60)
        idle = assembler.pop_idle_flows(now=12.0)  # 2 ثانية فقط — ضمن المهلة
        assert len(idle) == 0
        assert assembler.active_flow_count == 1

    def test_thread_safety(self) -> None:
        """
        NFR-CAP-01: اختبار أمان الخيوط — إضافة حزم متزامنة من 20 خيطًا.
        """
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        total_workers = 20

        def worker(worker_id: int) -> None:
            assembler.add_packet(
                f"10.0.{worker_id}.1", f"10.0.{worker_id}.2",
                1000 + worker_id, 80, 6,
                timestamp=float(worker_id), size_bytes=60,
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(total_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert assembler.active_flow_count == total_workers


# ================================================================================
# القسم 4: اختبارات FlowFeatureCalculator — حاسب الخصائص الإحصائية
# ================================================================================

class TestFlowFeatureCalculator:
    """
    FR-CAP-03: التحقق من حساب الخصائص الإحصائية لتدفقات الشبكة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    @pytest.fixture()
    def sample_three_packet_flow(self) -> Flow:
        """إنشاء تدفق نموذجي بثلاث حزم للاختبارات."""
        assembler = FlowAssembler(idle_timeout_seconds=5.0)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6,
                             timestamp=1.0, size_bytes=60, syn=True)
        assembler.add_packet("10.0.0.2", "10.0.0.1", 80, 1000, 6,
                             timestamp=1.1, size_bytes=1400, syn=True, ack=True, window_size=64240)
        assembler.add_packet("10.0.0.1", "10.0.0.2", 1000, 80, 6,
                             timestamp=1.2, size_bytes=52, ack=True)
        return assembler.flush_all()[0]

    def test_produces_all_required_features(self, sample_three_packet_flow: Flow) -> None:
        """التحقق من أن الخصائص المُنتَجة تحتوي على جميع المفاتيح المطلوبة."""
        features = FlowFeatureCalculator().compute(sample_three_packet_flow)
        # القائمة الكاملة للخصائص المتوقعة — تطابق ما يُنتجه FlowFeatureCalculator
        actual_keys = set(features.features.keys())
        core_keys: Final[set[str]] = {
            "Destination Port", "Protocol", "Flow Duration",
            "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Mean", "Bwd Packet Length Mean",
            "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Flow IAT Std",
            "Fwd IAT Mean", "Bwd IAT Mean",
            "SYN Flag Count", "ACK Flag Count", "RST Flag Count",
            "Average Packet Size", "Init_Win_bytes_forward",
            "FIN Flag Count", "PSH Flag Count", "URG Flag Count",
            "Down/Up Ratio", "Fwd PSH Flags",
        }
        assert core_keys.issubset(actual_keys), f"المفاتيح المفقودة: {core_keys - actual_keys}"

    def test_correct_packet_counts(self, sample_three_packet_flow: Flow) -> None:
        """التحقق من الأعداد الصحيحة للحزم الأمامية والخلفية."""
        features = FlowFeatureCalculator().compute(sample_three_packet_flow)
        assert features.features["Total Fwd Packets"] == 2.0
        assert features.features["Total Backward Packets"] == 1.0
        assert features.features["SYN Flag Count"] == 2.0

    def test_raises_on_empty_flow(self) -> None:
        """
        NFR-CAP-01: التحقق من أن حساب الخصائص على تدفق فارغ يرفع خطأ.
        """
        empty_flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, protocol=6)
        with pytest.raises(ValueError, match=".*"):
            FlowFeatureCalculator().compute(empty_flow)

    def test_single_packet_flow(self) -> None:
        """التدفق بحزمة واحدة — يجب أن تنتج خصائص مع مدة = 0."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow.add_packet(PacketObservation(timestamp=5.0, size_bytes=100, is_forward=True))
        features = FlowFeatureCalculator().compute(flow)
        assert features.features["Flow Duration"] == 0.0
        assert features.features["Total Fwd Packets"] == 1.0
        assert features.features["Total Backward Packets"] == 0.0
        assert features.features["Destination Port"] == 80.0
        assert features.features["Protocol"] == 6.0

    def test_compute_many_skips_empty_flows(self) -> None:
        """compute_many يجب أن يتخطى التدفقات الفارغة دون تعطل."""
        flow1 = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow1.add_packet(PacketObservation(timestamp=1.0, size_bytes=60, is_forward=True))
        flow2 = Flow(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=2000, dst_port=443, protocol=6)  # empty
        results = FlowFeatureCalculator().compute_many([flow1, flow2])
        assert len(results) == 1
        assert isinstance(results[0], FlowFeatures)

    def test_compute_many_all_empty(self) -> None:
        """compute_many مع كل التدفقات فارغة — يجب أن يعيد قائمة فارغة."""
        flow1 = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow2 = Flow(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=2000, dst_port=443, protocol=6)
        results = FlowFeatureCalculator().compute_many([flow1, flow2])
        assert len(results) == 0

    def test_flow_features_dataclass_fields(self) -> None:
        """التحقق من أن FlowFeatures يحتوي على جميع الحقول المطلوبة."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow.add_packet(PacketObservation(timestamp=1.0, size_bytes=60, is_forward=True))
        features = FlowFeatureCalculator().compute(flow)
        assert features.src_ip == "1.1.1.1"
        assert features.dst_ip == "2.2.2.2"
        assert features.src_port == 1000
        assert features.dst_port == 80
        assert features.protocol == 6

    def test_feature_calculator_forward_backward_flag_counts(self) -> None:
        """التحقق من أعداد أعلام TCP للأمام والخلف."""
        fwd_flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        fwd_flow.add_packet(PacketObservation(timestamp=1.0, size_bytes=60, is_forward=True, syn=True, ack=False))
        fwd_flow.add_packet(PacketObservation(timestamp=2.0, size_bytes=100, is_forward=True, ack=True, psh=True))
        fwd_flow.add_packet(PacketObservation(timestamp=3.0, size_bytes=50, is_forward=False, ack=True, rst=True))
        features = FlowFeatureCalculator().compute(fwd_flow)
        assert features.features["Fwd PSH Flags"] == 1.0
        assert features.features["RST Flag Count"] == 1.0


# ================================================================================
# القسم 4ب: اختبارات اتفاقية CICIDS2017 — خصائص طبقة النقل
# ================================================================================

class TestCICIDS2017TransportConvention:
    """
    FR-CAP-03 / FR-ML-01: الالتزام باتفاقية CICIDS2017 المُثبتة هندسيًا.

    الميزات تقيس طبقة النقل فقط:
      - min_seg_size_forward = أصغر رأس TCP أمامي (وليست أصغر حمولة)
      - Down/Up Ratio        = قسمة عددية صحيحة bwd // fwd
      - Active/Idle          = أصفار لتدفق أحادي الدفعة (عتبة 5s)؛ الدفعة الأخيرة
                               غير مُسجلة (CICFlowMeter لا يستدعي endActiveIdleTime)
    """

    @staticmethod
    def _flow_with(packets: list[PacketObservation]) -> Flow:
        flow = Flow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol=6)
        for p in packets:
            flow.add_packet(p)
        return flow

    def test_min_seg_size_forward_is_min_transport_header(self) -> None:
        """min_seg_size_forward يجب أن يساوي أصغر رأس نقل أمامي وليس أصغر حمولة."""
        flow = self._flow_with([
            PacketObservation(timestamp=0.0, size_bytes=100, is_forward=True, header_length=40),
            PacketObservation(timestamp=0.001, size_bytes=50, is_forward=True, header_length=32),
            PacketObservation(timestamp=0.002, size_bytes=20, is_forward=True, header_length=32),
        ])
        features = FlowFeatureCalculator().compute(flow)
        # أصغر حمولة هي 20، لكن أصغر رأس نقل هو 32
        assert features.features["Fwd Packet Length Min"] == 20.0
        assert features.features["min_seg_size_forward"] == 32.0
        assert features.features["Fwd Header Length"] == 104.0

    def test_down_up_ratio_is_integer_division(self) -> None:
        """Down/Up Ratio يُحسب كقسمة عددية صحيحة bwd // fwd."""
        flow = self._flow_with([
            PacketObservation(timestamp=float(i) * 0.001, size_bytes=10, is_forward=True)
            for i in range(40)
        ] + [
            PacketObservation(timestamp=float(i) * 0.001 + 0.05, size_bytes=10, is_forward=False)
            for i in range(30)
        ])
        features = FlowFeatureCalculator().compute(flow)
        assert features.features["Total Fwd Packets"] == 40.0
        assert features.features["Total Backward Packets"] == 30.0
        assert features.features["Down/Up Ratio"] == 0.0  # 30 // 40

    def test_active_idle_all_zero_for_single_burst(self) -> None:
        """تدفق أحادي الدفعة (لا فجوات تتجاوز 5s) — Active/Idle كلها أصفار."""
        flow = self._flow_with([
            PacketObservation(timestamp=0.0, size_bytes=10, is_forward=True),
            PacketObservation(timestamp=0.0005, size_bytes=10, is_forward=False),
            PacketObservation(timestamp=0.001, size_bytes=10, is_forward=True),
        ])
        features = FlowFeatureCalculator().compute(flow)
        for key in ("Active Mean", "Active Std", "Active Max", "Active Min",
                    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"):
            assert features.features[key] == 0.0, key

    def test_active_idle_records_only_closed_bursts(self) -> None:
        """فجوة تتجاوز 5s تُسجل الدفعة المُغلقة في Active والفجوة في Idle،
        والدفعة الأخيرة المتعقبة لا تُسجل أبدًا."""
        flow = self._flow_with([
            PacketObservation(timestamp=0.0, size_bytes=10, is_forward=True),
            PacketObservation(timestamp=0.002, size_bytes=10, is_forward=True),   # دفعة 2000µs
            PacketObservation(timestamp=6.0, size_bytes=10, is_forward=False),    # فجوة ~5.998s
            PacketObservation(timestamp=6.004, size_bytes=10, is_forward=False),  # دفعة أخيرة 4000µs
        ])
        features = FlowFeatureCalculator().compute(flow)
        assert features.features["Active Mean"] == 2000.0   # ليست 3000 (لو سُجلت الأخيرة)
        assert features.features["Active Max"] == 2000.0
        assert features.features["Active Std"] == 0.0
        assert features.features["Idle Mean"] == pytest.approx(5_998_000.0, rel=1e-3)
        assert features.features["Idle Max"] == pytest.approx(5_998_000.0, rel=1e-3)

    def test_activity_timeout_is_configurable(self) -> None:
        """NFR-CAP-01: حد نشاط الدفعة (Activity/Idle) قابل للتكوين بدلاً من قيمة صلبة."""
        packets = [
            PacketObservation(timestamp=0.0, size_bytes=10, is_forward=True),
            PacketObservation(timestamp=0.001, size_bytes=10, is_forward=True),   # دفعة أولى 1000µs
            PacketObservation(timestamp=3.0, size_bytes=10, is_forward=True),     # فجوة ~2.999s
            PacketObservation(timestamp=3.001, size_bytes=10, is_forward=True),   # دفعة أخيرة (لا تُسجل)
        ]
        flow = self._flow_with(packets)

        # العتبة الافتراضية 5s → الفجوة لا تغلق دفعة → Active صفر
        default_features = FlowFeatureCalculator().compute(flow)
        assert default_features.features["Active Mean"] == 0.0

        # عتبة مخصصة 2s → الفجوة تغلق الدفعة الأولى (1000µs) وتفتح Idle
        tuned_features = FlowFeatureCalculator(activity_timeout_seconds=2.0).compute(flow)
        assert tuned_features.features["Active Mean"] == 1000.0
        assert tuned_features.features["Idle Mean"] == pytest.approx(2_999_000.0, rel=1e-3)

    def test_flow_protocol_name_shared_helper(self) -> None:
        """NFR-CAP-01: تعيين اسم البروتوكول موحّد عبر دالة مشتركة واحدة."""
        from capture.flow import flow_protocol_name
        assert flow_protocol_name(6) == "TCP"
        assert flow_protocol_name(17) == "UDP"
        assert flow_protocol_name(1) == "Other"
        assert flow_protocol_name(0) == "Other"


# ================================================================================
# القسم 5: اختبارات Extractor Factory — مصنع مستخرج التدفقات
# ================================================================================

class TestFlowExtractorFactory:
    """
    FR-CAP-02: التحقق من إنشاء مستخرج التدفقات المناسب حسب البيئة.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    @patch.dict(os.environ, {}, clear=True)
    def test_default_extractor_is_native(self) -> None:
        """عند عدم وجود متغير AI_IDS_FLOW_EXTRACTOR، يجب استخدام NativeFlowExtractor."""
        from capture.extractor_factory import get_flow_extractor
        from capture.native_flow_extractor import NativeFlowExtractor
        extractor = get_flow_extractor()
        assert isinstance(extractor, NativeFlowExtractor)

    @patch.dict(os.environ, {"AI_IDS_FLOW_EXTRACTOR": "cicflowmeter"})
    def test_cicflowmeter_extractor_pure_python(self) -> None:
        """When set to cicflowmeter mode, the pure-Python adapter is returned."""
        with patch("capture.cicflowmeter_adapter.CICFlowMeterAdapter") as mock_adapter_cls:
            mock_instance = MagicMock()
            mock_adapter_cls.return_value = mock_instance
            from capture.extractor_factory import get_flow_extractor
            extractor = get_flow_extractor()
            mock_adapter_cls.assert_called_once_with()
            assert extractor is mock_instance

    @patch.dict(os.environ, {"AI_IDS_FLOW_EXTRACTOR": "cicflowmeter"}, clear=True)
    def test_cicflowmeter_no_path_needed(self) -> None:
        """CICFlowMeter mode now uses the Python package — no path validation needed."""
        if "AI_IDS_CICFLOWMETER_PATH" in os.environ:
            del os.environ["AI_IDS_CICFLOWMETER_PATH"]
        with patch("capture.cicflowmeter_adapter.CICFlowMeterAdapter") as mock_cls:
            mock_cls.return_value = MagicMock()
            from capture.extractor_factory import get_flow_extractor
            extractor = get_flow_extractor()
            assert extractor is not None

    @patch.dict(os.environ, {"AI_IDS_FLOW_EXTRACTOR": "unknown_mode"})
    def test_unknown_mode_uses_native(self) -> None:
        """وضع غير معروف — يجب أن يستخدم NativeFlowExtractor كوضع افتراضي."""
        from capture.extractor_factory import get_flow_extractor
        from capture.native_flow_extractor import NativeFlowExtractor
        extractor = get_flow_extractor()
        assert isinstance(extractor, NativeFlowExtractor)


# ================================================================================
# القسم 6: اختبارات الالتقاط المباشر (Live Capture) — Native + CICFlowMeter
# ================================================================================

class TestLiveCaptureServiceNative:
    """
    FR-CAP-02: اختبارات الالتقاط المباشر الحي عبر LiveCaptureService (الوضع الأصلي).

    تُبنى حزم Scapy حقيقية (IP/TCP مُحلَّلة من البايتات كما تفعل أداة التشخيص على
    الشبكة) وتُحقن مباشرة في مسار المعالجة عبر _handle_packet — نفس الدالة التي
    يستدعيها خيط PacketSniffer — ثم تُدفَّق التدفقات الخاملة عبر دورة الحياة ذاتها
    التي يستخدمها خيط Flush في الإنتاج.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    @staticmethod
    def _parsed_packet(
        src: str, dst: str, sport: int, dport: int,
        flags: str = "PA", payload: bytes = b"", t: float = 0.0,
    ):
        """يبني حزمة Scapy ثم يعيد تحليلها من بايتاتها لتكون كالحزم الملتقطة فعليًا."""
        from scapy.all import IP, Raw, TCP
        raw = bytes(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload))
        pkt = IP(raw)
        pkt.time = t
        return pkt

    @staticmethod
    def _service(tmp_path: Path, detection_service: Any) -> LiveCaptureService:
        """يبني الخدمة مع توجيه ملفات CSV إلى دليل مؤقت وليس إلى مجلد data الحقيقي."""
        patched = dataclasses.replace(
            get_settings(),
            captured_flows_dir=Path(tmp_path),
            flow_idle_timeout_seconds=2,
        )
        with patch("capture.live_capture_service.get_settings", return_value=patched):
            return LiveCaptureService(detection_service=detection_service)

    @staticmethod
    def _malicious_detection_service() -> MagicMock:
        """خدمة كشف وهمية تعيد نتيجة هجومية ثابتة دون الحاجة لنموذج ML حقيقي."""
        svc = MagicMock()

        def fake_run(*, model_id, raw_features, source_type, source_ip=None,
                     destination_ip=None, **_kwargs):
            return DetectionResult(
                detection=Detection(
                    model_id=model_id,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    prediction=1,
                    confidence=0.95,
                    source_type=source_type,
                    severity="HIGH",
                    attack_type="DDoS",
                    attack_reason="synthetic live packet",
                ),
                missing_features=[],
                alert_created=False,
                prediction=1,
                confidence=0.95,
                attack_type="DDoS",
                attack_reason="synthetic live packet",
            )

        svc.run.side_effect = fake_run
        return svc

    def test_pipeline_ingest_to_recent_flows_and_csv(self, tmp_path: Path) -> None:
        """حزم TCP حقيقية → تجميع تدفق واحد → معالجة → سجل في الذاكرة + ملفات CSV."""
        svc = self._malicious_detection_service()
        service = self._service(tmp_path, svc)
        service._model_id = 7
        service._model_name = "live-native-test"

        service._handle_packet(self._parsed_packet("10.0.0.1", "10.0.0.2", 12345, 80, flags="S", t=1_000_000.0))
        service._handle_packet(self._parsed_packet("10.0.0.2", "10.0.0.1", 80, 12345, flags="SA", t=1_000_000.1))
        service._handle_packet(self._parsed_packet("10.0.0.1", "10.0.0.2", 12345, 80, flags="PA", payload=b"X" * 40, t=1_000_000.2))

        assert service.status["packet_count"] == 3
        assert service.status["active_flows"] == 1
        assert service.status["mode"] == "native"

        idle = service._assembler.pop_idle_flows(now=1_000_100.0)
        service._process_flows(idle)

        records = service.get_recent_flows()
        assert len(records) == 1
        record = records[0]
        assert record.source_ip == "10.0.0.1"
        assert record.destination_ip == "10.0.0.2"
        assert record.protocol == 6
        assert record.prediction == 1
        assert record.confidence == 0.95
        assert record.attack_type == "DDoS"
        assert record.model_name == "live-native-test"

        master = service.get_master_csv_path()
        cleaned = service.get_cleaned_csv_path()
        assert master.exists() and master.stat().st_size > 0
        assert cleaned.exists() and cleaned.stat().st_size > 0
        df = pd.read_csv(cleaned)
        assert not df.empty
        assert df["prediction"].iloc[0] == 1

    def test_handle_packet_extracts_transport_payload(self, tmp_path: Path) -> None:
        """اتفاقية CICIDS2017 في الالتقاط الحي: الحجم = حمولة طبقة النقل، والرأس = رأس النقل."""
        service = self._service(tmp_path, MagicMock())
        service._handle_packet(self._parsed_packet("10.0.0.1", "10.0.0.2", 12345, 80,
                                                   flags="PA", payload=b"A" * 20, t=1.0))
        flow = service._assembler.flush_all()[0]
        obs = flow.packets[0]
        assert obs.size_bytes == 20      # 60 (IP كاملة) - 20 (رأس IP) - 20 (رأس TCP)
        assert obs.header_length == 20   # رأس TCP بدون خيارات
        assert obs.is_forward is True

    def test_handle_packet_udp_and_len_zero_fallback(self, tmp_path: Path) -> None:
        """رأس UDP ثابت (8) مع احتساب الحمولة، ومسار التراجع عندما يكون IP.len صفرًا."""
        from scapy.all import IP, Raw, UDP
        service = self._service(tmp_path, MagicMock())

        raw = bytes(IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=12345) / Raw(b"Z" * 8))
        udp_pkt = IP(raw)
        udp_pkt.time = 2.0
        service._handle_packet(udp_pkt)

        tcp_pkt = self._parsed_packet("10.0.0.1", "10.0.0.2", 12345, 80, flags="PA", payload=b"Q" * 5, t=3.0)
        tcp_pkt[IP].len = 0  # إجبار مسار التراجع إلى طول الحمولة المُحلَّلة
        service._handle_packet(tcp_pkt)

        flows = service._assembler.flush_all()
        udp_flow = next(f for f in flows if f.protocol == 17)
        tcp_flow = next(f for f in flows if f.protocol == 6)
        assert udp_flow.packets[0].size_bytes == 8      # 36 - 20 (IP) - 8 (UDP)
        assert udp_flow.packets[0].header_length == 8
        assert tcp_flow.packets[0].size_bytes == 5      # التراجع إلى len(payload)

    def test_whitelisted_flow_record_is_propagated(self, tmp_path: Path) -> None:
        """نتيجة الكشف الحية تُمرر حقلي whitelisted/blacklisted إلى سجل التدفق."""
        svc = MagicMock()
        svc.run.return_value = DetectionResult(
            detection=Detection(
                model_id=1, source_ip="10.0.0.1", destination_ip="10.0.0.2",
                prediction=0, confidence=1.0, source_type="live",
                severity="", attack_type="", attack_reason="trusted",
                is_whitelisted=True, is_blacklisted=False,
            ),
            missing_features=[], alert_created=False, prediction=0, confidence=1.0,
            is_whitelisted=True, is_blacklisted=False,
        )
        service = self._service(tmp_path, svc)
        service._model_id = 1
        service._model_name = "m"
        service._handle_packet(self._parsed_packet("10.0.0.1", "10.0.0.2", 12345, 80, t=5.0))
        service._process_flows(service._assembler.pop_idle_flows(now=60.0))
        record = service.get_recent_flows()[0]
        assert record.is_whitelisted is True
        assert record.is_blacklisted is False
        assert record.prediction == 0

    def test_process_flows_skipped_without_model(self, tmp_path: Path) -> None:
        """بدون نموذج محدد، يجب ألا تُجرى معالجة التدفقات ولا يُستدعى كشف ML."""
        svc = MagicMock()
        service = self._service(tmp_path, svc)
        service._model_id = None
        service._handle_packet(self._parsed_packet("10.0.0.1", "10.0.0.2", 12345, 80, t=1.0))
        service._process_flows(service._assembler.pop_idle_flows(now=60.0))
        svc.run.assert_not_called()
        assert service.get_recent_flows() == []

    def test_clear_master_csv_purges_files(self, tmp_path: Path) -> None:
        """تنظيف ملفات CSV الحية للوضع الأصلي."""
        service = self._service(tmp_path, MagicMock())
        service.get_master_csv_path().write_text("x")
        service.get_cleaned_csv_path().write_text("y")
        assert service.clear_master_csv() is True
        assert not service.get_master_csv_path().exists()
        assert not service.get_cleaned_csv_path().exists()

    def test_start_rejects_second_start(self, tmp_path: Path) -> None:
        """بدء الالتقاط الحي مرتين متتاليتين يجب أن يرفض بـ ConfigurationError."""
        service = self._service(tmp_path, MagicMock())
        service._sniffer = MagicMock()
        service._sniffer.is_running = True
        with pytest.raises(ConfigurationError):
            service.start("lo", 1, "m")

    def test_start_stop_lifecycle_with_mocked_sniffer(self, tmp_path: Path) -> None:
        """دورة الحياة start/stop تُنسق الحالة وتشغّل خيط Flush دون حزم شبكة حقيقية."""
        svc = self._malicious_detection_service()
        with patch("capture.live_capture_service.PacketSniffer") as sniffer_cls:
            service = self._service(tmp_path, svc)
            sniffer = service._sniffer
            sniffer.is_running = False
            service.start("lo", 7, "live-native-test")
            sniffer.start.assert_called_once_with("lo")
            assert service._flush_thread is not None
            sniffer.is_running = True
            assert service.is_running is True
            service.stop()
            sniffer.stop.assert_called_once()


# ================================================================================
# القسم 6ب: اختبارات الالتقاط المباشر — وضع CICFlowMeter (Python نقي)
# ================================================================================

class TestCICFlowMeterLiveCaptureService:
    """
    FR-CAP-02: اختبارات الالتقاط المباشر عبر CICFlowMeterLiveCaptureService.

    تُبنى FlowSession حقيقية من حزمة cicflowmeter (بنفس معالجة المصنع المؤقتة
    التي يستخدمها start()) وتُحقن حزم Scapy حقيقية عبر _on_packet، ثم تُفرَّغ
    التدفقات المنتهية عبر _flush_completed_flows — دورة الحياة ذاتها لخيط Flush.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    @staticmethod
    def _parsed_tcp_packet(
        src: str, dst: str, sport: int, dport: int,
        flags: str = "PA", payload: bytes = b"", t: float = 0.0,
    ):
        from scapy.all import IP, Raw, TCP
        raw = bytes(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload))
        pkt = IP(raw)
        pkt.time = t
        return pkt

    def _make_service(self, tmp_path: Path, detection_service: Any, csv_analysis_service: Any):
        import cicflowmeter.flow_session as _fs_mod
        from cicflowmeter.flow_session import FlowSession

        patched = dataclasses.replace(
            get_settings(),
            captured_flows_dir=Path(tmp_path),
            cicflowmeter_interval_seconds=2,
        )
        with patch("capture.cicflowmeter_live_capture_service.get_settings", return_value=patched):
            service = CICFlowMeterLiveCaptureService(
                detection_service=detection_service,
                csv_analysis_service=csv_analysis_service,
            )

        service._queue_writer = _QueueWriter(service._completed_flows)
        orig_factory = _fs_mod.output_writer_factory
        orig_expired = getattr(_fs_mod, "EXPIRED_UPDATE", 240)

        def _patched_factory(output_mode: Any, output: Any):
            if output_mode is None:
                return service._queue_writer
            return orig_factory(output_mode, output)

        _fs_mod.output_writer_factory = _patched_factory
        _fs_mod.EXPIRED_UPDATE = 10
        try:
            service._flow_session = FlowSession(output=None, output_mode=None)
        finally:
            _fs_mod.output_writer_factory = orig_factory
            _fs_mod.EXPIRED_UPDATE = orig_expired
        return service

    def test_live_pipeline_with_real_packets(self, tmp_path: Path) -> None:
        """حزم TCP حقيقية ثنائية الاتجاه → FlowSession → CSV + ML + سجل حديث."""
        fake_csv = MagicMock()
        summary = types.SimpleNamespace(
            total_rows=1, attack_count=1, normal_count=0,
            results=[types.SimpleNamespace(
                detection=types.SimpleNamespace(
                    source_ip="192.168.1.10", destination_ip="8.8.8.8",
                    prediction=1, confidence=0.9, severity="HIGH",
                ),
                attack_type="DDoS",
            )],
        )
        fake_csv.analyze.return_value = summary

        service = self._make_service(tmp_path, MagicMock(), fake_csv)
        service._model_id = 7
        service._model_name = "live-cicflowmeter-test"

        now = time.time()
        service._on_packet(self._parsed_tcp_packet("192.168.1.10", "8.8.8.8", 54321, 443,
                                                   flags="PA", payload=b"A" * 64, t=now - 300))
        service._on_packet(self._parsed_tcp_packet("8.8.8.8", "192.168.1.10", 443, 54321,
                                                   flags="PA", payload=b"B" * 64, t=now - 290))

        assert service._packet_count == 2
        assert service.status["flows_in_session"] == 1
        assert service.status["mode"] == "cicflowmeter"

        service._flush_completed_flows()

        assert fake_csv.analyze.called
        master = service.get_master_csv_path()
        cleaned = service.get_cleaned_csv_path()
        assert master.exists() and master.stat().st_size > 0
        assert cleaned.exists() and cleaned.stat().st_size > 0

        records = service.get_recent_flows()
        assert len(records) == 1
        record = records[0]
        assert record.source_ip == "192.168.1.10"
        assert record.destination_ip == "8.8.8.8"
        assert record.prediction == 1
        assert record.attack_type == "DDoS"
        assert record.model_name == "live-cicflowmeter-test"

    def test_start_rejects_second_start(self, tmp_path: Path) -> None:
        """بدء الالتقاط مرتين يجب أن يرفض بـ ConfigurationError."""
        service = self._make_service(tmp_path, MagicMock(), MagicMock())
        service._sniffer = MagicMock()
        service._sniffer.running = True
        with pytest.raises(ConfigurationError):
            service.start("eth0", 1, "m")

    def test_start_raises_when_dependencies_missing(self, tmp_path: Path) -> None:
        """غياب حزم cicflowmeter/scapy يجب أن يُرفض عند بدء التشغيل."""
        service = self._make_service(tmp_path, MagicMock(), MagicMock())
        service._sniffer = MagicMock(running=False)
        with patch.dict(sys.modules, {"cicflowmeter.flow_session": None, "cicflowmeter.writer": None}):
            with pytest.raises(ConfigurationError):
                service.start("eth0", 1, "m")

    def test_clear_master_csv_purges_files(self, tmp_path: Path) -> None:
        """تنظيف ملفات CSV الحية لوضع CICFlowMeter."""
        service = self._make_service(tmp_path, MagicMock(), MagicMock())
        service.get_master_csv_path().write_text("x")
        service.get_cleaned_csv_path().write_text("y")
        assert service.clear_master_csv() is True
        assert not service.get_master_csv_path().exists()
        assert not service.get_cleaned_csv_path().exists()


# ================================================================================
# القسم 7: اختبارات سيناريوهات الأخطاء المحتملة
# ================================================================================

class TestErrorScenarios:
    """
    NFR-CAP-01: التحقق من التعامل الآمن مع السيناريوهات الاستثنائية.
    """

    # أدخل لقطة الشاشة هنا لتوثيق نتيجة الاختبار

    def test_corrupted_pcap_rejection(self) -> None:
        """
        FR-CAP-01: الملفات التالفة — يجب رفضها بشكل آمن.
        يتم اختبار ذلك عبر محاولة تحميل ملف غير موجود.
        """
        from capture.native_flow_extractor import NativeFlowExtractor
        extractor = NativeFlowExtractor()
        with pytest.raises(Exception):
            extractor.extract_flows("nonexistent_file.pcap")

    def test_no_network_interface_handling(self) -> None:
        """
        FR-CAP-02: عدم وجود واجهة شبكة — يجب التعامل معها دون تعطل.
        نختبر هنا إنشاء NativeFlowExtractor الذي يعمل دون واجهة شبكة فعلية.
        """
        from capture.native_flow_extractor import NativeFlowExtractor
        extractor = NativeFlowExtractor()
        # extractor يجب أن يُنشأ دون الحاجة لواجهة شبكة
        assert extractor is not None

    def test_negative_timestamp(self) -> None:
        """
        الطابع الزمني السلبي — يجب أن يعمل بشكل طبيعي دون تعطل.
        """
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow.add_packet(PacketObservation(timestamp=-1.0, size_bytes=60, is_forward=True))
        flow.add_packet(PacketObservation(timestamp=0.0, size_bytes=100, is_forward=True))
        assert flow.last_timestamp == 0.0
        features = FlowFeatureCalculator().compute(flow)
        assert features.features["Flow Duration"] == 1_000_000.0  # 1 second in microseconds

    def test_zero_size_packet(self) -> None:
        """حزمة بحجم صفر — يجب ألا تسبب قسمة على صفر."""
        flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6)
        flow.add_packet(PacketObservation(timestamp=1.0, size_bytes=0, is_forward=True))
        features = FlowFeatureCalculator().compute(flow)
        assert features.features["Total Length of Fwd Packets"] == 0.0

    def test_extract_from_pcap_mixed_tcp_udp(self, tmp_path: Path) -> None:
        """
        FR-CAP-01: استخراج التدفقات من ملف PCAP يحتوي حزم TCP و UDP معًا.
        انحدار: كان هناك خطأ NameError (self غير معرف) عند مواجهة حزم UDP
        داخل دالة _read_packets الثابتة في NativeFlowExtractor.
        """
        from scapy.all import UDP, IP, TCP, Ether, wrpcap
        from capture.native_flow_extractor import NativeFlowExtractor

        packets = [
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=80, flags="S", window=64240),
            Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=80, dport=50000, flags="SA"),
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=80, flags="A"),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53) / b"\x00\x01\x00\x01",
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=12345) / b"\x00\x01\x00\x01",
        ]
        pcap_path = tmp_path / "mixed_tcp_udp.pcap"
        wrpcap(str(pcap_path), packets)

        extractor = NativeFlowExtractor()
        flows = extractor.extract_from_pcap(str(pcap_path))
        assert len(flows) > 0
        assert all(hasattr(flow, "features") for flow in flows)
