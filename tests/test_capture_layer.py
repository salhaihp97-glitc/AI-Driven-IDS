"""
===============================================================================
 وحدة اختبار طبقة الالتقاط ومعالجة التدفقات — CICFlowMeter
 Capture Layer & Flow Processing — Test Suite (CICFlowMeter-only)
===============================================================================

الوصف:
    تتحقق هذه الاختبارات من سلامة وكفاءة مكونات التقاط حزم الشبكة ومعالجة
    التدفقات. CICFlowMeter (Python نقي) هو المحرك الوحيد لاستخراج التدفقات
    في الالتقاط الحي وتحليل ملفات PCAP — لا يوجد مسار استخراج آخر.

الهدف:
    ضمان أن النظام قادر على:
    - استخراج التدفقات من ملفات PCAP عبر CICFlowMeterAdapter
    - الالتقاط الحي لحركة الشبكة عبر CICFlowMeterLiveCaptureService
    - تمرير التدفقات المستخرجة للمودل للتصنيف
    - التعامل الآمن مع الملفات التالفة والمدخلات غير الصالحة

المتطلبات المرتبطة:
    FR-CAP-01: استخراج التدفقات من ملفات PCAP
    FR-CAP-02: الالتقاط الحي لحركة الشبكة
    FR-CAP-03: حساب خصائص CICFlowMeter
    NFR-CAP-01: التعامل الآمن مع الأخطاء دون تعطل النظام

===============================================================================
"""

from __future__ import annotations

import dataclasses
import os
import sys
import time
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from capture.cicflowmeter_adapter import CICFlowMeterAdapter
from capture.cicflowmeter_live_capture_service import (
    CICFlowMeterLiveCaptureService,
    LiveFlowRecord,
    _QueueWriter,
)
from capture.flow_models import FlowFeatures, flow_protocol_name
from config.settings import get_settings
from core.exceptions import ConfigurationError


# ================================================================================
# القسم 1: اختبارات FlowFeatures — عقد البيانات المشترك
# ================================================================================

class TestFlowFeaturesContract:
    """FR-CAP-03: التحقق من عقد FlowFeatures الذي تستهلكه خطوط ML وPCAP والالتقاط الحي."""

    def test_construct_full(self) -> None:
        ff = FlowFeatures(
            src_ip="192.168.1.1", dst_ip="8.8.8.8",
            src_port=12345, dst_port=443, protocol=6,
            features={"Flow Duration": 10.0},
        )
        assert ff.src_ip == "192.168.1.1"
        assert ff.dst_ip == "8.8.8.8"
        assert ff.src_port == 12345
        assert ff.dst_port == 443
        assert ff.protocol == 6
        assert ff.features == {"Flow Duration": 10.0}

    def test_is_frozen(self) -> None:
        ff = FlowFeatures(
            src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, protocol=6, features={},
        )
        with pytest.raises(Exception):
            ff.src_ip = "9.9.9.9"  # type: ignore[misc]


# ================================================================================
# القسم 2: اختبارات flow_protocol_name — اسم البروتوكول الموحّد
# ================================================================================

class TestFlowProtocolName:
    """NFR-CAP-01: تعيين اسم البروتوكول عبر دالة مشتركة واحدة."""

    def test_mapping(self) -> None:
        assert flow_protocol_name(6) == "TCP"
        assert flow_protocol_name(17) == "UDP"
        assert flow_protocol_name(1) == "Other"
        assert flow_protocol_name(0) == "Other"


# ================================================================================
# القسم 3: اختبارات LiveFlowRecord — عقد واجهة عرض التدفقات الحية
# ================================================================================

class TestLiveFlowRecordUiContract:
    """FR-CAP-02: سجل التدفق الحي يلبّي الحقول التي يعتمدها العرض (protocol/whitelist/blacklist/reason)."""

    def test_fields_present_with_defaults(self) -> None:
        record = LiveFlowRecord(
            timestamp=1.0, source_ip="1.1.1.1", destination_ip="2.2.2.2",
            model_name="m", prediction=0, confidence=1.0,
        )
        assert record.protocol == 0
        assert record.is_whitelisted is False
        assert record.is_blacklisted is False
        assert record.attack_reason == ""
        assert record.source == "cicflowmeter"


# ================================================================================
# القسم 4: اختبارات CICFlowMeterAdapter — مستخرج PCAP (المحرك الوحيد)
# ================================================================================

class TestCICFlowMeterAdapter:
    """FR-CAP-01: استخراج التدفقات من ملفات PCAP عبر محرك CICFlowMeter النقي."""

    def test_extract_from_pcap_mixed_tcp_udp(self, tmp_path: Path) -> None:
        """حزم TCP و UDP معًا → تدفقات FlowFeatures ببروتوكولاتها الصحيحة."""
        from scapy.all import UDP, IP, TCP, Ether, wrpcap

        packets = [
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=80, flags="S"),
            Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=80, dport=50000, flags="SA"),
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=80, flags="A"),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53) / b"\x00\x01\x00\x01",
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=12345) / b"\x00\x01\x00\x01",
        ]
        pcap_path = tmp_path / "mixed_tcp_udp.pcap"
        wrpcap(str(pcap_path), packets)

        extractor = CICFlowMeterAdapter()
        flows = extractor.extract_from_pcap(str(pcap_path))
        assert len(flows) > 0
        assert all(isinstance(f, FlowFeatures) for f in flows)
        assert all(isinstance(f.features, dict) for f in flows)
        assert all(len(f.features) > 0 for f in flows)
        assert 6 in {f.protocol for f in flows}
        assert 17 in {f.protocol for f in flows}

    def test_missing_pcap_rejected(self, tmp_path: Path) -> None:
        """ملف غير موجود — يجب رفضه بـ ConfigurationError بشكل آمن."""
        extractor = CICFlowMeterAdapter()
        with pytest.raises(ConfigurationError):
            extractor.extract_from_pcap(str(tmp_path / "nonexistent.pcap"))

    def test_empty_pcap_returns_no_flows(self, tmp_path: Path) -> None:
        """PCAP بلا حزم — يعيد قائمة فارغة دون تعطل."""
        from scapy.all import wrpcap

        pcap_path = tmp_path / "empty.pcap"
        wrpcap(str(pcap_path), [])
        extractor = CICFlowMeterAdapter()
        assert extractor.extract_from_pcap(str(pcap_path)) == []

    def test_build_features_keeps_ports_skips_identity(self) -> None:
        """CICIDS2017 يُدرّب على Destination Port — الأبواب تبقى ميزات؛ الهوية (src_ip/dst_ip/protocol/timestamp) تُستثنى."""
        data = {
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "src_port": 123, "dst_port": 80, "protocol": 6, "timestamp": 1.0,
            "Flow Duration": 10, "Tot Fwd Pkts": 2,
        }
        features = CICFlowMeterAdapter._build_features(data)
        assert "src_ip" not in features
        assert "dst_ip" not in features
        assert "protocol" not in features
        assert "timestamp" not in features
        assert features["src_port"] == 123.0
        assert features["dst_port"] == 80.0
        assert features["Flow Duration"] == 10.0
        assert features["Tot Fwd Pkts"] == 2.0


# ================================================================================
# القسم 5: اختبارات Extractor Factory — المصنع (CICFlowMeter فقط)
# ================================================================================

class TestFlowExtractorFactory:
    """FR-CAP-01: المصنع يعيد دائمًا محرك CICFlowMeter — لا يوجد مسار بديل."""

    def test_always_returns_cicflowmeter_adapter(self) -> None:
        """حتى لو وُجد إعداد قديم (native)، يجب أن يُستدعى CICFlowMeterAdapter دائمًا."""
        with patch.dict(os.environ, {"AI_IDS_FLOW_EXTRACTOR": "native"}, clear=True):
            from capture.extractor_factory import get_flow_extractor
            extractor = get_flow_extractor()
            assert isinstance(extractor, CICFlowMeterAdapter)

    def test_constructs_adapter_once(self) -> None:
        """المصنع يُنشئ المحول عبر منشئ واحد بلا معاملات."""
        with patch("capture.cicflowmeter_adapter.CICFlowMeterAdapter") as mock_cls:
            mock_cls.return_value = MagicMock()
            from capture.extractor_factory import get_flow_extractor
            extractor = get_flow_extractor()
            mock_cls.assert_called_once_with()
            assert extractor is not None


# ================================================================================
# القسم 6: اختبارات مصنع الخدمة الحية — get_live_capture_service
# ================================================================================

class TestGetLiveCaptureService:
    """FR-CAP-02: مصنع الخدمة الحية يعيد CICFlowMeterLiveCaptureService دائمًا."""

    def test_returns_cicflowmeter_service(self) -> None:
        from capture.live_capture_service import get_live_capture_service

        get_live_capture_service.cache_clear()
        try:
            with patch("services.container.get_container") as mock_container, \
                 patch("capture.cicflowmeter_live_capture_service.CICFlowMeterLiveCaptureService") as mock_cls:
                container = MagicMock()
                container.detection_service = MagicMock()
                container.csv_analysis_service = MagicMock()
                container.log_repository = None
                mock_container.return_value = container
                mock_cls.return_value = MagicMock()

                svc = get_live_capture_service()
                mock_cls.assert_called_once()
                assert svc is not None
        finally:
            get_live_capture_service.cache_clear()


# ================================================================================
# القسم 7: اختبارات الالتقاط المباشر — CICFlowMeter (Python نقي)
# ================================================================================

class TestCICFlowMeterLiveCaptureService:
    """
    FR-CAP-02: اختبارات الالتقاط المباشر عبر CICFlowMeterLiveCaptureService.

    تُبنى FlowSession حقيقية من حزمة cicflowmeter (بنفس معالجة المصنع المؤقتة
    التي يستخدمها start()) وتُحقن حزم Scapy حقيقية عبر _on_packet، ثم تُفرَّغ
    التدفقات المنتهية عبر _flush_completed_flows — دورة الحياة ذاتها لخيط Flush.
    """

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
                prediction=1,
                confidence=0.9,
                attack_type="DDoS",
                attack_reason="",
                is_whitelisted=False,
                is_blacklisted=False,
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
        assert service.status["last_error"] == ""

        service._flush_completed_flows()

        assert fake_csv.analyze.called
        call_kwargs = fake_csv.analyze.call_args.kwargs
        assert call_kwargs.get("source_type") == "live"
        assert call_kwargs.get("skip_integration") is False
        assert "reset_signatures" not in call_kwargs
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
# القسم 8: اختبارات سيناريوهات الأخطاء المحتملة
# ================================================================================

class TestErrorScenarios:
    """
    NFR-CAP-01: التحقق من التعامل الآمن مع السيناريوهات الاستثنائية عبر مسار CICFlowMeter.
    """

    def test_missing_pcap_raises_configuration_error(self, tmp_path: Path) -> None:
        """FR-CAP-01: ملف PCAP تالف/غير موجود — رفض آمن بـ ConfigurationError."""
        extractor = CICFlowMeterAdapter()
        with pytest.raises(ConfigurationError):
            extractor.extract_from_pcap(str(tmp_path / "bad_file.pcap"))

    def test_flush_completed_flows_without_model_is_noop(self, tmp_path: Path) -> None:
        """بدون نموذج محدد، لا يُستدعى كشف ML ولا تُكتب سجلات حديثة."""
        service = self._make_service(tmp_path, MagicMock(), MagicMock())
        service._model_id = None
        service._flush_completed_flows()
        assert service.get_recent_flows() == []

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
