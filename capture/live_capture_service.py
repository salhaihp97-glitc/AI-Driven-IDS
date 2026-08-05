"""
Live Capture Service Module.

Orchestrates the real-time intrusion detection pipeline by binding network sniffers,
stateful flow builders, statistical calculators, and machine learning inference services.
Runs continuous packet aggregation loops inside isolated background threads to ensure 
state persistence across volatile UI lifecycle updates (e.g., Streamlit application reruns).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Deque, Optional, Dict, List, Any, Final, Union

import numpy as np
import pandas as pd

from capture.flow import Flow
from capture.flow_assembler import FlowAssembler
from capture.flow_feature_calculator import FlowFeatureCalculator
from config.constants import LogLevel, LogSource
from config.settings import get_settings
from core.entities.log_entry import LogEntry
from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger
from capture.packet_sniffer import PacketSniffer
from repositories.log_repository import LogRepository
from services.container import get_container
from services.detection_service import DetectionService

# Initialize Structural Component Logger
logger = get_logger("capture.live_capture_service")


@dataclass(frozen=True)
class LiveFlowRecord:
    """
    Immutable structured summary of a processed network connection flow 
    along with its associated machine learning inference classification.
    """
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: int
    packet_count: int
    byte_count: int
    model_name: str
    prediction: int
    confidence: float
    severity: str = ""
    attack_type: str = ""
    attack_reason: str = ""
    is_whitelisted: bool = False
    is_blacklisted: bool = False


class LiveCaptureService:
    """
    Native real-time high-throughput network capture pipeline orchestrator.
    
    Acts as a centralized coordination nexus, routing raw packets down through stateful 
    reassembly tracking maps, generating network features, and firing evaluations.
    """
    
    def __init__(
        self,
        detection_service: DetectionService,
        max_recent_flows: Optional[int] = None,
        log_repository: Optional[LogRepository] = None,
    ) -> None:
        """
        Sets up background workers, synchronization locks, and metrics collections buffers.
        """
        self._settings: Final = get_settings()
        self._detection_service: Final[DetectionService] = detection_service
        self._assembler: Final[FlowAssembler] = FlowAssembler(
            idle_timeout_seconds=self._settings.flow_idle_timeout_seconds
        )
        self._calculator: Final[FlowFeatureCalculator] = FlowFeatureCalculator(
            activity_timeout_seconds=self._settings.flow_activity_timeout_seconds
        )
        self._sniffer: Final[PacketSniffer] = PacketSniffer(
            on_packet=self._handle_packet,
            shutdown_timeout_seconds=self._settings.live_shutdown_timeout_seconds,
        )
        self._logs: Final[Optional[LogRepository]] = log_repository

        _max_recent: Final[int] = (
            max_recent_flows if max_recent_flows is not None else self._settings.live_max_recent_flows
        )
        self._recent_flows: Final[Deque[LiveFlowRecord]] = deque(maxlen=_max_recent)
        self._lock: Final[threading.Lock] = threading.Lock()
        self._flush_poll_seconds: Final[float] = self._settings.live_flush_poll_seconds
        self._shutdown_timeout_seconds: Final[float] = self._settings.live_shutdown_timeout_seconds

        # Operational Metrics Counters
        self._packet_count: int = 0
        self._model_id: Optional[int] = None
        self._model_name: str = ""

        # Background Eviction Worker Parameters
        self._flush_thread: Optional[threading.Thread] = None
        self._stop_flush: Final[threading.Event] = threading.Event()

        # Persistent CSV File Storage for Captured Flows (configurable via AI_IDS_CAPTURED_FLOWS_DIR)
        self._master_csv_path: Final[Path] = self._settings.captured_flows_dir / "captured_flows_master.csv"
        self._cleaned_csv_path: Final[Path] = self._settings.captured_flows_dir / "cleaned_flows_master.csv"

    def _log_system_event(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        """
        Commits system runtime changes securely into centralized logging storage engines.
        """
        if self._logs is not None:
            self._logs.add(LogEntry(source=LogSource.CAPTURE, level=level, message=message))

    def start(self, interface: str, model_id: int, model_name: str) -> None:
        """
        Spawns async packet capture threads and initiates active connection flusher tasks.
        """
        if self.is_running:
            logger.warning("Pipeline start rejected: Live capture worker loop already executing.")
            raise ConfigurationError("Live capture service pipeline is already running.")

        self._model_id = model_id
        self._model_name = model_name
        self._packet_count = 0
        self._stop_flush.clear()

        # Ensure CSV output directory exists
        self._master_csv_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Spawning core background flow assembly flusher threads...")
        self._sniffer.start(interface)
        
        self._flush_thread = threading.Thread(
            target=self._flush_loop, 
            name="AI-IDS-FlowFlusher", 
            daemon=True
        )
        self._flush_thread.start()
        
        logger.info("Live capture actively monitoring '%s' using inference model: '%s'.", interface, model_name)
        self._log_system_event(f"Live capture started on interface '{interface}' using model '{model_name}'.")

    def stop(self) -> None:
        """
        Unwinds capture threads safely, flushing any remaining network sessions to prevent data drops.
        """
        logger.info("Initiating structural decommissioning sequence across live capture workers...")
        self._sniffer.stop()
        self._stop_flush.set()
        
        if self._flush_thread:
            self._flush_thread.join(timeout=self._shutdown_timeout_seconds)
            
        # Process remaining active network segments left behind in memory spaces
        residual_flows: Final[List[Flow]] = self._assembler.flush_all()
        if residual_flows:
            logger.info("Processing remaining %d active flow contexts during shutdown flush.", len(residual_flows))
            self._process_flows(residual_flows)
            
        logger.info("Live network stream capture engine halted cleanly.")
        self._log_system_event(f"Live capture stopped. Total packets captured: {self._packet_count}.")

    @property
    def is_running(self) -> bool:
        """
        Verifies if hardware network sniffers are actively running.
        """
        return self._sniffer.is_running

    @property
    def status(self) -> dict[str, Any]:
        """
        Compiles performance metrics definitions to monitor processing pipelines.
        """
        return {
            "is_running": self.is_running,
            "packet_count": self._packet_count,
            "active_flows": self._assembler.active_flow_count,
            "model_name": self._model_name,
            "last_error": self._sniffer.last_error,
            "mode": "native",
            "master_csv_size_bytes": self._master_csv_path.stat().st_size if self._master_csv_path.exists() else 0,
        }

    def get_recent_flows(self, limit: int = 100) -> List[LiveFlowRecord]:
        """
        Thread-safe interface query pulling rolling logs out of local storage matrices.
        """
        with self._lock:
            return list(self._recent_flows)[-limit:]

    def get_master_csv_path(self) -> Path:
        """Returns the path to the master captured flows CSV file."""
        return self._master_csv_path

    def get_cleaned_csv_path(self) -> Path:
        """Returns the path to the cleaned flows CSV file."""
        return self._cleaned_csv_path

    def clear_master_csv(self) -> bool:
        """Purges archived CSV flow history files from disk."""
        with self._lock:
            try:
                for path in [self._master_csv_path, self._cleaned_csv_path]:
                    if path.exists():
                        path.unlink()
                logger.info("Native capture CSV logs purged successfully.")
                return True
            except Exception:
                logger.exception("Failed to purge native capture CSV files.")
        return False

    def _write_flows_to_csv(self, records: List[dict]) -> None:
        """Appends flow feature records to the master and cleaned CSV files."""
        with self._lock:
            try:
                df = pd.DataFrame(records)

                # Write raw captured flows
                master_exists = self._master_csv_path.exists() and self._master_csv_path.stat().st_size > 0
                df.to_csv(self._master_csv_path, mode='a', header=not master_exists, index=False)

                # Write cleaned flows (NaN/Inf replaced with 0.0)
                df_clean = df.copy()
                df_clean = df_clean.fillna(0.0)
                df_clean = df_clean.replace([np.inf, -np.inf], 0.0)
                cleaned_exists = self._cleaned_csv_path.exists() and self._cleaned_csv_path.stat().st_size > 0
                df_clean.to_csv(self._cleaned_csv_path, mode='a', header=not cleaned_exists, index=False)

                logger.debug("Persisted %d native capture flow records to CSV.", len(records))
            except Exception:
                logger.exception("Failed to write native capture flows to CSV.")

    @staticmethod
    def _transport_payload_length(ip_total_len: int, ip_header_len: int, transport_header_len: int, layer_payload: Any) -> int:
        """
        Computes the transport-layer payload byte count for a captured frame.

        Mirrors the CICFlowMeter convention used by the CICIDS2017 feature corpus the
        deployed models were trained on: packet size features count the bytes carried
        by the transport layer (TCP/UDP data), not the full IP datagram. Falls back to
        the parsed layer payload length when the IP total-length field is unavailable.
        """
        if ip_total_len > 0:
            return max(0, ip_total_len - ip_header_len - transport_header_len)
        try:
            return int(len(layer_payload))
        except Exception:  # noqa: BLE001 - defensive fallback for malformed captures
            return 0

    def _handle_packet(self, pkt) -> None:
        """
        Low-level intercept callback unpacking raw networking layers down into core tracking frames.
        """
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            logger.error("Scapy dependency resolution missing inside active packet extraction loop.")
            return

        if IP not in pkt:
            return
            
        ip_layer = pkt[IP]
        src_port: int = 0
        dst_port: int = 0
        syn = ack = rst = fin = psh = urg = ece = cwr = False
        window_size: int = 0
        header_length: int = 0
        size_bytes: int = len(pkt)

        ip_header_len: int = int(ip_layer.ihl) * 4
        ip_total_len: int = int(ip_layer.len)

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)
            flags = tcp_layer.flags
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            rst = bool(flags & 0x04)
            fin = bool(flags & 0x01)
            psh = bool(flags & 0x08)
            urg = bool(flags & 0x20)
            ece = bool(flags & 0x40)
            cwr = bool(flags & 0x80)
            window_size = int(tcp_layer.window)
            # CICIDS2017 training conventions: size features = transport payload
            # bytes, header features = transport header bytes (IP header excluded).
            tcp_header_len: int = int(tcp_layer.dataofs) * 4
            header_length = tcp_header_len
            size_bytes = self._transport_payload_length(ip_total_len, ip_header_len, tcp_header_len, tcp_layer.payload)

        elif UDP in pkt:
            udp_layer = pkt[UDP]
            src_port, dst_port = int(udp_layer.sport), int(udp_layer.dport)
            header_length = 8  # UDP header is always 8 bytes (transport layer only)
            size_bytes = self._transport_payload_length(ip_total_len, ip_header_len, 8, udp_layer.payload)

        else:
            header_length = ip_header_len

        self._assembler.add_packet(
            src_ip=ip_layer.src, 
            dst_ip=ip_layer.dst,
            src_port=src_port, 
            dst_port=dst_port, 
            protocol=int(ip_layer.proto),
            timestamp=float(pkt.time), 
            size_bytes=size_bytes,
            syn=syn, ack=ack, rst=rst, fin=fin, psh=psh, urg=urg,
            ece=ece, cwr=cwr,
            window_size=window_size,
            header_length=header_length,
        )
        
        with self._lock:
            self._packet_count += 1

    def _flush_loop(self) -> None:
        """
        Dedicated tracking routine scanning for connection drops and handling expirations.
        """
        while not self._stop_flush.is_set():
            time.sleep(self._flush_poll_seconds)
            idle_flows: Final[List[Flow]] = self._assembler.pop_idle_flows(now=time.time())
            if idle_flows:
                self._process_flows(idle_flows)

    def _process_flows(self, flows: List[Flow]) -> None:
        """
        Extracts feature signatures from closed/idle paths, runs model evaluations,
        and persists flow data to CSV files for historical analysis.
        """
        if not flows or self._model_id is None:
            return
            
        flow_records_for_csv: List[dict] = []
        
        for flow in flows:
            try:
                flow_features: Final = self._calculator.compute(flow)
                
                # Execute evaluation matching raw features against targeted classification maps
                result = self._detection_service.run(
                    model_id=self._model_id,
                    raw_features=flow_features.features,
                    source_type="live",
                    source_ip=flow_features.src_ip,
                    destination_ip=flow_features.dst_ip,
                )
                
                detection = result.detection
                prediction = detection.prediction if detection is not None else result.prediction
                confidence = detection.confidence if detection is not None else result.confidence
                severity = detection.severity if detection is not None else ""
                attack_type = result.attack_type
                attack_reason = result.attack_reason
                is_whitelisted = result.is_whitelisted
                is_blacklisted = result.is_blacklisted

                record = LiveFlowRecord(
                    timestamp=time.time(),
                    source_ip=flow_features.src_ip,
                    destination_ip=flow_features.dst_ip,
                    protocol=flow_features.protocol,
                    packet_count=len(flow.packets),
                    byte_count=int(sum(p.size_bytes for p in flow.packets)),
                    model_name=self._model_name,
                    prediction=prediction,
                    confidence=confidence,
                    severity=severity,
                    attack_type=attack_type,
                    attack_reason=attack_reason,
                    is_whitelisted=is_whitelisted,
                    is_blacklisted=is_blacklisted,
                )
                
                with self._lock:
                    self._recent_flows.append(record)

                # Accumulate flow data for CSV persistence
                csv_row = {"src_ip": flow_features.src_ip, "dst_ip": flow_features.dst_ip,
                           "src_port": flow_features.src_port, "dst_port": flow_features.dst_port,
                           "protocol": flow_features.protocol, "prediction": prediction,
                           "confidence": confidence, "attack_type": attack_type}
                csv_row.update(flow_features.features)
                flow_records_for_csv.append(csv_row)
                    
            except Exception:
                # Shield production loop: Isolated malformed flow processing faults must not crash packet collection
                logger.exception("Skipping problematic network flow segment due to unexpected computation fault.")

        # Persist collected flow records to CSV files
        if flow_records_for_csv:
            self._write_flows_to_csv(flow_records_for_csv)


@lru_cache(maxsize=1)
def get_live_capture_service() -> Union[LiveCaptureService, Any]:
    """
    Retrieves the process-wide orchestration singleton instance.
    
    Guarantees stateful logging buffers survive runtime context mutations caused 
    by continuous user-interface screen re-executions.
    """
    container = get_container()
    settings = get_settings()
    
    if settings.live_capture_mode == "cicflowmeter":
        from capture.cicflowmeter_live_capture_service import CICFlowMeterLiveCaptureService
        
        logger.info("System Instantiation: Spawning persistent singleton using external CICFlowMeter tracking profiles.")
        return CICFlowMeterLiveCaptureService(
            detection_service=container.detection_service,
            csv_analysis_service=container.csv_analysis_service,
            log_repository=container.log_repository,
        )
        
    logger.info("System Instantiation: Spawning persistent singleton utilizing the native Python Flow-Aggregation pipeline.")
    return LiveCaptureService(
        detection_service=container.detection_service, 
        log_repository=container.log_repository
    )