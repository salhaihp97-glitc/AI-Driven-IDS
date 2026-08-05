"""
CICFlowMeter Live Capture Service Module.

Pure-Python live network capture and feature extraction using the ``cicflowmeter``
package (>= 0.5.0).  Eliminates all Java binary and PCAP chunk-rotation dependencies.

Architecture:
  - scapy AsyncSniffer captures packets on a network interface.
  - Each packet is fed into a ``FlowSession`` that assembles bidirectional flows.
  - FlowSession's internal garbage_collect() pushes completed flows to a
    thread-safe ``_QueueWriter`` deque.
  - A background flush thread drains the queue, writes to master/cleaned CSV files,
    and feeds flows to the ML inference pipeline.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Final, Optional, List, Dict, Any

import numpy as np
import pandas as pd

from config.constants import LogLevel, LogSource
from config.settings import get_settings
from core.entities.log_entry import LogEntry
from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger
from repositories.log_repository import LogRepository
from services.csv_analysis_service import CsvAnalysisService
from services.detection_service import DetectionService

logger = get_logger("capture.cicflowmeter_live_capture_service")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class _QueueWriter:
    """Thread-safe output writer that captures flow dicts in a deque."""

    def __init__(self, target: Deque[Dict[str, Any]]) -> None:
        self._target = target
        self._lock = threading.Lock()

    def write(self, data: dict) -> None:
        with self._lock:
            self._target.append(data)


# ---------------------------------------------------------------------------
# Public value object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LiveFlowRecord:
    """Structured value object holding normalised historical records of processed in-memory flows."""
    timestamp: float
    source_ip: Optional[str]
    destination_ip: Optional[str]
    model_name: str
    prediction: int
    confidence: float
    source: str = "cicflowmeter"
    severity: str = ""
    attack_type: str = ""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class CICFlowMeterLiveCaptureService:
    """
    Pure-Python live network telemetry ingestion and processing service.

    Uses ``cicflowmeter.FlowSession`` + scapy ``AsyncSniffer`` to capture packets,
    assemble flows, and feed them through the ML inference pipeline in real-time.
    No Java binary or PCAP chunk rotation required.
    """

    def __init__(
        self,
        detection_service: DetectionService,
        csv_analysis_service: CsvAnalysisService,
        max_recent_flows: Optional[int] = None,
        log_repository: Optional[LogRepository] = None,
    ) -> None:
        self._settings: Final = get_settings()
        self._detection_service: Final[DetectionService] = detection_service
        self._csv_analysis_service: Final[CsvAnalysisService] = csv_analysis_service
        self._logs: Final[Optional[LogRepository]] = log_repository

        _max_recent: Final[int] = (
            max_recent_flows if max_recent_flows is not None else self._settings.live_max_recent_flows
        )
        self._recent_flows: Final[Deque[LiveFlowRecord]] = deque(maxlen=_max_recent)
        self._lock: Final[threading.Lock] = threading.Lock()

        # Runtime state
        self._packet_count: int = 0
        self._active_flows: int = 0
        self._model_id: Optional[int] = None
        self._model_name: str = ""

        # scapy AsyncSniffer instance (created on start)
        self._sniffer: Any = None

        # cicflowmeter FlowSession + completed-flow queue
        self._flow_session: Any = None
        self._completed_flows: Deque[Dict[str, Any]] = deque()
        self._queue_writer: Optional[_QueueWriter] = None

        # Background flush thread
        self._flush_thread: Optional[threading.Thread] = None
        self._stop_event: Final[threading.Event] = threading.Event()

        # CSV persistence paths (dynamically resolved from settings)
        captured_dir = get_settings().captured_flows_dir
        self._master_csv_path: Final[Path] = captured_dir / "captured_flows_master.csv"
        self._cleaned_csv_path: Final[Path] = captured_dir / "cleaned_flows_master.csv"

        # CSV header tracking
        self._master_header_written: bool = False
        self._cleaned_header_written: bool = False

        # Store originals for cleanup
        self._orig_expired_update: int = self._settings.cicflowmeter_expired_update_seconds
        self._orig_factory: Any = None

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------

    def _log_system_event(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        if self._logs is not None:
            self._logs.add(LogEntry(source=LogSource.CAPTURE, level=level, message=message))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, interface: str, model_id: int, model_name: str) -> None:
        """
        Launches live packet capture on *interface* and begins flow extraction + ML inference.

        Raises:
            ConfigurationError: If the service is already running or dependencies are missing.
        """
        if self.is_running:
            logger.warning("Pipeline execution request discarded: ingestion framework already active.")
            raise ConfigurationError("Live capture service pipeline is already running.")

        # --- Import dependencies ------------------------------------------------
        try:
            import cicflowmeter.flow_session as _fs_mod
            import cicflowmeter.writer as _writer_mod
            from cicflowmeter.flow_session import FlowSession
            from scapy.all import AsyncSniffer
        except ImportError as exc:
            raise ConfigurationError(
                "Required dependencies missing: 'scapy' and 'cicflowmeter' packages. "
                "Run: pip install scapy cicflowmeter"
            ) from exc

        # --- Ensure data directory exists ---------------------------------------
        self._master_csv_path.parent.mkdir(parents=True, exist_ok=True)

        # --- Reset state --------------------------------------------------------
        self._model_id = model_id
        self._model_name = model_name
        self._packet_count = 0
        self._active_flows = 0
        self._master_header_written = (
            self._master_csv_path.exists() and self._master_csv_path.stat().st_size > 0
        )
        self._cleaned_header_written = (
            self._cleaned_csv_path.exists() and self._cleaned_csv_path.stat().st_size > 0
        )
        self._stop_event.clear()
        self._completed_flows = deque()
        self._queue_writer = _QueueWriter(self._completed_flows)

        # --- BUG FIX #1: FlowSession constructor crashes when output_mode=None
        # because output_writer_factory(None, None) raises RuntimeError.
        # Solution: temporarily patch output_writer_factory in the flow_session
        # module namespace so it returns our _QueueWriter when output_mode is None.
        self._orig_factory = _fs_mod.output_writer_factory
        _queue_ref = self._queue_writer  # closure reference

        def _patched_factory(output_mode: Any, output: Any) -> _QueueWriter:
            if output_mode is None:
                return _queue_ref
            return self._orig_factory(output_mode, output)

        _fs_mod.output_writer_factory = _patched_factory

        # --- BUG FIX #3: Override EXPIRED_UPDATE for fast IDS latency. The constant
        # is imported via `from .constants import EXPIRED_UPDATE` into the flow_session
        # module namespace. Patching _fs_mod.EXPIRED_UPDATE directly modifies the
        # namespace that process() and garbage_collect() reference at runtime. The
        # target value is environment-driven (AI_IDS_CICFLOWMETER_EXPIRED_UPDATE_SECONDS).
        self._orig_expired_update = getattr(_fs_mod, "EXPIRED_UPDATE", self._settings.cicflowmeter_expired_update_seconds)
        target_expired_update: int = self._settings.cicflowmeter_expired_update_seconds
        _fs_mod.EXPIRED_UPDATE = target_expired_update
        logger.info(
            "Overriding cicflowmeter EXPIRED_UPDATE: %ds → %ds for fast IDS latency.",
            self._orig_expired_update,
            target_expired_update,
        )

        # --- Create FlowSession (now succeeds because patched factory handles None)
        try:
            self._flow_session = FlowSession(output=None, output_mode=None)
        except Exception as exc:
            self._restore_patches(_fs_mod)
            raise ConfigurationError(f"Failed to create FlowSession: {exc}") from exc
        finally:
            # Restore original factory — FlowSession already has our writer assigned
            _fs_mod.output_writer_factory = self._orig_factory

        # --- BUG FIX #2: Wrap toPacketList to prevent deletion of our writer ---
        _original_tpl = self._flow_session.toPacketList

        def _safe_toPacketList():
            """Prevent toPacketList from deleting our _QueueWriter."""
            with self._flow_session._lock:
                self._flow_session.garbage_collect(None)
            # Do NOT call del self.output_writer — just return super's result
            from scapy.sessions import DefaultSession
            return DefaultSession.toPacketList(self._flow_session)

        self._flow_session.toPacketList = _safe_toPacketList

        # --- Create async sniffer ----------------------------------------------
        self._sniffer = AsyncSniffer(
            iface=interface,
            prn=self._on_packet,
            store=False,
        )

        # --- Start background flush thread -------------------------------------
        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="AI-IDS-CICFlowMeterFlush",
            daemon=True,
        )

        logger.info("Starting live packet capture on interface: %s", interface)
        self._sniffer.start()
        self._flush_thread.start()

        logger.info(
            "CICFlowMeter live processing active on interface '%s' bound to model '%s'.",
            interface,
            model_name,
        )
        self._log_system_event(
            f"Live capture started on interface '{interface}' using model '{model_name}'."
        )

    def stop(self) -> None:
        """Gracefully stops capture, flushes remaining flows, and cleans up resources."""
        logger.info("Signaling shutdown across active live ingestion loops...")
        self._stop_event.set()

        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                logger.exception("Error stopping async sniffer.")

        if self._flush_thread is not None:
            self._flush_thread.join(timeout=self._settings.live_shutdown_timeout_seconds)
            self._flush_thread = None

        # Final flush of any remaining flows
        self._flush_completed_flows()

        # Restore patched constants
        try:
            import cicflowmeter.flow_session as _fs_mod
            self._restore_patches(_fs_mod)
        except Exception:
            pass

        self._sniffer = None
        self._flow_session = None
        self._queue_writer = None

        logger.info("Ingestion interface shutdown sequence finalized.")
        self._log_system_event(
            f"Live capture stopped. Total packets processed: {self._packet_count}."
        )

    def _restore_patches(self, _fs_mod: Any) -> None:
        """Restore original module-level constants after session ends."""
        try:
            if self._orig_factory is not None:
                _fs_mod.output_writer_factory = self._orig_factory
            _fs_mod.EXPIRED_UPDATE = self._orig_expired_update
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._sniffer is not None and self._sniffer.running

    @property
    def status(self) -> dict[str, Any]:
        return {
            "is_running": self.is_running,
            "packet_count": self._packet_count,
            "active_flows": self._active_flows,
            "flows_in_session": len(self._flow_session.flows) if self._flow_session else 0,
            "queue_backlog": len(self._completed_flows),
            "model_name": self._model_name,
            "mode": "cicflowmeter",
            "master_csv_size_bytes": (
                self._master_csv_path.stat().st_size
                if self._master_csv_path.exists()
                else 0
            ),
        }

    def get_recent_flows(self, limit: int = 100) -> List[LiveFlowRecord]:
        with self._lock:
            return list(self._recent_flows)[-limit:]

    def get_master_csv_path(self) -> Path:
        return self._master_csv_path

    def get_cleaned_csv_path(self) -> Path:
        return self._cleaned_csv_path

    def clear_master_csv(self) -> bool:
        with self._lock:
            try:
                for path in [self._master_csv_path, self._cleaned_csv_path]:
                    if path.exists():
                        path.unlink()
                self._master_header_written = False
                self._cleaned_header_written = False
                logger.info("Master CSV files purged successfully.")
                return True
            except Exception:
                logger.exception("Failed to purge master CSV files.")
        return False

    # ------------------------------------------------------------------
    # Packet callback
    # ------------------------------------------------------------------

    def _on_packet(self, pkt) -> None:
        """Called for every captured packet — feeds it into the FlowSession."""
        with self._lock:
            self._packet_count += 1
            count = self._packet_count
        try:
            self._flow_session.process(pkt)
        except Exception:
            logger.exception("FlowSession failed to process packet #%d.", count)

        if count % 1000 == 0:
            flows_in_session = len(self._flow_session.flows) if self._flow_session else 0
            queue_size = len(self._completed_flows)
            logger.info(
                "Packet #%d | Flows in session: %d | Queue backlog: %d | CSV bytes: %d",
                count, flows_in_session, queue_size,
                self._master_csv_path.stat().st_size if self._master_csv_path.exists() else 0,
            )

    # ------------------------------------------------------------------
    # Background flush loop
    # ------------------------------------------------------------------

    def _flush_loop(self) -> None:
        """Periodically expire idle flows and process them."""
        interval = get_settings().cicflowmeter_interval_seconds
        logger.info("Flush loop started with interval: %d seconds.", interval)

        while not self._stop_event.wait(timeout=interval):
            try:
                self._flush_completed_flows()
            except Exception:
                logger.exception("Flush loop iteration failed unexpectedly.")

    def _flush_completed_flows(self) -> None:
        """
        Actively expire idle flows from the FlowSession, drain the queue,
        write to CSV, and run ML inference.

        The flush thread MUST call garbage_collect() because FlowSession.process()
        only calls it every PACKETS_PER_GC (1000) packets. Without this call,
        flows accumulate in the session dict but never reach the output queue.
        """
        if self._flow_session is None:
            return

        # Step 1: Actively expire idle flows from the session into the queue
        try:
            before_count = len(self._flow_session.flows)
            self._flow_session.garbage_collect(time.time())
            after_count = len(self._flow_session.flows)
            flushed_count = before_count - after_count
            if flushed_count > 0:
                logger.debug(
                    "garbage_collect: %d flows expired (%d remaining in session).",
                    flushed_count, after_count,
                )
        except Exception:
            logger.exception("FlowSession garbage_collect failed.")

        # Drain the queue — all items that FlowSession has flushed
        batch: List[Dict[str, Any]] = []
        while True:
            try:
                batch.append(self._completed_flows.popleft())
            except IndexError:
                break

        if not batch:
            return

        self._active_flows = len(batch)
        logger.info("Flushed %d completed flows from queue.", len(batch))

        # Build a DataFrame from flow dicts
        try:
            df = pd.DataFrame(batch)
            if df.empty:
                return
            df.columns = df.columns.str.strip()
        except Exception:
            logger.exception("Failed to build DataFrame from completed flows.")
            return

        # 1. Write raw flows to master CSV (before sanitisation)
        try:
            with self._lock:
                df.to_csv(
                    self._master_csv_path,
                    mode="a",
                    header=not self._master_header_written,
                    index=False,
                )
                self._master_header_written = True
            logger.info("Wrote %d raw flow records to master CSV.", len(df))
        except Exception:
            logger.exception("Failed to write raw flows to master CSV.")

        # 2. Sanitise for ML pipeline
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0.0)
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0.0)

        # 3. Write cleaned flows to cleaned CSV
        try:
            with self._lock:
                df.to_csv(
                    self._cleaned_csv_path,
                    mode="a",
                    header=not self._cleaned_header_written,
                    index=False,
                )
                self._cleaned_header_written = True
            logger.info("Wrote %d cleaned flow records to cleaned CSV.", len(df))
        except Exception:
            logger.exception("Failed to write cleaned flows to cleaned CSV.")

        # 4. ML inference
        if self._csv_analysis_service and self._model_id:
            try:
                summary = self._csv_analysis_service.analyze(
                    model_id=self._model_id,
                    csv_path=str(self._cleaned_csv_path),
                )
                logger.info(
                    "ML inference complete — Evaluated: %d | Attack: %d | Normal: %d",
                    summary.total_rows,
                    summary.attack_count,
                    summary.normal_count,
                )
                self._append_recent_flows(summary)

                # Write ML results (prediction, confidence, attack_type) back to cleaned CSV
                try:
                    df_results = pd.read_csv(self._cleaned_csv_path)
                    if len(summary.results) == len(df_results):
                        df_results["prediction"] = [r.prediction for r in summary.results]
                        df_results["confidence"] = [r.confidence for r in summary.results]
                        df_results["attack_type"] = [r.attack_type for r in summary.results]
                        df_results.to_csv(self._cleaned_csv_path, index=False)
                        logger.debug("Wrote ML results (prediction, confidence, attack_type) back to cleaned CSV.")
                except Exception:
                    logger.exception("Failed to write ML results back to cleaned CSV.")
            except Exception:
                logger.exception("ML inference pipeline failed for live flows.")

    # ------------------------------------------------------------------
    # Recent flows buffer
    # ------------------------------------------------------------------

    def _append_recent_flows(self, summary) -> None:
        with self._lock:
            if not hasattr(summary, "results") or not summary.results:
                return
            for result in summary.results:
                self._recent_flows.append(
                    LiveFlowRecord(
                        timestamp=time.time(),
                        source_ip=getattr(result.detection, "source_ip", None),
                        destination_ip=getattr(result.detection, "destination_ip", None),
                        model_name=self._model_name,
                        prediction=getattr(result.detection, "prediction", 0),
                        confidence=getattr(result.detection, "confidence", 0.0),
                        severity=getattr(result.detection, "severity", ""),
                        attack_type=getattr(result, "attack_type", ""),
                    )
                )
