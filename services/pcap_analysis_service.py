"""
Packet Capture (PCAP) Binary Log Stream Analysis Service Module.

Governs file-system parsing orchestration routines, converting raw packet sequence streams 
into structured network flow matrices via custom feature extractors. Dispatches translated 
feature vectors to the core machine learning inference service to isolate potential security threats.

Pipeline stages (Pure-ML: the model is the sole authority for analysis/detection/classification):
  1. Extract raw per-flow features (CICFlowMeter).
  2. When macro-flow assembly is enabled, aggregate many tiny flows sharing a key into
     macro-flows so floods that are invisible per-flow reach the model.
  3. Every (macro-)flow is classified by the ML model alone. No rule/statistical layer
     overrides the model verdict — the model must observe the aggregate footprint that the
     macro-flow assembler (pure data engineering) hands it.
"""

from __future__ import annotations
from dataclasses import dataclass
import time
from typing import Final

from config.settings import get_settings
from core.exceptions import ValidationError
from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IFlowExtractor
from services.detection_service import DetectionResult, DetectionService
from services.model_service import ModelService

logger = get_logger("services.pcap_analysis_service")


@dataclass(frozen=True)
class PcapAnalysisSummary:
    """
    Immutable structured telemetry data transfer capsule capturing PCAP verification metadata.
    """
    total_flows: int
    attack_count: int
    normal_count: int
    results: list[DetectionResult]


class PcapAnalysisService:
    """
    Application core component orchestration interface executing network packet extraction and audits.
    """

    def __init__(
        self,
        detection_service: DetectionService,
        flow_extractor: IFlowExtractor,
        model_service: ModelService | None = None,
        macro_assembler: object | None = None,
    ) -> None:
        """
        Initializes the binary traffic analysis framework with required inference engines and extractors.
        """
        self._detection_service: Final[DetectionService] = detection_service
        self._extractor: Final[IFlowExtractor] = flow_extractor
        self._model_service: Final[ModelService | None] = model_service
        self._settings = get_settings()
        if macro_assembler is None:
            from capture.macro_flow_assembler import MacroFlowAssembler
            macro_assembler = MacroFlowAssembler()
        self._assembler: Final[object] = macro_assembler

    def analyze(self, model_id: int, pcap_path: str) -> PcapAnalysisSummary:
        """
        Ingests a raw packet storage capture file to map anomalies and compute vector threat metrics.

        Args:
            model_id: Primary database tracking key identifying the targeted deployment asset.
            pcap_path: System target path locating the raw binary packet capture collection.

        Returns:
            A populated PcapAnalysisSummary capturing processing performance counters.

        Raises:
            ValidationError: If the flow extraction interface returns empty feature lists.
        """
        logger.info("Starting PCAP extraction profile sequence: %s", pcap_path)

        start_time: Final[float] = time.time()

        # Ingest binary streams and compute traffic statistics via project integrated flow engines
        flow_features_list = self._extractor.extract_from_pcap(pcap_path)
        if not flow_features_list:
            raise ValidationError(
                "Ingestion Context Fault: The flow extraction subsystem failed to resolve "
                "valid packet data matrices from the targeted PCAP document asset."
            )

        # Aggregate tiny flows into macro-flows when enabled so aggregate attack footprints
        # (e.g. rotating-source-port SYN floods) physically reach the model. Macro units are
        # classified by the macro-aggregate model (``macro_rf_v1``), never by the per-flow
        # classifier -- the whole reason floods are invisible per-flow is that per-flow models
        # only see individual short connections.
        enabled_assembler = bool(getattr(self._assembler, "enabled", False))
        units = flow_features_list if not enabled_assembler else list(self._assembler.assemble(flow_features_list))

        # Resolve the macro model id once when assembly is active.
        macro_model_id: int | None = None
        if enabled_assembler and self._model_service is not None:
            macro_model_id = self._model_service.resolve_macro_model_id(getattr(self._settings, "macro_flow_model_id", None))
            if macro_model_id is None:
                macro_model_id = model_id

        logger.info(
            "Extracted %d flows in %.2fs. Assembled %d macro-flow units. Initializing model predictions...",
            len(flow_features_list), time.time() - start_time, len(units),
        )

        results: Final[list[DetectionResult]] = []
        attack_count: int = 0

        # Step through parsed structural traffic vectors to execute classification evaluations
        for index, flow_features in enumerate(units):
            if index % 100 == 0 and index > 0:
                logger.debug("Evaluation Progress: Classified %d/%d traffic vectors...", index, len(units))

            # Dispatch assembled units to the macro model; raw single flows use the caller's model.
            dispatch_model_id = macro_model_id if enabled_assembler else model_id

            try:
                # Dispatch normalized context attributes to the active verification loops.
                # The model is the sole authority: no rule/statistical layer overrides its
                # verdict. The macro-flow assembler only performed data engineering so the
                # aggregate attack footprint physically reaches the model.
                result = self._detection_service.run(
                    model_id=dispatch_model_id,
                    raw_features=flow_features.features,
                    source_type="pcap",
                    source_ip=flow_features.src_ip,
                    destination_ip=flow_features.dst_ip,
                    skip_integration=True,
                )
                results.append(result)

                # Any non-zero signature represents an established anomaly threat foot-print
                if result.detection is not None and result.detection.prediction != 0:
                    attack_count += 1

            except Exception as e:
                logger.error("Skipping structural row vector configuration at packet index %s due to prediction error: %s", index, e)

        logger.info(
            "PCAP Analysis Sequence Complete. Total flows: %d | Units: %d | Malicious: %d | Duration: %.2fs",
            len(flow_features_list), len(units), attack_count, time.time() - start_time,
        )

        return PcapAnalysisSummary(
            total_flows=len(units),
            attack_count=attack_count,
            normal_count=len(results) - attack_count,
            results=results,
        )
