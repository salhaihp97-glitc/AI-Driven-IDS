"""
Packet Capture (PCAP) Binary Log Stream Analysis Service Module.

Governs file-system parsing orchestration routines, converting raw packet sequence streams 
into structured network flow matrices via custom feature extractors. Dispatches translated 
feature vectors to the core machine learning inference service to isolate potential security threats.
"""

from __future__ import annotations
from dataclasses import dataclass
import time
from typing import Final

from core.exceptions import ValidationError
from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IFlowExtractor
from services.detection_service import DetectionResult, DetectionService

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

    def __init__(self, detection_service: DetectionService, flow_extractor: IFlowExtractor) -> None:
        """
        Initializes the binary traffic analysis framework with required inference engines and extractors.
        """
        self._detection_service: Final[DetectionService] = detection_service
        self._extractor: Final[IFlowExtractor] = flow_extractor

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

        logger.info("Extracted %d flows in %.2fs. Initializing model predictions...", len(flow_features_list), time.time() - start_time)

        # Fresh signature state so this file is audited independently of earlier batches
        self._detection_service.reset_signatures()

        results: Final[list[DetectionResult]] = []
        attack_count: int = 0

        # Step through parsed structural traffic vectors to execute classification evaluations
        for index, flow_features in enumerate(flow_features_list):
            if index % 100 == 0 and index > 0:
                logger.debug("Evaluation Progress: Classified %d/%d traffic vectors...", index, len(flow_features_list))

            try:
                # Dispatch normalized context attributes to the active verification loops
                result = self._detection_service.run(
                    model_id=model_id,
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

        logger.info("PCAP Analysis Sequence Complete. Total flows: %d | Malicious: %d | Duration: %.2fs", len(flow_features_list), attack_count, time.time() - start_time)

        return PcapAnalysisSummary(
            total_flows=len(flow_features_list),
            attack_count=attack_count,
            normal_count=len(results) - attack_count,
            results=results,
        )