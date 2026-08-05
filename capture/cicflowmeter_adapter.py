"""
CICFlowMeter Python Adapter Implementation Module.

Provides a production-ready IFlowExtractor implementation using the pure-Python
``cicflowmeter`` package (>= 0.5.0) for offline PCAP flow extraction. Eliminates
the external Java binary dependency entirely.

Architecture alignment:
  - Infrastructure Layer adapter implementing the IFlowExtractor domain contract.
  - In-memory processing: no temporary files or subprocess calls.
  - Produces FlowFeatures dataclass instances compatible with the ML inference pipeline.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Final, Dict, Any

from capture.flow_feature_calculator import FlowFeatures
from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IFlowExtractor

logger = get_logger("capture.cicflowmeter_adapter")


def _to_float(value: Any) -> float:
    """Safely cast a value to float, returning 0.0 on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class CICFlowMeterAdapter(IFlowExtractor):
    """
    Pure-Python CICFlowMeter adapter for offline PCAP feature extraction.

    Uses ``cicflowmeter.FlowSession`` to process PCAP files in-memory and
    converts the resulting flow data into ``FlowFeatures`` instances.
    """

    def extract_from_pcap(self, pcap_path: str) -> List[FlowFeatures]:
        """
        Extracts network flow features from a PCAP file using the Python CICFlowMeter.

        Args:
            pcap_path: Path to the PCAP file to process.

        Returns:
            A list of FlowFeatures instances, one per extracted network flow.

        Raises:
            ConfigurationError: If the PCAP file is invalid or extraction fails.
        """
        path = Path(pcap_path)
        if not path.exists() or path.stat().st_size == 0:
            raise ConfigurationError(f"PCAP file is missing or empty: '{pcap_path}'")

        logger.info("Starting Python CICFlowMeter extraction for: %s", pcap_path)
        start_time: float = time.perf_counter()

        try:
            from scapy.all import rdpcap, IP
            from cicflowmeter.flow_session import FlowSession
        except ImportError as exc:
            raise ConfigurationError(
                "Required dependencies missing: 'scapy' and 'cicflowmeter' packages are required. "
                "Run: pip install scapy cicflowmeter"
            ) from exc

        try:
            session = FlowSession(output_mode=None, output=None)

            packets = rdpcap(pcap_path)
            for pkt in packets:
                session.process(pkt)

            session.flush_flows()
            flows = list(session.get_flows())
        except ConfigurationError:
            raise
        except Exception as exc:
            raise ConfigurationError(
                f"CICFlowMeter extraction failed for '{pcap_path}': {exc}"
            ) from exc

        if not flows:
            logger.warning("No network flows extracted from: %s", pcap_path)
            return []

        results: List[FlowFeatures] = []
        for flow in flows:
            try:
                data = flow.get_data()
                features = self._build_features(data)
                results.append(FlowFeatures(
                    src_ip=str(data.get("src_ip", "")).strip(),
                    dst_ip=str(data.get("dst_ip", "")).strip(),
                    src_port=int(_to_float(data.get("src_port", 0))),
                    dst_port=int(_to_float(data.get("dst_port", 0))),
                    protocol=int(_to_float(data.get("protocol", 0))),
                    features=features,
                ))
            except Exception as exc:
                logger.warning("Skipping malformed flow record: %s", exc)

        elapsed: float = time.perf_counter() - start_time
        logger.info(
            "CICFlowMeter extraction complete: %d flows from '%s' in %.3fs",
            len(results), pcap_path, elapsed,
        )
        return results

    @staticmethod
    def _build_features(data: Dict[str, Any]) -> Dict[str, float]:
        """
        Convert raw CICFlowMeter flow data dict to a clean feature dict
        with CICIDS2017-compatible column names.
        """
        metadata_keys = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp"}
        features: Dict[str, float] = {}
        for key, value in data.items():
            if key in metadata_keys:
                continue
            features[key] = _to_float(value)
        return features
