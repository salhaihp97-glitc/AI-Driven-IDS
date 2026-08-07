"""
Flow Data Model Module (CICFlowMeter pipeline).

Defines the shared structural entities consumed by the sole flow-extraction backend
(CICFlowMeter) and the machine-learning inference pipeline:

  - ``FlowFeatures`` is the immutable per-flow telemetry contract produced by the
    extractor and consumed by ``IFlowExtractor`` / the ML layer.
  - ``flow_protocol_name`` maps an IANA transport protocol number to its
    human-readable label for the presentation layer.

These types are intentionally decoupled from any particular extractor implementation
so the pipeline has a single, stable data boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


def flow_protocol_name(protocol: int) -> str:
    """
    Maps a standard IANA transport protocol number to a human-readable label.

    Used by the live-flows presentation layer and any downstream consumer so
    protocol labelling stays in a single, shared location.
    """
    if protocol == 6:  # TCP
        return "TCP"
    if protocol == 17:  # UDP
        return "UDP"
    return "Other"


@dataclass(frozen=True)
class FlowFeatures:
    """Immutable per-flow telemetry capsule produced by the CICFlowMeter extractor."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    features: Dict[str, float]
