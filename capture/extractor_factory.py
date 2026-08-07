"""
Flow Extractor Factory Module.

CICFlowMeter (pure-Python) is the sole flow-extraction backend for offline PCAP
analysis. The factory keeps a single construction point so consumers resolve the
extractor through one stable seam rather than instantiating concrete classes
directly.

There is deliberately no mode branching: the native Python aggregation pipeline
has been removed, so this factory always returns the CICFlowMeter adapter.
"""

from __future__ import annotations

from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IFlowExtractor

# Initialize Component-Specific Logger Interface Instance
logger = get_logger("capture.extractor_factory")


def get_flow_extractor() -> IFlowExtractor:
    """
    Returns the sole supported flow extractor: the pure-Python CICFlowMeter adapter.

    Raises:
        ConfigurationError: If the required third-party packages are unavailable.
    """
    from capture.cicflowmeter_adapter import CICFlowMeterAdapter

    logger.info("Factory Action: Initializing pure-Python CICFlowMeterAdapter engine.")
    return CICFlowMeterAdapter()
