"""
Flow Extractor Factory Module.

Implements the Factory Pattern to decouple client subsystems from the structural 
instantiation details of different IFlowExtractor concrete implementations. Resolves 
dependencies dynamically at runtime using environmental variable configurations.
"""

from __future__ import annotations

import os
from typing import Final

from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IFlowExtractor

# Initialize Component-Specific Logger Interface Instance
logger = get_logger("capture.extractor_factory")

# Fallback Configuration Constants
DEFAULT_EXTRACTOR_MODE: Final[str] = "native"


def get_flow_extractor() -> IFlowExtractor:
    """
    Evaluates system environment variables to construct and return the chosen telemetry extraction provider.

    Raises:
        ConfigurationError: If the chosen strategy configuration lacks valid required dependencies.
    """
    raw_mode = os.getenv("AI_IDS_FLOW_EXTRACTOR", DEFAULT_EXTRACTOR_MODE)
    mode: Final[str] = str(raw_mode).strip().lower()

    logger.debug("Resolving flow extractor implementation strategy. Configured target key: '%s'", mode)

    if mode == "cicflowmeter":
        from capture.cicflowmeter_adapter import CICFlowMeterAdapter

        logger.info("Factory Action: Initializing pure-Python CICFlowMeterAdapter engine.")
        return CICFlowMeterAdapter()

    # Default Architectural Fallback Routing Logic
    from capture.native_flow_extractor import NativeFlowExtractor

    logger.info("Factory Action: Initializing local NativeFlowExtractor engine interface (Pure Python mode).")
    return NativeFlowExtractor()