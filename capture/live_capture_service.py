"""
Live Capture Service Factory Module.

CICFlowMeter (pure-Python) is the sole live-capture backend. This module exposes
the process-wide singleton factory so CLI, Streamlit UI, and monitoring consumers
all resolve one consistent service instance without constructing it themselves.

The factory is intentionally free of any alternative-extractor branching: the
native Python aggregation pipeline has been removed, so there is a single
instantiation path.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from infrastructure.logging.logger_factory import get_logger

logger = get_logger("capture.live_capture_service")


@lru_cache(maxsize=1)
def get_live_capture_service() -> Any:
    """
    Retrieves the process-wide orchestration singleton instance.

    Guarantees stateful logging buffers survive runtime context mutations caused
    by continuous user-interface screen re-executions.
    """
    from capture.cicflowmeter_live_capture_service import CICFlowMeterLiveCaptureService
    from config.settings import get_settings
    from services.container import get_container

    container = get_container()
    settings = get_settings()

    logger.info(
        "System Instantiation: Spawning persistent singleton using CICFlowMeter "
        "(expired-update=%ds, flush-interval=%ds).",
        settings.cicflowmeter_expired_update_seconds,
        settings.cicflowmeter_interval_seconds,
    )
    return CICFlowMeterLiveCaptureService(
        detection_service=container.detection_service,
        csv_analysis_service=container.csv_analysis_service,
        log_repository=container.log_repository,
    )
