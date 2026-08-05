"""
Infrastructure Telemetry Tracking and Health Monitoring Service Module.

Captures system resource consumption footprints (CPU, RAM, Disk, active threads, and 
network throughput deltas) alongside core application analytics (live processing rates 
and unacknowledged threat flags) to support real-time metrics auditing and telemetry charting.
"""

from __future__ import annotations

import threading
from typing import Final

import psutil

from core.entities.system_metric import SystemMetric
from infrastructure.logging.logger_factory import get_logger
from repositories.alert_repository import AlertRepository
from repositories.detection_repository import DetectionRepository
from repositories.system_metric_repository import SystemMetricRepository
from utils.time_utils import utc_minutes_ago_sql

logger = get_logger("services.monitoring_service")


class MonitoringService:
    """
    Central operational hub collecting and archiving system and application-level performance metrics.
    """

    def __init__(
        self,
        metric_repository: SystemMetricRepository,
        detection_repository: DetectionRepository | None = None,
        alert_repository: AlertRepository | None = None,
    ) -> None:
        """
        Initializes the monitoring engine with specific telemetry and state repositories.
        """
        self._repo: Final[SystemMetricRepository] = metric_repository
        self._detections: Final[DetectionRepository | None] = detection_repository
        self._alerts: Final[AlertRepository | None] = alert_repository
        self._last_net: psutil._common.snetio = psutil.net_io_counters()

    def capture_snapshot(self) -> SystemMetric:
        """
        Gathers system resource performance indicators and registers a time-series record.

        Returns:
            A persisted SystemMetric entity containing system and thread telemetry.
        """
        cpu: Final[float] = psutil.cpu_percent(interval=0.1)
        ram: Final[float] = psutil.virtual_memory().percent
        disk: Final[float] = psutil.disk_usage("/").percent
        net: Final[psutil._common.snetio] = psutil.net_io_counters()
        active_threads: Final[int] = threading.active_count()

        metric = SystemMetric(
            cpu_percent=cpu,
            ram_percent=ram,
            disk_percent=disk,
            network_sent_bytes=net.bytes_sent,
            network_recv_bytes=net.bytes_recv,
            active_threads=active_threads,
        )
        return self._repo.add(metric)

    def get_history(self, limit: int = 60) -> list[SystemMetric]:
        """
        Retrieves a chronological sequence of recent performance logs for charting.
        """
        return self._repo.get_recent(limit)

    def prune_old_metrics(self, hours: int = 24) -> int:
        """
        Flushes aged time-series performance records to prevent unbounded database expansion.
        """
        return self._repo.prune_older_than(hours)

    def get_prediction_rate_per_minute(self) -> float:
        """
        Calculates the count of analytics evaluation vectors verified over the past 60 seconds.
        """
        if self._detections is None:
            return 0.0
        since = utc_minutes_ago_sql(1)
        return float(self._detections.count_since(since))

    def get_active_alerts_count(self) -> int:
        """
        Returns the immediate count of unacknowledged high-priority security events.
        """
        if self._alerts is None:
            return 0
        return self._alerts.count_active()

    def get_network_throughput_bytes(self) -> dict[str, int]:
        """
        Computes network interface I/O delta metrics observed since the preceding check.

        Returns:
            A dictionary containing relative transmission and receipt deltas.
        """
        current: Final[psutil._common.snetio] = psutil.net_io_counters()
        delta: Final[dict[str, int]] = {
            "sent_bytes": max(0, current.bytes_sent - self._last_net.bytes_sent),
            "recv_bytes": max(0, current.bytes_recv - self._last_net.bytes_recv),
        }
        self._last_net = current
        return delta