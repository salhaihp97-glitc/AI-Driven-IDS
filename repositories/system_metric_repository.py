"""
System Telemetry Observability Infrastructure Repository Module.

Manages data persistence transitions targeting the time-series 'system_metrics' log space. 
Enforces append-only immutability rules over active telemetry tracks, supplying historical data 
retrieval vectors and background data truncation features.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from config.constants import TableNames
from core.entities.system_metric import SystemMetric
from core.exceptions import RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class SystemMetricRepository(BaseSQLiteRepository[SystemMetric]):
    """
    SQLite repository provider managing structured infrastructure capacity performance metrics.
    """

    table_name: Final[str] = TableNames.SYSTEM_METRICS

    def _row_to_entity(self, row: sqlite3.Row) -> SystemMetric:
        """
        Translates raw database record states into domain-layer SystemMetric entities.
        """
        return SystemMetric(
            id=row["id"],
            cpu_percent=row["cpu_percent"],
            ram_percent=row["ram_percent"],
            disk_percent=row["disk_percent"],
            network_sent_bytes=row["network_sent_bytes"],
            network_recv_bytes=row["network_recv_bytes"],
            active_threads=row["active_threads"],
            created_at=row["created_at"],
        )

    def add(self, entity: SystemMetric) -> SystemMetric:
        """
        Persists a newly captured hardware telemetry signature state into storage.

        Args:
            entity: The unstable transient diagnostic instance to save.

        Returns:
            The mutated domain entity updated with its database-generated index number.
        """
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO system_metrics
                    (cpu_percent, ram_percent, disk_percent, network_sent_bytes, network_recv_bytes, active_threads)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entity.cpu_percent,
                    entity.ram_percent,
                    entity.disk_percent,
                    entity.network_sent_bytes,
                    entity.network_recv_bytes,
                    entity.active_threads,
                ),
            )
            entity.id = cur.lastrowid
        return entity

    def update(self, entity: SystemMetric) -> SystemMetric:
        """
        Enforces runtime pipeline safety constraints against modifying historical performance logs.

        Raises:
            RecordNotFoundError: Always thrown to guarantee metric store immutability.
        """
        raise RecordNotFoundError("Data Integrity Fault: System health metrics are immutable records and cannot be altered.")

    def get_recent(self, limit: int = 60) -> list[SystemMetric]:
        """
        Extracts recent hardware telemetry tracking instances ordered chronologically.

        Reverses the raw descending query database array internally before outputting, 
        making it instantly compatible with timeline visualization charts.

        Args:
            limit: Structural window ceiling tracking the total entry rows to extract.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT * FROM system_metrics ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        return list(reversed([self._row_to_entity(row) for row in rows]))

    def prune_older_than(self, hours: int = 24) -> int:
        """
        Truncates ancient time-series records falling beyond the designated window length.

        Args:
            hours: Dynamic boundary count tracing backward from execution time.

        Returns:
            The total count of dropped database entry allocations.
        """
        with self._db.cursor() as cur:
            cur.execute(
                "DELETE FROM system_metrics WHERE created_at < datetime('now', ?)",
                (f"-{hours} hours",),
            )
            return cur.rowcount