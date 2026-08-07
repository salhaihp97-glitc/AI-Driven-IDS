"""
Alert Infrastructure Repository Module.

Handles persistence boundary transactions for data mapping operations involving the 'alerts' 
data space. Manages sliding window aggregation checks, incident acknowledgments, and 
real-time statistics counts.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Final, Optional

from config.constants import TableNames
from core.entities.alert import Alert
from core.exceptions import RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class AlertRepository(BaseSQLiteRepository[Alert]):
    """
    SQLite repository provider managing structured security incidents telemetry data.
    """
    
    table_name: Final[str] = TableNames.ALERTS

    def _row_to_entity(self, row: sqlite3.Row) -> Alert:
        """
        Translates raw database record states into domain-layer Alert entities.
        """
        return Alert(
            id=row["id"],
            source_ip=row["source_ip"],
            threat_type=row["threat_type"],
            detection_id=row["detection_id"],
            occurrences=row["occurrences"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            is_acknowledged=bool(row["is_acknowledged"]),
            telegram_sent=bool(row["telegram_sent"]),
        )

    def add(self, entity: Alert) -> Alert:
        """
        Persists a newly identified threat tracking entity to storage.

        Args:
            entity: The unstable transient domain instance to insert.

        Returns:
            The mutated domain entity stamped with its assigned row identity number.
        """
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (source_ip, threat_type, detection_id, occurrences, is_acknowledged, telegram_sent)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entity.source_ip, 
                    entity.threat_type, 
                    entity.detection_id, 
                    entity.occurrences,
                    int(entity.is_acknowledged),
                    int(entity.telegram_sent)
                ),
            )
            entity.id = cur.lastrowid
        return entity

    def update(self, entity: Alert) -> Alert:
        """
        Updates variable threat details for a tracking entry on the persistent layer.

        Args:
            entity: The modified domain instance target to synchronize.

        Returns:
            The verified updated entity reference.

        Raises:
            RecordNotFoundError: If the entry index is missing or could not be found.
        """
        if entity.id is None:
            raise RecordNotFoundError("Persistence Operations Fault: Cannot update an Alert lacking a valid id identifier.")

        # Preserve the domain-provided event timestamp (e.g. detection.created_at)
        # instead of forcing wall-clock aggregation; fall back to now when unset.
        last_seen_value: Final[Optional[str]] = (
            entity.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(entity.last_seen, datetime)
            else entity.last_seen
        )

        with self._db.cursor() as cur:
            cur.execute(
                """
                UPDATE alerts
                SET occurrences = ?, last_seen = COALESCE(?, datetime('now')),
                    is_acknowledged = ?, telegram_sent = ?
                WHERE id = ?
                """,
                (
                    entity.occurrences,
                    last_seen_value,
                    int(entity.is_acknowledged),
                    int(entity.telegram_sent),
                    entity.id
                ),
            )
            if cur.rowcount == 0:
                raise RecordNotFoundError(f"Persistence Target Missing: Alert identity record '{entity.id}' was not located.")
        return entity

    def find_active_window(self, source_ip: str, threat_type: str, window_minutes: int) -> Optional[Alert]:
        """
        Identifies recent tracking incidents that fall within a given time aggregation window.

        Used by the engine boundary layers to choose between incrementing metric logs 
        or generating a new separate alert record.

        Args:
            source_ip: Primary source IP string context.
            threat_type: Structural attack classification label identifier.
            window_minutes: Evaluation boundary length value calculated backward from now.

        Returns:
            An active Alert matching criteria parameters, or None if none match.
        """
        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT * FROM alerts
                WHERE source_ip = ? AND threat_type = ?
                  AND last_seen >= datetime('now', ?)
                ORDER BY last_seen DESC
                LIMIT 1
                """,
                (source_ip, threat_type, f"-{window_minutes} minutes"),
            )
            row = cur.fetchone()
        return self._row_to_entity(row) if row else None

    def get_recent(self, limit: int = 100) -> list[Alert]:
        """
        Extracts historical event logs ordered by recent observation stamps.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]

    def count_active(self) -> int:
        """
        Calculates the summation total of un-acknowledged alert records remaining.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE is_acknowledged = 0")
            return int(cur.fetchone()["c"])