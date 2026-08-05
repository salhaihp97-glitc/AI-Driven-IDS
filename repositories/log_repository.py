"""
System Telemetry and Audit Log Infrastructure Repository Module.

Manages data persistence operations targeting the centralized 'logs' dataset. Enforces write-once,
append-only persistence patterns to provide reliable runtime monitoring, debug tracing, and
immutable diagnostic records.
"""

from __future__ import annotations

import sqlite3
from typing import Final, Optional

from config.constants import LogLevel, LogSource, TableNames
from core.entities.log_entry import LogEntry
from core.exceptions import RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class LogRepository(BaseSQLiteRepository[LogEntry]):
    """SQLite repository provider managing multi-source diagnostic events and application traces."""

    table_name: Final[str] = TableNames.LOGS

    def _row_to_entity(self, row: sqlite3.Row) -> LogEntry:
        """Translates raw database record states into domain-layer LogEntry entities."""
        return LogEntry(
            id=row["id"],
            source=LogSource(row["source"]),
            level=LogLevel(row["level"]),
            message=row["message"],
            metadata=row["metadata"],
            created_at=row["created_at"],
        )

    def add(self, entity: LogEntry) -> LogEntry:
        """Persists a new transactional system log telemetry entry into storage."""
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO logs (source, level, message, metadata)
                VALUES (?, ?, ?, ?)
                """,
                (entity.source.value, entity.level.value, entity.message, entity.metadata),
            )
            entity.id = cur.lastrowid
        return entity

    def update(self, entity: LogEntry) -> LogEntry:
        """Enforces pipeline safety constraints against modifying historical audit logs."""
        raise RecordNotFoundError("Data Integrity Fault: System runtime logs are immutable records and cannot be altered.")

    def count(self, source: Optional[LogSource] = None, level: Optional[LogLevel] = None) -> int:
        """Returns the total number of log entries matching optional source/level filters."""
        query = "SELECT COUNT(*) AS cnt FROM logs WHERE 1=1"
        params: list = []
        if source is not None:
            query += " AND source = ?"
            params.append(source.value)
        if level is not None:
            query += " AND level = ?"
            params.append(level.value)
        with self._db.cursor() as cur:
            cur.execute(query, tuple(params))
            return int(cur.fetchone()["cnt"])

    def count_by_level(self) -> dict[str, int]:
        """Returns a mapping of each LogLevel value to its total occurrence count."""
        with self._db.cursor() as cur:
            cur.execute("SELECT level, COUNT(*) AS cnt FROM logs GROUP BY level")
            return {row["level"]: int(row["cnt"]) for row in cur.fetchall()}

    def count_by_source(self) -> dict[str, int]:
        """Returns a mapping of each LogSource value to its total occurrence count."""
        with self._db.cursor() as cur:
            cur.execute("SELECT source, COUNT(*) AS cnt FROM logs GROUP BY source")
            return {row["source"]: int(row["cnt"]) for row in cur.fetchall()}

    def search(
        self,
        source: Optional[LogSource] = None,
        level: Optional[LogLevel] = None,
        text: Optional[str] = None,
        limit: int = 200,
    ) -> list[LogEntry]:
        """Queries and filters system diagnostic logs based on multiple runtime criteria."""
        query = "SELECT * FROM logs WHERE 1=1"
        params: list = []

        if source is not None:
            query += " AND source = ?"
            params.append(source.value)

        if level is not None:
            query += " AND level = ?"
            params.append(level.value)

        if text:
            query += " AND message LIKE ?"
            params.append(f"%{text}%")

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._db.cursor() as cur:
            cur.execute(query, tuple(params))
            rows = cur.fetchall()

        return [self._row_to_entity(row) for row in rows]