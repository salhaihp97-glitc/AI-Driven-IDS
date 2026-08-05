"""
Detection Telemetry Infrastructure Repository Module.

Manages the data persistence layer for the 'detections' table space. Enforces an append-only,
immutable log configuration over telemetry transactions to maintain auditable security history.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from config.constants import TableNames
from core.entities.detection import Detection
from core.exceptions import RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class DetectionRepository(BaseSQLiteRepository[Detection]):
    """
    SQLite repository provider managing structured telemetry classification logs.
    """

    table_name: Final[str] = TableNames.DETECTIONS

    def _row_to_entity(self, row: sqlite3.Row) -> Detection:
        """
        Translates raw database record states into domain-layer Detection entities.
        """
        return Detection(
            id=row["id"],
            model_id=row["model_id"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            prediction=row["prediction"],
            confidence=row["confidence"],
            source_type=row["source_type"],
            raw_features=row["raw_features"],
            severity=row["severity"] if "severity" in row.keys() else "",
            attack_type=row["attack_type"] if "attack_type" in row.keys() else "",
            attack_reason=row["attack_reason"] if "attack_reason" in row.keys() else "",
            is_whitelisted=bool(row["is_whitelisted"]) if "is_whitelisted" in row.keys() else False,
            is_blacklisted=bool(row["is_blacklisted"]) if "is_blacklisted" in row.keys() else False,
            created_at=row["created_at"],
        )

    def add(self, entity: Detection) -> Detection:
        """
        Persists a newly computed inference classification event into storage.

        Args:
            entity: The unstable transient domain instance to insert.

        Returns:
            The mutated domain entity stamped with its assigned row identity number.
        """
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO detections
                    (model_id, source_ip, destination_ip, prediction, confidence, source_type, raw_features, severity, attack_type, attack_reason, is_whitelisted, is_blacklisted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity.model_id,
                    entity.source_ip,
                    entity.destination_ip,
                    entity.prediction,
                    entity.confidence,
                    entity.source_type,
                    entity.raw_features,
                    entity.severity,
                    entity.attack_type,
                    entity.attack_reason,
                    int(entity.is_whitelisted),
                    int(entity.is_blacklisted),
                ),
            )
            entity.id = cur.lastrowid
        return entity

    def update(self, entity: Detection) -> Detection:
        """
        Enforces pipeline safety constraints against modifying historical event entries.

        Raises:
            RecordNotFoundError: Always thrown to ensure transaction immutability contracts.
        """
        raise RecordNotFoundError("Data Integrity Fault: Detection logs are immutable structures and cannot be modified.")

    def get_recent(self, limit: int = 100, only_attacks: bool = False) -> list[Detection]:
        """
        Extracts recent detection logs with optional state classification screening.
        """
        query = "SELECT * FROM detections"
        if only_attacks:
            query += " WHERE prediction != 0"
        query += " ORDER BY created_at DESC LIMIT ?"

        with self._db.cursor() as cur:
            cur.execute(query, (limit,))
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]

    def count_since(self, since_iso: str, only_attacks: bool = False) -> int:
        """
        Calculates transactional event volume matching a specific ISO timestamp window.
        """
        query = "SELECT COUNT(*) as c FROM detections WHERE created_at >= ?"
        if only_attacks:
            query += " AND prediction != 0"

        with self._db.cursor() as cur:
            cur.execute(query, (since_iso,))
            return int(cur.fetchone()["c"])