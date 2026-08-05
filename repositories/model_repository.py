"""
Machine Learning Model Registry Infrastructure Repository Module.

Manages persistence operations targeting the 'models' registry dataset. Controls analytical asset 
tracking, deployment state updates, model identification queries, and atomic activation swaps.
"""

from __future__ import annotations

import sqlite3
from typing import Final, Optional

from config.constants import TableNames
from core.entities.model_record import ModelRecord
from core.exceptions import RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class ModelRepository(BaseSQLiteRepository[ModelRecord]):
    """
    SQLite repository provider managing metadata state matrices for registered machine learning models.
    """

    table_name: Final[str] = TableNames.MODELS

    def _row_to_entity(self, row: sqlite3.Row) -> ModelRecord:
        """
        Translates raw database record states into domain-layer ModelRecord entities.
        """
        return ModelRecord(
            id=row["id"],
            name=row["name"],
            file_path=row["file_path"],
            model_type=row["model_type"],
            version=row["version"],
            features_count=row["features_count"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            metadata=row["metadata"],
        )

    def add(self, entity: ModelRecord) -> ModelRecord:
        """
        Registers a new machine learning structural asset definition within storage.

        Args:
            entity: The unstable transient domain instance to insert.

        Returns:
            The mutated domain entity stamped with its assigned row identity number.
        """
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO models (name, file_path, model_type, version, features_count, is_active, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity.name,
                    entity.file_path,
                    entity.model_type,
                    entity.version,
                    entity.features_count,
                    int(entity.is_active),
                    entity.metadata,
                ),
            )
            entity.id = cur.lastrowid
        return entity

    def update(self, entity: ModelRecord) -> ModelRecord:
        """
        Modifies tracking parameters and deployment tags for a registered machine learning asset.

        Args:
            entity: The updated entity reference to synchronize.

        Returns:
            The verified updated instance reference.

        Raises:
            RecordNotFoundError: If the primary key is missing or could not be located in storage.
        """
        if entity.id is None:
            raise RecordNotFoundError("Persistence Operations Fault: Cannot update a ModelRecord lacking a valid id identifier.")

        with self._db.cursor() as cur:
            cur.execute(
                """
                UPDATE models
                SET name = ?, file_path = ?, model_type = ?, version = ?,
                    features_count = ?, is_active = ?, metadata = ?
                WHERE id = ?
                """,
                (
                    entity.name,
                    entity.file_path,
                    entity.model_type,
                    entity.version,
                    entity.features_count,
                    int(entity.is_active),
                    entity.metadata,
                    entity.id,
                ),
            )
            if cur.rowcount == 0:
                raise RecordNotFoundError(f"Persistence Target Missing: Model registry record '{entity.id}' was not located.")
        return entity

    def get_active(self) -> list[ModelRecord]:
        """
        Extracts all currently loaded, active machine learning inference models from the registry.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT * FROM models WHERE is_active = 1 ORDER BY id DESC")
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]

    def get_by_name(self, name: str) -> Optional[ModelRecord]:
        """
        Queries the database to resolve a model definition using its unique name key.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT * FROM models WHERE name = ?", (name,))
            row = cur.fetchone()
        return self._row_to_entity(row) if row else None

    def deactivate_all(self) -> None:
        """
        Executes a mass baseline sweep, shifting all registered assets offline uniformly.

        Typically invoked prior to promoting a newly selected pipeline entry to hot status.
        """
        with self._db.cursor() as cur:
            cur.execute("UPDATE models SET is_active = 0")