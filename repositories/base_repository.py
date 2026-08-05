"""
Generic SQLite Base Repository Module.

Establishes the base infrastructure repository architecture using the SQLite storage mechanism. 
Combines boilerplate transaction execution steps, row mapping requirements, and common record 
lookup filters behind a strongly-typed generic contract interface.
"""

from __future__ import annotations

import sqlite3
from abc import abstractmethod
from typing import Final, Generic, Optional, TypeVar

from core.interfaces.repository import IRepository
from database.connection import DatabaseConnection, get_db_connection

TEntity = TypeVar("TEntity")


class BaseSQLiteRepository(IRepository[TEntity], Generic[TEntity]):
    """
    Abstract SQLite base repository orchestrating transactional data access operations.
    
    Acts as a central class layer managing active cursors and entity conversion loops, 
    allowing implementation layers to focus strictly on schema variations.
    """
    
    table_name: str = ""  # Subclasses must override this property with an explicit TableNames variable

    def __init__(self, db: Optional[DatabaseConnection] = None) -> None:
        """
        Initializes the repository workspace with an active data context handle.
        """
        self._db: Final[DatabaseConnection] = db or get_db_connection()

    @abstractmethod
    def _row_to_entity(self, row: sqlite3.Row) -> TEntity:
        """
        Transforms a database row memory allocation into a structured domain entity wrapper.
        """

    def get_by_id(self, entity_id: int) -> Optional[TEntity]:
        """
        Queries storage to retrieve a single record mapping to the given integer key.

        Args:
            entity_id: Unique record identification identifier index.

        Returns:
            The mapped domain entity representation, or None if no match is found.
        """
        with self._db.cursor() as cur:
            cur.execute(f"SELECT * FROM {self.table_name} WHERE id = ?", (entity_id,))
            row = cur.fetchone()
        return self._row_to_entity(row) if row else None

    def get_all(self) -> list[TEntity]:
        """
        Extracts all table entries, returned in descending sequence based on primary indices.
        """
        with self._db.cursor() as cur:
            cur.execute(f"SELECT * FROM {self.table_name} ORDER BY id DESC")
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]

    def delete(self, entity_id: int) -> bool:
        """
        Removes a specific record from storage by targeting its unique identifier.

        Args:
            entity_id: Unique record identification identifier index.

        Returns:
            True if a target row was modified and dropped, otherwise False.
        """
        with self._db.cursor() as cur:
            cur.execute(f"DELETE FROM {self.table_name} WHERE id = ?", (entity_id,))
            return cur.rowcount > 0

    @abstractmethod
    def add(self, entity: TEntity) -> TEntity:
        """
        Persists a transient domain entity state within the target database engine layer.
        """

    @abstractmethod
    def update(self, entity: TEntity) -> TEntity:
        """
        Modifies tracking details for a registered entity inside structural storage tables.
        """