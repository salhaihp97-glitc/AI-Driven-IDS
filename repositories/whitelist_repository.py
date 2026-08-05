"""
Whitelist Network Access Control Infrastructure Module.

Manages data persistence transitions for the system access boundaries table 'whitelist_ips'. 
Provides atomic duplication protections, structural modification limits, and tracking queries 
to support low-latency evaluation pipelines.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from config.constants import TableNames
from core.entities.ip_list_entry import WhitelistIP
from core.exceptions import DuplicateRecordError, RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class WhitelistRepository(BaseSQLiteRepository[WhitelistIP]):
    """
    SQLite repository provider managing structured infrastructure network whitelists.
    """
    
    table_name: Final[str] = TableNames.WHITELIST_IPS

    def _row_to_entity(self, row: sqlite3.Row) -> WhitelistIP:
        """
        Translates raw database record states into domain-layer WhitelistIP entities.
        """
        return WhitelistIP(
            id=row["id"], 
            ip_address=row["ip_address"], 
            reason=row["reason"],
            created_at=row["created_at"]
        )

    def add(self, entity: WhitelistIP) -> WhitelistIP:
        """
        Persists a newly identified allowed network boundary profile into tracking tables.

        Args:
            entity: The transient instance to save.

        Returns:
            The mutated entity updated with its database-generated index number.

        Raises:
            DuplicateRecordError: If the target IP configuration has already been registered.
        """
        try:
            with self._db.cursor() as cur:
                cur.execute(
                    "INSERT INTO whitelist_ips (ip_address, reason) VALUES (?, ?)",
                    (entity.ip_address, entity.reason),
                )
                entity.id = cur.lastrowid
            return entity
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordError(
                f"Persistence Boundary Collision: Network resource locator identity '{entity.ip_address}' "
                f"is already managed within this registry dataset."
            ) from exc

    def update(self, entity: WhitelistIP) -> WhitelistIP:
        """
        Modifies variable attributes of an established firewall entity record.

        Args:
            entity: The updated entity reference to synchronize.

        Returns:
            The verified updated instance reference.

        Raises:
            RecordNotFoundError: If the underlying record identifier index is unassigned or invalid.
        """
        if entity.id is None:
            raise RecordNotFoundError("Persistence Operations Fault: Cannot update a WhitelistIP lacking a valid id identifier.")
            
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE whitelist_ips SET ip_address = ?, reason = ? WHERE id = ?",
                (entity.ip_address, entity.reason, entity.id),
            )
            if cur.rowcount == 0:
                raise RecordNotFoundError(f"Persistence Target Missing: Whitelist identity record '{entity.id}' was not located.")
        return entity

    def exists(self, ip_address: str) -> bool:
        """Validates whether a target network locator matches a registered allowance entry."""
        with self._db.cursor() as cur:
            cur.execute("SELECT 1 FROM whitelist_ips WHERE ip_address = ?", (ip_address,))
            return cur.fetchone() is not None

    def count(self) -> int:
        """Returns the total number of whitelisted IP entries."""
        with self._db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM whitelist_ips")
            return int(cur.fetchone()["cnt"])

    def search(self, text: str) -> list[WhitelistIP]:
        """Queries matching network resource configurations using pattern filters."""
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM whitelist_ips WHERE ip_address LIKE ? OR reason LIKE ? ORDER BY id DESC",
                (f"%{text}%", f"%{text}%"),
            )
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]