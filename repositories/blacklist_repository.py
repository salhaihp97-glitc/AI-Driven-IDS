"""
Blacklist Network Access Control Infrastructure Module.

Manages data persistence transitions for the system access boundaries table 'blacklist_ips'. 
Provides atomic duplication protections, structural modification limits, and tracking queries 
to support low-latency evaluation pipelines.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from config.constants import TableNames
from core.entities.ip_list_entry import BlacklistIP
from core.exceptions import DuplicateRecordError, RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class BlacklistRepository(BaseSQLiteRepository[BlacklistIP]):
    """
    SQLite repository provider managing structured infrastructure network blacklists.
    """
    
    table_name: Final[str] = TableNames.BLACKLIST_IPS

    def _row_to_entity(self, row: sqlite3.Row) -> BlacklistIP:
        """
        Translates raw database record states into domain-layer BlacklistIP entities.
        """
        return BlacklistIP(
            id=row["id"], 
            ip_address=row["ip_address"], 
            reason=row["reason"],
            created_at=row["created_at"]
        )

    def add(self, entity: BlacklistIP) -> BlacklistIP:
        """
        Persists a newly identified blocked network boundary profile into tracking tables.

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
                    "INSERT INTO blacklist_ips (ip_address, reason) VALUES (?, ?)",
                    (entity.ip_address, entity.reason),
                )
                entity.id = cur.lastrowid
            return entity
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordError(
                f"Persistence Boundary Collision: Network resource locator identity '{entity.ip_address}' "
                f"is already managed within this registry dataset."
            ) from exc

    def update(self, entity: BlacklistIP) -> BlacklistIP:
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
            raise RecordNotFoundError("Persistence Operations Fault: Cannot update a BlacklistIP lacking a valid id identifier.")
            
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE blacklist_ips SET ip_address = ?, reason = ? WHERE id = ?",
                (entity.ip_address, entity.reason, entity.id),
            )
            if cur.rowcount == 0:
                raise RecordNotFoundError(f"Persistence Target Missing: Blacklist identity record '{entity.id}' was not located.")
        return entity

    def exists(self, ip_address: str) -> bool:
        """Validates whether a target network locator matches a registered restriction entry."""
        with self._db.cursor() as cur:
            cur.execute("SELECT 1 FROM blacklist_ips WHERE ip_address = ?", (ip_address,))
            return cur.fetchone() is not None

    def get_by_ip(self, ip_address: str) -> BlacklistIP | None:
        """Returns the persistent blacklist record (with its block reason) for an IP, or None."""
        with self._db.cursor() as cur:
            cur.execute("SELECT * FROM blacklist_ips WHERE ip_address = ?", (ip_address,))
            row = cur.fetchone()
        return self._row_to_entity(row) if row is not None else None

    def count(self) -> int:
        """Returns the total number of blacklisted IP entries."""
        with self._db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM blacklist_ips")
            return int(cur.fetchone()["cnt"])

    def search(self, text: str) -> list[BlacklistIP]:
        """Queries matching network resource configurations using pattern filters."""
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM blacklist_ips WHERE ip_address LIKE ? OR reason LIKE ? ORDER BY id DESC",
                (f"%{text}%", f"%{text}%"),
            )
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]