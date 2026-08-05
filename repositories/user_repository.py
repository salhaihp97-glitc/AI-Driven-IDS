"""
Identity and Access Management Infrastructure Repository Module.

Manages data persistence transitions targeting the 'users' registry space. Controls profile 
provisioning actions, runtime security role synchronization, unique username boundary assertions, 
and authentication metadata logging.
"""

from __future__ import annotations

import sqlite3
from typing import Final, Optional

from config.constants import TableNames, UserRole
from core.entities.user import User
from core.exceptions import DuplicateRecordError, RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository


class UserRepository(BaseSQLiteRepository[User]):
    """
    SQLite repository provider managing credentials, active flags, and role assignments for system identities.
    """

    table_name: Final[str] = TableNames.USERS

    def _row_to_entity(self, row: sqlite3.Row) -> User:
        """
        Translates raw database record states into domain-layer User entities.
        """
        return User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            last_login_at=row["last_login_at"],
        )

    def add(self, entity: User) -> User:
        """
        Registers a new operational system entity identity into persistent storage.

        Args:
            entity: The unstable transient domain instance to insert.

        Returns:
            The mutated domain entity updated with its database-generated index number.

        Raises:
            DuplicateRecordError: If the designated username constraint conflicts with an existing profile.
        """
        try:
            with self._db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role, is_active)
                    VALUES (?, ?, ?, ?)
                    """,
                    (entity.username, entity.password_hash, entity.role.value, int(entity.is_active)),
                )
                entity.id = cur.lastrowid
            return entity
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordError(
                f"Identity Access Collision: The unique resource username account identifier "
                f"'{entity.username}' is already allocated inside this domain registry."
            ) from exc

    def update(self, entity: User) -> User:
        """
        Modifies access permissions, active states, and runtime metrics for an established user.

        Args:
            entity: The updated entity reference to synchronize.

        Returns:
            The verified updated instance reference.

        Raises:
            RecordNotFoundError: If the primary tracking key identifier is missing or invalid.
        """
        if entity.id is None:
            raise RecordNotFoundError("Persistence Operations Fault: Cannot update a User lacking a valid id identifier.")

        with self._db.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET username = ?, password_hash = ?, role = ?, is_active = ?, last_login_at = ?
                WHERE id = ?
                """,
                (
                    entity.username,
                    entity.password_hash,
                    entity.role.value,
                    int(entity.is_active),
                    entity.last_login_at,
                    entity.id,
                ),
            )
            if cur.rowcount == 0:
                raise RecordNotFoundError(f"Persistence Target Missing: User identity record '{entity.id}' was not located.")
        return entity

    def get_by_username(self, username: str) -> Optional[User]:
        """
        Queries the database to resolve an identity profile using its unique username string key.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
        return self._row_to_entity(row) if row else None

    def count(self) -> int:
        """
        Calculates the summation total of all registered identities on the system.
        """
        with self._db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as c FROM users")
            return int(cur.fetchone()["c"])