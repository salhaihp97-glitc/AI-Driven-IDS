"""
Telegram Subscriber Persistence Infrastructure Module.

Manages data persistence transitions for the system notification registry
table 'telegram_subscribers' plus runtime overrides for the Telegram Bot
credentials stored in the key-value 'settings' table.

Enables multi-user alert fan-out: independent chat subscriptions can be
registered, labelled, paused, or removed without restarting the application,
and a deployment owner can self-provision a bot token at runtime.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from config.constants import SubscriberStatus, TableNames
from core.entities.telegram_subscriber import TelegramSubscriber
from core.exceptions import DuplicateRecordError, RecordNotFoundError
from repositories.base_repository import BaseSQLiteRepository

# Settings table keys used for runtime bot credential overrides
_KEY_BOT_TOKEN: Final[str] = "telegram_bot_token"
_KEY_CHAT_ID: Final[str] = "telegram_chat_id"


class TelegramSubscriberRepository(BaseSQLiteRepository[TelegramSubscriber]):
    """
    SQLite repository provider managing structured Telegram recipient subscriptions.
    """

    table_name: Final[str] = TableNames.TELEGRAM_SUBSCRIBERS

    def _row_to_entity(self, row: sqlite3.Row) -> TelegramSubscriber:
        """
        Translates raw database record states into domain-layer subscriber entities.
        """
        return TelegramSubscriber(
            id=row["id"],
            chat_id=row["chat_id"],
            label=row["label"] or "",
            is_active=bool(row["is_active"]),
            status=SubscriberStatus(row["status"]),
            created_at=row["created_at"],
        )

    def add(self, entity: TelegramSubscriber) -> TelegramSubscriber:
        """
        Persists a newly registered chat subscription into the notification registry.

        Args:
            entity: The transient subscriber instance to save.

        Returns:
            The mutated entity updated with its database-generated index number.

        Raises:
            DuplicateRecordError: If the target chat identity has already been registered.
        """
        try:
            with self._db.cursor() as cur:
                cur.execute(
                    "INSERT INTO telegram_subscribers (chat_id, label, is_active, status) VALUES (?, ?, ?, ?)",
                    (entity.chat_id, entity.label or "", int(entity.is_active), entity.status.value),
                )
                entity.id = cur.lastrowid
            return entity
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordError(
                f"Persistence Boundary Collision: Telegram chat identity '{entity.chat_id}' "
                f"is already registered within this notification registry."
            ) from exc

    def update(self, entity: TelegramSubscriber) -> TelegramSubscriber:
        """
        Modifies variable attributes of an established subscriber record.

        Args:
            entity: The updated entity reference to synchronize.

        Returns:
            The verified updated instance reference.

        Raises:
            RecordNotFoundError: If the underlying record identifier index is unassigned or invalid.
        """
        if entity.id is None:
            raise RecordNotFoundError(
                "Persistence Operations Fault: Cannot update a TelegramSubscriber lacking a valid id identifier."
            )

        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE telegram_subscribers SET chat_id = ?, label = ?, is_active = ?, status = ? WHERE id = ?",
                (entity.chat_id, entity.label or "", int(entity.is_active), entity.status.value, entity.id),
            )
            if cur.rowcount == 0:
                raise RecordNotFoundError(
                    f"Persistence Target Missing: Subscriber identity record '{entity.id}' was not located."
                )
        return entity

    def exists(self, chat_id: str) -> bool:
        """Validates whether a chat identity is already registered as a subscriber."""
        with self._db.cursor() as cur:
            cur.execute("SELECT 1 FROM telegram_subscribers WHERE chat_id = ?", (chat_id,))
            return cur.fetchone() is not None

    def count(self) -> int:
        """Returns the total number of registered subscriber entries."""
        with self._db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM telegram_subscribers")
            return int(cur.fetchone()["cnt"])

    def get_by_chat_id(self, chat_id: str) -> TelegramSubscriber | None:
        """Queries a single subscriber record by its unique chat identity."""
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM telegram_subscribers WHERE chat_id = ?", (chat_id,)
            )
            row = cur.fetchone()
        return self._row_to_entity(row) if row else None

    def get_by_status(self, status: SubscriberStatus) -> list[TelegramSubscriber]:
        """Extracts all subscriber records matching a given approval status."""
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM telegram_subscribers WHERE status = ? ORDER BY id ASC",
                (status.value,),
            )
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]

    def get_pending(self) -> list[TelegramSubscriber]:
        """Returns all subscribers awaiting administrator approval, oldest first."""
        return self.get_by_status(SubscriberStatus.PENDING)

    def get_approved(self) -> list[TelegramSubscriber]:
        """Returns all subscribers granted alert delivery access, in registration order."""
        return self.get_by_status(SubscriberStatus.APPROVED)

    def get_active(self) -> list[TelegramSubscriber]:
        """Extracts all enabled and approved subscriber records in registration order."""
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM telegram_subscribers WHERE status = ? AND is_active = 1 ORDER BY id ASC",
                (SubscriberStatus.APPROVED.value,),
            )
            rows = cur.fetchall()
        return [self._row_to_entity(row) for row in rows]

    def list_chat_ids(self) -> list[str]:
        """Returns the ordered list of active, approved recipient chat identities."""
        return [sub.chat_id for sub in self.get_active()]

    def set_status(self, chat_id: str, status: SubscriberStatus) -> bool:
        """Transitions the approval lifecycle state of an existing subscriber subscription."""
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE telegram_subscribers SET status = ? WHERE chat_id = ?",
                (status.value, chat_id),
            )
            return cur.rowcount > 0

    def set_active(self, chat_id: str, is_active: bool) -> bool:
        """Toggles the delivery state of an existing subscriber subscription."""
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE telegram_subscribers SET is_active = ? WHERE chat_id = ?",
                (int(is_active), chat_id),
            )
            return cur.rowcount > 0

    def delete(self, entity_id: int) -> bool:
        """Removes a specific subscriber from the notification registry by primary key."""
        return super().delete(entity_id)

    # =========================================================================
    # Runtime Bot Credential Overrides (settings key-value table)
    # =========================================================================

    def get_runtime_bot_token(self) -> str:
        """Reads the runtime-provisioned bot token override, if one was stored."""
        return self._get_setting(_KEY_BOT_TOKEN)

    def set_runtime_bot_token(self, token: str) -> None:
        """Persists (or clears) the runtime bot token override in the settings table."""
        self._set_setting(_KEY_BOT_TOKEN, token)

    def get_runtime_chat_id(self) -> str:
        """Reads the runtime-provisioned legacy chat id override, if one was stored."""
        return self._get_setting(_KEY_CHAT_ID)

    def set_runtime_chat_id(self, chat_id: str) -> None:
        """Persists (or clears) the runtime legacy chat id override in the settings table."""
        self._set_setting(_KEY_CHAT_ID, chat_id)

    def _get_setting(self, key: str) -> str:
        with self._db.cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cur.fetchone()
        return row["value"] if row else ""

    def _set_setting(self, key: str, value: str) -> None:
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
                ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                               updated_at = datetime('now')
                """,
                (key, value),
            )
