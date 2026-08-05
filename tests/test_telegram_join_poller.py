"""
Telegram Join Request Poller Test Suite.

Validates the long-poll listener lifecycle, update parsing, enrollment
routing (pending requests, administrator auto-approval, duplicate
suppression), and the ``getUpdates`` transport — all without live network I/O.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from config.constants import SubscriberStatus
from core.entities.telegram_subscriber import TelegramSubscriber
from database.connection import DatabaseConnection
from infrastructure.notifications.telegram_join_poller import TelegramJoinPoller
from infrastructure.notifications.telegram_notifier import TelegramNotifier
from repositories.telegram_subscriber_repository import TelegramSubscriberRepository


def _make_notifier(db: DatabaseConnection, *, token: str = "fake-token", admin: str = "999") -> TelegramNotifier:
    """Notifier wired to an ephemeral registry with an explicit administrator chat."""
    return TelegramNotifier(
        bot_token=token,
        chat_id=admin,
        subscriber_repository=TelegramSubscriberRepository(db),
    )


def _make_poller(notifier: TelegramNotifier, repo: TelegramSubscriberRepository, **kwargs: Any) -> TelegramJoinPoller:
    return TelegramJoinPoller(notifier=notifier, subscriber_repository=repo, **kwargs)


def _private_message_update(chat_id: int | str, *, first: str = "", username: str = "", update_id: int = 1) -> dict[str, Any]:
    """Builds a Telegram update carrying a private-chat ``/start`` message."""
    return {
        "update_id": update_id,
        "message": {
            "chat": {"id": chat_id, "type": "private"},
            "from": {"first_name": first, "last_name": "", "username": username},
            "text": "/start",
        },
    }


# ========================================================================
# Section 1: Update Handling
# ========================================================================

class TestUpdateHandling:

    def test_private_message_creates_pending_request(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        with patch.object(notifier, "_send_raw") as mock_send:
            poller._handle_update(_private_message_update("111", first="Ali"))

        sub = repo.get_by_chat_id("111")
        assert sub is not None
        assert sub.status == SubscriberStatus.PENDING
        assert sub.label == "Ali"
        assert mock_send.call_count == 2  # administrator alert + requester ack

    def test_username_label_when_name_missing(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        with patch.object(notifier, "_send_raw"):
            poller._handle_update(_private_message_update("111", username="soc_alice"))

        assert repo.get_by_chat_id("111").label == "@soc_alice"

    def test_duplicate_registered_chat_is_ignored(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111", status=SubscriberStatus.PENDING))
        poller = _make_poller(notifier, repo)

        with patch.object(notifier, "_send_raw") as mock_send:
            poller._handle_update(_private_message_update("111"))

        mock_send.assert_not_called()
        assert len(repo.get_pending()) == 1

    def test_non_private_chat_is_ignored(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        update = _private_message_update("111")
        update["message"]["chat"]["type"] = "group"
        with patch.object(notifier, "_send_raw"):
            poller._handle_update(update)

        assert repo.get_by_chat_id("111") is None

    def test_administrator_chat_is_auto_approved(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db, admin="999")
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        with patch.object(notifier, "_send_raw"):
            poller._handle_update(_private_message_update("999", first="Admin"))

        sub = repo.get_by_chat_id("999")
        assert sub is not None
        assert sub.status == SubscriberStatus.APPROVED
        assert repo.get_pending() == []

    def test_pending_administrator_is_promoted_on_contact(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db, admin="999")
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="999", label="Admin", status=SubscriberStatus.PENDING))
        poller = _make_poller(notifier, repo)

        with patch.object(notifier, "_send_raw") as mock_send:
            poller._handle_update(_private_message_update("999"))

        assert repo.get_by_chat_id("999").status == SubscriberStatus.APPROVED
        assert mock_send.called

    def test_member_event_enrolls_group_chat(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        update = {
            "update_id": 5,
            "my_chat_member": {
                "chat": {"id": -100111, "type": "supergroup", "title": "SOC Team"},
                "new_chat_member": {"status": "member"},
            },
        }
        with patch.object(notifier, "_send_raw"):
            poller._handle_update(update)

        sub = repo.get_by_chat_id("-100111")
        assert sub is not None
        assert sub.status == SubscriberStatus.PENDING
        assert sub.label == "SOC Team"

    def test_member_event_leaving_status_is_ignored(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        update = {
            "update_id": 6,
            "my_chat_member": {
                "chat": {"id": -100111, "type": "supergroup"},
                "new_chat_member": {"status": "left"},
            },
        }
        poller._handle_update(update)

        assert repo.get_by_chat_id("-100111") is None


# ========================================================================
# Section 2: Polling Round
# ========================================================================

class TestPollingRound:

    def test_poll_once_advances_offset_and_routes_updates(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db, admin="999")
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        updates = [
            _private_message_update("111", first="Ali", update_id=7),
            _private_message_update("222", first="Sara", update_id=9),
        ]
        with patch.object(poller, "_fetch_updates", return_value=updates):
            next_offset = poller._poll_once(0)

        assert next_offset == 10
        assert poller._last_poll_at > 0
        assert repo.get_by_chat_id("111") is not None
        assert repo.get_by_chat_id("222") is not None

    def test_fetch_updates_parses_api_result(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        with patch("infrastructure.notifications.telegram_join_poller.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"ok": True, "result": [{"update_id": 3}]},
            )
            result = poller._fetch_updates(0)

        assert result == [{"update_id": 3}]
        payload = mock_post.call_args.kwargs["json"]
        assert payload["offset"] == 0
        assert payload["timeout"] == 25

    def test_fetch_updates_returns_empty_on_http_error(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        with patch("infrastructure.notifications.telegram_join_poller.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=400, text="Bad Request")
            assert poller._fetch_updates(0) == []

        assert "HTTP 400" in poller.last_error

    def test_fetch_updates_returns_empty_on_api_error(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        repo = TelegramSubscriberRepository(db)
        poller = _make_poller(notifier, repo)

        with patch("infrastructure.notifications.telegram_join_poller.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"ok": False, "description": "Conflict: terminated by other getUpdates request"},
            )
            assert poller._fetch_updates(0) == []

        assert "Conflict" in poller.last_error


# ========================================================================
# Section 3: Poller Lifecycle
# ========================================================================

class TestPollerLifecycle:

    def test_start_requires_bot_token(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db, token="")
        poller = _make_poller(notifier, TelegramSubscriberRepository(db))

        assert poller.start() is False
        assert poller.last_error
        assert poller.is_running is False

    def test_start_and_stop_round_trip(self, db: DatabaseConnection) -> None:
        notifier = _make_notifier(db)
        poller = _make_poller(notifier, TelegramSubscriberRepository(db))

        try:
            assert poller.start() is True
            assert poller.is_running is True
            assert poller.start() is True  # idempotent
        finally:
            poller.stop()

        assert poller.is_running is False
