"""
Telegram Multi-Subscriber Feature Test Suite.

Validates the persistence registry, recipient resolution fallbacks, broadcast
fan-out to every active subscriber, runtime bot credential overrides, and the
IoC container wiring — without requiring live Telegram Bot API credentials.
"""

from __future__ import annotations

from typing import Any, Final

import pytest
from unittest.mock import MagicMock, patch

from config.constants import SubscriberStatus, TableNames
from core.entities.telegram_subscriber import TelegramSubscriber
from core.exceptions import DuplicateRecordError, ValidationError
from database.connection import DatabaseConnection
from infrastructure.notifications.telegram_notifier import TelegramNotifier
from repositories.telegram_subscriber_repository import TelegramSubscriberRepository
from services.container import Container
from utils.validators import validate_chat_id


# ========================================================================
# Helper — synchronous thread stand-in for deterministic async testing
# ========================================================================

class _FakeThread:
    """Executes the target synchronously on ``start()`` for test determinism."""

    def __init__(self, target: Any = None, args: tuple[Any, ...] = (), **_: Any) -> None:
        self._target: Any = target
        self._args: tuple[Any, ...] = args

    def start(self) -> None:
        if self._target is not None:
            self._target(*self._args)


def _notifier_with_subscribers(
    db: DatabaseConnection,
    chat_ids: list[str],
    *,
    bot_token: str = "fake-token-123",
    legacy_chat_id: str = "",
    static_chat_ids: list[str] | None = None,
) -> tuple[TelegramNotifier, TelegramSubscriberRepository]:
    """Builds a notifier wired to an ephemeral subscriber registry.

    ``chat_id`` is passed explicitly (never ``None``) so the notifier does not
    fall back to the environment-configured chat id during tests.
    """
    repo = TelegramSubscriberRepository(db)
    for chat_id in chat_ids:
        repo.add(TelegramSubscriber(chat_id=chat_id, label=f"Subscriber {chat_id}"))
    notifier = TelegramNotifier(
        bot_token=bot_token,
        chat_id=legacy_chat_id,
        chat_ids=static_chat_ids,
        subscriber_repository=repo,
    )
    return notifier, repo


# ========================================================================
# Section 1: Chat ID Validation
# ========================================================================

class TestChatIdValidation:

    def test_accepts_positive_chat_id(self) -> None:
        assert validate_chat_id(" 123456789 ") == "123456789"

    def test_accepts_negative_group_chat_id(self) -> None:
        assert validate_chat_id("-1001234567890") == "-1001234567890"

    def test_rejects_non_numeric(self) -> None:
        with pytest.raises(ValidationError):
            validate_chat_id("@someuser")

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            validate_chat_id("   ")


# ========================================================================
# Section 2: Subscriber Repository
# ========================================================================

class TestSubscriberRepository:

    def test_add_and_get_by_chat_id(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        sub = repo.add(TelegramSubscriber(chat_id="111", label="SOC 1"))

        fetched = repo.get_by_chat_id("111")
        assert fetched is not None
        assert fetched.id == sub.id
        assert fetched.chat_id == "111"
        assert fetched.label == "SOC 1"
        assert fetched.is_active is True

    def test_duplicate_chat_id_raises(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111"))

        with pytest.raises(DuplicateRecordError):
            repo.add(TelegramSubscriber(chat_id="111"))

    def test_update_label_and_state(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        sub = repo.add(TelegramSubscriber(chat_id="111"))

        sub.label = "Renamed"
        sub.is_active = False
        repo.update(sub)

        fetched = repo.get_by_chat_id("111")
        assert fetched is not None
        assert fetched.label == "Renamed"
        assert fetched.is_active is False

    def test_get_active_filters_paused(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111"))
        repo.add(TelegramSubscriber(chat_id="222"))
        repo.set_active("222", False)

        assert repo.list_chat_ids() == ["111"]
        assert repo.count() == 2

    def test_set_active_toggles(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111"))

        assert repo.set_active("111", False) is True
        assert repo.list_chat_ids() == []

        assert repo.set_active("111", True) is True
        assert repo.list_chat_ids() == ["111"]

    def test_delete_removes_subscriber(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        sub = repo.add(TelegramSubscriber(chat_id="111"))

        assert repo.delete(sub.id) is True
        assert repo.get_by_chat_id("111") is None
        assert repo.delete(sub.id) is False

    def test_runtime_credential_overrides_round_trip(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        assert repo.get_runtime_bot_token() == ""
        assert repo.get_runtime_chat_id() == ""

        repo.set_runtime_bot_token("rt-token-abc")
        repo.set_runtime_chat_id("987654")
        assert repo.get_runtime_bot_token() == "rt-token-abc"
        assert repo.get_runtime_chat_id() == "987654"

        repo.set_runtime_bot_token("")
        assert repo.get_runtime_bot_token() == ""


# ========================================================================
# Section 2b: Approval Status Lifecycle
# ========================================================================

class TestSubscriberStatusLifecycle:

    def test_default_status_is_approved(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111"))

        fetched = repo.get_by_chat_id("111")
        assert fetched is not None
        assert fetched.status == SubscriberStatus.APPROVED

    def test_pending_subscriber_is_excluded_from_delivery(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111", status=SubscriberStatus.PENDING))

        assert [p.chat_id for p in repo.get_pending()] == ["111"]
        assert repo.get_approved() == []
        assert repo.list_chat_ids() == []

    def test_pending_ordering_is_oldest_first(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="222", status=SubscriberStatus.PENDING))
        repo.add(TelegramSubscriber(chat_id="111", status=SubscriberStatus.PENDING))

        assert [p.chat_id for p in repo.get_pending()] == ["222", "111"]

    def test_set_status_transitions_lifecycle(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111", status=SubscriberStatus.PENDING))

        assert repo.set_status("111", SubscriberStatus.APPROVED) is True
        assert repo.get_by_chat_id("111").status == SubscriberStatus.APPROVED
        assert repo.set_status("999", SubscriberStatus.APPROVED) is False

    def test_delivery_targets_require_approved_and_active(self, db: DatabaseConnection) -> None:
        repo = TelegramSubscriberRepository(db)
        repo.add(TelegramSubscriber(chat_id="111"))  # approved + active
        repo.add(TelegramSubscriber(chat_id="222"))  # approved + paused
        repo.add(TelegramSubscriber(chat_id="333", status=SubscriberStatus.PENDING))
        repo.set_active("222", False)

        assert repo.list_chat_ids() == ["111"]


# ========================================================================
# Section 3: Recipient Resolution Fallbacks
# ========================================================================

class TestRecipientResolution:

    def test_repo_takes_precedence_over_legacy_chat_id(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(
            db, ["111", "222"], legacy_chat_id="999",
        )
        assert set(notifier._recipient_chat_ids()) == {"111", "222"}

    def test_falls_back_to_legacy_chat_id_when_registry_empty(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        assert notifier._recipient_chat_ids() == ["999"]

    def test_falls_back_to_static_chat_ids(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, [], static_chat_ids=["333", "444"])
        assert set(notifier._recipient_chat_ids()) == {"333", "444"}

    def test_paused_subscribers_are_excluded(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, ["111", "222"])
        repo.set_active("222", False)
        assert notifier._recipient_chat_ids() == ["111"]

    def test_is_configured_true_with_token_and_subscriber(self, db: DatabaseConnection) -> None:
        wired, _ = _notifier_with_subscribers(db, ["111"])
        assert wired.is_configured is True

    def test_is_configured_false_without_recipients(self, db: DatabaseConnection) -> None:
        empty, _ = _notifier_with_subscribers(db, [], bot_token="tok")
        assert empty.is_configured is False

    def test_is_configured_false_without_token(self, db: DatabaseConnection) -> None:
        no_token, _ = _notifier_with_subscribers(db, ["111"], bot_token="")
        assert no_token.is_configured is False


# ========================================================================
# Section 4: Broadcast Fan-Out
# ========================================================================

class TestBroadcast:

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_send_with_retry_delivers_to_every_active_subscriber(
        self, mock_post: MagicMock, db: DatabaseConnection,
    ) -> None:
        mock_post.return_value = MagicMock(status_code=200)
        notifier, _ = _notifier_with_subscribers(db, ["111", "222", "333"])

        notifier._send_with_retry("broadcast payload")

        assert mock_post.call_count == 3
        chat_ids = {call.kwargs["json"]["chat_id"] for call in mock_post.call_args_list}
        assert chat_ids == {"111", "222", "333"}

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    @patch("infrastructure.notifications.telegram_notifier.threading.Thread")
    def test_threat_alert_fans_out_asynchronously(
        self, mock_thread_cls: MagicMock, mock_post: MagicMock, db: DatabaseConnection,
    ) -> None:
        mock_thread_cls.side_effect = _FakeThread
        mock_post.return_value = MagicMock(status_code=200)
        notifier, _ = _notifier_with_subscribers(db, ["111", "222"])

        result = notifier.send_threat_alert(
            threat_type="DDoS", source_ip="1.1.1.1", model_name="rf_v3", confidence=0.95,
        )

        assert result is True
        assert mock_thread_cls.call_count == 1
        assert mock_post.call_count == 2
        chat_ids = {call.kwargs["json"]["chat_id"] for call in mock_post.call_args_list}
        assert chat_ids == {"111", "222"}

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_test_alert_reaches_all_recipients(
        self, mock_post: MagicMock, db: DatabaseConnection,
    ) -> None:
        mock_post.return_value = MagicMock(status_code=200)
        notifier, _ = _notifier_with_subscribers(db, ["111", "222"])

        assert notifier.send_test_alert() is True
        assert mock_post.call_count == 2

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    @patch("infrastructure.notifications.telegram_notifier.time.sleep")
    def test_failed_recipient_does_not_block_others(
        self, mock_sleep: MagicMock, mock_post: MagicMock, db: DatabaseConnection,
    ) -> None:
        responses = [
            MagicMock(status_code=500),  # recipient 111 — attempt 1
            MagicMock(status_code=500),  # recipient 111 — attempt 2
            MagicMock(status_code=500),  # recipient 111 — attempt 3
            MagicMock(status_code=200),  # recipient 222 — attempt 1
        ]
        mock_post.side_effect = responses
        notifier, _ = _notifier_with_subscribers(db, ["111", "222"])

        notifier._send_with_retry("payload")

        assert mock_post.call_count == 4
        delivered = [call.kwargs["json"]["chat_id"] for call in mock_post.call_args_list]
        assert delivered[-1] == "222"
        assert mock_sleep.call_count == 2

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    @patch("infrastructure.notifications.telegram_notifier.time.sleep")
    def test_no_recipients_drops_silently(
        self, mock_sleep: MagicMock, mock_post: MagicMock, db: DatabaseConnection,
    ) -> None:
        notifier, _ = _notifier_with_subscribers(db, [])

        notifier._send_with_retry("payload")
        mock_post.assert_not_called()


# ========================================================================
# Section 5: Registry Management via Notifier
# ========================================================================

class TestNotifierRegistry:

    def test_active_subscriber_count(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, ["111", "222"])
        assert notifier.active_subscriber_count() == 2

        repo.set_active("222", False)
        assert notifier.active_subscriber_count() == 1

    def test_list_subscribers_reflects_registry(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, ["111"])
        subs = notifier.list_subscribers()
        assert len(subs) == 1
        assert subs[0].chat_id == "111"

    def test_add_subscriber_validates_chat_id(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, [])
        with pytest.raises(ValidationError):
            notifier.add_subscriber("not-a-number")

    def test_remove_subscriber(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, ["111"])
        assert notifier.remove_subscriber("111") is True
        assert notifier.remove_subscriber("111") is False

    def test_set_subscriber_active(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, ["111"])
        assert notifier.set_subscriber_active("111", False) is True
        assert notifier.active_subscriber_count() == 0


# ========================================================================
# Section 6: Container Wiring
# ========================================================================

class TestContainerWiring:

    def test_container_exposes_subscriber_repository(self, db: DatabaseConnection) -> None:
        container = Container(db)
        assert isinstance(container.telegram_subscriber_repository, TelegramSubscriberRepository)
        assert container.telegram_subscriber_repository.table_name == TableNames.TELEGRAM_SUBSCRIBERS

    def test_notifier_wired_with_registry(self, db: DatabaseConnection) -> None:
        container = Container(db)
        container.telegram_subscriber_repository.add(TelegramSubscriber(chat_id="123"))

        notifier = container.telegram_notifier
        assert notifier.active_subscriber_count() == 1
        assert notifier._recipient_chat_ids() == ["123"]

    def test_runtime_token_override_is_respected(self, db: DatabaseConnection) -> None:
        container = Container(db)
        container.telegram_subscriber_repository.set_runtime_bot_token("rt-token-xyz")

        notifier = container.telegram_notifier
        assert notifier.bot_token == "rt-token-xyz"


# ========================================================================
# Section 7: Join Request Lifecycle (approve / reject / kick)
# ========================================================================

class TestJoinLifecycle:

    def test_request_join_creates_pending_and_alerts_admin(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, [], legacy_chat_id="999")

        with patch.object(notifier, "_send_raw") as mock_send:
            assert notifier.request_join("111", "Ali") is True

        sub = repo.get_by_chat_id("111")
        assert sub is not None
        assert sub.status == SubscriberStatus.PENDING
        assert sub.label == "Ali"
        assert mock_send.call_count == 2
        assert mock_send.call_args_list[0].args[1] == "999"  # admin alert
        assert mock_send.call_args_list[1].args[1] == "111"  # requester ack

    def test_request_join_is_idempotent(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, [], legacy_chat_id="999")

        assert notifier.request_join("111") is True
        assert notifier.request_join("111") is False
        assert len(repo.get_pending()) == 1

    def test_request_join_ignores_existing_approved(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, ["111"], legacy_chat_id="999")

        assert notifier.request_join("111") is False
        assert repo.get_by_chat_id("111").status == SubscriberStatus.APPROVED

    def test_approve_subscriber_promotes_and_welcomes(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        notifier.request_join("111", "Ali")

        with patch.object(notifier, "_send_raw") as mock_send:
            assert notifier.approve_subscriber("111") is True

        sub = repo.get_by_chat_id("111")
        assert sub.status == SubscriberStatus.APPROVED
        assert sub.is_active is True
        mock_send.assert_called_once()
        assert "Approved" in mock_send.call_args.args[0]
        assert mock_send.call_args.args[1] == "111"

    def test_approve_missing_subscriber_returns_false(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        assert notifier.approve_subscriber("99999") is False

    def test_reject_subscriber_deletes_registration(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        notifier.request_join("111")

        with patch.object(notifier, "_send_raw"):
            assert notifier.reject_subscriber("111") is True

        assert repo.get_by_chat_id("111") is None
        assert repo.get_pending() == []

    def test_kick_subscriber_revokes_access(self, db: DatabaseConnection) -> None:
        notifier, repo = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        notifier.add_subscriber("111")

        with patch.object(notifier, "_send_raw"):
            assert notifier.kick_subscriber("111") is True

        assert repo.get_by_chat_id("111") is None
        assert notifier.kick_subscriber("111") is False

    def test_pending_and_approved_listings(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        notifier.request_join("111", "Ali")
        notifier.request_join("222", "Sara")
        notifier.approve_subscriber("222")

        assert [p.chat_id for p in notifier.pending_subscribers()] == ["111"]
        assert [a.chat_id for a in notifier.approved_subscribers()] == ["222"]

    def test_approved_subscribers_receive_delivery(self, db: DatabaseConnection) -> None:
        notifier, _ = _notifier_with_subscribers(db, [], legacy_chat_id="999")
        notifier.request_join("111")
        notifier.approve_subscriber("111")

        assert notifier._recipient_chat_ids() == ["111"]
        assert notifier.active_subscriber_count() == 1
