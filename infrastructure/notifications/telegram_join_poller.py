"""
Telegram Join Request Poller Infrastructure Module.

Implements the inbound half of the self-service enrollment workflow. A
daemon thread long-polls the Telegram Bot API ``getUpdates`` endpoint and
translates first-contact messages (or member-join events) into pending
subscription requests that an administrator must explicitly approve before
the chat receives any alert delivery.

Design properties:
  - Single-writer guarantee: only one poller may consume ``getUpdates`` per
    bot token, so the component refuses to start twice and is wired as a
    process-wide singleton through the IoC container.
  - Non-blocking application lifecycle: the polling loop runs on a daemon
    thread that is stopped via a cooperative ``threading.Event``.
  - Fault tolerant: transport failures are logged and the loop back-off
    retries without crashing; the last error is surfaced to the UI.
  - Idempotent enrollment: repeated messages from an already-registered chat
    never produce duplicate requests or duplicate administrator alerts.
"""

from __future__ import annotations

import threading
import time
import traceback
from typing import Any, Final, Optional

import requests

from config.constants import SubscriberStatus
from core.entities.telegram_subscriber import TelegramSubscriber
from infrastructure.logging.logger_factory import get_logger

logger = get_logger("infrastructure.telegram_join_poller")

# ---------------------------------------------------------------------------
# Transport Constants
# ---------------------------------------------------------------------------

_GET_UPDATES_URL: Final[str] = "https://api.telegram.org/bot{token}/getUpdates"
_DEFAULT_POLL_INTERVAL: Final[float] = 1.0
_DEFAULT_LONG_POLL_TIMEOUT: Final[int] = 25
_REQUEST_TIMEOUT: Final[int] = 30


class TelegramJoinPoller:
    """
    Long-polling listener that turns inbound bot messages into pending requests.

    Thread-safe: ``start``/``stop``/``is_running`` are guarded by an internal
    lock so concurrent Streamlit reruns cannot spawn duplicate pollers.
    """

    def __init__(
        self,
        notifier: Any,
        subscriber_repository: Any,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        long_poll_timeout: int = _DEFAULT_LONG_POLL_TIMEOUT,
        requests_timeout: int = _REQUEST_TIMEOUT,
    ) -> None:
        self._notifier: Final[Any] = notifier
        self._repo: Final[Any] = subscriber_repository
        self._poll_interval: Final[float] = poll_interval
        self._long_poll_timeout: Final[int] = long_poll_timeout
        self._requests_timeout: Final[int] = requests_timeout

        self._stop: Final[threading.Event] = threading.Event()
        self._lock: Final[threading.Lock] = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._last_error: str = ""
        self._last_poll_at: float = 0.0

    # ------------------------------------------------------------------
    # Public Lifecycle API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """``True`` when the polling worker thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_error(self) -> str:
        """The most recent polling error message, or an empty string."""
        return self._last_error

    @property
    def last_poll_at(self) -> float:
        """Monotonic timestamp of the last successful ``getUpdates`` round, or 0.0."""
        return self._last_poll_at

    def start(self) -> bool:
        """
        Spawns the long-polling worker thread if it is not already running.

        Requires a configured bot token; otherwise returns ``False`` and records
        the reason in ``last_error``.

        Returns:
            ``True`` when the poller is running after this call.
        """
        with self._lock:
            if self.is_running:
                return True
            if not self._notifier.bot_token:
                self._last_error = "No bot token configured. Provision one in Settings first."
                logger.warning("Join poller start rejected: %s", self._last_error)
                return False

            self._stop.clear()
            self._last_error = ""
            self._thread = threading.Thread(
                target=self._poll_loop,
                name="tg-join-poller",
                daemon=True,
            )
            self._thread.start()
            logger.info("Telegram join request poller started.")
            return True

    def stop(self) -> None:
        """Signals the poller to stop and blocks until the worker exits."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        with self._lock:
            self._thread = None
        logger.info("Telegram join request poller stopped.")

    # ------------------------------------------------------------------
    # Polling Loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Continuously fetches updates until the stop event is signalled."""
        offset: int = 0
        while not self._stop.is_set():
            try:
                offset = self._poll_once(offset)
            except Exception:  # noqa: BLE001 - Poller must never die from a malformed update
                self._last_error = traceback.format_exc(limit=2)
                logger.exception("Telegram join poller round failed.")
            self._stop.wait(self._poll_interval)

    def _poll_once(self, offset: int) -> int:
        """
        Executes a single polling round and returns the next ``getUpdates`` offset.

        Extracted from the loop for deterministic unit testing: each round
        fetches updates, advances the cursor past the highest received update id,
        and routes every update through the enrollment handler.
        """
        updates: list[dict[str, Any]] = self._fetch_updates(offset)
        self._last_poll_at = time.monotonic()
        for update in updates or []:
            update_id = update.get("update_id")
            if update_id is not None:
                offset = max(offset, int(update_id) + 1)
            self._handle_update(update)
        return offset

    def _fetch_updates(self, offset: int) -> list[dict[str, Any]]:
        """
        Performs a single long-poll against the Telegram ``getUpdates`` endpoint.

        Returns:
            The list of update dictionaries delivered by the API.
        """
        if not self._notifier.bot_token:
            return []
        endpoint: Final[str] = _GET_UPDATES_URL.format(token=self._notifier.bot_token)
        payload: Final[dict[str, Any]] = {
            "offset": offset,
            "timeout": self._long_poll_timeout,
        }

        response = requests.post(
            endpoint,
            json=payload,
            timeout=self._requests_timeout,
        )

        if response.status_code != 200:
            self._last_error = f"getUpdates HTTP {response.status_code}: {response.text[:200]}"
            logger.warning("Telegram getUpdates rejected. HTTP %d: %s", response.status_code, response.text[:200])
            return []

        data = response.json()
        if not data.get("ok"):
            self._last_error = f"Telegram API error: {data.get('description', 'unknown')}"
            logger.warning("Telegram getUpdates API error: %s", self._last_error)
            return []

        return data.get("result", [])

    # ------------------------------------------------------------------
    # Update Handling
    # ------------------------------------------------------------------

    def _handle_update(self, update: dict[str, Any]) -> None:
        """
        Routes a single Telegram update into the enrollment workflow.

        Supports:
          - ``message`` updates from private chats (user directly contacts bot).
          - ``my_chat_member`` updates where the bot's own membership changed
            (e.g. it was added to a group), enrolling the group chat itself.
        """
        message = update.get("message")
        if message is not None:
            self._handle_message(message)
            return

        my_chat_member = update.get("my_chat_member")
        if my_chat_member is not None:
            self._handle_member_event(my_chat_member)

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Extracts a join request from an inbound private chat message."""
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            return

        chat_id_s: str = str(chat_id)

        if chat.get("type") != "private":
            logger.debug("Ignoring non-private chat update (type='%s').", chat.get("type"))
            return

        from_user = message.get("from") or {}
        label = self._build_label(from_user)
        self._process_join(chat_id_s, label)

    def _handle_member_event(self, my_chat_member: dict[str, Any]) -> None:
        """Enrolls the bot's own chat when it is added to a group."""
        chat = my_chat_member.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            return

        chat_id_s: str = str(chat_id)
        new_status = ((my_chat_member.get("new_chat_member") or {}).get("status") or "")
        if new_status not in {"member", "administrator"}:
            return

        label = (chat.get("title") or f"Group {chat_id_s}").strip()
        self._process_join(chat_id_s, label)

    # ------------------------------------------------------------------
    # Enrollment Routing
    # ------------------------------------------------------------------

    def _process_join(self, chat_id: str, label: str) -> None:
        """
        Routes an enrollment signal to the appropriate lifecycle action.

        The configured administrator chat is auto-approved (the owner should
        not require its own approval); every other unknown chat becomes a
        pending request that alerts the administrator.
        """
        if self._notifier.admin_chat_id and chat_id == self._notifier.admin_chat_id:
            existing = self._repo.get_by_chat_id(chat_id)
            if existing is None:
                self._repo.add(
                    TelegramSubscriber(
                        chat_id=chat_id,
                        label=label or "Administrator",
                        status=SubscriberStatus.APPROVED,
                    )
                )
                self._notifier.send_to_chat(chat_id, "Administrator subscription auto-registered.")
                logger.info("Administrator chat '%s' auto-registered as approved subscriber.", chat_id)
            elif existing.status == SubscriberStatus.PENDING:
                self._notifier.approve_subscriber(chat_id)
            return

        if self._repo.get_by_chat_id(chat_id) is None:
            self._notifier.request_join(chat_id, label)

    @staticmethod
    def _build_label(from_user: dict[str, Any]) -> str:
        """Derives a human-readable display label from a Telegram user object."""
        first = (from_user.get("first_name") or "").strip()
        last = (from_user.get("last_name") or "").strip()
        username = (from_user.get("username") or "").strip()
        full = " ".join(part for part in (first, last) if part).strip()
        return full or (f"@{username}" if username else "")
