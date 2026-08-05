"""
Telegram Notification Infrastructure Module.

Implements a production-grade asynchronous notification service for dispatching
cybersecurity threat alerts via the Telegram Bot HTTP API. Designed for zero-blocking
operation within the real-time detection pipeline using daemon-thread dispatch with
exponential backoff retry semantics and circuit-breaker fault tolerance.

Architecture alignment:
  - Infrastructure Layer adapter — domain-agnostic message transport.
  - Fire-and-forget threading model ensures detection latency stays below 5ms.
  - Circuit breaker pattern prevents cascade failures on sustained Telegram outages.
  - Structured HTML payloads conforming to SOC analyst readability standards.
  - Multi-user fan-out: notifications are delivered to every active subscriber
    registered in the persistence registry, with per-recipient retry isolation.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Optional

import requests

from config.constants import SubscriberStatus
from config.settings import get_settings
from infrastructure.logging.logger_factory import get_logger

logger = get_logger("infrastructure.telegram_notifier")

# ---------------------------------------------------------------------------
# Transport Constants
# ---------------------------------------------------------------------------

_API_BASE: Final[str] = "https://api.telegram.org/bot{token}/sendMessage"
_REQUEST_TIMEOUT: Final[int] = 5
_MAX_RETRIES: Final[int] = 3
_RETRY_BASE_DELAY: Final[float] = 0.5
_CIRCUIT_BREAKER_THRESHOLD: Final[int] = 5
_CIRCUIT_BREAKER_RESET_SECONDS: Final[float] = 60.0


# ---------------------------------------------------------------------------
# Severity Classification
# ---------------------------------------------------------------------------

def _classify_severity(confidence: float) -> tuple[str, str]:
    """Map ML confidence score to a threat severity tier.

    Returns:
        A ``(label, emoji)`` tuple for display in the notification payload.
    """
    if confidence >= 0.90:
        return "CRITICAL", "\U0001f534"
    if confidence >= 0.70:
        return "HIGH", "\U0001f7e0"
    if confidence >= 0.40:
        return "MEDIUM", "\U0001f7e1"
    return "LOW", "\U0001f7e2"


# ---------------------------------------------------------------------------
# Telegram Notifier
# ---------------------------------------------------------------------------

class TelegramNotifier:
    """Thread-safe, non-blocking Telegram alert dispatcher with fault tolerance.

    All public ``send_*`` methods are **asynchronous**: they enqueue the HTTP
    request on a daemon thread and return immediately.  The detection pipeline
    is never blocked by network I/O.

    Fault tolerance:
        * Up to 3 retries per message with exponential backoff.
        * Circuit breaker opens after 5 consecutive failures and auto-resets
          after 60 seconds, preventing thundering-herd retries against a
          degraded Telegram endpoint.
    """

    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        chat_ids: list[str] | None = None,
        subscriber_repository: Any | None = None,
    ) -> None:
        settings = get_settings()
        self._bot_token: str = bot_token if bot_token is not None else (settings.telegram_bot_token or "")
        self._chat_id: str = chat_id if chat_id is not None else (settings.telegram_chat_id or "")
        self._chat_ids: list[str] = list(chat_ids) if chat_ids else []
        # Optional persistence adapter managing the active subscriber registry.
        # When supplied, active subscribers take precedence over static chat ids.
        self._subscriber_repo: Any | None = subscriber_repository

        # Circuit breaker state — guarded by _lock
        self._lock: Final[threading.Lock] = threading.Lock()
        self._consecutive_failures: int = 0
        self._circuit_open_until: float = 0.0

    # ------------------------------------------------------------------
    # Public Properties
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """``True`` when a bot token and at least one delivery recipient are present."""
        return bool(self._bot_token and self._recipient_chat_ids())

    @property
    def is_circuit_open(self) -> bool:
        """``True`` when the circuit breaker is tripped (fail-open state)."""
        with self._lock:
            return time.monotonic() < self._circuit_open_until

    @property
    def bot_token(self) -> str:
        """Exposes the currently active bot token (masked in logs)."""
        return self._bot_token

    @property
    def admin_chat_id(self) -> str:
        """
        Resolves the administrator's notification chat identity.

        This is the chat that receives join-request alerts and is treated as
        the bot owner (auto-approved without administrator intervention).
        """
        return self._chat_id

    def _recipient_chat_ids(self) -> list[str]:
        """
        Resolves the ordered list of delivery targets.

        Priority order:
          1. Active subscribers from the persistence registry (when wired).
          2. Static ``chat_ids`` supplied at construction time.
          3. Legacy single ``chat_id`` fallback.

        When the registry is wired but every subscriber is paused, delivery is
        suppressed entirely rather than resurrecting the legacy chat id.

        Resolved fresh on every dispatch so runtime subscription changes take
        effect immediately without an application restart.
        """
        if self._subscriber_repo is not None:
            registered = self._subscriber_repo.list_chat_ids()
            if registered:
                return registered
            if self._subscriber_repo.count() > 0:
                return []
        if self._chat_ids:
            return list(self._chat_ids)
        return [self._chat_id] if self._chat_id else []

    # ------------------------------------------------------------------
    # Public Send Methods (fire-and-forget)
    # ------------------------------------------------------------------

    def send_threat_alert(
        self,
        threat_type: str,
        source_ip: Optional[str],
        model_name: str,
        confidence: float,
        alert_id: Optional[int] = None,
        destination_ip: Optional[str] = None,
        source_type: Optional[str] = None,
        occurred_at: Optional[datetime] = None,
    ) -> bool:
        """Dispatch a new-threat notification asynchronously.

        Builds a structured HTML payload and hands it off to a daemon
        thread for transmission.  Returns immediately without blocking the caller.

        Args:
            threat_type: Classification label of the detected attack vector.
            source_ip: Originating network address of the threat.
            model_name: Identifier of the ML model that produced the prediction.
            confidence: Prediction confidence score in [0.0, 1.0].
            alert_id: Persistence-layer primary key for cross-referencing.
            destination_ip: Target network endpoint address.
            source_type: Ingestion channel (``csv``, ``pcap``, ``live``).
            occurred_at: Timestamp of the detection event (UTC).

        Returns:
            ``True`` always (actual delivery is async). Check logs for failures.
        """
        severity_label, severity_emoji = _classify_severity(confidence)
        event_time: Final[datetime] = occurred_at or datetime.now(UTC)
        formatted_time: Final[str] = event_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        text = self._build_threat_message(
            severity_label=severity_label,
            severity_emoji=severity_emoji,
            threat_type=threat_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            model_name=model_name,
            confidence=confidence,
            formatted_time=formatted_time,
            alert_id=alert_id,
            source_type=source_type,
        )
        self._dispatch_async(text)
        return True

    def send_escalation_alert(
        self,
        threat_type: str,
        source_ip: Optional[str],
        model_name: str,
        confidence: float,
        occurrences: int,
        alert_id: Optional[int] = None,
        destination_ip: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> bool:
        """Dispatch an escalation notification when occurrence count crosses a threshold.

        Escalation messages inform SOC analysts that a previously seen threat
        is continuing and the occurrence count has escalated significantly.

        Returns:
            ``True`` always (actual delivery is async).
        """
        severity_label, severity_emoji = _classify_severity(confidence)
        formatted_time: Final[str] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        text = self._build_escalation_message(
            severity_label=severity_label,
            severity_emoji=severity_emoji,
            threat_type=threat_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            model_name=model_name,
            confidence=confidence,
            occurrences=occurrences,
            formatted_time=formatted_time,
            alert_id=alert_id,
            source_type=source_type,
        )
        self._dispatch_async(text)
        return True

    def send_test_alert(self) -> bool:
        """Dispatch a connectivity test payload to every active recipient.

        This is a **synchronous** call — used by the settings UI to verify
        that bot credentials are functional and at least one chat is reachable.

        Returns:
            ``True`` when at least one recipient confirmed delivery.
        """
        recipients: Final[list[str]] = self._recipient_chat_ids()
        if not recipients:
            logger.warning("No active Telegram recipients configured — test alert dropped.")
            return False

        text = (
            "\U0001f916 <b>AI-IDS Connectivity Test</b>\n\n"
            "\u2705 Telegram integration is <b>operational</b>.\n"
            f"\U0001f551 <code>{datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}</code>"
        )
        results = [self._send_raw(text, chat_id) for chat_id in recipients]
        return any(results)

    # ------------------------------------------------------------------
    # Subscriber Registry Management
    # ------------------------------------------------------------------

    def list_subscribers(self) -> list[Any]:
        """Returns all registered subscribers from the persistence registry.

        Returns an empty list when the registry adapter is not wired.
        """
        if self._subscriber_repo is None:
            return []
        return self._subscriber_repo.get_all()

    def active_subscriber_count(self) -> int:
        """Returns the number of currently enabled delivery recipients."""
        return len(self._recipient_chat_ids())

    def add_subscriber(self, chat_id: str, label: str = "") -> Any:
        """Registers a new chat subscription for alert delivery.

        Args:
            chat_id: The numeric Telegram chat identity to register.
            label: Optional human-readable display label for the subscriber.

        Returns:
            The persisted TelegramSubscriber entity.

        Raises:
            ValidationError: If the chat identity is malformed.
            DuplicateRecordError: If the chat identity is already subscribed.
        """
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        from core.entities.telegram_subscriber import TelegramSubscriber
        from utils.validators import validate_chat_id

        validated_chat_id: Final[str] = validate_chat_id(chat_id)
        normalized_label: Final[str | None] = (label or "").strip() or None
        return self._subscriber_repo.add(
            TelegramSubscriber(chat_id=validated_chat_id, label=normalized_label)
        )

    def remove_subscriber(self, chat_id: str) -> bool:
        """Unsubscribes a chat identity from future alert delivery."""
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        subscriber = self._subscriber_repo.get_by_chat_id(chat_id)
        if subscriber is None or subscriber.id is None:
            return False
        return self._subscriber_repo.delete(subscriber.id)

    def set_subscriber_active(self, chat_id: str, is_active: bool) -> bool:
        """Pauses or resumes delivery to a registered chat subscription."""
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        return self._subscriber_repo.set_active(chat_id, is_active)

    def set_bot_token(self, token: str) -> None:
        """Provisions a new bot token and persists it as the runtime override."""
        token = (token or "").strip()
        self._bot_token = token
        if self._subscriber_repo is not None:
            self._subscriber_repo.set_runtime_bot_token(token)

    # ------------------------------------------------------------------
    # Join Request Lifecycle (self-service enrollment, admin-gated)
    # ------------------------------------------------------------------

    def send_to_chat(self, chat_id: str, text: str) -> bool:
        """Sends an arbitrary message to a specific chat (synchronous, best-effort)."""
        target = chat_id if chat_id is not None else self._chat_id
        if not self._bot_token or not target:
            return False
        return self._send_raw(text, target)

    def pending_subscribers(self) -> list[Any]:
        """Returns all subscriber records awaiting administrator approval."""
        if self._subscriber_repo is None:
            return []
        return self._subscriber_repo.get_pending()

    def approved_subscribers(self) -> list[Any]:
        """Returns all subscriber records granted alert delivery access."""
        if self._subscriber_repo is None:
            return []
        return self._subscriber_repo.get_approved()

    def request_join(self, chat_id: str, label: str = "") -> bool:
        """
        Registers a self-service enrollment request from a new chat identity.

        The identity is stored in ``PENDING`` state and the administrator is
        alerted so they can approve or reject the request. The operation is
        idempotent: an already-approved or already-pending chat is left
        untouched and no duplicate admin alert is dispatched.

        Args:
            chat_id: The numeric Telegram chat identity requesting access.
            label: Optional human-readable display label for the requester.

        Returns:
            ``True`` when a new pending request was created, ``False`` when the
            identity was already registered in any state.
        """
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        from core.entities.telegram_subscriber import TelegramSubscriber
        from utils.validators import validate_chat_id

        validated_chat_id: Final[str] = validate_chat_id(chat_id)
        normalized_label: Final[str | None] = (label or "").strip() or None

        existing = self._subscriber_repo.get_by_chat_id(validated_chat_id)
        if existing is not None:
            logger.info(
                "Join request ignored for '%s' (already registered as '%s').",
                validated_chat_id,
                existing.status.value,
            )
            return False

        self._subscriber_repo.add(
            TelegramSubscriber(
                chat_id=validated_chat_id,
                label=normalized_label,
                status=SubscriberStatus.PENDING,
            )
        )
        logger.info("New Telegram join request registered for chat '%s'.", validated_chat_id)

        display = normalized_label or validated_chat_id
        if self._chat_id:
            self._send_raw(self._build_join_request_admin_message(display, validated_chat_id), self._chat_id)
        self._send_raw(self._build_join_pending_message(), validated_chat_id)
        return True

    def approve_subscriber(self, chat_id: str) -> bool:
        """
        Grants alert delivery access to a pending (or any registered) chat identity.

        The subscription is promoted to ``APPROVED``, re-enabled, and the
        recipient receives a welcome confirmation message.

        Returns:
            ``True`` when the identity existed and was approved.
        """
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        from utils.validators import validate_chat_id

        validated_chat_id: Final[str] = validate_chat_id(chat_id)
        existing = self._subscriber_repo.get_by_chat_id(validated_chat_id)
        if existing is None:
            return False

        self._subscriber_repo.set_status(validated_chat_id, SubscriberStatus.APPROVED)
        self._subscriber_repo.set_active(validated_chat_id, True)
        logger.info("Administrator approved Telegram subscriber chat '%s'.", validated_chat_id)
        self._send_raw(self._build_approved_message(), validated_chat_id)
        return True

    def reject_subscriber(self, chat_id: str) -> bool:
        """
        Rejects a pending enrollment request and removes the registration entirely.

        The requester is notified that their request was declined and the record
        is deleted so the identity no longer occupies the registry.

        Returns:
            ``True`` when a matching registration existed and was removed.
        """
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        from utils.validators import validate_chat_id

        validated_chat_id: Final[str] = validate_chat_id(chat_id)
        existing = self._subscriber_repo.get_by_chat_id(validated_chat_id)
        if existing is None or existing.id is None:
            return False

        logger.info("Administrator rejected Telegram enrollment request for chat '%s'.", validated_chat_id)
        self._send_raw(self._build_rejected_message(), validated_chat_id)
        return self._subscriber_repo.delete(existing.id)

    def kick_subscriber(self, chat_id: str) -> bool:
        """
        Revokes delivery access from an approved subscriber and removes it.

        A best-effort notice is sent to the removed chat before the record is
        deleted so the identity no longer receives any future notifications.

        Returns:
            ``True`` when a matching registration existed and was removed.
        """
        if self._subscriber_repo is None:
            raise RuntimeError("Telegram subscriber registry is not wired to a persistence adapter.")
        from utils.validators import validate_chat_id

        validated_chat_id: Final[str] = validate_chat_id(chat_id)
        existing = self._subscriber_repo.get_by_chat_id(validated_chat_id)
        if existing is None or existing.id is None:
            return False

        logger.info("Administrator revoked Telegram delivery access for chat '%s'.", validated_chat_id)
        self._send_raw(self._build_kicked_message(), validated_chat_id)
        return self._subscriber_repo.delete(existing.id)

    # ------------------------------------------------------------------
    # Message Builders
    # ------------------------------------------------------------------

    @staticmethod
    def _esc_html(text: str) -> str:
        """Escape HTML special characters for safe Telegram HTML rendering."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _code(text: str) -> str:
        """Wrap *text* in a Telegram HTML code span."""
        return f"<code>{TelegramNotifier._esc_html(str(text))}</code>"

    def _build_threat_message(
        self,
        *,
        severity_label: str,
        severity_emoji: str,
        threat_type: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
        model_name: str,
        confidence: float,
        formatted_time: str,
        alert_id: Optional[int],
        source_type: Optional[str],
    ) -> str:
        """Construct the primary new-threat HTML notification body."""
        alert_id_display = f"#{alert_id}" if alert_id is not None else "pending"

        lines = [
            "\U0001f6a8 <b>AI-IDS THREAT DETECTED</b>",
            "",
            f"\u250c {severity_emoji} <b>Severity:</b> {self._code(severity_label)}",
            f"\u251c <b>Alert ID:</b> {self._code(alert_id_display)}",
            f"\u251c <b>Timestamp:</b> {self._code(formatted_time)}",
            f"\u251c <b>Threat Type:</b> {self._code(threat_type)}",
            f"\u251c <b>Source IP:</b> {self._code(source_ip or 'N/A')}",
        ]

        if destination_ip:
            lines.append(f"\u251c <b>Destination IP:</b> {self._code(destination_ip)}")

        lines += [
            f"\u251c <b>Inference Model:</b> {self._code(model_name)}",
            f"\u251c <b>Confidence:</b> {self._code(f'{confidence:.2%}')}",
        ]

        if source_type:
            lines.append(f"\u251c <b>Source Type:</b> {self._code(source_type.upper())}")

        lines += [
            "\u2514" + "\u2500" * 30,
            "",
            "\u26a0\ufe0f <b>Recommended Actions:</b>",
        ]

        if confidence >= 0.90:
            lines += [
                "  1) <b>Immediate containment</b> \u2014 isolate source host",
                "  2) Block IP at perimeter firewall",
                "  3) Capture full packet trace for forensics",
            ]
        elif confidence >= 0.70:
            lines += [
                "  1) Investigate source IP activity logs",
                "  2) Monitor lateral movement attempts",
                "  3) Review related alerts in dashboard",
            ]
        else:
            lines += [
                "  1) Review alert in AI-IDS dashboard",
                "  2) Cross-reference with threat intelligence feeds",
            ]

        return "\n".join(lines)

    def _build_escalation_message(
        self,
        *,
        severity_label: str,
        severity_emoji: str,
        threat_type: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
        model_name: str,
        confidence: float,
        occurrences: int,
        formatted_time: str,
        alert_id: Optional[int],
        source_type: Optional[str],
    ) -> str:
        """Construct an escalation notification for rising occurrence counts."""
        alert_id_display = f"#{alert_id}" if alert_id is not None else "pending"

        lines = [
            "\U0001f4c8 <b>AI-IDS THREAT ESCALATION</b>",
            "",
            f"\u250c {severity_emoji} <b>Severity:</b> {self._code(severity_label)}",
            f"\u251c <b>Alert ID:</b> {self._code(alert_id_display)}",
            f"\u251c <b>Occurrences:</b> {self._code(str(occurrences))}",
            f"\u251c <b>Timestamp:</b> {self._code(formatted_time)}",
            f"\u251c <b>Threat Type:</b> {self._code(threat_type)}",
            f"\u251c <b>Source IP:</b> {self._code(source_ip or 'N/A')}",
        ]

        if destination_ip:
            lines.append(f"\u251c <b>Destination IP:</b> {self._code(destination_ip)}")

        lines += [
            f"\u251c <b>Inference Model:</b> {self._code(model_name)}",
            f"\u251c <b>Confidence:</b> {self._code(f'{confidence:.2%}')}",
        ]

        if source_type:
            lines.append(f"\u251c <b>Source Type:</b> {self._code(source_type.upper())}")

        lines += [
            "\u2514" + "\u2500" * 30,
            "",
            f"\u26a0\ufe0f This threat has been observed <b>{occurrences} times</b>. Consider escalating response.",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Join Request Message Builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_join_request_admin_message(display: str, chat_id: str) -> str:
        """Construct the administrator alert for a new pending enrollment request."""
        return "\n".join([
            "\U0001f4e5 <b>AI-IDS Subscription Request</b>",
            "",
            f"\u250c <b>Requester:</b> {TelegramNotifier._esc_html(display)}",
            f"\u251c <b>Chat ID:</b> <code>{TelegramNotifier._esc_html(chat_id)}</code>",
            "\u2514 Approve or reject this request from the AI-IDS Settings page.",
        ])

    @staticmethod
    def _build_join_pending_message() -> str:
        """Construct the acknowledgement sent to a requester awaiting approval."""
        return "\n".join([
            "\U0001f513 <b>Subscription Request Received</b>",
            "",
            "Your request to receive AI-IDS alert notifications has been submitted.",
            "An administrator will review and approve it shortly.",
        ])

    @staticmethod
    def _build_approved_message() -> str:
        """Construct the welcome confirmation sent after administrator approval."""
        return "\n".join([
            "\u2705 <b>Subscription Approved</b>",
            "",
            "You are now subscribed to AI-IDS alert notifications.",
            "You will receive threat and escalation alerts from now on.",
        ])

    @staticmethod
    def _build_rejected_message() -> str:
        """Construct the denial notice sent to a rejected requester."""
        return "\n".join([
            "\u26d4 <b>Subscription Request Declined</b>",
            "",
            "Your request to receive AI-IDS alert notifications was not approved.",
            "You will not receive any further notifications.",
        ])

    @staticmethod
    def _build_kicked_message() -> str:
        """Construct the revocation notice sent to a removed subscriber."""
        return "\n".join([
            "\U0001f6ab <b>Subscription Revoked</b>",
            "",
            "An administrator has removed you from AI-IDS alert notifications.",
            "You will no longer receive any further notifications.",
        ])

    # ------------------------------------------------------------------
    # Async Dispatch (threading)
    # ------------------------------------------------------------------

    def _dispatch_async(self, text: str) -> None:
        """Enqueue a Telegram send on a daemon thread for non-blocking delivery.

        The recipient list is resolved on the **caller's** thread and passed into
        the daemon thread. This keeps all persistence access on application
        threads and avoids spawning short-lived SQLite connections on background
        dispatch threads (which could outlive caller transactions).
        """
        recipients: Final[list[str]] = self._recipient_chat_ids()
        if not recipients:
            logger.warning("No active Telegram recipients configured — notification dropped.")
            return

        thread = threading.Thread(
            target=self._send_with_retry,
            args=(text, recipients),
            daemon=True,
            name="tg-notify",
        )
        thread.start()

    # ------------------------------------------------------------------
    # Retry Logic with Exponential Backoff
    # ------------------------------------------------------------------

    def _send_with_retry(self, text: str, recipients: list[str] | None = None) -> None:
        """Attempt delivery to every active recipient with backoff retries.

        Each recipient is attempted independently so that a single invalid
        chat id cannot block delivery to the remaining subscribers. The circuit
        breaker state is updated once per dispatch round.

        Args:
            text: The rendered HTML message body.
            recipients: Pre-resolved delivery targets. When ``None`` the list is
                resolved from the current configuration on the calling thread.
        """
        if self.is_circuit_open:
            logger.warning("Circuit breaker is open — dropping Telegram notification.")
            return

        if recipients is None:
            recipients = self._recipient_chat_ids()
        if not recipients:
            logger.warning("No active Telegram recipients configured — notification dropped.")
            return

        delivered_all: bool = True
        for chat_id in recipients:
            if not self._deliver_with_retry(text, chat_id):
                delivered_all = False

        if delivered_all:
            self._on_success()
        else:
            self._on_failure()

    def _deliver_with_retry(self, text: str, chat_id: str) -> bool:
        """Attempt delivery to a single chat id with exponential backoff.

        Args:
            text: The rendered HTML message body.
            chat_id: The target recipient chat identity.

        Returns:
            ``True`` when the message reached the recipient on any attempt.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, _MAX_RETRIES + 1):
            if self._send_raw(text, chat_id):
                return True
            last_error = RuntimeError(f"Attempt {attempt}/{_MAX_RETRIES} failed")
            if attempt < _MAX_RETRIES:
                delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                time.sleep(delay)

        if last_error is not None:
            logger.error("Telegram delivery to %s failed: %s", chat_id, last_error)
        return False

    # ------------------------------------------------------------------
    # Circuit Breaker
    # ------------------------------------------------------------------

    def _on_success(self) -> None:
        """Reset circuit breaker on successful delivery."""
        with self._lock:
            self._consecutive_failures = 0
            self._circuit_open_until = 0.0

    def _on_failure(self) -> None:
        """Increment failure count; trip breaker when threshold is breached."""
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= _CIRCUIT_BREAKER_THRESHOLD:
                self._circuit_open_until = time.monotonic() + _CIRCUIT_BREAKER_RESET_SECONDS
                logger.error(
                    "Circuit breaker tripped after %d consecutive failures. "
                    "Notifications paused for %.0fs.",
                    self._consecutive_failures,
                    _CIRCUIT_BREAKER_RESET_SECONDS,
                )

    # ------------------------------------------------------------------
    # Low-Level HTTP Transport
    # ------------------------------------------------------------------

    def _send_raw(self, text: str, chat_id: Optional[str] = None) -> bool:
        """Execute a single HTTP POST to the Telegram sendMessage endpoint.

        Args:
            text: The rendered HTML message body.
            chat_id: Explicit target chat identity; falls back to the legacy
                configured ``chat_id`` when omitted.

        Returns:
            ``True`` on HTTP 200, ``False`` on any transport or API error.
        """
        target_chat_id: str = chat_id if chat_id is not None else self._chat_id
        if not self._bot_token or not target_chat_id:
            return False

        try:
            endpoint: Final[str] = _API_BASE.format(token=self._bot_token)
            payload: Final[dict[str, Any]] = {
                "chat_id": target_chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }

            response = requests.post(
                endpoint,
                json=payload,
                timeout=_REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                logger.debug("Telegram notification delivered successfully.")
                return True

            # Handle rate limiting (429) with longer backoff
            if response.status_code == 429:
                retry_after = response.json().get("parameters", {}).get("retry_after", 5)
                logger.warning("Telegram rate limit hit. Retry after %ds.", retry_after)
                time.sleep(retry_after)
                return False

            logger.error(
                "Telegram API rejected message. HTTP %d: %s",
                response.status_code,
                response.text[:300],
            )
            return False

        except requests.Timeout:
            logger.error("Telegram API request timed out after %ds.", _REQUEST_TIMEOUT)
            return False
        except requests.ConnectionError:
            logger.error("Failed to establish connection to Telegram API.")
            return False
        except requests.RequestException as exc:
            logger.error("Telegram transport error: %s", exc)
            return False
