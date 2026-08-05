"""
Threat Event Core Alert Engine Module.

Centralizes decision-making flows triggered following a malicious classification prediction event.
Coordinates validation checking across active whitelist constraints, handles historical window
deduplication/aggregation updates, dispatches external real-time warning alerts, and triggers
automatic Windows Firewall IP blocking for confirmed threats.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from config.settings import get_settings
from core.entities.alert import Alert
from core.entities.detection import Detection
from infrastructure.logging.logger_factory import get_logger
from infrastructure.notifications.telegram_notifier import TelegramNotifier
from repositories.alert_repository import AlertRepository
from services.ip_list_service import IpListService

if TYPE_CHECKING:
    from services.firewall_service import FirewallService

logger = get_logger("services.alert_engine")

DEFAULT_THREAT_TYPE: Final[str] = "Anomalous / Malicious Traffic"

_ESCALATION_THRESHOLDS: Final[frozenset[int]] = frozenset({5, 10, 25, 50, 100})


class AlertEngine:
    """
    Decoupled workflow manager executing threat processing and event mitigation logic.
    """

    def __init__(
        self,
        alert_repository: AlertRepository,
        ip_list_service: IpListService,
        notifier: TelegramNotifier,
        aggregation_window_minutes: int | None = None,
        firewall_service: FirewallService | None = None,
    ) -> None:
        """
        Initializes the alert engine with its mandatory persistence layers, filters, notification clients,
        and optional firewall integration for automatic threat mitigation.
        """
        self._alerts: Final[AlertRepository] = alert_repository
        self._ip_lists: Final[IpListService] = ip_list_service
        self._notifier: Final[TelegramNotifier] = notifier
        self._firewall: FirewallService | None = firewall_service
        self._window_minutes: Final[int] = (
            aggregation_window_minutes or get_settings().alert_aggregation_window_minutes
        )

    def process_detection(
        self,
        detection: Detection,
        model_name: str,
        threat_type: str = DEFAULT_THREAT_TYPE,
    ) -> Alert | None:
        """
        Processes a compute classification result to evaluate security incident actions.

        Applies three sequential validation passes:
        1. Short-circuits instantly if the payload does not reflect an active attack state
           (unless the IP is blacklisted — forced alert for blocked IPs).
        2. For whitelisted IPs: skips alert creation but logs the detection.
        3. For blacklisted IPs: creates immediate alert regardless of model prediction.
        4. Aggregates values into matching recent historical events.

        Args:
            detection: The target data telemetry log instance containing structural model predictions.
            model_name: Identity tag tracking which active analytical asset issued the decision.
            threat_type: String classification categorizing the detected threat vector.

        Returns:
            The created or aggregated domain Alert entity tracker instance, or None if suppressed.
        """
        source_ip: Final[str] = detection.source_ip or "unknown"

        # ── Whitelist handling: skip alert, log and return ──
        if detection.is_whitelisted or (detection.source_ip and self._ip_lists.is_whitelisted(detection.source_ip)):
            if detection.prediction != 0:
                logger.info(
                    "Whitelisted IP %s traffic classified as %s — admin test, alert suppressed.",
                    source_ip, detection.attack_type,
                )
            return None

        # ── Blacklist handling: force alert regardless of model prediction ──
        is_blacklisted = detection.is_blacklisted or (detection.source_ip and self._ip_lists.is_blacklisted(detection.source_ip))
        if is_blacklisted:
            threat_type = "Blocked IP Attempting Access"
            logger.warning("Blacklisted IP %s attempting network access — immediate alert.", source_ip)

        # ── If prediction is benign and not blacklisted, no alert ──
        if detection.prediction == 0 and not is_blacklisted:
            return None

        existing: Final[Alert | None] = self._alerts.find_active_window(
            source_ip=source_ip,
            threat_type=threat_type,
            window_minutes=self._window_minutes,
        )

        if existing is not None:
            existing.occurrences += 1
            existing.last_seen = detection.created_at
            self._alerts.update(existing)
            logger.info(
                "Aggregated threat signature event [ID=%s] targeting %s/%s. Total counter tier raised to: %s.",
                existing.id, source_ip, threat_type, existing.occurrences,
            )

            if existing.occurrences in _ESCALATION_THRESHOLDS:
                self._notifier.send_escalation_alert(
                    threat_type=threat_type,
                    source_ip=source_ip,
                    model_name=model_name,
                    confidence=detection.confidence,
                    occurrences=existing.occurrences,
                    alert_id=existing.id,
                    destination_ip=detection.destination_ip,
                    source_type=getattr(detection, "source_type", None),
                )

            return existing

        alert = Alert(
            source_ip=source_ip,
            threat_type=threat_type,
            detection_id=detection.id or 0,
        )
        alert = self._alerts.add(alert)

        sent: Final[bool] = self._notifier.send_threat_alert(
            threat_type=threat_type,
            source_ip=source_ip,
            model_name=model_name,
            confidence=detection.confidence,
            alert_id=alert.id,
            destination_ip=detection.destination_ip,
            source_type=detection.source_type,
        )

        if sent:
            alert.telegram_sent = True
            self._alerts.update(alert)

        # Auto-block at Windows Firewall level for confirmed threats
        if self._firewall is not None and source_ip != "unknown":
            try:
                self._firewall.auto_block_on_threat(
                    ip_address=source_ip,
                    reason=f"Threat detected: {threat_type} (confidence={detection.confidence:.2f})",
                )
            except Exception as fw_exc:
                logger.error("Firewall auto-block failed for %s: %s", source_ip, fw_exc)

        action = "BLACKLISTED IP ACCESS" if is_blacklisted else "Threat detected"
        logger.warning("New critical system threat record [ID=%s] for %s (%s) — %s.", alert.id, source_ip, threat_type, action)
        return alert
