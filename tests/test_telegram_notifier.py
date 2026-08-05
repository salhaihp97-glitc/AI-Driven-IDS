"""
Telegram Notifier Unit Test Suite.

Validates message construction, severity classification, async dispatch,
retry semantics, circuit-breaker fault tolerance, and HTTP transport
without requiring live Telegram Bot API credentials.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from infrastructure.notifications.telegram_notifier import (
    TelegramNotifier,
    _classify_severity,
    _CIRCUIT_BREAKER_RESET_SECONDS,
    _CIRCUIT_BREAKER_THRESHOLD,
    _MAX_RETRIES,
)


# ========================================================================
# Fixtures
# ========================================================================

@pytest.fixture()
def configured_notifier() -> TelegramNotifier:
    """Notifier with fake credentials pre-injected."""
    return TelegramNotifier(bot_token="fake-token-123", chat_id="123456")


@pytest.fixture()
def unconfigured_notifier() -> TelegramNotifier:
    """Notifier with no credentials — should gracefully no-op."""
    return TelegramNotifier(bot_token="", chat_id="")


# ========================================================================
# Section 1: Severity Classification
# ========================================================================

class TestSeverityClassification:

    def test_critical_threshold(self) -> None:
        label, emoji = _classify_severity(0.95)
        assert label == "CRITICAL"
        assert emoji == "\U0001f534"

    def test_high_threshold(self) -> None:
        label, emoji = _classify_severity(0.75)
        assert label == "HIGH"
        assert emoji == "\U0001f7e0"

    def test_medium_threshold(self) -> None:
        label, emoji = _classify_severity(0.45)
        assert label == "MEDIUM"
        assert emoji == "\U0001f7e1"

    def test_low_threshold(self) -> None:
        label, emoji = _classify_severity(0.20)
        assert label == "LOW"
        assert emoji == "\U0001f7e2"

    def test_boundary_critical(self) -> None:
        label, _ = _classify_severity(0.90)
        assert label == "CRITICAL"

    def test_boundary_high(self) -> None:
        label, _ = _classify_severity(0.70)
        assert label == "HIGH"

    def test_boundary_medium(self) -> None:
        label, _ = _classify_severity(0.40)
        assert label == "MEDIUM"

    def test_zero_confidence(self) -> None:
        label, _ = _classify_severity(0.0)
        assert label == "LOW"

    def test_max_confidence(self) -> None:
        label, _ = _classify_severity(1.0)
        assert label == "CRITICAL"


# ========================================================================
# Section 2: Configuration State
# ========================================================================

class TestConfiguration:

    def test_configured_notifier(self, configured_notifier: TelegramNotifier) -> None:
        assert configured_notifier.is_configured is True

    def test_unconfigured_notifier(self, unconfigured_notifier: TelegramNotifier) -> None:
        assert unconfigured_notifier.is_configured is False

    def test_partial_token_only(self) -> None:
        n = TelegramNotifier(bot_token="abc", chat_id="")
        assert n.is_configured is False

    def test_partial_chat_id_only(self) -> None:
        n = TelegramNotifier(bot_token="", chat_id="123")
        assert n.is_configured is False

    def test_none_uses_settings(self) -> None:
        n = TelegramNotifier()
        assert isinstance(n._bot_token, str)
        assert isinstance(n._chat_id, str)


# ========================================================================
# Section 3: HTML Escaping
# ========================================================================

class TestEscaping:

    def test_escapes_ampersand(self) -> None:
        escaped = TelegramNotifier._esc_html("a & b")
        assert escaped == "a &amp; b"

    def test_escapes_angle_brackets(self) -> None:
        escaped = TelegramNotifier._esc_html("<script>")
        assert escaped == "&lt;script&gt;"

    def test_code_span_escapes_html(self) -> None:
        raw = "a < b"
        code = TelegramNotifier._code(raw)
        assert code == "<code>a &lt; b</code>"

    def test_code_span_preserves_dots(self) -> None:
        raw = "192.168.1.100"
        code = TelegramNotifier._code(raw)
        assert code == "<code>192.168.1.100</code>"

    def test_code_span_with_specials(self) -> None:
        raw = "model-v3_best"
        code = TelegramNotifier._code(raw)
        assert code == "<code>model-v3_best</code>"

    def test_esc_preserves_alphanumeric(self) -> None:
        escaped = TelegramNotifier._esc_html("abc123")
        assert escaped == "abc123"


# ========================================================================
# Section 4: Message Construction
# ========================================================================

class TestMessageConstruction:

    def test_threat_message_contains_required_fields(self, configured_notifier: TelegramNotifier) -> None:
        msg = configured_notifier._build_threat_message(
            severity_label="CRITICAL",
            severity_emoji="\U0001f534",
            threat_type="DDoS Amplification",
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            model_name="random_forest_v3",
            confidence=0.97,
            formatted_time="2026-07-25 10:00:00 UTC",
            alert_id=42,
            source_type="live",
        )
        assert "THREAT DETECTED" in msg
        assert "CRITICAL" in msg
        assert "42" in msg
        assert "192.168.1.100" in msg
        assert "10.0.0.1" in msg
        assert "random_forest_v3" in msg
        assert "97.00%" in msg
        assert "LIVE" in msg
        assert "Recommended Actions" in msg
        assert "isolate source host" in msg

    def test_threat_message_optional_fields_absent(self, configured_notifier: TelegramNotifier) -> None:
        msg = configured_notifier._build_threat_message(
            severity_label="LOW",
            severity_emoji="\U0001f7e2",
            threat_type="Port Scan",
            source_ip=None,
            destination_ip=None,
            model_name="rf_test",
            confidence=0.30,
            formatted_time="2026-07-25 10:00:00 UTC",
            alert_id=None,
            source_type=None,
        )
        assert "N/A" in msg
        assert "pending" in msg
        assert "Destination IP" not in msg
        assert "Source Type" not in msg

    def test_threat_message_high_severity_actions(self, configured_notifier: TelegramNotifier) -> None:
        msg = configured_notifier._build_threat_message(
            severity_label="HIGH",
            severity_emoji="\U0001f7e0",
            threat_type="Scan",
            source_ip="1.1.1.1",
            destination_ip=None,
            model_name="rf",
            confidence=0.75,
            formatted_time="2026-01-01 00:00:00 UTC",
            alert_id=1,
            source_type="csv",
        )
        assert "Investigate source IP" in msg

    def test_threat_message_low_severity_actions(self, configured_notifier: TelegramNotifier) -> None:
        msg = configured_notifier._build_threat_message(
            severity_label="LOW",
            severity_emoji="\U0001f7e2",
            threat_type="Minor",
            source_ip="1.1.1.1",
            destination_ip=None,
            model_name="rf",
            confidence=0.20,
            formatted_time="2026-01-01 00:00:00 UTC",
            alert_id=1,
            source_type=None,
        )
        assert "Review alert in AI-IDS dashboard" in msg

    def test_escalation_message_contains_occurrences(self, configured_notifier: TelegramNotifier) -> None:
        msg = configured_notifier._build_escalation_message(
            severity_label="HIGH",
            severity_emoji="\U0001f7e0",
            threat_type="Brute Force SSH",
            source_ip="10.0.0.50",
            destination_ip=None,
            model_name="xgb_model",
            confidence=0.82,
            occurrences=25,
            formatted_time="2026-07-25 11:00:00 UTC",
            alert_id=7,
            source_type=None,
        )
        assert "ESCALATION" in msg
        assert "25" in msg
        assert "Brute Force SSH" in msg
        assert "10.0.0.50" in msg
        assert "25 times" in msg

    def test_escalation_message_with_destination_ip(self, configured_notifier: TelegramNotifier) -> None:
        msg = configured_notifier._build_escalation_message(
            severity_label="HIGH",
            severity_emoji="\U0001f7e0",
            threat_type="XSS",
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            model_name="rf",
            confidence=0.80,
            occurrences=10,
            formatted_time="2026-01-01 00:00:00 UTC",
            alert_id=3,
            source_type=None,
        )
        assert "5.6.7.8" in msg
        assert "Destination IP" in msg


# ========================================================================
# Section 5: HTTP Transport (Mocked)
# ========================================================================

class TestHTTPTransport:

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_send_raw_success(self, mock_post: MagicMock, configured_notifier: TelegramNotifier) -> None:
        mock_post.return_value = MagicMock(status_code=200)
        result = configured_notifier._send_raw("test message")
        assert result is True
        mock_post.assert_called_once()

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_send_raw_failure(self, mock_post: MagicMock, configured_notifier: TelegramNotifier) -> None:
        mock_post.return_value = MagicMock(status_code=400, text="Bad Request")
        result = configured_notifier._send_raw("test message")
        assert result is False

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_send_raw_timeout(self, mock_post: MagicMock, configured_notifier: TelegramNotifier) -> None:
        import requests as _req
        mock_post.side_effect = _req.Timeout("timed out")
        result = configured_notifier._send_raw("test message")
        assert result is False

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_send_raw_connection_error(self, mock_post: MagicMock, configured_notifier: TelegramNotifier) -> None:
        import requests as _req
        mock_post.side_effect = _req.ConnectionError("refused")
        result = configured_notifier._send_raw("test message")
        assert result is False

    def test_send_raw_unconfigured(self, unconfigured_notifier: TelegramNotifier) -> None:
        result = unconfigured_notifier._send_raw("test message")
        assert result is False

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_send_raw_payload_structure(self, mock_post: MagicMock, configured_notifier: TelegramNotifier) -> None:
        mock_post.return_value = MagicMock(status_code=200)
        configured_notifier._send_raw("hello world")

        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["chat_id"] == "123456"
        assert payload["text"] == "hello world"
        assert payload["parse_mode"] == "HTML"
        assert payload["disable_web_page_preview"] is True


# ========================================================================
# Section 6: Circuit Breaker
# ========================================================================

class TestCircuitBreaker:

    def test_initial_state_closed(self, configured_notifier: TelegramNotifier) -> None:
        assert configured_notifier.is_circuit_open is False

    @patch("infrastructure.notifications.telegram_notifier.time.sleep")
    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_opens_after_threshold_failures(
        self, mock_post: MagicMock, mock_sleep: MagicMock, configured_notifier: TelegramNotifier,
    ) -> None:
        import requests as _req
        mock_post.side_effect = _req.ConnectionError("fail")

        for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
            configured_notifier._send_with_retry("msg")

        assert configured_notifier.is_circuit_open is True

    @patch("infrastructure.notifications.telegram_notifier.time.sleep")
    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_circuit_open_blocks_sends(
        self, mock_post: MagicMock, mock_sleep: MagicMock, configured_notifier: TelegramNotifier,
    ) -> None:
        import requests as _req
        mock_post.side_effect = _req.ConnectionError("fail")

        for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
            configured_notifier._send_with_retry("msg")

        mock_post.reset_mock()
        mock_sleep.reset_mock()
        configured_notifier._send_with_retry("msg")
        mock_post.assert_not_called()

    @patch("infrastructure.notifications.telegram_notifier.time")
    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_circuit_resets_after_timeout(
        self, mock_post: MagicMock, mock_time: MagicMock, configured_notifier: TelegramNotifier,
    ) -> None:
        import requests as _req
        mock_time.sleep = MagicMock()
        mock_post.side_effect = _req.ConnectionError("fail")
        mock_time.monotonic.return_value = 0.0

        for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
            configured_notifier._send_with_retry("msg")

        assert configured_notifier.is_circuit_open is True

        mock_time.monotonic.return_value = _CIRCUIT_BREAKER_RESET_SECONDS + 1.0
        assert configured_notifier.is_circuit_open is False

    @patch("infrastructure.notifications.telegram_notifier.time.sleep")
    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_success_resets_failure_count(
        self, mock_post: MagicMock, mock_sleep: MagicMock, configured_notifier: TelegramNotifier,
    ) -> None:
        import requests as _req
        mock_post.side_effect = _req.ConnectionError("fail")

        for _ in range(_CIRCUIT_BREAKER_THRESHOLD - 1):
            configured_notifier._send_with_retry("msg")

        mock_post.side_effect = None
        mock_post.return_value = MagicMock(status_code=200)
        configured_notifier._send_with_retry("msg")

        assert configured_notifier._consecutive_failures == 0
        assert configured_notifier.is_circuit_open is False


# ========================================================================
# Section 7: Retry Semantics
# ========================================================================

class TestRetrySemantics:

    @patch("infrastructure.notifications.telegram_notifier.time.sleep")
    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_retries_on_failure(
        self, mock_post: MagicMock, mock_sleep: MagicMock, configured_notifier: TelegramNotifier,
    ) -> None:
        import requests as _req
        mock_post.side_effect = _req.ConnectionError("fail")

        configured_notifier._send_with_retry("msg")

        assert mock_post.call_count == _MAX_RETRIES
        assert mock_sleep.call_count == _MAX_RETRIES - 1

    @patch("infrastructure.notifications.telegram_notifier.requests.post")
    def test_stops_after_first_success(
        self, mock_post: MagicMock, configured_notifier: TelegramNotifier,
    ) -> None:
        mock_post.return_value = MagicMock(status_code=200)
        configured_notifier._send_with_retry("msg")
        assert mock_post.call_count == 1


# ========================================================================
# Section 8: Async Dispatch (Thread Start)
# ========================================================================

class TestAsyncDispatch:

    @patch("infrastructure.notifications.telegram_notifier.threading.Thread")
    def test_dispatch_starts_daemon_thread(self, mock_thread_cls: MagicMock, configured_notifier: TelegramNotifier) -> None:
        mock_thread = MagicMock()
        mock_thread_cls.return_value = mock_thread

        configured_notifier._dispatch_async("payload")

        mock_thread_cls.assert_called_once()
        call_kwargs = mock_thread_cls.call_args.kwargs
        assert call_kwargs["daemon"] is True
        assert call_kwargs["target"] == configured_notifier._send_with_retry
        mock_thread.start.assert_called_once()

    def test_send_threat_alert_returns_true(self, configured_notifier: TelegramNotifier) -> None:
        result = configured_notifier.send_threat_alert(
            threat_type="Test",
            source_ip="1.1.1.1",
            model_name="test_model",
            confidence=0.85,
        )
        assert result is True

    def test_send_escalation_returns_true(self, configured_notifier: TelegramNotifier) -> None:
        result = configured_notifier.send_escalation_alert(
            threat_type="Test",
            source_ip="1.1.1.1",
            model_name="test_model",
            confidence=0.85,
            occurrences=10,
        )
        assert result is True
