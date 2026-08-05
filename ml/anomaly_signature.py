"""
Configurable Anomaly Signature Augmentation Module.

Augments machine learning verdicts with deterministic, settings-driven signature rules
designed to capture well-understood attack patterns that CICIDS2017-trained models cannot
generalize to (e.g., loopback SYN floods with zero application payload). All thresholds are
resolved from environment-driven settings so detection sensitivity is tunable per deployment
without code changes, keeping the augmentation layer fully auditable and reproducible.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Final

from config.settings import Settings, get_settings
from ml.feature_mapper import FeatureMapper

# Semantic attack labels assigned when a signature fires (displayed in the UI and alerts).
SYN_FLOOD_ATTACK_TYPE: Final[str] = "SYN Flood"
PORT_SCAN_ATTACK_TYPE: Final[str] = "Port Scan"
LOW_CONFIDENCE_ATTACK_TYPE: Final[str] = "Suspicious - Low Confidence"


@dataclass(frozen=True)
class SignatureHit:
    """
    Immutable outcome capsule produced by a signature evaluation.

    A non-attack verdict is represented by a fully defaulted instance so callers can
    branch safely without extra None-handling ceremony.
    """
    is_attack: bool = False
    attack_type: str = ""
    reason: str = ""
    confidence: float = 0.0


class AnomalySignatureEngine:
    """
    Deterministic rule engine fusing configured thresholds over normalized telemetry.

    Feature lookup reuses the same semantic alignment engine as the ML inference pipeline
    so signature rules operate on canonical CICIDS2017 feature names regardless of the
    ingestion channel's native casing or aliases.
    """

    # Canonical CICIDS2017 feature tags consumed by the signature rules. Alignment is
    # handled by FeatureMapper so inbound telemetry may arrive under any alias/casing.
    _SIGNATURE_FEATURES: Final[list[str]] = [
        "Flow Duration",
        "Total Fwd Packets",
        "SYN Flag Count",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Destination Port",
    ]

    def __init__(
        self,
        settings: Settings | None = None,
        feature_mapper: FeatureMapper | None = None,
    ) -> None:
        """
        Initializes the engine with the process configuration and alignment helper.

        Args:
            settings: Optional settings override (defaults to the process singleton).
            feature_mapper: Optional semantic alignment engine (defaults to a fresh mapper).
        """
        self._settings: Final[Settings] = settings or get_settings()
        self._mapper: Final[FeatureMapper] = feature_mapper or FeatureMapper()
        self._scan_tracker: Final[_PortScanTracker] = _PortScanTracker(
            window_seconds=self._settings.signature_port_scan_window_seconds,
            min_dst_ports=self._settings.signature_port_scan_min_dst_ports,
            cooldown_seconds=self._settings.signature_port_scan_cooldown_seconds,
        )

    def assess(
        self,
        raw_features: dict[str, float],
        ml_benign_confidence: float | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        now: float | None = None,
    ) -> SignatureHit:
        """
        Evaluates raw telemetry against the configured signature rule set.

        Args:
            raw_features: Extracted flow telemetry keyed by any supported feature alias.
            ml_benign_confidence: Optional benign-class probability emitted by the ML model.
                When provided and below the configured low-confidence threshold, the flow is
                treated as a detection even though the model labelled it benign.
            source_ip: Optional source endpoint identifier used for cross-flow scan tracking.
            destination_ip: Optional destination endpoint used for cross-flow scan tracking.
            now: Optional epoch timestamp override (injected by tests); defaults to wall clock.

        Returns:
            A SignatureHit describing whether an out-of-distribution pattern was matched.
        """
        if not self._settings.signature_engine_enabled:
            return SignatureHit()

        vector, missing_features = self._mapper.map_with_report(raw_features, self._SIGNATURE_FEATURES)
        if missing_features:
            # Signature-critical telemetry is absent: refuse to fire rather than risk
            # a false positive on structurally incomplete streams.
            return SignatureHit()

        values: Final[dict[str, float]] = dict(zip(self._SIGNATURE_FEATURES, vector))

        syn_hit = self._assess_syn_flood(values)
        if syn_hit.is_attack:
            return syn_hit

        scan_hit = self._assess_port_scan(values, source_ip, destination_ip, now)
        if scan_hit.is_attack:
            return scan_hit

        return self._assess_low_confidence(ml_benign_confidence)

    def reset(self) -> None:
        """
        Clears cross-flow tracking state so a new independent analysis batch starts clean.

        Used before auditing a fresh CSV/PCAP file so each analysis reports its own
        detections regardless of earlier batches. Live capture keeps the cooldown active.
        """
        self._scan_tracker.reset()

    def _assess_syn_flood(self, values: dict[str, float]) -> SignatureHit:
        """
        Detects SYN floods: a sustained burst of SYN segments carrying negligible payload.

        A healthy TCP connection establishes with a single SYN, so flows aggregating many
        SYN segments together with an empty or near-empty payload are overwhelmingly
        indicative of a handshake-flooding or port-scanning pattern the model may not have
        been trained to recognize.
        """
        syn_count: Final[float] = values["SYN Flag Count"]
        fwd_packets: Final[float] = values["Total Fwd Packets"]
        total_payload: Final[float] = (
            values["Total Length of Fwd Packets"] + values["Total Length of Bwd Packets"]
        )

        if syn_count < self._settings.signature_syn_flood_min_syn:
            return SignatureHit()

        if total_payload > self._settings.signature_syn_flood_max_payload_bytes:
            return SignatureHit()

        fwd_syn_ratio = syn_count / fwd_packets if fwd_packets > 0 else 0.0
        if fwd_syn_ratio < self._settings.signature_syn_flood_min_fwd_syn_ratio:
            return SignatureHit()

        duration_seconds: Final[float] = values["Flow Duration"] / 1_000_000.0
        reason = (
            f"SYN flood signature override: {syn_count:.0f} SYN segments "
            f"(forward ratio {fwd_syn_ratio:.0%}) with {total_payload:.0f} payload bytes "
            f"across {duration_seconds:.2f}s - out-of-distribution pattern missed by the CICIDS2017-trained model"
        )
        return SignatureHit(
            is_attack=True,
            attack_type=SYN_FLOOD_ATTACK_TYPE,
            reason=reason,
            confidence=self._settings.signature_confidence,
        )

    def _assess_port_scan(
        self,
        values: dict[str, float],
        source_ip: str | None,
        destination_ip: str | None,
        now: float | None,
    ) -> SignatureHit:
        """
        Detects port scans via cross-flow aggregation.

        A fast scan (e.g., ``nmap -F``) contacts dozens of distinct destination ports on a
        single host using one short flow per port, so no individual flow looks anomalous to
        the per-flow SYN flood rule or to the CICIDS2017-trained models. The engine therefore
        tracks the distinct destination ports observed from a source to a destination within a
        sliding window and fires once the configured count is exceeded.
        """
        if not (source_ip and destination_ip):
            return SignatureHit()

        timestamp: Final[float] = time.time() if now is None else now
        dst_port: Final[int] = int(values["Destination Port"])
        if not self._scan_tracker.observe(source_ip, destination_ip, dst_port, timestamp):
            return SignatureHit()

        reason = (
            f"Port scan signature override: {source_ip} probed "
            f"{self._settings.signature_port_scan_min_dst_ports}+ distinct destination ports on "
            f"{destination_ip} within {self._settings.signature_port_scan_window_seconds:.0f}s - "
            "out-of-distribution pattern missed by the CICIDS2017-trained model"
        )
        return SignatureHit(
            is_attack=True,
            attack_type=PORT_SCAN_ATTACK_TYPE,
            reason=reason,
            confidence=self._settings.signature_confidence,
        )

    def _assess_low_confidence(self, ml_benign_confidence: float | None) -> SignatureHit:
        """
        Flags benign-labelled flows whose benign-class probability is implausibly low.

        Disabled by default (threshold 0.0); enable by raising the configured threshold.
        Guards against models that confidently miss novel attack families by surfacing
        structurally uncertain benign verdicts for operator review.
        """
        threshold: Final[float] = self._settings.signature_low_confidence_benign_threshold
        if ml_benign_confidence is None or threshold <= 0.0:
            return SignatureHit()

        if ml_benign_confidence >= threshold:
            return SignatureHit()

        reason = (
            f"Low-confidence benign override: model benign probability {ml_benign_confidence:.1%} "
            f"falls below the configured review threshold {threshold:.0%}"
        )
        return SignatureHit(
            is_attack=True,
            attack_type=LOW_CONFIDENCE_ATTACK_TYPE,
            reason=reason,
            confidence=max(self._settings.signature_confidence, 1.0 - ml_benign_confidence),
        )


class _PortScanTracker:
    """
    Bounded sliding-window state tracking destination-port diversity per endpoint pair.

    Port scans produce many distinct destination ports from a source to a destination within
    a short interval, so the distinct-port count inside a configurable window is a strong,
    cheap-to-maintain scan indicator. The tracker is memory-bounded: the least recently used
    endpoint pair is evicted once the capacity ceiling is reached.
    """

    def __init__(
        self,
        window_seconds: float,
        min_dst_ports: int,
        cooldown_seconds: float = 0.0,
        max_entries: int = 2048,
    ) -> None:
        """
        Initializes the tracker with windowing and capacity boundaries.

        Args:
            window_seconds: Sliding window duration over which distinct ports accumulate.
            min_dst_ports: Number of distinct destination ports that constitutes a scan.
            cooldown_seconds: Minimum pause between repeat scan fires for the same endpoint
                pair, preventing a single sustained scan from flooding the alert stream.
            max_entries: Upper bound of endpoint pairs retained to cap memory growth.
        """
        self._window_seconds: Final[float] = window_seconds
        self._min_dst_ports: Final[int] = min_dst_ports
        self._cooldown_seconds: Final[float] = cooldown_seconds
        self._max_entries: Final[int] = max_entries
        self._records: Final[OrderedDict[tuple[str, str], deque[tuple[float, int]]]] = OrderedDict()
        self._last_fire_ts: Final[dict[tuple[str, str], float]] = {}

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, now: float) -> bool:
        """
        Records a destination port observation and reports whether a scan has been exceeded.

        A scan fires only when the distinct destination ports within the window reach the
        threshold. Subsequent fires for the same endpoint pair are suppressed until the
        configured cooldown has elapsed so one sustained scan yields a bounded alert stream.

        Args:
            src_ip: Source endpoint identifier.
            dst_ip: Destination endpoint identifier.
            dst_port: Destination port observed on this flow.
            now: Epoch timestamp of the observation.

        Returns:
            True when a scan is detected and not suppressed by an active cooldown.
        """
        key: Final[tuple[str, str]] = (src_ip, dst_ip)

        if key not in self._records:
            if len(self._records) >= self._max_entries:
                evicted = self._records.popitem(last=False)
                self._last_fire_ts.pop(evicted[0], None)
            self._records[key] = deque()
        else:
            self._records.move_to_end(key)

        window_records: Final[deque[tuple[float, int]]] = self._records[key]
        while window_records and now - window_records[0][0] > self._window_seconds:
            window_records.popleft()
        window_records.append((now, dst_port))

        if len({port for _, port in window_records}) < self._min_dst_ports:
            return False

        last_fire: Final[float | None] = self._last_fire_ts.get(key)
        if last_fire is not None and now - last_fire < self._cooldown_seconds:
            return False

        self._last_fire_ts[key] = now
        return True

    def reset(self) -> None:
        """Clears all tracked endpoint pairs and fire timestamps."""
        self._records.clear()
        self._last_fire_ts.clear()
