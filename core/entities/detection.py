"""
Detection Domain Entity Module.

Defines the core structural domain representation for a single analytical inference event.
Captures machine learning model predictions, confidence metrics, network vector metadata,
and source footprints for audit and alert pipeline tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional


@dataclass
class Detection:
    """
    Domain entity model capturing a unique machine learning model evaluation event.

    Serves as the granular transaction record storing telemetry inferences,
    underlying feature spaces, and source network paths.
    """
    model_id: int
    source_ip: Optional[str]
    destination_ip: Optional[str]
    prediction: int  # 0 = Benign, non-zero = Malicious
    confidence: float
    source_type: str  # "csv" | "pcap" | "live"
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    raw_features: Optional[str] = None
    severity: str = ""
    attack_type: str = ""
    attack_reason: str = ""
    is_whitelisted: bool = False
    is_blacklisted: bool = False

    @staticmethod
    def classify_severity(
        confidence: float,
        is_malicious: bool,
        *,
        critical_threshold: float = 0.90,
        high_threshold: float = 0.70,
        medium_threshold: float = 0.40,
    ) -> str:
        """Classify detection severity based on confidence score.

        Single canonical severity classifier shared by the detection pipeline and
        the presentation layer. Thresholds are exposed as keyword arguments with
        documented defaults so consumers can tune band boundaries without forking
        the classification logic.

        Args:
            confidence: Prediction confidence between 0.0 and 1.0.
            is_malicious: Whether the prediction is non-benign.
            critical_threshold: Confidence above which severity is CRITICAL.
            high_threshold: Confidence above which severity is HIGH.
            medium_threshold: Confidence above which severity is MEDIUM.

        Returns:
            Severity string: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "" for benign.
        """
        if not is_malicious:
            return ""
        if confidence >= critical_threshold:
            return "CRITICAL"
        if confidence >= high_threshold:
            return "HIGH"
        if confidence >= medium_threshold:
            return "MEDIUM"
        return "LOW"
