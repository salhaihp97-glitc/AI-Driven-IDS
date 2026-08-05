"""
Alert Domain Entity Module.

Defines the core structural domain representation for aggregated security threat notifications.
Combines multiple correlated telemetry detections mapping to an active threat signature into
a unified administrative lifecycle tracking context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional


@dataclass
class Alert:
    """
    Domain entity model capturing aggregated security threat alert states.

    Acts as the primary analytical target for administrative incident tracking,
    mitigation updates, and automated outbound notification alerts.
    """
    source_ip: str
    threat_type: str
    detection_id: int
    id: Optional[int] = None
    occurrences: int = 1
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_acknowledged: bool = False
    telegram_sent: bool = False
