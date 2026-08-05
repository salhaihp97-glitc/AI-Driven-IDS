"""
Setting Domain Entity Module.

Defines the core structural domain representation for dynamic application configurations.
Allows runtime system properties, threshold adjustments, and toggle variables to be persisted
and modified safely without requiring complete environment restarts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Setting:
    """
    Domain entity model capturing a dynamic key-value application configuration entry.
    
    Acts as the primary analytical target for persistent runtime overrides, 
    operational feature flags, and component telemetry thresholds.
    """
    key: str
    value: str
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))