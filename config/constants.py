"""
Project-Wide Constants Module.

Acts as the single source of truth for architectural invariants, database schema definitions, 
access control roles, telemetry logging categories, and baseline feature column matrix structures. 
Prevents magic string anti-patterns across downstream application layers.
"""

from __future__ import annotations

from enum import Enum
from typing import Final


class TableNames:
    """
    Immutably defines core relational database table names mapping to the active system schema.
    """
    USERS: Final[str] = "users"
    SETTINGS: Final[str] = "settings"
    MODELS: Final[str] = "models"
    DETECTIONS: Final[str] = "detections"
    ALERTS: Final[str] = "alerts"
    LOGS: Final[str] = "logs"
    WHITELIST_IPS: Final[str] = "whitelist_ips"
    BLACKLIST_IPS: Final[str] = "blacklist_ips"
    SYSTEM_METRICS: Final[str] = "system_metrics"
    TELEGRAM_SUBSCRIBERS: Final[str] = "telegram_subscribers"


class UserRole(str, Enum):
    """
    Represents authorization tiers evaluated by the access control subsystem.
    """
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class LogLevel(str, Enum):
    """
    Defines structural application tracking operational severity thresholds.
    """
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogSource(str, Enum):
    """
    Identifies the subsystem context originating a telemetry log record entry.
    """
    PREDICTION = "PREDICTION"
    SYSTEM = "SYSTEM"
    CAPTURE = "CAPTURE"
    USER = "USER"
    ERROR = "ERROR"


class SubscriberStatus(str, Enum):
    """
    Represents the approval lifecycle state of a Telegram alert recipient.

    A chat identity starts as ``PENDING`` when it first contacts the bot and
    is only promoted to ``APPROVED`` after an administrator explicitly grants
    it alert delivery access. ``APPROVED`` is the default for legacy rows so
    pre-existing registrations remain eligible for delivery without migration.
    """
    PENDING = "pending"
    APPROVED = "approved"


# Baseline System Seeding Invariants (Overridden during initial configuration setup)
DEFAULT_ADMIN_USERNAME: Final[str] = "admin"
DEFAULT_ADMIN_PASSWORD: Final[str] = "admin"  # noqa: S105 — Only utilized to seed initial database schemas