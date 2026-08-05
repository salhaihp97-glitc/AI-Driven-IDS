"""
Telegram Subscriber Domain Entity Module.

Defines the core structural domain representation for a single Telegram recipient
registered to receive AI-IDS threat notifications. Acts as a pure data container,
fully decoupled from persistence mechanics and Telegram transport internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

from config.constants import SubscriberStatus


@dataclass
class TelegramSubscriber:
    """
    Domain entity model capturing a Telegram chat recipient configuration.

    Each entry maps to a unique Telegram ``chat_id`` (user or group) that should
    receive broadcast threat notifications. The ``is_active`` flag provides a
    non-destructive opt-out mechanism without losing the registration record,
    while ``status`` tracks the administrator approval lifecycle: requests
    arrive as ``PENDING`` and are promoted to ``APPROVED`` only after an
    administrator grants access.
    """
    chat_id: str
    id: Optional[int] = None
    label: str = ""
    is_active: bool = True
    status: SubscriberStatus = SubscriberStatus.APPROVED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
