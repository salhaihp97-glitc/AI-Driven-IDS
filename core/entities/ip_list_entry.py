"""
IP List Entries Domain Module.

Defines the core structural domain representations for IP access control management. 
Handles explicit network address exemptions (Whitelist) and systemic containment blocks (Blacklist) 
utilized by the core filtering and alert aggregation pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional


@dataclass
class WhitelistIP:
    """
    Domain entity model capturing an explicit network address exclusion entry.
    
    Addresses tracked by this registry bypass standard threat generation workflows 
    to mitigate administrative false positives on authorized hosts.
    """
    ip_address: str
    reason: Optional[str] = None
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class BlacklistIP:
    """
    Domain entity model capturing an explicit network address containment entry.

    Addresses tracked by this registry trigger immediate operational escalation
    or isolation enforcement flags upon telemetry match detection.
    """
    ip_address: str
    reason: Optional[str] = None
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))