"""
Core Entities Initialization Module.

Serves as the centralized domain object exposition layer for the AI-IDS system. 
Aggregates and exposes the complete set of structural domain entities via an explicit 
__all__ package export contract to simplify module imports across downstream services.
"""

from __future__ import annotations

from core.entities.alert import Alert
from core.entities.detection import Detection
from core.entities.ip_list_entry import BlacklistIP, WhitelistIP
from core.entities.log_entry import LogEntry
from core.entities.model_record import ModelRecord
from core.entities.setting import Setting
from core.entities.system_metric import SystemMetric
from core.entities.user import User

__all__ = [
    "Alert",
    "Detection",
    "WhitelistIP",
    "BlacklistIP",
    "LogEntry",
    "ModelRecord",
    "Setting",
    "SystemMetric",
    "User",
]