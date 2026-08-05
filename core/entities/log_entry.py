"""
Log Entry Domain Entity Module.

Defines the core structural domain representation for systemic and analytical event logs.
Captures system execution events, diagnostic signals, user tracking steps, and performance 
telemetry alongside extensible metadata contexts for audit trails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional
from config.constants import LogLevel, LogSource


@dataclass
class LogEntry:
    """
    Domain entity model capturing an isolated application telemetry or audit event.
    
    Serves as the granular structural log record tracked by centralized storage backends 
    to sustain cross-functional system observability and historical diagnosis.
    """
    source: LogSource
    level: LogLevel
    message: str
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: Optional[str] = None  # JSON-encoded string container capturing contextual extra attributes