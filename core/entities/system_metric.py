"""
System Metric Domain Entity Module.

Defines the core structural domain representation for hardware and host runtime metric snapshots.
Captures compute, memory, storage utilization, network interface throughput, and execution thread
counts to enable system performance monitoring and diagnostic reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional


@dataclass
class SystemMetric:
    """
    Domain entity model capturing an isolated infrastructure resource usage snapshot.
    
    Serves as the granular tracking record utilized by monitoring dashboards and system 
    health alert triggers to supervise host stability and computing resource overhead.
    """
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    network_sent_bytes: int
    network_recv_bytes: int
    active_threads: int
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))