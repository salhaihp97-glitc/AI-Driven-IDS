"""
Core Interfaces Initialization Module.

Serves as the centralized exposition layer for foundational domain and infrastructure contracts. 
Aggregates and exposes structural interface definitions via an explicit __all__ package export 
contract to simplify component implementation and dependency inversion setups across the system.
"""

from __future__ import annotations

from core.interfaces.repository import IRepository
from core.interfaces.security import IPasswordHasher

__all__ = [
    "IRepository",
    "IPasswordHasher",
]