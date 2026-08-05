"""
User Domain Entity Module.

Defines the core structural domain representation for identity profiles within the system.
Adheres strictly to the Single Responsibility Principle by acting as a pure data container,
completely decoupled from persistence mechanics or password hashing algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

from config.constants import UserRole


@dataclass
class User:
    """
    Domain entity model capturing identity metadata and structural access privileges.

    Acts as the primary analytical target for authentication verification, identity checks,
    and role-based security boundary enforcement across the application ecosystem.
    """
    username: str
    password_hash: str
    role: UserRole = UserRole.ADMIN
    id: Optional[int] = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_login_at: Optional[datetime] = None
