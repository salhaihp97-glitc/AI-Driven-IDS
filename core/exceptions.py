"""
Unified Exception Hierarchy Module.

Defines the core structural exception catalog for the AI-IDS application. Wraps low-level 
system and runtime errors into specific domain exceptions to ensure consistent error 
handling, categorization, and tracking across the UI and service layers.
"""

from __future__ import annotations

from typing import Any, Optional


class IDSBaseException(Exception):
    """Root architectural exception class for all custom domain errors within the AI-IDS system."""
    
    def __init__(self, message: str, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.details: dict[str, Any] = details or {}


# ---------------------------------------------------------------------------
# Infrastructure / Relational Persistence Layer Errors
# ---------------------------------------------------------------------------

class DatabaseError(IDSBaseException):
    """Raised when an underlying structural persistence mechanism or transactional layer fails."""


class RecordNotFoundError(IDSBaseException):
    """Raised when an application repository query yields empty results against mandatory targets."""


class DuplicateRecordError(IDSBaseException):
    """Raised when data insertion violates an existing structural database uniqueness constraint."""


# ---------------------------------------------------------------------------
# Identity Management / Security Layer Errors
# ---------------------------------------------------------------------------

class AuthenticationError(IDSBaseException):
    """Raised when provided entity authentication credentials fail validation checks."""


# ---------------------------------------------------------------------------
# Domain Logic / Validation Layer Errors
# ---------------------------------------------------------------------------

class ValidationError(IDSBaseException):
    """Raised when incoming transaction parameters breach business logic constraints."""


# ---------------------------------------------------------------------------
# System Bootstrapping / Configuration Layer Errors
# ---------------------------------------------------------------------------

class ConfigurationError(IDSBaseException):
    """Raised when initial environment settings parameters are missing, malformed, or unreachable."""