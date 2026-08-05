"""
Time utilities — produces datetime strings in the exact format SQLite's
`datetime('now')` uses: "YYYY-MM-DD HH:MM:SS" (space separator, no
microseconds, no 'T', no timezone suffix).

Why this file exists: Python's `datetime.utcnow().isoformat()` produces
"2026-07-07T04:31:14.123456" — a DIFFERENT string format than what's
stored in the `created_at` columns (via SQLite's own `datetime('now')`
default). Comparing these two formats with a plain SQL `>=` is a
lexicographic string comparison, and 'T' (0x54) sorts differently than
' ' (0x20) at the same character position — silently breaking any
"since X" query. Every part of the codebase that needs "now" or "N
minutes/hours ago" for a SQL comparison must go through this module
instead of calling `datetime.utcnow().isoformat()` directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

_SQL_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def utc_now_sql() -> str:
    return datetime.now(UTC).strftime(_SQL_DATETIME_FORMAT)


def utc_minutes_ago_sql(minutes: int) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes)).strftime(_SQL_DATETIME_FORMAT)


def utc_hours_ago_sql(hours: int) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours)).strftime(_SQL_DATETIME_FORMAT)
