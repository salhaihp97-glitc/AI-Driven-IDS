"""
Generic, DB-independent validation helpers.

These raise ValidationError on failure so callers (services) can catch a
single exception type regardless of which rule failed.
"""

from __future__ import annotations

import ipaddress
import re

from core.exceptions import ValidationError

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not _USERNAME_PATTERN.match(username):
        raise ValidationError(
            "Username must be 3-32 characters and contain only letters, digits, dots, dashes, or underscores."
        )
    return username


def validate_password_strength(password: str, minimum_length: int = 8) -> str:
    if not password or len(password) < minimum_length:
        raise ValidationError(f"Password must be at least {minimum_length} characters long.")
    return password


def validate_ip_address(ip_address: str) -> str:
    ip_address = (ip_address or "").strip()
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValidationError(f"'{ip_address}' is not a valid IP address.") from exc
    return ip_address


def validate_chat_id(chat_id: str) -> str:
    """
    Validates and normalizes a Telegram chat identifier.

    Telegram chat IDs are signed integer strings (users are positive, groups and
    channels are negative). Surrounding whitespace is stripped; an empty or
    malformed value is rejected.

    Returns:
        The trimmed chat identifier.
    """
    chat_id = (chat_id or "").strip()
    normalized = chat_id[1:] if chat_id.startswith("-") else chat_id
    if not normalized.isdigit():
        raise ValidationError(f"'{chat_id}' is not a valid Telegram chat ID. Use a signed numeric chat identifier.")
    return chat_id


def sanitize_for_display(value: str) -> str:
    """Escape characters that could enable XSS when rendering user-controlled text in the UI."""
    if value is None:
        return ""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
