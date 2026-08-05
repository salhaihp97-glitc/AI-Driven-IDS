"""
Session helpers — the only module that touches Streamlit's raw
`st.session_state` dict directly for auth-related state. Pages call these
functions instead, keeping the session-state key names in one place.
"""

from __future__ import annotations

from typing import Optional

import streamlit as st

from core.entities.user import User

# Centralized immutable session state storage key boundary
_USER_KEY = "ai_ids_current_user"


def get_current_user() -> Optional[User]:
    """Retrieves the authenticated user entity from the active session scope."""
    return st.session_state.get(_USER_KEY)


def set_current_user(user: User) -> None:
    """Binds the authenticated user entity to the secure session context."""
    st.session_state[_USER_KEY] = user


def clear_current_user() -> None:
    """Purges the user credentials from session memory during sign-out sequences."""
    st.session_state.pop(_USER_KEY, None)


def is_authenticated() -> bool:
    """Evaluates whether a verified security principal exists in the current runtime context."""
    return get_current_user() is not None