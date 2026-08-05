"""Auth guard — call `require_login()` at the top of every protected page."""

from __future__ import annotations

import streamlit as st

from config.constants import UserRole
from ui.session import get_current_user, is_authenticated


def require_login() -> None:
    """
    Enforces centralized session authentication boundaries.
    Blocks downstream rendering pipelines if the current context is unauthenticated.
    """
    if not is_authenticated():
        st.error("🔒 Identity Verification Required: Secure session context not discovered.")
        st.info("You must authenticate before accessing security operational telemetry frames.")
        
        # Actionable fallback trigger to redirect to login panel smoothly
        if st.button("👉 Go to Authentication Center", key="redirect_to_login_btn", width="stretch"):
            st.switch_page("ui/pages/login.py")
            
        st.stop()


def require_admin() -> None:
    """
    Enforces role-based access control boundaries for administrator-only actions.

    Blocks the current page for authenticated non-admin principals (operator /
    viewer). Call this at the top of a page or before rendering an
    administrative section so that bot credentials and subscriber management
    stay under admin control.
    """
    require_login()
    user = get_current_user()
    if user is None or user.role != UserRole.ADMIN:
        st.error("🚫 Access Denied: This section is restricted to administrators only.")
        if st.button("👉 Back to Dashboard", key="redirect_to_dashboard_btn", width="stretch"):
            st.switch_page("app.py")
        st.stop()