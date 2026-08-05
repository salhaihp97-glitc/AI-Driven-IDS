"""Login page. No business logic here — everything goes through AuthService."""

from __future__ import annotations

import streamlit as st

from core.exceptions import AuthenticationError
from services.container import get_container
from ui.session import set_current_user

# 1. Structural Page Layout Configuration
st.title("Login")

# Domain Layer Context Discovery
container = get_container()

# ==========================================
# SECURE CENTRALIZED AUTHENTICATION FORM
# ==========================================
with st.form("login_form"):
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    submitted = st.form_submit_button("login", width="stretch")

if submitted:
    try:
        # Business logic is fully encapsulated inside the AuthService container boundary
        user = container.auth_service.login(username, password)
        set_current_user(user)
        st.success(f"Access granted. Welcome, {user.username} 👋")
        st.rerun()
    except AuthenticationError as exc:
        st.error(str(exc))
