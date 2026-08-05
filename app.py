"""
Main Streamlit Gateway and Application Entrypoint Router.

Orchestrates system-wide database boot-seeding routines, initializes framework configurations, 
and enforces absolute session authentication barriers across the entire user interface layer. 
Isolates UI views from data layers by translating valid identity credentials into strict navigation groups.
"""

from __future__ import annotations

import streamlit as st

from database.bootstrap import run as bootstrap_database
from infrastructure.logging.logger_factory import get_logger
from ui.session import is_authenticated

logger = get_logger("ui.app_entrypoint")

# --- Explicit Core Page Layout Configuration ---
st.set_page_config(page_title="AI-IDS Core Engine", page_icon="🛡️", layout="wide")

# --- Idempotent Database Initialization Hook ---
try:
    bootstrap_database()
except Exception as e:
    logger.critical("System Boot Failure: Database schema could not be verified or seeded. Error: %s", e)
    st.error("System Boot Failure: A critical error occurred during backend resource initialization.")
    st.stop()

# --- Structural View Registrations ---
login_page = st.Page("ui/pages/login.py", title="Login")
dashboard_page = st.Page("ui/pages/dashboard.py", title="Dashboard", default=True)
detection_page = st.Page("ui/pages/detection.py", title="Detection")
live_capture_page = st.Page("ui/pages/live_capture.py", title="Live Capture")
live_flows_page = st.Page("ui/pages/live_flows.py", title="Live Flows")
alerts_page = st.Page("ui/pages/alerts.py", title="Alerts")
logs_page = st.Page("ui/pages/logs.py", title="Logs")
models_page = st.Page("ui/pages/models.py", title="Models")
model_eval_page = st.Page("ui/pages/model_evaluation.py", title="Model Evaluation")
monitoring_page = st.Page("ui/pages/monitoring.py", title="Monitoring")
whitelist_page = st.Page("ui/pages/whitelist.py", title="Whitelist")
blacklist_page = st.Page("ui/pages/blacklist.py", title="Blacklist")
firewall_page = st.Page("ui/pages/firewall.py", title="Firewall Control")
settings_page = st.Page("ui/pages/settings.py", title="Settings")

# --- Strict Authentication Gating & Grouped Navigation Mapping ---
if is_authenticated():
    navigation = st.navigation(
        {
            "Analytics Overview": [dashboard_page, detection_page],
            "Live Ingestion": [live_capture_page, live_flows_page],
            "Threat Mitigation": [alerts_page, whitelist_page, blacklist_page, firewall_page],
            "Model Management": [models_page, model_eval_page],
            "System Infrastructure": [logs_page, monitoring_page, settings_page],
        }
    )
else:
    # Universal fallback redirect loop: unauthorized connections are forced into isolation
    navigation = st.navigation([login_page])

# --- Execute Render Loop ---
navigation.run()