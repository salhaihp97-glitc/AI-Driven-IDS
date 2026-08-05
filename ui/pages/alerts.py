"""
Alerts Page — Incident Response & Threat Triage.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Final, List
import streamlit as st

from services.container import get_container
from ui.auth_guard import require_login

require_login()

st.title("Warnings and threats")

container = get_container()
alerts_repo: Final = container.alert_repository
detection_repo: Final = container.detection_repository
model_service: Final = container.model_service

if "expanded_alert_id" not in st.session_state:
    st.session_state["expanded_alert_id"] = None

show_only_active = st.checkbox("Show unacknowledged only", value=True)

all_alerts: List[Any] = alerts_repo.get_recent(limit=300)
filtered_alerts: List[Any] = (
    [alert for alert in all_alerts if not alert.is_acknowledged]
    if show_only_active
    else all_alerts
)

st.markdown("---")

if not filtered_alerts:
    st.success("No pending security alerts.")
else:
    try:
        models_catalog = {model.id: model.name for model in model_service.list_models()}
    except Exception:
        models_catalog = {}

    for alert in filtered_alerts:
        with st.container(border=True):
            cols = st.columns([3, 1.5, 2, 2, 2.5])
            with cols[0]:
                st.markdown(f"**{alert.threat_type}**")
                st.markdown(f"Source IP: `{alert.source_ip}`")
            cols[1].metric("Occurrences", f"{alert.occurrences:,}")
            cols[2].markdown(f"First: `{alert.first_seen}`")
            cols[3].markdown(f"Last: `{alert.last_seen}`")
            with cols[4]:
                telegram_status = "Sent" if alert.telegram_sent else "Not sent"
                st.markdown(f"Telegram: {telegram_status}")
                action_cols = st.columns(2)
                with action_cols[0]:
                    if not alert.is_acknowledged:
                        if st.button("Acknowledge", key=f"ack_{alert.id}", width="stretch"):
                            alert.is_acknowledged = True
                            alerts_repo.update(alert)
                            st.toast(f"Alert #{alert.id} acknowledged")
                            st.rerun()
                    else:
                        st.caption("Acknowledged")
                with action_cols[1]:
                    is_expanded = st.session_state["expanded_alert_id"] == alert.id
                    btn_label = "Collapse" if is_expanded else "Inspect"
                    if st.button(btn_label, key=f"det_{alert.id}", width="stretch"):
                        st.session_state["expanded_alert_id"] = None if is_expanded else alert.id
                        st.rerun()

            if st.session_state["expanded_alert_id"] == alert.id:
                st.markdown("---")
                with st.spinner("Loading detection details..."):
                    detection = detection_repo.get_by_id(alert.detection_id)
                    if detection is None:
                        st.warning("Detection record no longer available.")
                    else:
                        resolved_model_name = models_catalog.get(detection.model_id, f"Model ID: {detection.model_id}")
                        d1, d2, d3, d4, d5 = st.columns(5)
                        d1.metric("Model", resolved_model_name)
                        d2.metric("Confidence", f"{detection.confidence:.2%}")
                        d3.metric("Severity", detection.severity or "N/A")
                        d4.metric("Source", str(detection.source_type).upper())
                        d5.metric("Destination IP", detection.destination_ip or "N/A")
                        d6, d7 = st.columns(2)
                        d6.metric("Attack Type", detection.attack_type or "N/A")
                        d7.metric("Prediction", str(detection.prediction))

                        if detection.attack_reason:
                            st.info(f"**Attack Reason:** {detection.attack_reason}")

                        st.markdown("**Raw Features:**")
                        raw_features_payload: Dict[str, Any] = {}
                        if detection.raw_features:
                            try:
                                if isinstance(detection.raw_features, str):
                                    raw_features_payload = json.loads(detection.raw_features)
                                else:
                                    raw_features_payload = detection.raw_features
                                st.json(raw_features_payload, expanded=False)
                            except (TypeError, ValueError, json.JSONDecodeError):
                                st.code(str(detection.raw_features), language="text")
                        else:
                            st.caption("No raw features recorded.")