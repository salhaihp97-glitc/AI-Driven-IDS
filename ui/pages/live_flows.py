"""
Live Flows Page — Real-time Security Event Log.

Renders the rolling window of live capture results from the active capture service
(both ``native`` and ``cicflowmeter`` backends expose the same ``get_recent_flows``
API), so classification/severity/protocol display is identical across capture modes.
"""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from capture.flow_models import flow_protocol_name
from capture.live_capture_service import get_live_capture_service
from config.settings import get_settings
from ui.auth_guard import require_login

st.set_page_config(page_title="Live Flows", layout="wide")
require_login()

settings = get_settings()
live_service = get_live_capture_service()
is_running = live_service.status.get("is_running", False)

if "lf_refresh_interval" not in st.session_state:
    st.session_state.lf_refresh_interval = 5

ctrl_col1, ctrl_col2 = st.columns([3, 1])
with ctrl_col1:
    interval = st.select_slider(
        "Refresh interval",
        options=[2, 3, 5, 10, 15, 30],
        value=st.session_state.lf_refresh_interval,
        format_func=lambda x: f"{x}s",
        key="lf_interval_slider",
    )
    st.session_state.lf_refresh_interval = interval
with ctrl_col2:
    st.markdown(f"**Capture**\n\n`{'Running' if is_running else 'Stopped'}`")

st.title("Live capture results")
st.markdown("---")


@st.fragment(run_every=max(1.0, interval))
def _render_live_flows() -> None:
    """Renders the rolling live flow table on an asynchronous refresh cadence.

    The block runs on Streamlit's fragment scheduler instead of a blocking
    ``time.sleep`` + ``st.rerun`` loop in the script thread. The previous
    approach froze the page (controls became unresponsive) and starved the
    websocket ping handler, causing the browser to drop the connection under
    sustained live streams.
    """
    live_records = live_service.get_recent_flows(limit=settings.live_flows_limit)
    running = live_service.status.get("is_running", False)

    if not live_records:
        if running:
            st.info("Capture active — waiting for first flow result.")
        else:
            st.info("No data. Start a capture session from the Live Capture page.")
        return

    total_flows = len(live_records)
    attack_count = sum(1 for r in live_records if r.prediction != 0)
    threat_ratio = (attack_count / total_flows) * 100 if total_flows > 0 else 0
    model_name = live_records[0].model_name if live_records else "Unknown"

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Traffic Flows", f"{total_flows:,}")
    m2.metric(
        "Threats",
        f"{attack_count:,}",
        delta=f"{threat_ratio:.1f}% ratio" if attack_count > 0 else None,
        delta_color="inverse",
    )
    m3.metric("Model", model_name)
    m4.metric("Status", "Running" if running else "Stopped")

    st.markdown("---")

    rows = []
    for r in reversed(live_records):
        if r.is_blacklisted:
            status = "Blocked"
            classification = "Blocked IP Attempting Access"
        elif r.is_whitelisted:
            status = "Admin Test"
            classification = "Admin Test (Whitelisted)"
        elif r.prediction == 0:
            status = "Normal"
            classification = "Benign"
        else:
            status = "Attack"
            classification = f"Attack ({r.attack_type or 'Unknown'})"

        rows.append({
            "Timestamp": datetime.fromtimestamp(r.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": r.source_ip,
            "Destination IP": r.destination_ip,
            "Protocol": flow_protocol_name(r.protocol),
            "Status": status,
            "Attack Type": r.attack_type or "-",
            "Severity": r.severity or "-",
            "Confidence": r.confidence * 100.0,
            "Attack Reason": r.attack_reason,
        })

    sec_display = pd.DataFrame(rows)
    st.dataframe(
        sec_display,
        width="stretch",
        height=400,
        column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Attack Type": st.column_config.TextColumn("Attack Type", width="medium"),
            "Attack Reason": st.column_config.TextColumn("Reason", width="large"),
            "Confidence": st.column_config.ProgressColumn(
                "Confidence", min_value=0.0, max_value=100.0, format="%.1f%%"
            ),
        },
        hide_index=True,
    )


_render_live_flows()
