"""
Monitoring Page — Real-time System Telemetry & Resource Profiling.
"""

from __future__ import annotations

import time
import pandas as pd
import streamlit as st

from services.container import get_container
from ui.auth_guard import require_login

st.set_page_config(page_title="System Monitor", layout="wide")
require_login()

container = get_container()
monitoring_service = container.monitoring_service

live_status = None
try:
    from capture.live_capture_service import get_live_capture_service
    live_status = get_live_capture_service().status
except Exception:
    pass

if "monitor_refresh_interval" not in st.session_state:
    st.session_state.monitor_refresh_interval = 5

st.title("System Monitor")

ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 2, 1])
with ctrl_col1:
    interval = st.select_slider(
        "Refresh interval",
        options=[2, 3, 5, 10, 15, 30],
        value=st.session_state.monitor_refresh_interval,
        format_func=lambda x: f"{x}s",
        key="mon_refresh_slider",
    )
    st.session_state.monitor_refresh_interval = interval
with ctrl_col2:
    st.markdown("&nbsp;")
    if st.button("Refresh Now", key="mon_refresh_btn", width="stretch"):
        st.rerun()
with ctrl_col3:
    st.markdown(f"**Auto**\n\n`every {interval}s`")

st.markdown("---")

snapshot = monitoring_service.capture_snapshot()
network_throughput = monitoring_service.get_network_throughput_bytes()
prediction_rate = monitoring_service.get_prediction_rate_per_minute()
active_alerts_count = monitoring_service.get_active_alerts_count()

sent_kb = float(network_throughput.get("sent_bytes", 0)) / 1024.0
recv_kb = float(network_throughput.get("recv_bytes", 0)) / 1024.0

cpu_color = "normal" if snapshot.cpu_percent < 80 else ("inverse" if snapshot.cpu_percent < 95 else "off")
ram_color = "normal" if snapshot.ram_percent < 80 else ("inverse" if snapshot.ram_percent < 95 else "off")
disk_color = "normal" if snapshot.disk_percent < 80 else ("inverse" if snapshot.disk_percent < 95 else "off")

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("CPU", f"{snapshot.cpu_percent:.1f}%", delta=None, delta_color=cpu_color)
m2.metric("RAM", f"{snapshot.ram_percent:.1f}%", delta=None, delta_color=ram_color)
m3.metric("Disk", f"{snapshot.disk_percent:.1f}%", delta=None, delta_color=disk_color)
m4.metric("Threads", f"{snapshot.active_threads:,}")
m5.metric("Prediction Rate", f"{prediction_rate:.0f} /min")
m6.metric("Active Alerts", f"{active_alerts_count:,}", delta_color="inverse" if active_alerts_count > 0 else "off")

st.markdown("---")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("**Network**")
    st.markdown(f"Sent: `{sent_kb:,.1f} KB`")
    st.markdown(f"Received: `{recv_kb:,.1f} KB`")

with col2:
    st.markdown("**Capture**")
    if live_status and live_status.get("is_running", False):
        st.markdown(f"State: `Running`")
        st.markdown(f"Packets: `{live_status.get('packet_count', 0):,}`")
        st.markdown(f"Flows: `{live_status.get('active_flows', 0):,}`")
    else:
        st.markdown("State: `Idle`")
        st.markdown("No active capture session.")

with col3:
    st.markdown("**Model**")
    active_models = container.model_service.get_active_models()
    if active_models:
        for m in active_models:
            st.markdown(f"- `{m.name}` ({m.features_count} features)")
    else:
        st.markdown("No active models deployed.")

with col4:
    st.markdown("**Firewall**")
    try:
        fw = container.firewall_service
        status = fw.get_firewall_status()
        st.markdown(f"Rules: `{status['total_rules']}`")
        st.markdown(f"Blocked: `{status['blocked_count']}`")
        st.markdown(f"Admin: `{'Granted' if status['is_admin'] else 'Denied'}`")
    except Exception:
        st.markdown("Firewall not available.")

st.markdown("---")

st.subheader("Resource Timeline")
chart_holder = st.empty()

historical_telemetry = monitoring_service.get_history(limit=30)

if historical_telemetry:
    records = [
        {
            "Time Index": dp.created_at,
            "CPU": float(dp.cpu_percent),
            "RAM": float(dp.ram_percent),
            "Disk": float(dp.disk_percent),
        }
        for dp in historical_telemetry
    ]
    df_stream = pd.DataFrame(records)
    df_stream["Time Index"] = pd.to_datetime(df_stream["Time Index"])
    df_stream = df_stream.set_index("Time Index")

    new_snapshot = monitoring_service.capture_snapshot()
    new_data = pd.DataFrame(
        {
            "CPU": [float(new_snapshot.cpu_percent)],
            "RAM": [float(new_snapshot.ram_percent)],
            "Disk": [float(new_snapshot.disk_percent)],
        },
        index=pd.DatetimeIndex([pd.Timestamp.now()]),
    )
    df_stream = pd.concat([df_stream, new_data])

    chart_holder.line_chart(df_stream, height=350)
else:
    st.info("No historical telemetry data yet. Data will appear as the system runs.")

st.markdown("---")

clean_col1, clean_col2 = st.columns(2)
with clean_col1:
    if st.button("Force Refresh", key="mon_force_refresh", width="stretch"):
        st.rerun()
with clean_col2:
    if st.button("Flush Records (>24h)", key="mon_prune", width="stretch"):
        with st.spinner("Cleaning old telemetry records..."):
            removed = monitoring_service.prune_old_metrics(24)
            st.success(f"Removed {removed:,} records.")
            st.rerun()

time.sleep(interval)
st.rerun()
