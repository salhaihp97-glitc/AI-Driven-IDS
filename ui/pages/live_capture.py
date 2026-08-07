"""
Live Capture Page — Real-Time Network Packet Ingestion & Threat Inference.
"""

from __future__ import annotations

import streamlit as st

from capture.interface_lister import NetworkInterfaceLister
from capture.live_capture_service import get_live_capture_service
from config.settings import get_settings
from core.exceptions import ConfigurationError
from services.container import get_container
from ui.auth_guard import require_login

require_login()

settings = get_settings()
container = get_container()

live_service = get_live_capture_service()

st.title("Live Capture")
st.caption("CICFlowMeter capture")

active_models = container.model_service.get_active_models()
if not active_models:
    st.warning("No active models. Deploy one in the Models console.")
    st.stop()

interfaces = NetworkInterfaceLister().list_interfaces()
if not interfaces:
    st.error("No network interfaces found.")
    st.stop()

col1, col2 = st.columns(2)
with col1:
    iface_labels = {iface.display_name: iface.system_name for iface in interfaces}
    selected_iface_label = st.selectbox("Interface", list(iface_labels.keys()))
    selected_iface = iface_labels[selected_iface_label]
with col2:
    model_options = {f"{m.name} ({m.model_type})": m for m in active_models}
    selected_model_label = st.selectbox("Model", list(model_options.keys()))
    selected_model = model_options[selected_model_label]

status = live_service.status

btn_col1, btn_col2 = st.columns(2)
with btn_col1:
    if st.button("Start Capture", disabled=status["is_running"]):
        try:
            live_service.start(selected_iface, selected_model.id, selected_model.name)
            st.rerun()
        except ConfigurationError as exc:
            st.error(str(exc))
with btn_col2:
    if st.button("Stop", disabled=not status["is_running"]):
        live_service.stop()
        st.rerun()

st.divider()

status = live_service.status
if status.get("last_error"):
    st.error(f"Error: {status.get('last_error')}")


@st.fragment(run_every=max(1.0, settings.live_ui_poll_interval))
def _render_live_metrics() -> None:
    """Renders the live capture metrics on an asynchronous refresh cadence.

    The block runs on Streamlit's fragment scheduler instead of blocking the
    script thread in a synchronous sleep loop. This keeps the page responsive
    (start/stop controls still clickable) and avoids freezing the websocket,
    which previously caused the browser to drop the connection under sustained
    live traffic.
    """
    current = live_service.status
    c1, c2, c3 = st.columns(3)
    if current["is_running"]:
        c1.metric("Status", "Running")
        c2.metric("Packets", f"{current['packet_count']:,}")
        c3.metric("Flows", f"{current['active_flows']:,}")
    else:
        c1.metric("Status", "Idle")
        c2.metric("Packets", f"{current['packet_count']:,}")
        c3.metric("Flows", f"{current['active_flows']:,}")


_render_live_metrics()

if hasattr(live_service, 'get_master_csv_path'):
    st.divider()
    st.subheader("CSV Management")
    master_csv_path = live_service.get_master_csv_path()
    if master_csv_path.exists() and master_csv_path.stat().st_size > 0:
        csv_size_kb = master_csv_path.stat().st_size / 1024
        st.success(f"CSV size: {csv_size_kb:.2f} KB")
        manage_col1, manage_col2 = st.columns(2)
        with manage_col1:
            with open(master_csv_path, "rb") as file:
                st.download_button("Export CSV", data=file, file_name="captured_flows_master.csv", mime="text/csv")
        with manage_col2:
            if st.button("Clear CSV"):
                if live_service.clear_master_csv():
                    st.toast("CSV cleared")
                    st.rerun()
                else:
                    st.error("Failed to clear CSV.")
    else:
        st.info("No data yet.")

st.divider()