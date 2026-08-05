"""
Dashboard Page — Security Operations Center (SOC) Overview.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from services.container import get_container
from ui.auth_guard import require_login
from utils.time_utils import utc_hours_ago_sql

require_login()

st.title("Dashboard")
st.markdown("---")

container = get_container()
detections_repo = container.detection_repository
alerts_repo = container.alert_repository
model_service = container.model_service

col1, col2, col3, col4 = st.columns(4)
time_horizon_24h = utc_hours_ago_sql(24)

total_flows_24h = detections_repo.count_since(time_horizon_24h)
attacks_count_24h = detections_repo.count_since(time_horizon_24h, only_attacks=True)
active_alerts_count = alerts_repo.count_active()
total_active_models = len(model_service.get_active_models())

col1.metric("Flows (24h)", f"{total_flows_24h:,}")
col2.metric("Attacks (24h)", f"{attacks_count_24h:,}", delta="Detected" if attacks_count_24h > 0 else None, delta_color="inverse")
col3.metric("Alerts", f"{active_alerts_count:,}")
col4.metric("Active Models", f"{total_active_models}")

st.divider()

recent_telemetry = detections_repo.get_recent(limit=200)
if recent_telemetry:
    telemetry_payload = []
    for data_point in recent_telemetry:
        pred_val = int(data_point.prediction)
        if pred_val == 0:
            readable = "Normal"
        else:
            readable = f"Attack ({data_point.attack_type or 'Unknown'})"
        telemetry_payload.append({"Timestamp": data_point.created_at, "Traffic State": readable})

    df_telemetry = pd.DataFrame(telemetry_payload)
    df_telemetry["Timestamp"] = pd.to_datetime(df_telemetry["Timestamp"])
    df_telemetry["Time Bucket"] = df_telemetry["Timestamp"].dt.floor("min")
    grouped = df_telemetry.groupby(["Time Bucket", "Traffic State"]).size().reset_index(name="Volume")
    traffic_chart = px.line(grouped, x="Time Bucket", y="Volume", color="Traffic State", title="Traffic Timeline", color_discrete_map={"Normal": "#2ecc71"})
    traffic_chart.update_layout(xaxis_title="Time", yaxis_title="Flow Volume", template="plotly_white")
    st.plotly_chart(traffic_chart, width="stretch")
else:
    st.info("No telemetry data yet. Run detection (CSV/PCAP) or live capture first.")

st.divider()

st.subheader("Attacks Over Time (24h)")
attack_telemetry = detections_repo.get_recent(limit=2000, only_attacks=True)
if attack_telemetry:
    attack_records = []
    for det in attack_telemetry:
        atk = det.attack_type if det.attack_type else f"Class {det.prediction}"
        attack_records.append({"Timestamp": det.created_at, "Attack Type": atk, "Confidence": float(det.confidence) if det.confidence else 0.0})
    df_attacks = pd.DataFrame(attack_records)
    df_attacks["Timestamp"] = pd.to_datetime(df_attacks["Timestamp"])
    df_attacks["Time Bucket"] = df_attacks["Timestamp"].dt.floor("5min")
    timeline = df_attacks.groupby(["Time Bucket", "Attack Type"]).size().reset_index(name="Count")
    fig = px.area(timeline, x="Time Bucket", y="Count", color="Attack Type", title="Attack Timeline (24h)", template="plotly_white")
    fig.update_layout(xaxis_title="Time", yaxis_title="Attack Count", hovermode="x unified")
    st.plotly_chart(fig, width="stretch")

    conf_col, src_col = st.columns(2)
    with conf_col:
        st.caption("Confidence Distribution")
        import plotly.graph_objects as go
        fig_conf = go.Figure()
        fig_conf.add_trace(go.Histogram(x=df_attacks["Confidence"], nbinsx=30, marker_color="#e74c3c", opacity=0.8))
        fig_conf.update_layout(xaxis_title="Confidence", yaxis_title="Frequency", template="plotly_white", bargap=0.05)
        st.plotly_chart(fig_conf, width="stretch")
    with src_col:
        st.caption("Attack Type Distribution")
        type_counts = df_attacks["Attack Type"].value_counts().reset_index()
        type_counts.columns = ["Attack Type", "Count"]
        fig_pie = px.pie(type_counts, values="Count", names="Attack Type", template="plotly_white", hole=0.35)
        fig_pie.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_pie, width="stretch")
else:
    st.info("No attacks recorded in the last 24 hours.")

st.divider()

st.subheader("Incident Log")
recent_system_alerts = alerts_repo.get_recent(limit=10)
if recent_system_alerts:
    alerts_df = pd.DataFrame([{
        "Source IP": alert.source_ip,
        "Threat Type": alert.threat_type,
        "Occurrences": int(alert.occurrences),
        "Last Seen": alert.last_seen,
        "Status": "Acknowledged" if alert.is_acknowledged else "Active",
    } for alert in recent_system_alerts])
    st.dataframe(alerts_df, column_config={"Occurrences": st.column_config.NumberColumn("Count", format="%d")}, width="stretch", hide_index=True)
else:
    st.info("No incidents. Network is clear.")