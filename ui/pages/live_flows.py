"""
Live Flows Page — Real-time Security Event Log.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from capture.flow import flow_protocol_name
from capture.live_capture_service import get_live_capture_service
from config.settings import get_settings
from core.entities.detection import Detection
from services.container import get_container
from ui.auth_guard import require_login

st.set_page_config(page_title="Live Flows", layout="wide")
require_login()

settings = get_settings()
mode = settings.live_capture_mode
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

if mode == "cicflowmeter":
    cleaned_csv_path = settings.captured_flows_dir / "cleaned_flows_master.csv"

    if cleaned_csv_path.exists() and cleaned_csv_path.stat().st_size > 0:
        try:
            df_full = pd.read_csv(cleaned_csv_path)
            df_full = df_full.iloc[::-1].reset_index(drop=True)
            df_full.columns = [c.strip() for c in df_full.columns]
            columns_lower = {c.lower(): c for c in df_full.columns}

            total_flows = len(df_full)
            prediction_col = next((columns_lower[c] for c in ['prediction', 'label'] if c in columns_lower), None)

            attack_count = 0
            if prediction_col:
                def _is_anomaly(val) -> bool:
                    cleaned_val = str(val).strip().lower()
                    return cleaned_val not in ['0', '0.0', 'benign', 'natural', 'normal']
                attack_count = df_full[prediction_col].apply(_is_anomaly).sum()

            threat_ratio = (attack_count / total_flows) * 100 if total_flows > 0 else 0

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Traffic Flows", f"{total_flows:,}")
            m2.metric("Threats", f"{attack_count:,}", delta=f"{threat_ratio:.1f}% ratio" if attack_count > 0 else None, delta_color="inverse")
            m3.metric("Model", live_service.status.get("model_name") or "Unknown")
            m4.metric("Status", "Running" if is_running else "Stopped")

            st.markdown("---")

            sec_display = pd.DataFrame()

            time_col = next((columns_lower[c] for c in ['timestamp', 'time', 'flow_start'] if c in columns_lower), None)
            sec_display["Timestamp"] = df_full[time_col] if time_col else "N/A"

            src_ip_col = next((columns_lower[c] for c in ['src ip', 'source ip', 'src_ip', 'source_ip'] if c in columns_lower), None)
            dst_ip_col = next((columns_lower[c] for c in ['dst ip', 'destination ip', 'dst_ip', 'destination_ip'] if c in columns_lower), None)
            sec_display["Source IP"] = df_full[src_ip_col] if src_ip_col else "Unknown"
            sec_display["Destination IP"] = df_full[dst_ip_col] if dst_ip_col else "Unknown"

            src_port_col = next((columns_lower[c] for c in ['src port', 'source port', 'src_port', 'source_port', 'sport'] if c in columns_lower), None)
            dst_port_col = next((columns_lower[c] for c in ['dst port', 'destination port', 'dst_port', 'destination_port', 'dport'] if c in columns_lower), None)
            sec_display["Src Port"] = pd.to_numeric(df_full[src_port_col] if src_port_col else 0, errors='coerce').fillna(0).astype(int)
            sec_display["Dst Port"] = pd.to_numeric(df_full[dst_port_col] if dst_port_col else 0, errors='coerce').fillna(0).astype(int)

            proto_col = next((columns_lower[c] for c in ['protocol', 'proto'] if c in columns_lower), None)
            sec_display["Protocol"] = df_full[proto_col].apply(
                flow_protocol_name
            ) if proto_col else "Other"

            if prediction_col:
                sec_display["Status"] = df_full[prediction_col].apply(
                    lambda x: "Normal" if not _is_anomaly(x) else "Attack"
                )
            else:
                sec_display["Status"] = "Normal"

            attack_type_col = next((columns_lower[c] for c in ['attack_type', 'attack type'] if c in columns_lower), None)
            if attack_type_col and prediction_col:
                sec_display["Attack Type"] = df_full.apply(
                    lambda row: (
                        row[attack_type_col]
                        if _is_anomaly(row[prediction_col]) and pd.notnull(row[attack_type_col])
                        and str(row[attack_type_col]).strip()
                        else ("BENIGN" if not _is_anomaly(row[prediction_col]) else "Unknown")
                    ),
                    axis=1,
                )
            elif prediction_col:
                sec_display["Attack Type"] = df_full[prediction_col].apply(
                    lambda x: "BENIGN" if not _is_anomaly(x) else "Unknown"
                )
            else:
                sec_display["Attack Type"] = "BENIGN"

            conf_col = next((columns_lower[c] for c in ['confidence', 'probability', 'prob'] if c in columns_lower), None)
            if conf_col:
                sec_display["Confidence"] = df_full[conf_col].apply(
                    lambda c: float(c) * 100 if float(c) <= 1.0 else float(c)
                )
            else:
                sec_display["Confidence"] = 100.0

            if prediction_col:
                # Use the single canonical severity classifier (core.entities.detection).
                sec_display["Severity"] = [
                    Detection.classify_severity(conf / 100.0, _is_anomaly(pred))
                    for conf, pred in zip(sec_display["Confidence"], df_full[prediction_col])
                ]
            else:
                sec_display["Severity"] = ""

            reason_col = next(
                (columns_lower[c] for c in ['attack_reason', 'attack reason', 'reason'] if c in columns_lower),
                None,
            )
            if reason_col:
                sec_display["Attack Reason"] = df_full[reason_col]
            elif prediction_col and conf_col:
                sec_display["Attack Reason"] = df_full.apply(
                    lambda row: (
                        f"ML model classified as threat with "
                        f"{float(row[conf_col]) * 100 if float(row[conf_col]) <= 1.0 else float(row[conf_col]):.1f}% confidence"
                        if _is_anomaly(row[prediction_col])
                        else "Traffic classified as benign by ML model"
                    ),
                    axis=1,
                )
            else:
                sec_display["Attack Reason"] = ""

            st.dataframe(
                sec_display,
                width="stretch",
                height=400,
                column_config={
                    "Src Port": st.column_config.NumberColumn("Src Port", format="%d"),
                    "Dst Port": st.column_config.NumberColumn("Dst Port", format="%d"),
                    "Status": st.column_config.TextColumn("Status", width="small"),
                    "Attack Type": st.column_config.TextColumn("Attack Type", width="medium"),
                    "Severity": st.column_config.TextColumn("Severity", width="small"),
                    "Attack Reason": st.column_config.TextColumn("Reason", width="large"),
                    "Confidence": st.column_config.ProgressColumn(
                        "Confidence", min_value=0.0, max_value=100.0, format="%.1f%%"
                    ),
                },
                hide_index=True,
            )

        except Exception as exc:
            st.error(str(exc))
    else:
        st.info("No capture data available. Start a capture session first.")
else:
    records = live_service.get_recent_flows(limit=settings.live_flows_limit)

    if records:
        total_flows = len(records)
        attack_count = sum(1 for r in records if r.prediction != 0)
        threat_ratio = (attack_count / total_flows) * 100 if total_flows > 0 else 0
        model_name = records[0].model_name if records else "Unknown"

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Traffic Flows", f"{total_flows:,}")
        m2.metric(
            "Threats",
            f"{attack_count:,}",
            delta=f"{threat_ratio:.1f}% ratio" if attack_count > 0 else None,
            delta_color="inverse",
        )
        m3.metric("Model", model_name)
        m4.metric("Status", "Running" if is_running else "Stopped")

        st.markdown("---")

        rows = []
        for r in reversed(records):
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
                "Confidence": r.confidence * 100.0 if r.confidence <= 1.0 else r.confidence,
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
    else:
        if is_running:
            st.info("Capture active — waiting for first flow result.")
        else:
            st.info("No data. Start a capture session from the Live Capture page.")

time.sleep(interval)
st.rerun()
