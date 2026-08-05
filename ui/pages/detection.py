"""
Detection Page — Upload CSV or PCAP, run through the Unified Prediction Pipeline.
Optimized with reactive multi-class label encoding and enterprise layout constraints.
Fully compliant with production English UI/UX specifications.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from core.exceptions import ConfigurationError, ValidationError
from services.container import get_container
from ui.auth_guard import require_login

require_login()


def _get_top_features(detection, top_n: int = 3) -> str:
    """Extract top contributing feature names and values as a short summary string."""
    if not detection or not detection.raw_features:
        return "-"
    try:
        features = json.loads(detection.raw_features)
    except Exception:
        return "-"
    if not features:
        return "-"
    sorted_items = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
    return ", ".join(f"{name}={value:.4f}" for name, value in sorted_items[:top_n])


def _get_feature_df(detection) -> pd.DataFrame:
    """Return a full DataFrame of features ordered by absolute contribution."""
    if not detection or not detection.raw_features:
        return pd.DataFrame()
    try:
        features = json.loads(detection.raw_features)
    except Exception:
        return pd.DataFrame()
    sorted_items = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
    return pd.DataFrame(sorted_items, columns=["Feature", "Value"])


st.title("Log analysis (CSV / PCAP)")
st.markdown("---")

container = get_container()
model_service = container.model_service
active_models = model_service.get_active_models()

if not active_models:
    st.warning("No active machine learning models. Deploy a model in the Models console.")
    st.stop()

model_options = {f"{m.name} ({m.model_type}, {m.features_count} Features)": m for m in active_models}
selected_label = st.selectbox("Select Model", list(model_options.keys()))
selected_model = model_options[selected_label]

tab_csv, tab_pcap = st.tabs(["CSV Analysis", "PCAP Analysis"])

with tab_csv:
    st.markdown("Upload a CSV file with network flow features for batch analysis")
    csv_file = st.file_uploader("CSV File", type=["csv"], key="csv_uploader")

    if csv_file is not None:
        st.success(f"File `{csv_file.name}` loaded")
        if st.button("Analyze", key="run_csv"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_csv:
                temp_csv.write(csv_file.getvalue())
                csv_path = Path(temp_csv.name)

            try:
                with st.spinner("Running model inference..."):
                    summary = container.csv_analysis_service.analyze(selected_model.id, str(csv_path))
                try:
                    csv_path.unlink()
                except Exception:
                    pass

                st.success(f"Analysis complete: {summary.total_rows} rows processed")
                c1, c2, c3 = st.columns(3)
                c1.metric("Total Rows", f"{summary.total_rows:,}")
                c2.metric("Benign", f"{summary.normal_count:,}")
                c3.metric("Threats", f"{summary.attack_count:,}", delta=f"{summary.attack_count} flagged" if summary.attack_count > 0 else None, delta_color="inverse")

                if summary.results:
                    payload = []
                    for r in summary.results:
                        pred_val = int(r.detection.prediction)
                        if r.is_blacklisted:
                            status = "Blocked"
                            result_label = "Blocked IP Attempting Access"
                        elif r.is_whitelisted:
                            status = "Admin Test"
                            result_label = "Admin Test Traffic (Whitelisted)"
                        elif pred_val == 0:
                            status = "Normal"
                            result_label = "Benign"
                        else:
                            status = "Attack"
                            atk = r.attack_type if r.attack_type else f"Class {pred_val}"
                            result_label = f"Attack ({atk})"

                        payload.append({
                            "Source IP": r.detection.source_ip or "Unknown",
                            "Status": status,
                            "Attack Type": r.attack_type or "-",
                            "Confidence": f"{r.detection.confidence:.1%}",
                            "Severity": r.detection.severity or "-",
                            "Top Features": _get_top_features(r.detection) if status == "Attack" else "-",
                            "Attack Reason": r.attack_reason,
                            "Missing Features": len(r.missing_features),
                        })

                    results_df = pd.DataFrame(payload)
                    st.subheader("Results")
                    st.dataframe(results_df, width="stretch", column_config={
                        "Status": st.column_config.TextColumn("Status", width="small"),
                        "Attack Type": st.column_config.TextColumn("Attack Type", width="medium"),
                        "Attack Reason": st.column_config.TextColumn("Reason", width="large"),
                        "Confidence": st.column_config.TextColumn("Confidence", width="small"),
                        "Missing Features": st.column_config.NumberColumn("Missing", width="small"),
                    }, hide_index=True)

                    attack_results = [r for r in summary.results if r.detection and r.detection.prediction != 0]
                    if attack_results:
                        with st.expander(f"Feature Details — {len(attack_results)} detected threats"):
                            for i, r in enumerate(attack_results[:5]):
                                df_feat = _get_feature_df(r.detection)
                                if not df_feat.empty:
                                    st.markdown(f"**Result #{i + 1}** — `{r.detection.source_ip or 'Unknown'}` — *{r.attack_type or 'Unknown'}*")
                                    st.dataframe(df_feat, width="stretch", hide_index=True)
                else:
                    st.info("No results returned.")

            except (ValidationError, ConfigurationError) as exc:
                st.error(str(exc))
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")

with tab_pcap:
    st.markdown("Upload a PCAP/PCAPNG file for flow extraction and analysis")
    pcap_file = st.file_uploader("PCAP File", type=["pcap", "pcapng"], key="pcap_uploader")

    if pcap_file is not None:
        st.success(f"File `{pcap_file.name}` loaded")
        if st.button("Analyze", key="run_pcap"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_pcap:
                temp_pcap.write(pcap_file.getvalue())
                pcap_path = Path(temp_pcap.name)

            try:
                with st.spinner("Extracting flows and running model inference..."):
                    summary = container.pcap_analysis_service.analyze(selected_model.id, str(pcap_path))
                try:
                    pcap_path.unlink()
                except Exception:
                    pass

                st.success(f"Analysis complete: {summary.total_flows} flows extracted and evaluated")
                p1, p2, p3 = st.columns(3)
                p1.metric("Total Flows", f"{summary.total_flows:,}")
                p2.metric("Benign", f"{summary.normal_count:,}")
                p3.metric("Threats", f"{summary.attack_count:,}", delta=f"{summary.attack_count} flagged" if summary.attack_count > 0 else None, delta_color="inverse")

                if summary.results:
                    payload = []
                    for r in summary.results:
                        pred_val = int(r.detection.prediction)
                        if r.is_blacklisted:
                            status = "Blocked"
                            result_label = "Blocked IP Attempting Access"
                        elif r.is_whitelisted:
                            status = "Admin Test"
                            result_label = "Admin Test Traffic (Whitelisted)"
                        elif pred_val == 0:
                            status = "Normal"
                            result_label = "Benign"
                        else:
                            status = "Attack"
                            atk = r.attack_type if r.attack_type else f"Class {pred_val}"
                            result_label = f"Attack ({atk})"

                        payload.append({
                            "Source IP": r.detection.source_ip or "Unknown",
                            "Destination IP": r.detection.destination_ip or "Unknown",
                            "Status": status,
                            "Attack Type": r.attack_type or "-",
                            "Confidence": f"{r.detection.confidence:.1%}",
                            "Severity": r.detection.severity or "-",
                            "Top Features": _get_top_features(r.detection) if status == "Attack" else "-",
                            "Attack Reason": r.attack_reason,
                        })

                    results_df = pd.DataFrame(payload)
                    st.subheader("Results")
                    st.dataframe(results_df, width="stretch", column_config={
                        "Status": st.column_config.TextColumn("Status", width="small"),
                        "Attack Type": st.column_config.TextColumn("Attack Type", width="medium"),
                        "Top Features": st.column_config.TextColumn("Top Features", width="large"),
                        "Attack Reason": st.column_config.TextColumn("Reason", width="large"),
                        "Confidence": st.column_config.TextColumn("Confidence", width="small"),
                    }, hide_index=True)

                    attack_results = [r for r in summary.results if r.detection and r.detection.prediction != 0]
                    if attack_results:
                        with st.expander(f"Feature Details — {len(attack_results)} detected threats"):
                            for i, r in enumerate(attack_results[:5]):
                                df_feat = _get_feature_df(r.detection)
                                if not df_feat.empty:
                                    st.markdown(f"**Result #{i + 1}** — `{r.detection.source_ip or 'Unknown'}` — *{r.attack_type or 'Unknown'}*")
                                    st.dataframe(df_feat, width="stretch", hide_index=True)
                else:
                    st.info("No results returned.")

            except (ValidationError, ConfigurationError) as exc:
                st.error(str(exc))
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")