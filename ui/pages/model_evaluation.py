"""
Model Evaluation & Comparison Dashboard.
Comprehensive ML model evaluation interface with dynamic metrics,
per-class breakdown, head-to-head comparison, and export.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from config.settings import get_settings
from services.container import get_container
from services.model_metadata_service import ModelMetadataService, ModelProfile
from ui.auth_guard import require_login

require_login()
st.set_page_config(page_title="Model Evaluation", layout="wide")
st.title("Model Evaluation & Comparison Dashboard")

meta_service = ModelMetadataService()
container = get_container()

profiles = meta_service.get_all_profiles()
comparison = meta_service.get_comparison()
classes = meta_service.get_classes()

if not profiles:
    st.warning("No evaluation data found. Run model evaluation first.")
    st.stop()

rf = comparison.rf_profile
xgb = comparison.xgb_profile

st.markdown("---")

summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
summary_col1.metric("Test Samples", f"{rf.total_samples:,}")
summary_col2.metric("Attack Classes", f"{len(classes) - 1}")
summary_col3.metric("Models Evaluated", f"{len(profiles)}")
winner = comparison.winner_accuracy
summary_col4.metric("Overall Winner", winner, delta=f"Acc: {max(rf.accuracy, xgb.accuracy):.4%}")

st.markdown("---")

model_names = {p.display_name: p for p in profiles}
default_idx = 0 if rf.accuracy >= xgb.accuracy else 1
selected_name = st.selectbox("Select model for detailed view", list(model_names.keys()), index=default_idx)
selected = model_names[selected_name]

tab_overview, tab_per_class, tab_comparison, tab_features, tab_export = st.tabs([
    "Overview", "Per-Class Breakdown", "Model Comparison", "Feature Schema", "Export",
])

with tab_overview:
    st.subheader("Model Specifications")
    spec_data = []
    settings = get_settings()
    for p in profiles:
        fpath = None
        for candidate in ["random_forest_v3.joblib", "xgboost_pipeline_v2.joblib"]:
            candidate_path = settings.models_dir / candidate
            if candidate_path.exists():
                fpath = candidate_path
                break
        size_kb = fpath.stat().st_size / 1024 if fpath and fpath.exists() else 0

        spec_data.append({
            "Model": p.display_name,
            "Version": p.version,
            "Architecture": p.model_type.replace("_", " ").title(),
            "Features": p.features_count,
            "Test Samples": f"{p.total_samples:,}",
            "Attack Classes": len(classes) - 1,
            "File Size (KB)": f"{size_kb:,.1f}",
        })
    st.dataframe(pd.DataFrame(spec_data), use_container_width=True, hide_index=True)

    st.subheader("Global Performance Metrics")
    metrics_data = {
        "Metric": [
            "Accuracy", "MCC", "Weighted Precision", "Weighted Recall",
            "Weighted F1", "Macro Precision", "Macro Recall", "Macro F1",
            "Attack Detection Rate", "Benign Detection Rate",
            "False Positive Rate", "False Negative Rate",
        ],
        "Random Forest V3": [
            f"{rf.accuracy:.6f}", f"{rf.mcc:.6f}",
            f"{rf.weighted_avg['precision']:.6f}", f"{rf.weighted_avg['recall']:.6f}",
            f"{rf.weighted_avg['f1_score']:.6f}", f"{rf.macro_avg['precision']:.6f}",
            f"{rf.macro_avg['recall']:.6f}", f"{rf.macro_avg['f1_score']:.6f}",
            f"{rf.attack_detection_rate:.6f}", f"{rf.benign_detection_rate:.6f}",
            f"{rf.false_positive_rate:.6f}", f"{rf.false_negative_rate:.6f}",
        ],
        "XGBoost Pipeline V2": [
            f"{xgb.accuracy:.6f}", f"{xgb.mcc:.6f}",
            f"{xgb.weighted_avg['precision']:.6f}", f"{xgb.weighted_avg['recall']:.6f}",
            f"{xgb.weighted_avg['f1_score']:.6f}", f"{xgb.macro_avg['precision']:.6f}",
            f"{xgb.macro_avg['recall']:.6f}", f"{xgb.macro_avg['f1_score']:.6f}",
            f"{xgb.attack_detection_rate:.6f}", f"{xgb.benign_detection_rate:.6f}",
            f"{xgb.false_positive_rate:.6f}", f"{xgb.false_negative_rate:.6f}",
        ],
    }
    st.dataframe(pd.DataFrame(metrics_data).set_index("Metric"), use_container_width=True)

    st.subheader("Performance Chart")
    chart_df = pd.DataFrame({
        "Metric": ["Accuracy", "MCC", "Attack Detection", "Benign Detection", "FPR", "FNR"],
        "Random Forest V3": [rf.accuracy, rf.mcc, rf.attack_detection_rate, rf.benign_detection_rate, rf.false_positive_rate, rf.false_negative_rate],
        "XGBoost Pipeline V2": [xgb.accuracy, xgb.mcc, xgb.attack_detection_rate, xgb.benign_detection_rate, xgb.false_positive_rate, xgb.false_negative_rate],
    })
    fig_global = go.Figure()
    fig_global.add_trace(go.Bar(
        name="Random Forest V3", x=chart_df["Metric"], y=chart_df["Random Forest V3"],
        marker_color="#3498db",
        text=[f"{v:.4f}" for v in chart_df["Random Forest V3"]],
        textposition="outside", textfont=dict(size=10),
    ))
    fig_global.add_trace(go.Bar(
        name="XGBoost Pipeline V2", x=chart_df["Metric"], y=chart_df["XGBoost Pipeline V2"],
        marker_color="#e74c3c",
        text=[f"{v:.4f}" for v in chart_df["XGBoost Pipeline V2"]],
        textposition="outside", textfont=dict(size=10),
    ))
    fig_global.update_layout(
        barmode="group",
        xaxis_title="Metric", yaxis_title="Score",
        template="plotly_white", legend_title_text="Model",
        font=dict(size=12),
        yaxis=dict(gridcolor="#e0e0e0", rangemode="tozero"),
        xaxis=dict(gridcolor="#e0e0e0"),
        height=450,
    )
    st.plotly_chart(fig_global, width="stretch")
    st.caption("Higher is better for Accuracy, MCC, Detection Rates. Lower is better for FPR, FNR.")

    st.subheader("Attack Category Analysis")
    categories = {
        "DoS": ["DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris"],
        "Brute Force": ["FTP-Patator", "SSH-Patator"],
        "Web Attacks": ["Web Attack / Brute Force", "Web Attack / Sql Injection", "Web Attack / XSS"],
        "Reconnaissance": ["PortScan", "Bot"],
        "Advanced Threats": ["Infiltration", "Heartbleed"],
    }
    cat_rows = []
    for cat_name, cat_classes in categories.items():
        for p in profiles:
            cat_metrics = [pc for pc in p.per_class if pc.class_name in cat_classes]
            if cat_metrics:
                avg_f1 = sum(m.f1_score for m in cat_metrics) / len(cat_metrics)
                avg_recall = sum(m.recall for m in cat_metrics) / len(cat_metrics)
                cat_rows.append({
                    "Category": cat_name, "Model": p.display_name,
                    "Avg F1": f"{avg_f1:.4f}", "Avg Recall": f"{avg_recall:.4f}",
                    "Classes": len(cat_metrics),
                })
    if cat_rows:
        cat_df = pd.DataFrame(cat_rows)
        st.dataframe(cat_df, use_container_width=True, hide_index=True)
        fig_cat = go.Figure()
        for model_name in cat_df["Model"].unique():
            mdata = cat_df[cat_df["Model"] == model_name].copy()
            mdata["Avg F1"] = mdata["Avg F1"].astype(float)
            color = "#3498db" if "Random Forest" in model_name else "#e74c3c"
            fig_cat.add_trace(go.Bar(
                name=model_name, x=mdata["Category"], y=mdata["Avg F1"],
                marker_color=color,
                text=[f"{v:.4f}" for v in mdata["Avg F1"]],
                textposition="outside", textfont=dict(size=10),
            ))
        fig_cat.update_layout(
            barmode="group", title="Average F1-Score by Attack Category",
            xaxis_title="Attack Category", yaxis_title="Average F1-Score",
            template="plotly_white", legend_title_text="Model",
            font=dict(size=12), yaxis=dict(gridcolor="#e0e0e0", rangemode="tozero"),
            xaxis=dict(gridcolor="#e0e0e0"), height=420,
        )
        st.plotly_chart(fig_cat, width="stretch")
        st.caption("Average F1-Score per attack category — higher is better.")

with tab_per_class:
    st.subheader(f"Per-Class Performance: {selected.display_name}")

    per_class_data = []
    for pc in sorted(selected.per_class, key=lambda x: x.f1_score):
        status = "PERFECT" if pc.recall == 1.0 else (
            "Good" if pc.recall >= 0.9 else ("Weak" if pc.recall >= 0.5 else "Poor")
        )
        per_class_data.append({
            "Attack Class": pc.class_name,
            "Precision": f"{pc.precision:.4f}",
            "Recall": f"{pc.recall:.4f}",
            "F1-Score": f"{pc.f1_score:.4f}",
            "Support": f"{int(pc.support):,}",
            "Status": status,
        })

    df_pc = pd.DataFrame(per_class_data)
    st.dataframe(df_pc, use_container_width=True, hide_index=True)

    weak = [pc for pc in selected.per_class if pc.recall < 0.5 and pc.support >= 2]
    if weak:
        st.warning(
            f"Low detection classes (recall < 50%): "
            f"{', '.join(w.class_name for w in weak)}. "
            "Consider collecting more training data for these attack types."
        )

    strong = [pc for pc in selected.per_class if pc.recall >= 0.95]
    if strong:
        st.info(
            f"Strong detection classes (recall >= 95%): "
            f"{', '.join(s.class_name for s in strong)}."
        )

    f1_df = pd.DataFrame({
        "Class": [pc.class_name for pc in selected.per_class],
        "F1-Score": [pc.f1_score for pc in selected.per_class],
    }).sort_values("F1-Score", ascending=True)
    st.subheader("F1-Score per Class")
    st.bar_chart(f1_df.set_index("Class"), use_container_width=True)

    support_df = pd.DataFrame({
        "Class": [pc.class_name for pc in selected.per_class],
        "Samples": [int(pc.support) for pc in selected.per_class],
    }).sort_values("Samples", ascending=False)
    st.subheader("Test Samples per Class")
    st.bar_chart(support_df.set_index("Class"), use_container_width=True)

    with st.expander("Confusion Matrix"):
        short_labels = []
        seen = set()
        for i, label in enumerate(classes):
            if label.startswith("Web Attack"):
                short = label.replace("Web Attack ", "Web/")[:14]
            elif label.startswith("DoS "):
                short = "DoS " + label[4:12]
            elif label.startswith("FTP-") or label.startswith("SSH-"):
                short = label[:12]
            else:
                short = label[:14]
            base = short
            counter = 1
            while short in seen:
                counter += 1
                short = f"{base[:11]}_{counter}"
            seen.add(short)
            short_labels.append(short)

        with st.expander("Class Label Legend", expanded=False):
            legend_df = pd.DataFrame({"Short": short_labels, "Full Class Name": list(classes)})
            st.dataframe(legend_df, use_container_width=True, hide_index=True)

        for p in profiles:
            st.markdown(f"**{p.display_name}**")
            cm = p.confusion_matrix.matrix
            if cm:
                cm_df = pd.DataFrame(cm, index=short_labels, columns=short_labels)
                st.dataframe(cm_df, use_container_width=True)
                diag = [cm[i][i] for i in range(len(cm))]
                row_totals = [sum(row) for row in cm]
                acc_df = pd.DataFrame({
                    "Class": list(classes),
                    "Correct": diag,
                    "Total": row_totals,
                    "Recall": [f"{d / t:.4f}" if t > 0 else "N/A" for d, t in zip(diag, row_totals)],
                })
                st.dataframe(acc_df, use_container_width=True, hide_index=True)

with tab_comparison:
    st.subheader("Random Forest vs XGBoost")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            "**Random Forest wins on:** "
            + (", ".join(comparison.rf_better_classes) if comparison.rf_better_classes else "No classes")
        )
    with col2:
        st.markdown(
            "**XGBoost wins on:** "
            + (", ".join(comparison.xgb_better_classes) if comparison.xgb_better_classes else "No classes")
        )
    if comparison.tied_classes:
        st.caption(f"Tied: {', '.join(comparison.tied_classes)}")

    st.subheader("Winner By Metric")
    winners = {
        "Accuracy": comparison.winner_accuracy,
        "F1 Score": comparison.winner_f1,
        "MCC": comparison.winner_mcc,
        "Attack Detection Rate": comparison.winner_attack_detection,
        "False Negative Rate": comparison.winner_false_negative,
    }
    win_df = pd.DataFrame(list(winners.items()), columns=["Metric", "Winner"])
    st.dataframe(win_df, use_container_width=True, hide_index=True)

    st.divider()

    st.subheader("Per-Class F1 Comparison")
    compare_data = []
    for cls_name in classes:
        rf_pc = next((pc for pc in rf.per_class if pc.class_name == cls_name), None)
        xgb_pc = next((pc for pc in xgb.per_class if pc.class_name == cls_name), None)
        if rf_pc and xgb_pc:
            diff = rf_pc.f1_score - xgb_pc.f1_score
            winner_tag = "RF" if diff > 0.001 else ("XGB" if diff < -0.001 else "Tie")
            compare_data.append({
                "Class": cls_name,
                "RF F1": f"{rf_pc.f1_score:.4f}",
                "XGB F1": f"{xgb_pc.f1_score:.4f}",
                "Delta": f"{diff:+.4f}",
                "Winner": winner_tag,
            })
    st.dataframe(pd.DataFrame(compare_data), use_container_width=True, hide_index=True)

    st.divider()

    st.subheader("Summary Metrics")
    summary = {
        "Metric": ["Accuracy", "MCC", "Weighted F1", "Macro F1", "ADR", "FPR", "FNR"],
        "Random Forest V3": [
            f"{rf.accuracy:.6f}", f"{rf.mcc:.6f}",
            f"{rf.weighted_avg['f1_score']:.6f}", f"{rf.macro_avg['f1_score']:.6f}",
            f"{rf.attack_detection_rate:.6f}", f"{rf.false_positive_rate:.6f}",
            f"{rf.false_negative_rate:.6f}",
        ],
        "XGBoost Pipeline V2": [
            f"{xgb.accuracy:.6f}", f"{xgb.mcc:.6f}",
            f"{xgb.weighted_avg['f1_score']:.6f}", f"{xgb.macro_avg['f1_score']:.6f}",
            f"{xgb.attack_detection_rate:.6f}", f"{xgb.false_positive_rate:.6f}",
            f"{xgb.false_negative_rate:.6f}",
        ],
    }
    st.dataframe(pd.DataFrame(summary).set_index("Metric"), use_container_width=True)

with tab_features:
    st.subheader("CICIDS Feature Schema")

    for p in profiles:
        with st.expander(f"{p.display_name} — {p.features_count} features", expanded=False):
            feat_df = pd.DataFrame({
                "#": range(1, p.features_count + 1),
                "Feature Name": p.feature_names,
            })
            st.dataframe(feat_df, use_container_width=True, hide_index=True)

    st.subheader("Feature Categories")
    categories_map = {
        "Flow Statistics": ["Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Flow IAT"],
        "Forward Packets": ["Fwd Packet Length", "Fwd IAT", "Fwd PSH", "Fwd Header", "Fwd Packets/s", "Fwd Segment"],
        "Backward Packets": ["Bwd Packet Length", "Bwd IAT", "Bwd Header", "Bwd Packets/s", "Bwd Segment"],
        "Packet Statistics": ["Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "Average Packet Size"],
        "TCP Flags": ["FIN Flag", "SYN Flag", "RST Flag", "PSH Flag", "ACK Flag", "URG Flag", "CWR Flag", "ECE Flag"],
        "Subflow": ["Subflow Fwd", "Subflow Bwd"],
        "Window Sizes": ["Init_Win_bytes"],
        "Active/Idle": ["Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"],
    }
    all_features = set(rf.feature_names)
    cat_rows = []
    for cat_name, keywords in categories_map.items():
        matched = [f for f in all_features if any(kw.lower() in f.lower() for kw in keywords)]
        cat_rows.append({
            "Category": cat_name,
            "Count": len(matched),
            "Features": ", ".join(sorted(matched)[:3]) + ("..." if len(matched) > 3 else ""),
        })
    st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True)

with tab_export:
    st.subheader("Download Evaluation Report")

    report_data = {
        "report_title": "AI-IDS Model Evaluation Report",
        "models_evaluated": [p.display_name for p in profiles],
        "total_test_samples": rf.total_samples,
        "attack_classes": len(classes) - 1,
        "results": {},
    }
    for p in profiles:
        report_data["results"][p.display_name] = {
            "accuracy": p.accuracy,
            "mcc": p.mcc,
            "features_count": p.features_count,
            "attack_detection_rate": p.attack_detection_rate,
            "benign_detection_rate": p.benign_detection_rate,
            "fpr": p.false_positive_rate,
            "fnr": p.false_negative_rate,
            "weighted_avg": p.weighted_avg,
            "macro_avg": p.macro_avg,
            "per_class": {
                pc.class_name: {
                    "precision": pc.precision,
                    "recall": pc.recall,
                    "f1_score": pc.f1_score,
                    "support": int(pc.support),
                } for pc in p.per_class
            },
            "confusion_matrix": p.confusion_matrix.matrix,
        }

    report_json = json.dumps(report_data, indent=2, ensure_ascii=False)

    export_col1, export_col2 = st.columns(2)
    with export_col1:
        st.download_button(
            label="Download JSON Report",
            data=report_json,
            file_name="ai_ids_model_evaluation_report.json",
            mime="application/json",
            type="primary",
            use_container_width=True,
        )
    with export_col2:
        csv_rows = []
        for p in profiles:
            for pc in p.per_class:
                csv_rows.append({
                    "Model": p.display_name,
                    "Class": pc.class_name,
                    "Precision": pc.precision,
                    "Recall": pc.recall,
                    "F1-Score": pc.f1_score,
                    "Support": int(pc.support),
                })
        csv_data = pd.DataFrame(csv_rows).to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download CSV — Per-Class Metrics",
            data=csv_data,
            file_name="ai_ids_per_class_metrics.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with st.expander("Preview JSON Report"):
        preview = report_json[:3000] + ("\n... (truncated)" if len(report_json) > 3000 else "")
        st.code(preview, language="json")
