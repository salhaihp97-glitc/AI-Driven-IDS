"""
System Diagnostic & Security Audit Logs Page.

Provides SOC analysts with a real-time, filterable, and exportable view of all
system telemetry, detection events, and administrative audit trail records.
Features severity breakdown statistics, source distribution, and auto-refresh.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from config.constants import LogLevel, LogSource
from services.container import get_container
from ui.auth_guard import require_login

require_login()

st.title("System Diagnostic & Security Audit Logs")

container = get_container()
log_repo = container.log_repository

# =========================================================================
# STATISTICS DASHBOARD
# =========================================================================

level_counts = log_repo.count_by_level()
source_counts = log_repo.count_by_source()
total_logs = sum(level_counts.values())

col_stats = st.columns(5)
with col_stats[0]:
    st.metric("Total Records", f"{total_logs:,}")
with col_stats[1]:
    errors = level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0)
    st.metric("Errors & Critical", f"{errors:,}", delta=None)
with col_stats[2]:
    st.metric("Warnings", f"{level_counts.get('WARNING', 0):,}")
with col_stats[3]:
    st.metric("Info Events", f"{level_counts.get('INFO', 0):,}")
with col_stats[4]:
    st.metric("Debug Events", f"{level_counts.get('DEBUG', 0):,}")

st.markdown("---")

# =========================================================================
# SOURCE DISTRIBUTION BAR
# =========================================================================

if source_counts:
    source_df = pd.DataFrame(
        [{"Source": src, "Count": cnt} for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1])]
    )
    st.bar_chart(source_df.set_index("Source")["Count"], horizontal=True, height=120)

st.markdown("---")

# =========================================================================
# FILTER LAYER
# =========================================================================

col1, col2, col3, col4 = st.columns(4)
with col1:
    source_filter = st.selectbox(
        "Source Component",
        ["All Sources"] + [s.value for s in LogSource],
        index=0,
    )
with col2:
    level_filter = st.selectbox(
        "Severity Level",
        ["All Levels"] + [l.value for l in LogLevel],
        index=0,
    )
with col3:
    text_filter = st.text_input("Message Search", placeholder="Enter keywords...")
with col4:
    limit = st.number_input("Max Records", min_value=50, max_value=5000, value=500, step=50)

source = None if source_filter == "All Sources" else LogSource(source_filter)
level = None if level_filter == "All Levels" else LogLevel(level_filter)

# =========================================================================
# QUERY EXECUTION
# =========================================================================

logs = log_repo.search(source=source, level=level, text=text_filter or None, limit=limit)

# =========================================================================
# DATA PRESENTATION
# =========================================================================

if logs:
    st.subheader(f"Results ({len(logs):,} of {total_logs:,} total)")

    _LEVEL_COLORS = {
        "DEBUG": "\U0001f7e2",
        "INFO": "\U0001f535",
        "WARNING": "\U0001f7e1",
        "ERROR": "\U0001f7e0",
        "CRITICAL": "\U0001f534",
    }

    rows = []
    for log in logs:
        rows.append({
            "Timestamp": log.created_at,
            "Severity": f"{_LEVEL_COLORS.get(log.level.value, '')} {log.level.value}",
            "Source": log.source.value,
            "Message": log.message,
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, width="stretch", height=500, use_container_width=True)

    # Export section
    st.markdown("---")
    col_dl1, col_dl2 = st.columns([1, 3])
    with col_dl1:
        st.download_button(
            label="Export CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="ai_ids_audit_logs.csv",
            mime="text/csv",
            use_container_width=True,
        )
else:
    st.info("No log records matched the current filter criteria.")

# =========================================================================
# AUTO-REFRESH
# =========================================================================

st.markdown("---")
if st.button("Refresh Logs", use_container_width=True):
    st.rerun()
