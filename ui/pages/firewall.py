"""
Firewall Rules Management Page.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from config.constants import LogSource
from core.exceptions import ValidationError
from services.container import get_container
from ui.auth_guard import require_login
from utils.validators import validate_ip_address

require_login()

container = get_container()
firewall_service = container.firewall_service
log_repository = container.log_repository

if "fw_last_refresh" not in st.session_state:
    st.session_state.fw_last_refresh = time.time()
if "fw_auto_refresh" not in st.session_state:
    st.session_state.fw_auto_refresh = False
if "fw_refresh_interval" not in st.session_state:
    st.session_state.fw_refresh_interval = 10

header_left, header_right = st.columns([5, 1])
with header_left:
    st.title("Firewall Control")
    st.caption("Windows Defender Firewall — Live Management")
with header_right:
    auto_refresh = st.toggle("Auto-refresh", value=st.session_state.fw_auto_refresh, key="fw_ar_toggle")
    st.session_state.fw_auto_refresh = auto_refresh
    if auto_refresh:
        interval = st.select_slider("Interval", options=[5, 10, 15, 30, 60], value=st.session_state.fw_refresh_interval, format_func=lambda x: f"{x}s", key="fw_int_slider")
        st.session_state.fw_refresh_interval = interval

st.markdown("---")

status = firewall_service.get_firewall_status()
is_windows = status["is_windows"]
is_admin = status["is_admin"]
can_modify = is_windows and is_admin

with st.container(border=True):
    status_col, perm_col, refresh_col = st.columns([2, 2, 1])
    with status_col:
        if not is_windows:
            st.error("Platform: Non-Windows — operations simulated")
        elif not is_admin:
            st.warning("Platform: Windows — Admin required for changes")
        else:
            st.success("Platform: Windows — Full Control active")
    with perm_col:
        bl_count = len(firewall_service.get_blocked_ips())
        al_count = len(firewall_service.get_allowed_ips())
        st.markdown(f"**Permissions:** {'Read/Write' if can_modify else 'Read-Only'} | **Blacklist:** {bl_count} | **Whitelist:** {al_count}")
    with refresh_col:
        ts = datetime.fromtimestamp(st.session_state.fw_last_refresh, tz=timezone.utc).strftime("%H:%M:%S")
        st.caption(f"Updated: {ts}")

#m1, m2, m3, m4, m5 = st.columns(5)
#m1.metric("Total Rules", value=status["total_rules"], delta=f"{status['blocked_count']} block / {status['allowed_count']} allow" if status["total_rules"] else None)
#m2.metric("Blocked IPs", value=status["blocked_count"], delta=f"{status['blocked_count']} active" if status["blocked_count"] else "None", delta_color="inverse" if status["blocked_count"] else "off")
#m3.metric("Allowed IPs", value=status["allowed_count"])
#m4.metric("Engine", value="netsh advfirewall" if is_windows else "N/A")
#m5.metric("Admin", value="Granted" if is_admin else "Denied", delta="Full access" if is_admin else "Elevation needed", delta_color="normal" if is_admin else "inverse")

st.markdown("---")

tab_rules, tab_ops, tab_intel, tab_sync, tab_audit = st.tabs(["Active Rules", "IP Operations", "IP Intelligence", "Sync & Bulk", "Audit Trail"])

with tab_rules:
    rules = firewall_service.get_all_rules()
    if rules:
        col_filter, col_action = st.columns([3, 1])
        with col_filter:
            search_ip = st.text_input("Filter IP or name", placeholder="e.g. 192.168", key="fw_rule_filter")
        with col_action:
            st.markdown("&nbsp;")
            if st.button("Refresh", key="fw_refresh_rules", width="stretch"):
                st.rerun()

        filtered = rules
        if search_ip:
            q = search_ip.lower()
            filtered = [r for r in rules if q in r.remote_ip.lower() or q in r.rule_name.lower()]

        df_rules = pd.DataFrame([{
            "Status": "BLOCKED" if "BLOCK" in r.rule_name.upper() else "ALLOWED",
            "IP Address": r.remote_ip,
            "Action": r.action,
            "Enabled": "Yes" if r.enabled else "No",
            "Rule Name": r.rule_name,
            "Description": r.description or "-",
            "Profiles": r.profile or "All",
        } for r in filtered])

        st.dataframe(df_rules, width="stretch", height=min(350, 60 + len(df_rules) * 35), column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "IP Address": st.column_config.TextColumn("IP", width="medium"),
            "Action": st.column_config.TextColumn("Action", width="small"),
            "Rule Name": st.column_config.TextColumn("Rule Name", width="large"),
        }, hide_index=True)
        st.caption(f"{len(filtered)} of {len(rules)} rules")
    else:
        st.info("No AI-IDS firewall rules active.")

with tab_ops:
    if not can_modify and is_windows:
        st.warning("Firewall changes require Admin privileges. Database operations still work.")
    elif not is_windows:
        st.info("Non-Windows — operations logged but not applied.")

    op_block, op_allow, op_remove = st.tabs(["Block IP", "Allow IP", "Remove Rule"])
    with op_block:
        with st.form("block_ip_form", clear_on_submit=True):
            cols = st.columns([1, 3])
            ip_block = cols[0].text_input("IP Address", placeholder="192.168.1.100")
            reason_block = cols[1].text_input("Reason", placeholder="Threat context")
            if st.form_submit_button("Block IP", type="primary", use_container_width=True):
                try:
                    validated = validate_ip_address(ip_block)
                    result = firewall_service.manual_block(validated, reason_block)
                    parts = []
                    if result.get("blacklist_added"): parts.append("blacklisted")
                    if result.get("firewall_blocked"): parts.append("blocked")
                    else: parts.append("firewall rule FAILED")
                    st.toast(f"IP `{validated}`: {', '.join(parts)}")
                    st.rerun()
                except (ValidationError, Exception) as exc:
                    st.error(str(exc))

    with op_allow:
        with st.form("allow_ip_form", clear_on_submit=True):
            cols = st.columns([1, 3])
            ip_allow = cols[0].text_input("IP Address", placeholder="10.0.0.5")
            reason_allow = cols[1].text_input("Reason", placeholder="Trusted host")
            if st.form_submit_button("Allow IP", type="primary", use_container_width=True):
                try:
                    validated = validate_ip_address(ip_allow)
                    result = firewall_service.manual_allow(validated, reason_allow)
                    parts = []
                    if result.get("blacklist_removed"): parts.append("unblacklisted")
                    if result.get("whitelist_added"): parts.append("whitelisted")
                    if result.get("firewall_allowed"): parts.append("allowed")
                    else: parts.append("firewall rule FAILED")
                    st.toast(f"IP `{validated}`: {', '.join(parts)}")
                    st.rerun()
                except (ValidationError, Exception) as exc:
                    st.error(str(exc))

    with op_remove:
        with st.form("remove_ip_form", clear_on_submit=True):
            ip_remove = st.text_input("IP Address", placeholder="192.168.1.100")
            if st.form_submit_button("Remove Rules", use_container_width=True):
                try:
                    validated = validate_ip_address(ip_remove)
                    removed = firewall_service.remove_ip_rule(validated)
                    st.toast(f"Rules for `{validated}` removed" if removed else f"No rules for `{validated}`")
                    st.rerun()
                except (ValidationError, Exception) as exc:
                    st.error(str(exc))

# ══════════════════════════════════════════════════════════════════════════
# TAB 3: IP INTELLIGENCE LOOKUP
# ══════════════════════════════════════════════════════════════════════════

with tab_intel:
    st.subheader("IP Intelligence Lookup")
    st.caption("Check an IP against firewall, blacklist, and whitelist simultaneously")

    lookup_ip = st.text_input("IP Address", placeholder="192.168.1.100", key="fw_lookup_ip")
    if lookup_ip:
        try:
            ip_val = validate_ip_address(lookup_ip)
        except Exception:
            ip_val = lookup_ip

        ip_service = container.ip_list_service
        col_fw, col_bl, col_wl = st.columns(3)

        with col_fw:
            with st.container(border=True):
                st.markdown("**Firewall Status**")
                fw_blocked = firewall_service.is_blocked(ip_val)
                fw_allowed = firewall_service.is_allowed(ip_val)
                if fw_blocked:
                    st.error("BLOCKED by firewall")
                elif fw_allowed:
                    st.success("ALLOWED by firewall")
                else:
                    st.info("No rule")

        with col_bl:
            with st.container(border=True):
                st.markdown("**Blacklist Status**")
                bl_status = ip_service.is_blacklisted(ip_val)
                if bl_status:
                    st.error("BLACKLISTED")
                else:
                    st.info("Not blacklisted")

        with col_wl:
            with st.container(border=True):
                st.markdown("**Whitelist Status**")
                wl_status = ip_service.is_whitelisted(ip_val)
                if wl_status:
                    st.success("WHITELISTED")
                else:
                    st.info("Not whitelisted")

        if fw_blocked or bl_status:
            st.error(f"**Verdict for `{ip_val}`:** BLOCKED — traffic is dropped at firewall level.")
        elif wl_status:
            st.success(f"**Verdict for `{ip_val}`:** TRUSTED — whitelisted, auto-block disabled.")
        else:
            st.info(f"**Verdict for `{ip_val}`:** No action.")

# ══════════════════════════════════════════════════════════════════════════
# TAB 4: SYNC & BULK OPERATIONS
# ══════════════════════════════════════════════════════════════════════════

with tab_sync:
    st.subheader("Firewall Synchronization")
    st.caption("Reconcile firewall rules with blacklist/whitelist database")

    with st.container(border=True):
        sync_col, info_col = st.columns([2, 3])
        with sync_col:
            if st.button("Sync Firewall with Database", type="primary", key="fw_sync_btn"):
                if not can_modify:
                    st.error("Sync requires Admin privileges.")
                else:
                    with st.spinner("Synchronizing..."):
                        stats = firewall_service.sync_firewall_with_lists()
                    st.session_state.fw_last_refresh = time.time()
                    if stats["allowed"] or stats["blocked"] or stats["removed"]:
                        st.success(f"Sync: {stats['allowed']} allow, {stats['blocked']} block, {stats['removed']} removed.")
                    else:
                        st.info("Already in sync.")
                    st.rerun()

        with info_col:
            bl_entries = container.blacklist_repository.get_all()
            wl_entries = container.whitelist_repository.get_all()
            st.markdown(f"Database: {len(bl_entries)} blacklisted, {len(wl_entries)} whitelisted")

# ══════════════════════════════════════════════════════════════════════════
# TAB 5: AUDIT TRAIL
# ══════════════════════════════════════════════════════════════════════════

with tab_audit:
    st.subheader("Firewall Audit Trail")
    st.caption("Log of all firewall operations")

    try:
        fw_logs = log_repository.search(source=LogSource.SYSTEM, text="[FIREWALL]", limit=100)
    except Exception:
        fw_logs = []

    if fw_logs:
        df_audit = pd.DataFrame([{
            "Timestamp": entry.created_at,
            "Level": entry.level.value if hasattr(entry.level, "value") else str(entry.level),
            "Message": entry.message,
        } for entry in fw_logs])
        st.dataframe(df_audit, width="stretch", height=min(400, 60 + len(df_audit) * 30), hide_index=True)
        st.caption(f"{len(fw_logs)} entries")
    else:
        st.info("No firewall audit entries yet.")

st.markdown("---")

# Auto-refresh for live metrics
if st.session_state.fw_auto_refresh:
    interval = st.session_state.fw_refresh_interval
    st.caption(f"Auto-refresh every {interval}s — metrics update automatically")
    time.sleep(interval)
    st.rerun()
