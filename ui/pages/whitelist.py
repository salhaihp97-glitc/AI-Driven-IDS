"""
Whitelist Management — Trusted Network Exemptions.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from core.exceptions import DuplicateRecordError, RecordNotFoundError, ValidationError
from services.container import get_container
from ui.auth_guard import require_login

require_login()

st.title("Whitelist Management")

container = get_container()
ip_service = container.ip_list_service

total = ip_service.count_whitelist()
st.metric(label="Whitelisted IPs", value=total)
st.markdown("---")

with st.form("add_whitelist_form", clear_on_submit=True):
    st.subheader("Add IP to Whitelist")
    col1, col2 = st.columns([1, 2])
    ip_address = col1.text_input("IP Address", placeholder="e.g. 10.0.0.1")
    reason = col2.text_input("Reason", placeholder="e.g. Trusted internal server")
    if st.form_submit_button("Add", use_container_width=True):
        try:
            ip_service.add_to_whitelist(ip_address, reason)
            st.success(f"IP `{ip_address}` whitelisted.")
            st.rerun()
        except (ValidationError, DuplicateRecordError) as exc:
            st.error(str(exc))

st.markdown("---")

col_import, col_export = st.columns(2)
with col_import:
    with st.expander("Bulk Import (CSV)", expanded=False):
        st.caption("CSV with columns: `ip_address`, `reason` (optional)")
        uploaded = st.file_uploader("CSV", type=["csv"], key="wl_import")
        if uploaded is not None:
            try:
                import_df = pd.read_csv(uploaded)
                if "ip_address" not in import_df.columns:
                    st.error("Missing `ip_address` column.")
                else:
                    added, skipped = 0, 0
                    for _, row in import_df.iterrows():
                        ip_val = str(row["ip_address"]).strip()
                        reason_val = str(row.get("reason", "")).strip() if pd.notna(row.get("reason")) else ""
                        try:
                            ip_service.add_to_whitelist(ip_val, reason_val)
                            added += 1
                        except (ValidationError, DuplicateRecordError):
                            skipped += 1
                    st.success(f"Import: {added} added, {skipped} skipped")
                    st.rerun()
            except Exception as exc:
                st.error(str(exc))

with col_export:
    with st.expander("Export (CSV)", expanded=False):
        entries = ip_service.list_whitelist()
        if entries:
            export_df = pd.DataFrame([{"ip_address": e.ip_address, "reason": e.reason or "", "added_at": str(e.created_at)} for e in entries])
            st.download_button("Download CSV", data=export_df.to_csv(index=False).encode("utf-8"), file_name="ai_ids_whitelist.csv", mime="text/csv", use_container_width=True)
        else:
            st.caption("No entries.")

st.markdown("---")

search_text = st.text_input("Search", placeholder="Search by IP or reason...", key="wl_search")
entries = ip_service.search_whitelist(search_text) if search_text else ip_service.list_whitelist()

if "editing_wl_id" not in st.session_state:
    st.session_state["editing_wl_id"] = None
if "confirm_del_wl_id" not in st.session_state:
    st.session_state["confirm_del_wl_id"] = None

if entries:
    for entry in entries:
        is_editing = st.session_state["editing_wl_id"] == entry.id
        is_confirming_delete = st.session_state["confirm_del_wl_id"] == entry.id

        if is_editing:
            with st.form(f"edit_wl_{entry.id}"):
                cols = st.columns([2, 3, 1, 1])
                new_ip = cols[0].text_input("IP", value=entry.ip_address, key=f"wl_ip_{entry.id}")
                new_reason = cols[1].text_input("Reason", value=entry.reason or "", key=f"wl_reason_{entry.id}")
                save = cols[2].form_submit_button("Save", use_container_width=True)
                cancel = cols[3].form_submit_button("Cancel", use_container_width=True)
                if save:
                    try:
                        ip_service.update_whitelist_entry(entry.id, new_ip, new_reason)
                        st.session_state["editing_wl_id"] = None
                        st.success(f"Updated `{new_ip}`")
                        st.rerun()
                    except (ValidationError, RecordNotFoundError) as exc:
                        st.error(str(exc))
                if cancel:
                    st.session_state["editing_wl_id"] = None
                    st.rerun()
        elif is_confirming_delete:
            with st.container(border=True):
                st.warning(f"Delete `{entry.ip_address}`?")
                c1, c2 = st.columns(2)
                if c1.button("Yes, Delete", key=f"confirm_del_wl_{entry.id}", use_container_width=True, type="primary"):
                    ip_service.remove_from_whitelist(entry.id)
                    st.session_state["confirm_del_wl_id"] = None
                    st.toast(f"Deleted `{entry.ip_address}`")
                    st.rerun()
                if c2.button("Cancel", key=f"cancel_del_wl_{entry.id}", use_container_width=True):
                    st.session_state["confirm_del_wl_id"] = None
                    st.rerun()
        else:
            with st.container(border=True):
                cols = st.columns([2, 3, 1, 1])
                cols[0].markdown(f"**`{entry.ip_address}`**")
                cols[1].markdown(f"_{entry.reason or 'No reason'}_")
                if cols[1].button("Edit", key=f"edit_wl_{entry.id}", use_container_width=True):
                    st.session_state["editing_wl_id"] = entry.id
                    st.rerun()
                if cols[2].button("Delete", key=f"del_wl_{entry.id}", use_container_width=True, type="secondary"):
                    st.session_state["confirm_del_wl_id"] = entry.id
                    st.rerun()
                if cols[3].button("Copy", key=f"copy_wl_{entry.id}", use_container_width=True):
                    st.code(entry.ip_address, language=None)
else:
    st.info("Whitelist is empty.")
