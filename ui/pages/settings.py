"""
Settings Page — change username/password, manage Telegram alert integration
(admin-only bot credentials + subscriber registry), view system prefs.
Fully compliant with production English UI/UX specifications.
"""

from __future__ import annotations

import streamlit as st

from config.constants import UserRole
from config.settings import get_settings
from core.entities.user import User
from core.exceptions import AuthenticationError, DuplicateRecordError, ValidationError
from services.container import get_container
from ui.auth_guard import require_login
from ui.session import clear_current_user, get_current_user, set_current_user

# 1. Structural Page Layout Configuration
require_login()

st.title("Settings")

# Domain Layer Context Discovery
container = get_container()
settings = get_settings()
user = get_current_user()
assert user is not None


# ==========================================
# TAB RENDERERS
# ==========================================

def _render_account_tab(current_user: User) -> None:
    st.subheader("Modify Account Identifier")
    with st.form("change_username_form"):
        new_username = st.text_input("New Username", value=current_user.username)
        if st.form_submit_button("Update Identity Profile", width="stretch"):
            try:
                updated = container.auth_service.change_username(current_user, new_username)
                set_current_user(updated)
                st.success("Identity profile updated successfully.")
                st.rerun()
            except ValidationError as exc:
                st.error(str(exc))

    st.subheader("Rotate Authentication Keys")
    with st.form("change_password_form"):
        current_password = st.text_input("Current Cryptographic Password", type="password")
        new_password = st.text_input("New Cryptographic Password", type="password")
        if st.form_submit_button("Update Password Matrix", width="stretch"):
            try:
                container.auth_service.change_password(current_user, current_password, new_password)
                st.success("Authentication credentials updated successfully.")
            except (AuthenticationError, ValidationError) as exc:
                st.error(str(exc))

    st.divider()
    # FIX: Changed type="destructive" to type="primary" to eliminate the StreamlitAPIException crash
    if st.button("Terminate Session (Sign Out)", type="primary", width="stretch"):
        clear_current_user()
        st.rerun()


def _render_telegram_tab() -> None:
    notifier = container.telegram_notifier
    poller = container.telegram_join_poller
    pending = notifier.pending_subscribers()
    approved = notifier.approved_subscribers()
    active_count = notifier.active_subscriber_count()

    st.caption("Administrator control only — configure your own bot and the people who receive alerts.")

    if notifier.is_configured:
        st.success(f"Integration Operational: bot token registered and {active_count} active recipient(s).")
    else:
        st.warning("Integration Incomplete: provide a bot token and at least one subscriber to enable delivery.")

    # ---- Bot credentials ----
    st.subheader("1. Bot Credentials")
    st.caption(
        "Acquire a token from Telegram's @BotFather, or paste the token of an existing bot "
        "deployment you own. The value is stored locally and never exposed in plain text."
    )
    with st.form("telegram_bot_form"):
        bot_token = st.text_input(
            "Bot Token",
            value=notifier.bot_token,
            type="password",
            placeholder="1234567890:AAH...",
            help="Issued by BotFather at https://t.me/BotFather",
        )
        if st.form_submit_button("Save Bot Token", width="stretch"):
            if not bot_token.strip():
                st.error("Validation Fault: bot token cannot be empty.")
            else:
                notifier.set_bot_token(bot_token)
                st.success("Bot token provisioned successfully. You can now send a test alert.")

    if st.button("Dispatch Test Alert to All Subscribers", width="stretch"):
        sent = notifier.send_test_alert()
        if sent:
            st.success("Test notification delivered to at least one recipient.")
        else:
            st.error(
                "Delivery Failure: no recipient confirmed receipt. Verify the token, "
                "subscribers, and network connectivity to api.telegram.org."
            )

    st.divider()

    # ---- Join requests (pending approvals) ----
    st.subheader("2. Pending Join Requests")
    st.caption(
        "When someone messages your bot (or the bot is added to a group), they appear here as "
        "pending requests. Approve to grant alert access, or reject to delete the request."
    )

    if not pending:
        st.info("No pending join requests. Ask recipients to message the bot to request access.")
    else:
        header_c1, header_c2, header_c3, header_c4 = st.columns([1.4, 2, 1.2, 2])
        header_c1.markdown("**Chat ID**")
        header_c2.markdown("**Requester**")
        header_c3.markdown("**Received**")
        header_c4.markdown("**Actions**")

        for sub in pending:
            row_c1, row_c2, row_c3, row_c4 = st.columns([1.4, 2, 1.2, 2])
            row_c1.markdown(f"`{sub.chat_id}`")
            row_c2.markdown(sub.label or "—")
            row_c3.markdown(str(sub.created_at)[:16])
            col_approve, col_reject = row_c4.columns(2)
            if col_approve.button("Approve", key=f"tg_approve_{sub.chat_id}", type="primary"):
                if notifier.approve_subscriber(sub.chat_id):
                    st.success(f"Subscriber {sub.chat_id} approved and notified.")
                else:
                    st.error(f"Approval failed: chat {sub.chat_id} is no longer registered.")
                st.rerun()
            if col_reject.button("Reject", key=f"tg_reject_{sub.chat_id}"):
                if notifier.reject_subscriber(sub.chat_id):
                    st.warning(f"Request from {sub.chat_id} rejected and removed.")
                else:
                    st.error(f"Rejection failed: chat {sub.chat_id} is no longer registered.")
                st.rerun()

    st.divider()

    # ---- Approved subscriber registry ----
    st.subheader("3. Subscriber Registry (approved recipients)")
    st.caption(
        "Every approved subscriber receives threat and escalation notifications. "
        "You can pause delivery, resume it, or permanently remove (kick) a subscriber."
    )

    with st.form("telegram_subscriber_form"):
        col_chat, col_label = st.columns([1, 1])
        new_chat_id = col_chat.text_input("Chat ID", placeholder="e.g. 123456789")
        new_label = col_label.text_input("Label", placeholder="e.g. SOC Analyst - Ahmad")
        if st.form_submit_button("Register Subscriber Directly", width="stretch"):
            chat_clean = new_chat_id.strip()
            if not chat_clean:
                st.error("Validation Fault: a chat ID is required.")
            elif not chat_clean.lstrip("-").isdigit():
                st.error("Validation Fault: chat ID must be numeric (no '@' or spaces).")
            else:
                try:
                    notifier.add_subscriber(chat_clean, new_label.strip())
                    st.success(f"Subscriber {chat_clean} registered and approved.")
                    st.rerun()
                except (DuplicateRecordError, ValidationError) as exc:
                    st.error(str(exc))

    if not approved:
        st.info("No approved subscribers yet. Approve pending requests or register a chat directly.")
    else:
        st.markdown("**Approved Subscribers**")
        header_c1, header_c2, header_c3, header_c4, header_c5 = st.columns([1.4, 2, 1, 1, 2])
        header_c1.markdown("**Chat ID**")
        header_c2.markdown("**Label**")
        header_c3.markdown("**State**")
        header_c4.markdown("**Delivery**")
        header_c5.markdown("**Actions**")

        for sub in approved:
            row_c1, row_c2, row_c3, row_c4, row_c5 = st.columns([1.4, 2, 1, 1, 2])
            row_c1.markdown(f"`{sub.chat_id}`")
            row_c2.markdown(sub.label or "—")
            row_c3.markdown("Active" if sub.is_active else "Paused")
            row_c4.markdown("Enabled" if sub.is_active else "Muted")
            col_kick, col_toggle = row_c5.columns(2)
            if col_kick.button("Kick", key=f"tg_kick_{sub.chat_id}"):
                if notifier.kick_subscriber(sub.chat_id):
                    st.warning(f"Subscriber {sub.chat_id} removed from alert delivery.")
                else:
                    st.error(f"Removal failed: chat {sub.chat_id} is no longer registered.")
                st.rerun()
            if sub.is_active:
                if col_toggle.button("Pause", key=f"tg_pause_{sub.chat_id}"):
                    notifier.set_subscriber_active(sub.chat_id, False)
                    st.rerun()
            else:
                if col_toggle.button("Resume", key=f"tg_resume_{sub.chat_id}"):
                    notifier.set_subscriber_active(sub.chat_id, True)
                    st.rerun()

    st.divider()

    # ---- Join request listener ----
    st.subheader("4. Join Request Listener (long-poll)")
    st.caption(
        "Runs a background listener that watches the bot for new join requests. "
        "Only one listener can poll a bot token at a time, so start it here and leave it running."
    )

    if poller.is_running:
        st.success("Listener is running and accepting join requests.")
        if st.button("Stop Listener", width="stretch"):
            poller.stop()
            st.rerun()
    else:
        if poller.last_error:
            st.error(f"Listener stopped with an error: {poller.last_error}")
        else:
            st.warning("Listener is stopped. Start it to accept join requests from the bot.")
        if st.button("Start Listener", width="stretch"):
            started = poller.start()
            if started:
                st.success("Listener started. Join requests will now be captured.")
            else:
                st.error(poller.last_error or "Listener could not be started.")
            st.rerun()

    st.divider()

    # ---- Setup guide ----
    with st.expander("Integration Setup Guide"):
        st.markdown(
            """
            **Step 1 - Create your bot**
            Open Telegram and message [@BotFather](https://t.me/BotFather). Send `/newbot`,
            choose a name and username, then copy the issued HTTP API token into the
            **Bot Token** field above.

            **Step 2 - Register the administrator chat**
            Message your own bot with `/start`, then open
            `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser; the
            `chat.id` value inside `message` is the numeric Chat ID. Register it under
            **Subscriber Registry** — the owner is treated as an approved recipient.

            **Step 3 - Let people request access**
            Ask each person who should receive alerts to message your bot. Start the
            **Join Request Listener**, and their request will appear under
            **Pending Join Requests**. Approve to grant alert access or reject to delete.

            **Step 4 - Verify**
            Click **Dispatch Test Alert to All Subscribers** and confirm the message
            arrives on each approved chat. You can pause, resume, or permanently kick
            any subscriber at any time.

            > Credentials and subscriptions persist in the local database and survive
            > application restarts. Only administrators can approve, reject, or remove
            > subscribers. The token never appears in logs.
            """
        )


def _render_system_tab() -> None:
    st.markdown("### Runtime System Constants")

    st.write("Target Environment:", f"`{settings.app_env}`")
    st.write("Database Persistence Path:", f"`{str(settings.database_path)}`")
    st.write("Model Binary Store Directory:", f"`{str(settings.models_dir)}`")
    st.write("Diagnostic Logs Storage Path:", f"`{str(settings.logs_dir)}`")
    st.write("Alert Window Aggregation Constraint:", f"{settings.alert_aggregation_window_minutes} minutes")
    st.write("Live Capture Flow Idle Timeout:", f"{settings.flow_idle_timeout_seconds} seconds")

    st.divider()
    st.markdown("Platform Database Maintenance")
    if st.button("Clear Telemetry History (>24h)", help="Prune older metrics from the database to improve system speed.", width="stretch"):
        removed = container.monitoring_service.prune_old_metrics(24)
        st.success(f"System sweep complete: Safely removed {removed:,} obsolete performance log entries.")


# ==========================================
# CENTRALIZED SYSTEM INTERFACE TABS
# ==========================================

is_admin = user.role == UserRole.ADMIN

if is_admin:
    tab_account, tab_telegram, tab_system = st.tabs([
        "Identity Access Management",
        "Telegram Alert Integration",
        "System Architecture Preferences",
    ])
else:
    tab_account, tab_system = st.tabs([
        "Identity Access Management",
        "System Architecture Preferences",
    ])

# ------------------------------------------
# TAB 1: IDENTITY ACCESS MANAGEMENT (all roles)
# ------------------------------------------
with tab_account:
    _render_account_tab(user)

# ------------------------------------------
# TAB 2: TELEGRAM ALERT INTEGRATION (admin only)
# ------------------------------------------
if is_admin:
    with tab_telegram:
        _render_telegram_tab()
else:
    st.info("🚫 Telegram alert integration is restricted to administrators. "
            "Contact an administrator to configure the bot and its subscribers.")

# ------------------------------------------
# TAB 3: SYSTEM ARCHITECTURE PREFERENCES
# ------------------------------------------
with tab_system:
    _render_system_tab()
