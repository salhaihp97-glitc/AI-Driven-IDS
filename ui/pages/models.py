"""
Models page — register new model files, activate/deactivate them.
Fully compliant with production English UI/UX specifications.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from config.settings import get_settings
from core.exceptions import ConfigurationError, DuplicateRecordError
from services.container import get_container
from ui.auth_guard import require_login

# 1. Structural Page Layout Configuration
require_login()

st.title("Model Controller")

# Domain Layer Context Discovery
container = get_container()
model_service = container.model_service
settings = get_settings()

# ==========================================
# PIPELINE ARCHITECTURE REGISTRATION
# ==========================================
st.subheader("Register New Machine Learning Model")
with st.form("register_model_form"):
    name = st.text_input("Model Identifiable Name")
    model_type = st.selectbox("Architecture Type", ["random_forest", "xgboost", "other"])
    version = st.text_input("Semantic Versioning Tag", value="1.0")
    uploaded_file = st.file_uploader("Model Serialization Asset (.joblib / .pkl / .json)", type=["joblib", "pkl", "json", "ubj"])
    submitted = st.form_submit_button("Add", width="stretch")

    if submitted:
        if not name or uploaded_file is None:
            st.error("Validation Failed: Both identifier name and serialization binary are mandatory fields.")
        else:
            dest_path = settings.models_dir / uploaded_file.name
            dest_path.write_bytes(uploaded_file.getvalue())
            try:
                record = model_service.register_model(name, str(dest_path), model_type, version)
                st.success(f"✅ Success: Pipeline '{record.name}' registered successfully with {record.features_count} calculated feature vectors.")
                st.rerun()
            except (ConfigurationError, DuplicateRecordError) as exc:
                st.error(str(exc))

st.divider()

# ==========================================
# REGISTERED ARCHITECTURES MANAGEMENT LAYER
# ==========================================
st.subheader("Deployed Pipeline Records")

records = model_service.list_models()
if not records:
    st.info("💡 Repository Empty: No machine learning classification architectures registered inside the system database yet.")
else:
    for record in records:
        with st.container(border=True):
            cols = st.columns([3, 2, 2, 2, 2])
            
            # Identity Column Matrix Bindings
            cols[0].markdown(f"{record.name}\n\nArchitecture: `{record.model_type}` | Tag: `v{record.version}`")
            cols[1].metric("Feature Count", record.features_count or 0)
            
            # State Management Labels
            status_text = "🟢 Active Model" if record.is_active else "⚪ Disarmed"
            cols[2].markdown(f"Status:\n{status_text}")
            cols[3].markdown(f"Registration Date:\n{record.created_at}")
            
            # Asynchronous Dynamic State Inversion Controls
            with cols[4]:
                if record.is_active:
                    if st.button("Deactivate", key=f"deactivate_{record.id}", width="stretch"):
                        model_service.deactivate(record.id)
                        st.rerun()
                else:
                    if st.button("Activate", key=f"activate_{record.id}", type="primary", width="stretch"):
                        model_service.activate(record.id)
                        st.rerun()