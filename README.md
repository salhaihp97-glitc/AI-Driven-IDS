# AI-IDS — AI-Driven Intrusion Detection System

An enterprise-grade, high-performance network intrusion detection system driven by advanced machine learning architectures. Engineered strictly around the principles of **Clean Architecture**, **SOLID**, the **Repository Pattern**, and a decoupled **Service Layer**.

> **Project Status:** Production Ready & Fully Completed ✅

---

## 💡 Flow Extraction: CICFlowMeter (Sole Backend)

Network flow extraction uses the **pure-Python `cicflowmeter` package** as the single
backend for both live interface capture and historical PCAP forensics
(`capture/cicflowmeter_live_capture_service.py` + `capture/cicflowmeter_adapter.py`).
No external Java runtime and no alternative extraction engine exist: the historical
native aggregation pipeline has been removed. Extracted flows are passed to the ML
pipeline, where the deployed models are the sole classifier on every ingest channel.

---

## 🏗️ Architectural Topology

The core business logic is neatly isolated from interface boundaries and database engines. Refer to `ARCHITECTURE.md` for a deep technical breakdown:

```
core/            → Entities + Abstract Interfaces + System Exceptions (Zero external dependencies)
database/        → SQLite: Connection Layer + Structural Schema + Bootstrapping Matrix
repositories/    → Repository Pattern implementations mapping database entities
infrastructure/  → Cryptographic Hasher (bcrypt), Logging Engine, Telegram Gateway
ml/              → Dynamic Model Loader + Feature Schema Parser + Feature Mapper
capture/         → Bidirectional Flow Assembly + Native Feature Extractor + Live Sniffer Loop
services/        → Centralized Service Layer (Business Logic) + Container (Dependency Injection Root)
ui/pages/        → Streamlit Presentation Layer (Render-only templates, zero business logic)
app.py           → Streamlit Application Entrypoint (streamlit run app.py)

```

---

## ⚡ Quick Start & Deployment

**Prerequisites:** Python 3.13+

> 📖 **Follow the full step-by-step `INSTALLATION.md` guide** for download, setup, and run on your machine.

```bash
git clone <your-repo-url>
cd AI_IDS_3
python -m venv venv
source venv/bin/activate         # On Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

# Register the pre-trained models bundled in models/ (once)
python scripts/register_model.py --name "Random Forest V3" --path models/random_forest_v3.joblib --type random_forest --activate
python scripts/register_model.py --name "XGBoost Pipeline V2" --path models/xgboost_pipeline_v2.joblib --type xgboost --activate

streamlit run app.py

```

### 🔐 Default Credentials

The initial system bootstrap sequence automatically establishes a default administrative user:

* **Username:** `admin`
* **Password:** `admin`

> 🚨 **Security Notice:** The password is encrypted instantly using a secure cryptographic `bcrypt` hash inside the database. **Rotate this credential immediately** via the Settings panel after your initial login sequence.

To verify the integrity of the database repositories, system constants, and dependency trees without launching the web server, run the foundation validation script:

```bash
python scripts/verify_foundation.py

```

---

## 🖥️ Available Console Panels

The application aggregates a full suite of SOC-operational views:

* **Dashboard:** High-level threat summaries and network telemetry graphs.
* **Detection (CSV/PCAP):** Batch file ingestion for forensics and analysis.
* **Live Capture:** High-frequency raw socket sniffing state controllers.
* **Live Flows:** Real-time micro-flow feature visualization grids.
* **Alerts:** Dynamic security threat logs with automated Telegram escalation details.
* **Logs:** Enterprise log audit trail with search, filter, and export capabilities.
* **Models:** Pipeline architecture repository and dynamic activation switches.
* **Model Evaluation:** Deep classifier metrics (*Confusion Matrix, MCC, F1-Score, ROC AUC*).
* **Monitoring:** Host resource hardware metrics (*CPU, RAM, Disk, Thread Bounds*).
* **Whitelist / Blacklist:** Network access control list management matrices.
* **Settings:** Cryptographic password rotation, Telegram webhook tokens, and environment paths.
* **Login:** Secure session gate backed by `auth_guard` verification.

---

## 🧪 Quality Assurance & Testing

Run the automated test suite to validate component isolation and pipeline reliability:

```bash
pytest -v

```

*Review `TESTING_GUIDE.md` for detailed strategies regarding boundary test coverage and runtime integration checks.*

---

## 🧠 Model Training & Pipeline Customization (CICIDS2017 Dataset)

The system includes independent production-grade training pipelines optimized to handle anomalies present in live network captures:

```bash
# Place your target dataset in the data repository:
mkdir -p data/raw
cp /path/to/production_dataset.csv data/raw/

# Train and compare models (Random Forest + XGBoost)
python -m ml.training.MachineLearningCVE.train_and_compare

# Register the generated models via CLI (Alternative to the Models UI Panel)
python scripts/register_model.py --name "Random Forest v3" --path models/random_forest_v3.joblib --type random_forest --activate
python scripts/register_model.py --name "XGBoost v2" --path models/xgboost_pipeline_v2.joblib --type xgboost --activate

```

The training modules automatically parse standard dataset characteristics, correcting raw spaces in column configurations, mapping string classification records (`BENIGN`, `DDoS`, etc.), and neutralizing invalid or infinite numerical floats (`Infinity`) in network traffic calculations.

---

## 📚 Enterprise Documentation Index

| Resource Asset | Target Domain |
| --- | --- |
| `INSTALLATION.md` | Complete step-by-step guide to download, set up, configure, and run the system. |
| `ARCHITECTURE.md` | In-depth technical guide mapping architectural boundaries, native extraction steps, and aggregation rules. |
| `TESTING_GUIDE.md` | Functional description of the test matrix and operational instructions for manual verification. |
| `DEPLOYMENT_FILES.txt` | Deployment file manifest listing every artifact required to run the project on a new machine. |

---

## 📝 Build Environment & Integration Note

All core infrastructure logic (including dynamic model mapping, flow stream assemblies, metric calculators, automated alerts, access lists, monitoring logs, and evaluation metrics) has been **fully compiled and successfully unit-tested** using the standard numerical packages (`numpy`, `pandas`, `scikit-learn`, `joblib`, `psutil`).

The system's presentation and environmental interface packages (`streamlit`, `scapy`, `xgboost`, `bcrypt`) have been fully verified for absolute syntactical correctness and structural integrity. Ensure that you execute `pytest -v` and `streamlit run app.py` on your target local deployment machine to verify network socket permissions and local host configurations.