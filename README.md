# AI-IDS: AI-Driven Intrusion Detection System

AI-IDS is a network intrusion detection system that detects and responds to
suspicious traffic using machine learning models trained on the
[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset. It runs as a
Streamlit web application, with a layered Python core — capture, services, and
repository layers over SQLite — and a CLI for headless operation.

Traffic can be analyzed at two granularities:

* **Per-flow** — every connection (e.g. a single three-packet TCP exchange) is
  classified by the per-flow CICIDS2017 models (`Random Forest V3`,
  `XGBoost Pipeline V2`, 15 classes).
* **Macro-flow** — short flows that share `src_ip, dst_ip, dst_port, protocol`
  are aggregated over a sliding window and the aggregate footprint is classified
  by a macro model (`Macro RF V2`, `Macro XGB V2`, 7 classes). This second level
  exists because floods that rotate their source port are invisible per-flow:
  each connection looks normal, but the aggregate is a SYN flood or a port scan.

On every ingestion channel the active ML model is the sole classification
authority. IP reputation lists, firewall blocks, and Telegram notifications
annotate or react to model verdicts; they never override them.

## Features

* Live interface capture and offline PCAP / CSV analysis via pure-Python
  CICFlowMeter feature extraction (no Java runtime).
* Macro-flow assembly with a sliding window for flood and scan detection.
* Batch audit pipelines that stream large CSV files in chunks, with an
  in-memory path used by live capture (no temporary CSV round-trip).
* 15-class per-flow models and 7-class macro models (BENIGN plus DDoS,
  DoS Hulk, DoS Slowhttptest, PortScan, SSH-Patator, SYN Flood).
* Automatic Windows Firewall blocking of confirmed attackers (disable with
  `AI_IDS_AUTO_BLOCK_ENABLED=false`), with a protected-infrastructure guard that
  never blocks the host, its gateway, or configured IPs.
* Telegram alert fan-out to registered subscribers with aggregation and
  escalation windows.
* Whitelist / blacklist IP management.
* Web UI (Streamlit) and command-line operation.
* Host resource monitoring, detection and log audit trails, model registry with
  dynamic activation.

## Repository layout

```
app.py                Streamlit entry point (streamlit run app.py)
cli.py                First-run setup wizard + operations CLI
core/                 Domain entities, abstract interfaces, exceptions (no external deps)
database/             SQLite connection, schema, and bootstrap logic
repositories/         Repository pattern over the persistence layer
infrastructure/       Hashing (bcrypt), logging, Telegram gateway, firewall adapter
ml/                   Model loader, feature schema & mapper, inference adapters
ml/training/          Training pipelines (per-flow models)
capture/              Flow extraction, macro-flow assembly, live capture service
services/             Business logic and the dependency-injection container
ui/pages/             Streamlit pages (rendering only)
scripts/              One-shot provisioning, training, and maintenance helpers
tests/                Test suite
```

See `ARCHITECTURE.md` for a deeper breakdown of the layers and their boundaries.

## Models

The models shipped in `models/` are pre-trained. The database registry tracks
them with dynamic activation; `setup_deployment.py` registers everything in one
pass on a fresh checkout.

| id | Name | Type | Scope | Classes | Accuracy | MCC |
|----|------|------|-------|---------|----------|-----|
| 8  | Macro XGB V2 | XGBoost | macro-flow | 7 | 0.9988 | 0.9986 |
| 7  | Macro RF V2 | Random Forest | macro-flow | 7 | 0.9964 | 0.9958 |
| 6  | Macro XGB V1 | XGBoost | macro-flow | 4 | — | — |
| 5  | Macro RF V1 | Random Forest | macro-flow | 4 | — | — |
| 4  | XGBoost Pipeline V2 | XGBoost | per-flow | 15 | 0.9984 | — |
| 3  | Random Forest V3 | Random Forest | per-flow | 15 | 0.9984 | — |
| 2  | Xgboost (legacy) | XGBoost | per-flow | — | — | — |
| 1  | test | Random Forest | — | — | — | — |

Entries 1 and 2 are legacy test records left in the registry; the active runtime
models are 3, 4, 5, 6, 8. Metrics come from `models_evaluation_results.json`
and `models/macro_models_evaluation.json` (840 held-out macro samples at
`n_per_class=800` training).

Macro model selection is configured with `AI_IDS_MACRO_FLOW_MODEL_ID` — **8**
(*Macro XGB V2*) is the current default and has the best MCC.

## Getting started

### Prerequisites

* Python 3.13.
* `pip`.
* Interface capture and PCAP extraction require raw-socket privileges
  (root on Linux, Npcap on Windows). CSV-only analysis works without either.

### Install and run

```bash
git clone https://github.com/salhaihp97-glitc/AI-Driven-IDS.git
cd AI-Driven-IDS

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux / macOS

pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` at least to set `AI_IDS_SECRET_KEY` and, if you want alerts,
`AI_IDS_TELEGRAM_BOT_TOKEN` / `AI_IDS_TELEGRAM_CHAT_ID`. The template documents
every option.

Register the bundled model artifacts and enable macro-flow assembly (one shot):

```bash
python scripts/setup_deployment.py
```

`setup_deployment.py` also accepts an optional CSV to smoke-test the detection
pipeline, e.g. `python scripts/setup_deployment.py data/captured_flows_master.csv`.

Start the web UI:

```bash
streamlit run app.py           # or: python cli.py launch
```

The first launch bootstraps the database schema and seeds a default
administrator:

* Username: `admin`
* Password: `admin`

The password is stored as a bcrypt hash. Change it from the Settings page after
logging in.

### CLI

`python cli.py` with no arguments auto-detects first run and opens the setup
wizard or a console menu. Subcommands are available for scripting:

```bash
python cli.py status
python cli.py list-models
python cli.py list-interfaces

python cli.py analyze-csv  --model-id 8 --file data/captured_flows_master.csv
python cli.py analyze-pcap --model-id 8 --file capture.pcap

python cli.py live-capture --model-id 8 --interface eth0 --packets 200
python cli.py predict      --model-id 8 --data '{"Flow Duration": 10, ...}'
python cli.py alerts       --limit 20
```

Use `python cli.py <command> --help` for the full flag list.

## Configuration

Key settings (all are read from the environment, see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `AI_IDS_DB_PATH` | `data/ai_ids.db` | SQLite database file |
| `AI_IDS_MACRO_FLOW_ENABLED` | `true` | Aggregate flows before classification |
| `AI_IDS_MACRO_FLOW_MODEL_ID` | `8` | Macro model used for assembled units |
| `AI_IDS_AUTO_BLOCK_ENABLED` | `true` | Master switch for firewall auto-block |
| `AI_IDS_PROTECTED_IPS` | *(empty)* | Additional IPs that are never blocked/alarmed |
| `AI_IDS_TELEGRAM_BOT_TOKEN` | *(empty)* | Telegram bot token for alerts |
| `AI_IDS_TELEGRAM_CHAT_ID` | *(empty)* | Emergency chat for alert fan-out |
| `AI_IDS_ML_DECISION_THRESHOLD` | `0.5` | Adapter sensitivity knob |
| `AI_IDS_LOG_LEVEL` | `INFO` | Logging verbosity |

## How detection works

1. **Extraction** — `cicflowmeter` turns live packets or PCAP/CSV rows into the
   70-feature CICIDS2017 footprint (`capture/`).
2. **Assembly (macro)** — when enabled, short flows sharing a key are merged
   into macro-flow units over the configured window.
3. **Inference** — the feature vector is aligned to the model's training
   footprint (scaler + feature order) and classified by the active model
   (`ml/`, `services/detection_service.py`).
4. **Alerting** — malicious verdicts go through the alert engine, which applies
   whitelist/blacklist context, aggregates repeated events in the alert window,
   escalates at threshold crossovers, triggers firewall blocking (if enabled and
   the IP is not protected), and fans out to Telegram subscribers.

## Testing

```bash
python -m pytest tests/ -q
```

On a clean checkout the suite passes with **420 passed, 10 skipped, 0 failed**
(≈90 s). The tests (repository, service, capture, ML, firewall, Telegram,
NFR) build their own fixtures in temp directories, so they can run without a
database or network privileges. See `TESTING_GUIDE.md` for the test matrix.

## Training

Per-flow models — place CICIDS2017 CSVs under
`ml/training/MachineLearningCVE/data/` (gitignored) and run:

```bash
python -m ml.training.MachineLearningCVE.train_and_compare
```

Macro models — training aggregates per-key member flows so distributions match
runtime assembly, then fits both a Random Forest and an XGBoost:

```bash
python scripts/train_macro_models.py          # optional: --n-per-class 800 --seed 42
```

Register any resulting artifact and make it live:

```bash
python scripts/register_model.py --name "My Model" \
    --path models/your_model.joblib --type random_forest --activate
```

## Operations on Linux / deployment

* Run the IDS host as root (capture privileges and firewall control).
* One-shot provisioning is `python scripts/setup_deployment.py`.
* `scripts/security_scan.py` audits the running web app (OWASP-ZAP-style
  checks) and writes an HTML report.
* `scripts/availability_monitor.py` polls the app and reports downtime
  (use `--help` for the interval options).
* Go through `INSTALLATION.md` and `DEPLOYMENT_FILES.txt` when moving the
  project to a fresh machine.

## Repository documentation

| File | Contents |
|---|---|
| `ARCHITECTURE.md` | Layer boundaries, extraction and aggregation rules |
| `INSTALLATION.md` | Step-by-step setup and configuration |
| `RUNNING_GUIDE.md` | Running the system day-to-day |
| `TESTING_GUIDE.md` | Test matrix and manual verification |
| `LIVE_CAPTURE_TEST_GUIDE.md` | Live capture / Kali attack verification |
| `FINAL_ATTACK_TEST_PROCEDURE.md` | Verified end-to-end attack test procedure |
| `DEPLOYMENT_FILES.txt` | File manifest required on a new machine |