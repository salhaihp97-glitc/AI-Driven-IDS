# AI-IDS Live Attack Detection — Final Verified Procedure (Kali → Debian)

> This procedure is the **verified** end-to-end path that makes the IDS detect
> attacks launched from Kali. It was validated against the real captured attack
> file (`captured_flows_master.csv`) — 1420 flows, of which the SYN-flood burst
> (1180 flows on :8080) is classified as **SYN Flood** and the nmap scan as
> **PortScan/DDoS** once macro-flow assembly is active.

---

## 1. Why attacks appeared as "no attack" before

- The per-flow CICIDS2017 models (RF V3 / XGBoost V2) classify **each flow alone**.
- A rotating-source-port SYN flood = thousands of tiny 3-packet flows. Individually
  each one looks like a normal short connection → model says BENIGN.
- Fix = **macro-flow assembly** (`capture/macro_flow_assembler.py`): groups all flows
  sharing `src_ip, dst_ip, dst_port, protocol` (excluding src_port) and re-derives the
  aggregate footprint, then hands ONE macro-flow to a macro-aggregate model
  (**id=8 `Macro XGB V2`**, RandomForest alternative **id=7 `Macro RF V2`**) which was
  trained on aggregate features and labels it, e.g. **SYN Flood / DDoS / PortScan**.

**Verified result on the real capture (macro enabled, XGB V2 id=8):**
```
rows=1420  attack=193  normal=1227   -> attack_type includes SYN Flood
```

**Why two macro models?** The original build script (`build_macro_model.py`) only trained a
RandomForest and — critically — gave every member flow a *different* `src_ip`, so the
assembler never actually aggregated during training (each member became its own group).
The model was therefore fitted on RAW per-flow vectors while inference sees true aggregates
(distributional mismatch). The new `scripts/train_macro_models.py` fixes this: all members
of one macro sample share the same key (only `src_port` rotates, exactly like a real flood),
so training vectors are true aggregates matching runtime. It then trains **both** RF and
XGBoost on the identical corrected matrix:

```
RANDOM FOREST (7-class V2):  accuracy=0.9964  MCC=0.9958
XGBOOST     (7-class V2):    accuracy=0.9988  MCC=0.9986
```

Both V2 learners are registered and active; `AI_IDS_MACRO_FLOW_MODEL_ID` selects the
runtime learner (`7` = Macro RF V2, `8` = Macro XGB V2 — recommended). V2 models cover
**7 classes** — BENIGN, DDoS, PortScan, SYN Flood, DoS Hulk, DoS Slowhttptest,
SSH-Patator — so every one of the five Kali attacks (nmap, hping3, hulk, slowhttptest,
hydra) receives its own label. The legacy V1 models (id 5/6, 4 classes) remain
registered as fallbacks.

---

## 2. Prerequisites on Debian (the IDS host)

The Debian copy MUST contain these files (from the **current** project, `‏‏AI_IDS_3`):

```
capture/macro_flow_assembler.py          # macro engine (was MISSING in older copies)
models/macro_rf_v1.joblib                # macro model RF V1 (legacy, 4 classes)
models/macro_rf_v1.joblib.meta.json      # macro model metadata
models/macro_xgb_v1.joblib               # macro model XGBoost V1 (legacy, 4 classes)
models/macro_xgb_v1.joblib.meta.json     # macro XGBoost V1 metadata
models/macro_rf_v2.joblib                # macro model RF V2 (7 classes)
models/macro_rf_v2.joblib.meta.json      # macro RF V2 metadata
models/macro_xgb_v2.joblib               # macro model XGB V2 (7 classes, recommended)
models/macro_xgb_v2.joblib.meta.json     # macro XGB V2 metadata
models/macro_models_evaluation.json      # RF vs XGB evaluation record
scripts/setup_deployment.py              # one-shot provisioning
```

If any of these are missing, **copy the whole current `‏‏AI_IDS_3` folder to Debian** —
do not reuse an old zip.

---

## 3. One-shot provisioning on Debian (run once, as root)

```bash
cd /path/to/AI_IDS_3
python scripts/setup_deployment.py            # registers models + enables macro
python scripts/setup_deployment.py data/captured_flows_master.csv   # optional smoke test
```

What it does:
1. Registers all six artifacts: `Random Forest V3`, `XGBoost Pipeline V2`, `Macro RF V1`,
   `Macro XGB V1`, `Macro RF V2` and `Macro XGB V2`.
2. Activates the recommended macro model (`Macro XGB V2`, id=8).
3. Sets `AI_IDS_MACRO_FLOW_ENABLED=true` in `.env`.
4. (With a CSV arg) verifies the pipeline — prints `PASS — attacks detected`.

**Then restart the app and the live capture** so the new settings load:
```bash
pkill -f "streamlit run app.py"; pkill -f "cli.py"
streamlit run app.py &          # UI
python cli.py live-capture -m 8 -i ens33   # or via the UI Live Capture page, model 8
```

---

## 4. Launch attacks from Kali

```bash
sudo bash kali_attack_test.sh 192.168.145.129
```
Or run attacks individually, **~30s apart** (the IDS flushes every ~15s):

| # | Attack (Kali)                     | Expected detection        |
|---|-----------------------------------|---------------------------|
| 1 | `nmap -sS -T4 192.168.145.129`    | `PortScan` / `DDoS`       |
| 2 | `hping3 -S --flood -p 8080 -c 60000 192.168.145.129` | `SYN Flood` / `DDoS` |
| 3 | `python3 hulk.py http://192.168.145.129:8080/`        | `DoS Hulk` (per-flow)     |
| 4 | `slowhttptest -c 200 -B -u http://192.168.145.129:8080/` | `DoS Slowhttptest` |
| 5 | `hydra -l root -P rockyou.txt 192.168.145.129 ssh`    | `SSH-Patator` / `Brute Force` |

---

## 5. Where to see results

1. **Cleaned CSV** (has prediction columns — the master CSV does NOT):
   ```bash
   python3 -c "import pandas as pd; d=pd.read_csv('data/cleaned_flows_master.csv'); print(d.groupby('attack_type').size())"
   ```
2. **UI → Live Flows / Alerts** pages (alerts also fire Telegram).
3. **Logs**: `logs/ai_ids.log` → lines `Malicious footprint detected! Class: ...` and
   `Macro-flow assembly active: N raw rows -> M macro-flow units (macro model id=8).`
---

## 6. Troubleshooting

- **No `Macro-flow assembly active` log line** → macro disabled or old copy. Run step 3.
- **`model 8 not registered`** → the DB predates the V2 models. Run step 3 (it registers them).
- **To switch the macro learner** → set `AI_IDS_MACRO_FLOW_MODEL_ID=7` in `.env` (RF V2)
  or keep `8` (XGB V2); both V2 learners were trained on true aggregate vectors.
- **All flows BENIGN even with macro** → confirm you attacked long enough for a full
  flush window (≥15s) and that the target HTTP server is up for HTTP attacks.
- **`Firewall block_ip requires administrator`** → expected on Debian unless the IDS runs
  as root with iptables available; alerts still fire regardless.
