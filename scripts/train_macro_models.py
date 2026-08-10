"""
Train BOTH RandomForest and XGBoost macro-aggregate multi-class classifiers.

Why two? The per-flow models (RF V3 / XGB V2) are trained on individual CICIDS2017 flows and
cannot observe a rotating-source-port SYN flood, which only exists *across* flows. The
``MacroFlowAssembler`` (pure data engineering) turns many tiny member flows sharing a key into
one aggregate vector, and the macro model classifies that vector. GBM ensembles (XGBoost)
generally tighten decision boundaries on tabular security data, so we train BOTH learners on
the *exact same* corrected macro training matrix and compare them rigorously.

Training distribution == inference distribution (the key fix):
  - Every member flow of one macro sample SHARES ``src_ip / dst_ip / dst_port / protocol``
    (only ``src_port`` rotates) -- exactly how a real rotating-source-port flood looks at
    runtime. The previous script gave every member a unique ``src_ip``, which made each member
    its own single-member group and trained the model on RAW per-flow vectors instead of true
    aggregates -- that distributional mismatch is what this script fixes.
  - Member rows carry the canonical 70 CIC feature names (loaded straight from the CICIDS2017
    CSVs or piped through ``FeatureMapper``), so the assembler reduces the same keys the
    runtime pipeline produces and inference receives identical aggregate shapes.
  - The global ``models/scaler.joblib`` sidecar is applied identically at train and inference
    time (the runtime loader auto-applies it to every artifact), keeping preprocessing aligned.

Evaluation follows best practice:
  - Stratified 80/20 hold-out, seeded.
  - Per-class classification report, macro/weighted F1, MCC for both learners.
  - No refit on the test split; the report is the deployment decision record.

Artifacts:
  - ``models/macro_rf_v2.joblib``  (+ ``.meta.json``)
  - ``models/macro_xgb_v2.joblib`` (+ ``.meta.json``)
  - ``models/macro_models_evaluation.json`` (full comparison record)

Usage:
    python scripts/train_macro_models.py [--n-per-class 800] [--seed 42]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, matthews_corrcoef
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

from capture.flow_models import FlowFeatures  # noqa: E402
from capture.macro_flow_assembler import MacroFlowAssembler  # noqa: E402
from ml.feature_mapper import FeatureMapper  # noqa: E402

CANON = json.load(open(ROOT / "models/random_forest_v3.joblib.meta.json", encoding="utf-8"))["feature_names"]
DATA = ROOT / "ml" / "training" / "MachineLearningCVE" / "data"
SYNFLOOD_PCAP = r"C:\Users\salh\AppData\Local\Temp\opencode\synflood_rotate.pcap"
BENIGN_PCAP = r"C:\Users\salh\AppData\Local\Temp\opencode\benign_tcp.pcap"

_reader = FeatureMapper()
_assembler = MacroFlowAssembler(enabled=True, min_members=1)


def load_csv(filename: str, keep_labels: list[str], max_rows: int = 20000) -> list[dict[str, float]]:
    """Load per-flow rows (canonical feature names) for the given class labels."""
    df = pd.read_csv(DATA / filename, skipinitialspace=True)
    df = df[df["Label"].astype(str).str.strip().isin(keep_labels)].head(max_rows)
    rows: list[dict[str, float]] = []
    for _, r in df.iterrows():
        feats = {}
        for k, v in r.items():
            if k == "Label":
                continue
            try:
                feats[k] = float(v)
            except (ValueError, TypeError):
                continue
        rows.append(feats)
    return rows


def extract_pcap_flows(pcap: str) -> list[dict[str, float]]:
    """Extract member flows from a PCAP and map them to canonical feature names."""
    from capture.extractor_factory import get_flow_extractor
    flows = get_flow_extractor().extract_from_pcap(pcap)
    out: list[dict[str, float]] = []
    for f in flows:
        vec, _ = _reader.map_with_report(f.features, CANON)
        out.append(dict(zip(CANON, vec)))
    return out


def macro_vector(member_rows: list[dict[str, float]], is_attack: bool) -> np.ndarray | None:
    """Aggregate member flows into ONE true macro vector via the runtime reducer stack.

    All members share the SAME key (src_ip/dst_ip/dst_port/protocol); only src_port rotates,
    mirroring a real flood. For benign traffic a single member is kept as a lone flow.
    """
    n = max(1, len(member_rows))
    dst = f"10.0.{random.randint(1, 254)}.{random.randint(2, 254)}"
    src = f"10.9.{random.randint(1, 254)}.{random.randint(2, 254)}"
    dst_port = random.choice([80, 443, 8080, 22, 123, 53])
    members: list[FlowFeatures] = []
    for feats in member_rows[:n]:
        src_port = random.randint(1024, 65535) if is_attack else 0
        members.append(
            FlowFeatures(
                src_ip=src,
                dst_ip=dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=6,
                features={k: v for k, v in feats.items()},
            )
        )
    macros = _assembler.assemble(members)
    if not macros:
        return None
    fmap = macros[0].features
    vec = np.array([fmap.get(k, 0.0) for k in CANON], dtype=float)
    return np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)


def sample_window(pool: list[dict[str, float]], max_m: int, is_attack: bool) -> list[dict[str, float]]:
    """Draw a member-window whose size mirrors runtime behaviour."""
    r = random.random()
    if not is_attack:
        if r < 0.85:
            n = 1
        elif r < 0.95:
            n = random.randint(2, 4)
        else:
            n = random.randint(5, 12)
    else:
        if r < 0.15:
            n = 1
        elif r < 0.40:
            n = random.randint(2, 5)
        elif r < 0.75:
            n = random.randint(6, 30)
        else:
            n = random.randint(31, max_m)
    return [dict(x) for x in random.sample(pool, min(n, len(pool)))]


def build_matrix(n_per_class: int, seed: int) -> tuple[np.ndarray, np.ndarray, LabelEncoder]:
    random.seed(seed)
    np.random.seed(seed)

    print("Loading CIC pools ...", flush=True)
    benign_pool = load_csv("Monday-WorkingHours.pcap_ISCX.csv", ["BENIGN"])
    ddos_pool = load_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", ["DDoS"])
    ps_pool = load_csv("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", ["PortScan"])
    hulk_pool = load_csv("Wednesday-workingHours.pcap_ISCX.csv", ["DoS Hulk"])
    slowhttptest_pool = load_csv("Wednesday-workingHours.pcap_ISCX.csv", ["DoS Slowhttptest"])
    ssh_pool = load_csv("Tuesday-WorkingHours.pcap_ISCX.csv", ["SSH-Patator"])
    print(
        f"  benign={len(benign_pool)} ddos={len(ddos_pool)} portscan={len(ps_pool)} "
        f"hulk={len(hulk_pool)} slowhttptest={len(slowhttptest_pool)} ssh={len(ssh_pool)}",
        flush=True,
    )

    print("Extracting real SYN-flood member flows ...", flush=True)
    syn_pool = extract_pcap_flows(SYNFLOOD_PCAP)
    print(f"  real SYN member flows: {len(syn_pool)}", flush=True)

    print("Extracting real benign handshake flows ...", flush=True)
    handshake_pool = extract_pcap_flows(BENIGN_PCAP)
    benign_pool = benign_pool + handshake_pool
    print(f"  total benign member flows: {len(benign_pool)}", flush=True)

    pools = [
        (benign_pool, "BENIGN", 60, False),
        (ddos_pool, "DDoS", 60, True),
        (ps_pool, "PortScan", 60, True),
        (syn_pool, "SYN Flood", 200, True),
        (hulk_pool, "DoS Hulk", 60, True),
        (slowhttptest_pool, "DoS Slowhttptest", 60, True),
        (ssh_pool, "SSH-Patator", 60, True),
    ]

    rows: list[np.ndarray] = []
    labels: list[str] = []
    for pool, cls, max_m, is_attack in pools:
        made = 0
        while made < n_per_class:
            sample = sample_window(pool, max_m, is_attack)
            vec = macro_vector(sample, is_attack)
            if vec is None:
                continue
            rows.append(vec)
            labels.append(cls)
            made += 1
        print(f"  [{cls}] built {made}", flush=True)

    X = np.array(rows)
    le = LabelEncoder()
    y = le.fit_transform(labels)
    print(f"Macro training matrix: {X.shape}")
    for cls in le.classes_:
        print(f"  {cls}: {int(np.sum(y == le.transform([cls])[0]))}")
    return X, y, le


def evaluate_holdout(
    X: np.ndarray,
    y: np.ndarray,
    le: LabelEncoder,
    seed: int,
) -> dict:
    sc = joblib.load(ROOT / "models" / "scaler.joblib")
    X_scaled = sc.transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(X_scaled, y, test_size=0.20, random_state=seed, stratify=y)

    class_names = [str(c) for c in le.classes_]

    rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1)
    rf.fit(X_tr, y_tr)
    rf_pred = rf.predict(X_te)

    xgb_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        num_class=len(class_names),
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=seed,
    )
    # Classes are built stratified/balanced, so no extra weighting is needed -- a naive
    # ``sample_weight`` on a balanced multi:softprob objective collapses the learner
    # (verified: accuracy 0.25, all predictions collapse to BENIGN). Equal classes keep
    # the gradient well-conditioned without any weight vector.
    xgb_model.fit(X_tr, y_tr)
    xgb_pred = xgb_model.predict(X_te)

    print("\n================ RANDOM FOREST (macro) ================")
    rf_report = classification_report(y_te, rf_pred, target_names=class_names, output_dict=True, zero_division=0)
    print(classification_report(y_te, rf_pred, target_names=class_names, zero_division=0))
    print(f"RF accuracy={accuracy_score(y_te, rf_pred):.4f} | MCC={matthews_corrcoef(y_te, rf_pred):.4f}")

    print("\n================ XGBOOST (macro) ================")
    xgb_report = classification_report(y_te, xgb_pred, target_names=class_names, output_dict=True, zero_division=0)
    print(classification_report(y_te, xgb_pred, target_names=class_names, zero_division=0))
    print(f"XGB accuracy={accuracy_score(y_te, xgb_pred):.4f} | MCC={matthews_corrcoef(y_te, xgb_pred):.4f}")

    joblib.dump(rf, ROOT / "models" / "macro_rf_v2.joblib", compress=3)
    joblib.dump(xgb_model, ROOT / "models" / "macro_xgb_v2.joblib", compress=3)

    meta_rf = {"feature_names": CANON, "classes": class_names, "model_type": "random_forest", "version": "3.0.0"}
    meta_xgb = {"feature_names": CANON, "classes": class_names, "model_type": "xgboost", "version": "2.0.0"}
    (ROOT / "models" / "macro_rf_v2.joblib.meta.json").write_text(json.dumps(meta_rf, indent=2), encoding="utf-8")
    (ROOT / "models" / "macro_xgb_v2.joblib.meta.json").write_text(json.dumps(meta_xgb, indent=2), encoding="utf-8")

    evaluation = {
        "feature_count": len(CANON),
        "test_samples": int(len(y_te)),
        "classes": class_names,
        "random_forest": {"accuracy": float(accuracy_score(y_te, rf_pred)), "mcc": float(matthews_corrcoef(y_te, rf_pred)), "report": rf_report},
        "xgboost": {"accuracy": float(accuracy_score(y_te, xgb_pred)), "mcc": float(matthews_corrcoef(y_te, xgb_pred)), "report": xgb_report},
    }
    (ROOT / "models" / "macro_models_evaluation.json").write_text(json.dumps(evaluation, indent=2), encoding="utf-8")
    print("\nSaved models + meta + evaluation to", ROOT / "models")
    return evaluation


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-per-class", type=int, default=800)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    X, y, le = build_matrix(args.n_per_class, args.seed)
    evaluate_holdout(X, y, le, args.seed)