"""
Build a multi-class macro-flow training dataset and train the model.

Pure-ML alignment: a rotating-source-port SYN flood only exists *across* flows, so no
per-flow model can see it. This script trains a model on MACRO-AGGREGATE feature vectors
so the ML model itself becomes the sole authority for analysis/detection/classification.

Training vectors are produced by feeding real per-flow rows (from the CIC-IDS2017 CSVs and
the captured SYN-flood pcap) through the SAME reduction stack used at runtime
(MacroFlowAssembler reducers + FeatureMapper), so training and inference share one
feature distribution. No signature rules are encoded -- the boundary is learned.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

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
SEED = 42
random.seed(SEED)
np.random.seed(SEED)


_reader = FeatureMapper()
_assembler = MacroFlowAssembler(enabled=True, min_members=2)


def load_csv(filename: str, keep_labels: list[str], max_rows: int = 20000) -> list[dict[str, float]]:
    """Load per-flow rows (canonical feature names) for the given class labels."""
    df = pd.read_csv(DATA / filename, skipinitialspace=True)
    df = df[df["Label"].isin(keep_labels)].head(max_rows)
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


def extract_syn_flood_flows() -> list[dict[str, float]]:
    """Extract the real SYN-flood member flows (snake_case) and map to canonical names."""
    from capture.extractor_factory import get_flow_extractor
    flows = get_flow_extractor().extract_from_pcap(SYNFLOOD_PCAP)
    out: list[dict[str, float]] = []
    for f in flows:
        vec, _ = _reader.map_with_report(f.features, CANON)
        out.append(dict(zip(CANON, vec)))
    return out


def extract_benign_handshake_flows() -> list[dict[str, float]]:
    """Extract real completed-handshake benign flows so tiny benign traffic is learned."""
    from capture.extractor_factory import get_flow_extractor
    flows = get_flow_extractor().extract_from_pcap(BENIGN_PCAP)
    out: list[dict[str, float]] = []
    for f in flows:
        vec, _ = _reader.map_with_report(f.features, CANON)
        out.append(dict(zip(CANON, vec)))
    return out


def macro_vector(member_rows: list[dict[str, float]]) -> np.ndarray | None:
    """Aggregate member flows into one macro vector via the runtime reducer stack.

    Member rows already carry canonical CIC feature names, so the assembler reduces on
    those exact keys and the resulting macro ``features`` dict is directly indexable by
    the canonical schema -- no FeatureMapper round-trip needed.
    """
    members: list[FlowFeatures] = []
    dst = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_port = random.choice([80, 443, 8080, 22, 123, 53])
    for feats in member_rows:
        ff = FlowFeatures(
            src_ip=f"1.2.3.{random.randint(1, 254)}",
            dst_ip=dst,
            src_port=random.randint(1024, 65535),
            dst_port=dst_port,
            protocol=6,
            features={k: v for k, v in feats.items()},
        )
        members.append(ff)
    macros = _assembler.assemble(members)
    if not macros:
        return None
    fmap = macros[0].features
    vec = np.array([fmap.get(k, 0.0) for k in CANON], dtype=float)
    return np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)

def sample_window(pool: list[dict[str, float]], max_m: int) -> list[dict[str, float]]:
    """Draw a member-window whose size mirrors the runtime mix.

    Runtime reality: most benign traffic arrives as lone flows (each client is its own
    assembler group), while attacks may aggregate. Weight window sizes toward the small
    end so single-flow and small-window signatures are well represented for every class.
    """
    r = random.random()
    if r < 0.40:
        n = 1
    elif r < 0.70:
        n = random.randint(2, 5)
    elif r < 0.90:
        n = random.randint(6, 30)
    else:
        n = random.randint(31, max_m)
    return [dict(x) for x in random.sample(pool, min(n, len(pool)))]


def main(n_per_class: int = 1200) -> None:
    print("Loading CIC benign / DDoS / PortScan pools ...")
    benign_pool = load_csv("Monday-WorkingHours.pcap_ISCX.csv", ["BENIGN"])
    ddos_pool = load_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", ["DDoS"])
    ps_pool = load_csv("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", ["PortScan"])
    print(f"  benign={len(benign_pool)} ddos={len(ddos_pool)} portscan={len(ps_pool)}")

    print("Extracting real SYN-flood member flows ...")
    syn_pool = extract_syn_flood_flows()
    print(f"  real SYN member flows: {len(syn_pool)}")

    print("Extracting real benign handshake flows ...")
    handshake_pool = extract_benign_handshake_flows()
    print(f"  real benign member flows: {len(handshake_pool)}")
    benign_pool = benign_pool + handshake_pool

    pools = [
        (benign_pool, "BENIGN", 60),
        (ddos_pool, "DDoS", 60),
        (ps_pool, "PortScan", 60),
        (syn_pool, "SYN Flood", 120),
    ]

    rows: list[np.ndarray] = []
    labels: list[str] = []
    for pool, cls, max_m in pools:
        made = 0
        while made < n_per_class:
            sample = sample_window(pool, max_m)
            vec = macro_vector(sample)
            if vec is None:
                continue
            rows.append(vec)
            labels.append(cls)
            made += 1
            if made % 200 == 0:
                print(f"  [{cls}] {made}/{n_per_class}", flush=True)

    X = np.array(rows)
    y = np.array(labels)
    print(f"Macro training matrix: {X.shape}")
    for c in sorted(set(labels)):
        print(f"  {c}: {labels.count(c)}")

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y_enc, test_size=0.2, random_state=SEED, stratify=y_enc)

    # The runtime loader applies the global ``models/scaler.joblib`` sidecar to every
    # model artifact, so this model must be trained on that exact scaled space to keep
    # inference aligned (see ``ModelLoader._load_sidecar_scaler``).
    global_scaler_path = ROOT / "models" / "scaler.joblib"
    sc = joblib.load(global_scaler_path)
    X_tr_s = sc.transform(X_tr)
    X_te_s = sc.transform(X_te)

    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=SEED, n_jobs=-1)
    rf.fit(X_tr_s, y_tr)
    pred = rf.predict(X_te_s)
    print("\nClassification Report:")
    print(classification_report(y_te, pred, target_names=[str(c) for c in le.classes_], zero_division=0))

    out_dir = ROOT / "models"
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, out_dir / "macro_rf_v1.joblib", compress=3)
    meta = {
        "feature_names": CANON,
        "classes": [str(c) for c in le.classes_],
        "model_type": "random_forest",
        "version": "1.0.0",
    }
    (out_dir / "macro_rf_v1.joblib.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print("Saved macro model to", out_dir / "macro_rf_v1.joblib")


if __name__ == "__main__":
    main()