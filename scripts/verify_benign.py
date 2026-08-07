import sys
import json
import random
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

import pandas as pd
import numpy as np

from ml.model_loader import ModelLoader
from ml.feature_mapper import FeatureMapper
from capture.flow_models import FlowFeatures
from capture.macro_flow_assembler import MacroFlowAssembler

CANON = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["feature_names"]
mapper = FeatureMapper()
loader = ModelLoader()
adapter = loader.load("models/macro_rf_v1.joblib", "random_forest")
classes = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["classes"]
asmb = MacroFlowAssembler(enabled=True, min_members=2)
random.seed(1)

# captured_flows_master.csv is headerless raw rows: 5 identity cols + 74 features? 
# Use column indexing: read raw, assume first 5 are ip/ip/sp/dp/proto and rest features.
df = pd.read_csv("data/captured_flows_master.csv", header=None)
print("shape", df.shape, "ncols", df.shape[1])

# Determine feature count: extractor produced 78 keys including src_port/dst_port.
# Row columns: src_ip, dst_ip, src_port, dst_port, protocol, timestamp?, then features...
# From header sample: 192.168.126.128,94.198.159.11,54998,123,17,2026-08-06 18:31:05,0.407...,...
# So col0=src_ip,1=dst_ip,2=src_port,3=dst_port,4=proto,5=timestamp,6..=features
feat_cols = list(range(6, df.shape[1]))

def to_flows(df):
    out = []
    for _, r in df.iterrows():
        feats = {}
        for c in feat_cols:
            v = pd.to_numeric(r[c], errors="coerce")
            if pd.isna(v):
                continue
            feats[str(c)] = float(v)
        ff = FlowFeatures(src_ip=str(r[0]), dst_ip=str(r[1]),
                          src_port=int(float(r[2])), dst_port=int(float(r[3])),
                          protocol=int(float(r[4])), features=feats)
        out.append(ff)
    return out

flows = to_flows(df)
print("benign member flows:", len(flows))
macs = asmb.assemble(flows)
for m in macs:
    vec, missing = mapper.map_with_report(m.features, adapter.required_features)
    pred = adapter.predict(vec)
    conf = adapter.predict_confidence(vec)
    print(f"benign macro {m.dst_ip}:{m.dst_port} -> class={pred} ({classes[pred]}) conf={conf:.3f} missing={len(missing)}")
    if pred != 0:
        # show top contributing features
        vals = {name: vec[i] for i, name in enumerate(adapter.required_features)}
        top = sorted(vals.items(), key=lambda kv: abs(kv[1]), reverse=True)[:8]
        print("   top:", ", ".join(f"{k}={v:.0f}" for k, v in top))