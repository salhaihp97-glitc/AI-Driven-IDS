import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")
from capture.extractor_factory import get_flow_extractor
from ml.feature_mapper import FeatureMapper
from ml.model_loader import ModelLoader

CANON = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["feature_names"]
CLASSES = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["classes"]
mapper = FeatureMapper()
adapter = ModelLoader().load("models/macro_rf_v1.joblib", "random_forest")

import numpy as np
# check raw estimator feature count & classes
est = adapter._estimator
print("n_classes:", est.n_classes_, "classes:", CLASSES)
print("feature count:", est.n_features_in_)

for tag, pcap in [("BENIGN", r"C:\Users\salh\AppData\Local\Temp\opencode\benign_tcp.pcap"),
                  ("SYNFLOOD", r"C:\Users\salh\AppData\Local\Temp\opencode\synflood_rotate.pcap")]:
    flows = get_flow_extractor().extract_from_pcap(pcap)
    print(f"\n== {tag}: first 5 per-flow predictions ==")
    for f in flows[:5]:
        vec, _ = mapper.map_with_report(f.features, adapter.required_features)
        print("  pred", adapter.predict(vec), CLASSES[adapter.predict(vec)], "conf %.3f" % adapter.predict_confidence(vec))

# probe: what do extreme zero and scaled vectors look like
zero = np.zeros((1, len(CANON)))
print("\nzeros ->", adapter.predict(zero), CLASSES[adapter.predict(zero)])