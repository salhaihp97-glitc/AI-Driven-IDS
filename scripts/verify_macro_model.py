import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from ml.model_loader import ModelLoader
from ml.feature_mapper import FeatureMapper
from capture.extractor_factory import get_flow_extractor
from capture.macro_flow_assembler import MacroFlowAssembler

CANON = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["feature_names"]
CLASSES = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["classes"]
mapper = FeatureMapper()
adapter = ModelLoader().load("models/macro_rf_v1.joblib", "random_forest")
asmb = MacroFlowAssembler(enabled=True, min_members=2)

for pcap, tag in [(r"C:\Users\salh\AppData\Local\Temp\opencode\benign_tcp.pcap", "BENIGN TCP"),
                  (r"C:\Users\salh\AppData\Local\Temp\opencode\synflood_rotate.pcap", "SYN FLOOD")]:
    flows = get_flow_extractor().extract_from_pcap(pcap)
    print(f"== {tag}: {len(flows)} flows -> {len(asmb.assemble(flows))} macros")
    for m in asmb.assemble(flows):
        vec, missing = mapper.map_with_report(m.features, adapter.required_features)
        pred = adapter.predict(vec)
        conf = adapter.predict_confidence(vec)
        print(f"   macro {m.dst_ip}:{m.dst_port} -> class={pred} ({CLASSES[pred]}) conf={conf:.3f} missing={len(missing)}")