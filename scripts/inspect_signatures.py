import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")
from capture.extractor_factory import get_flow_extractor
from ml.feature_mapper import FeatureMapper

CANON = json.load(open("models/macro_rf_v1.joblib.meta.json", encoding="utf-8"))["feature_names"]
mapper = FeatureMapper()

def sig(flows, n=4):
    for f in flows[:n]:
        vec, miss = mapper.map_with_report(f.features, CANON)
        d = dict(zip(CANON, vec))
        keys = ["SYN Flag Count","ACK Flag Count","RST Flag Count","FIN Flag Count","Total Fwd Packets",
                "Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets","Flow Duration"]
        print("  ", {k: round(float(d[k]),2) for k in keys})

print("=== BENIGN TCP flows (completed handshakes) ===")
sig(get_flow_extractor().extract_from_pcap(r"C:\Users\salh\AppData\Local\Temp\opencode\benign_tcp.pcap"))

print("=== SYN FLOOD member flows ===")
sig(get_flow_extractor().extract_from_pcap(r"C:\Users\salh\AppData\Local\Temp\opencode\synflood_rotate.pcap"))