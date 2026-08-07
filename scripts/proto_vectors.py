import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from capture.extractor_factory import get_flow_extractor
from capture.macro_flow_assembler import MacroFlowAssembler
from ml.feature_mapper import FeatureMapper

CANON = json.load(open("models/random_forest_v3.joblib.meta.json", encoding="utf-8"))["feature_names"]
mapper = FeatureMapper()


def macro_vectors(pcap):
    flows = get_flow_extractor().extract_from_pcap(pcap)
    asmb = MacroFlowAssembler(enabled=True, min_members=2)
    macs = asmb.assemble(flows)
    out = []
    for m in macs:
        vec, missing = mapper.map_with_report(m.features, CANON)
        out.append((m, vec, missing))
    return flows, asmb, out


def rep(vec):
    i = {n: vec[CANON.index(n)] for n in
         ("SYN Flag Count", "ACK Flag Count", "RST Flag Count", "Total Fwd Packets",
          "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
          "Flow Duration", "Flow Bytes/s")}
    return "  ".join(f"{k}={v:.0f}" for k, v in i.items())


print("== SYN FLOOD ==")
flows, asmb, out = macro_vectors(r"C:\Users\salh\AppData\Local\Temp\opencode\synflood_rotate.pcap")
print("member flows:", len(flows))
for m, vec, miss in out:
    print("macro", m.dst_ip, ":" + str(m.dst_port), "missing", len(miss))
    print("   ", rep(vec))

print("\n== BENIGN (test.pcapng) ==")
flows2, asmb2, out2 = macro_vectors(r"C:\Users\salh\Desktop\from_ahmad\__AI_IDS_3 (2)\??AI_IDS_3\test.pcapng".replace("??", "\u0391"))
print("member flows:", len(flows2))
for m, vec, miss in out2:
    print("macro", m.dst_ip, ":" + str(m.dst_port), "missing", len(miss))
    print("   ", rep(vec))