import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from services.container import get_container

c = get_container()
svc = c.pcap_analysis_service
for pcap, tag in [(r"C:\Users\salh\AppData\Local\Temp\opencode\benign_tcp.pcap", "BENIGN TCP"),
                  (r"C:\Users\salh\AppData\Local\Temp\opencode\synflood_rotate.pcap", "SYN FLOOD")]:
    summary = svc.analyze(model_id=5, pcap_path=pcap)
    print(f"== {tag}")
    print(f"   total_units={summary.total_flows} attacks={summary.attack_count} normal={summary.normal_count}")
    for r in summary.results[:6]:
        print(f"     pred={r.prediction} ({r.attack_type}) conf={r.confidence:.3f} reason={r.attack_reason[:90]}")
    print()