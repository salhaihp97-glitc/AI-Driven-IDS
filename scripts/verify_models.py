import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")
import pandas as pd

from services.container import get_container

c = get_container()
svc = c.csv_analysis_service

src = Path(r"ml\training\MachineLearningCVE\data\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
df_full = pd.read_csv(src)
slice_csv = Path(r"C:\Users\salh\AppData\Local\Temp\opencode\portscan_band.csv")
df_full.iloc[100000:101200].to_csv(slice_csv, index=False)
lb = df_full.iloc[100000:101200][" Label"].value_counts()
print("band labels:", lb.to_dict())

for mid, name in [(3, "RF V3"), (4, "XGB V2")]:
    s = svc.analyze(model_id=mid, csv_path=str(slice_csv), source_type="test", skip_integration=True)
    from collections import Counter
    at = Counter(r.attack_type for r in s.results)
    benign = at.pop("BENIGN", 0)
    print(f"{name}: units={len(s.results)} attacks={sum(at.values())} benign={benign}")
    print("   labels:", dict(at.most_common(10)))
