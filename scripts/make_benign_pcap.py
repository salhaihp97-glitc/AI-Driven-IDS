import sys, random
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")
from scapy.all import Ether, IP, TCP, wrpcap

random.seed(7)
pkts = []
# 300 completed TCP handshakes to a single server:80 with varied payloads
for i in range(300):
    sport = random.randint(1024, 65535)
    src = f"10.1.{random.randint(0,255)}.{random.randint(1,254)}"
    ack = random.randint(1000, 50000)
    pkts.append(Ether()/IP(src=src, dst="10.9.9.9")/TCP(sport=sport, dport=80, flags="S", seq=ack))
    pkts.append(Ether()/IP(src="10.9.9.9", dst=src)/TCP(sport=80, dport=sport, flags="SA", seq=ack+1, ack=ack+1))
    pkts.append(Ether()/IP(src=src, dst="10.9.9.9")/TCP(sport=sport, dport=80, flags="A", seq=ack+2, ack=ack+2))
    pkts.append(Ether()/IP(src=src, dst="10.9.9.9")/TCP(sport=sport, dport=80, flags="PA", seq=ack+3, ack=ack+2)/bytes(64))
    pkts.append(Ether()/IP(src="10.9.9.9", dst=src)/TCP(sport=80, dport=sport, flags="PA", seq=ack+2, ack=ack+3)/bytes(128))
    pkts.append(Ether()/IP(src=src, dst="10.9.9.9")/TCP(sport=sport, dport=80, flags="FA", seq=ack+3, ack=ack+3))
    pkts.append(Ether()/IP(src="10.9.9.9", dst=src)/TCP(sport=80, dport=sport, flags="FA", seq=ack+3, ack=ack+4))
    pkts.append(Ether()/IP(src=src, dst="10.9.9.9")/TCP(sport=sport, dport=80, flags="A", seq=ack+4, ack=ack+4))
wrpcap(r"C:\Users\salh\AppData\Local\Temp\opencode\benign_tcp.pcap", pkts)
print("wrote benign pcap", len(pkts), "packets")
