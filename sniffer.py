from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from collections import Counter, defaultdict
from datetime import datetime

proto_count = Counter()
src_count   = Counter()
dst_count   = Counter()
ports       = Counter()
dns_queries = Counter()

def handle(pkt):
    if IP in pkt:
        ip = pkt[IP]
        src_count[ip.src] += 1
        dst_count[ip.dst] += 1

    if TCP in pkt:
        proto_count["TCP"] += 1
        ports[f"tcp/{pkt[TCP].dport}"] += 1
    elif UDP in pkt:
        proto_count["UDP"] += 1
        if DNS in pkt:
            proto_count["DNS"] += 1
            q = pkt[DNS].qd.qname.decode(errors="ignore") if pkt[DNS].qd else ""
            if q: dns_queries[q.rstrip('.')] += 1
        else:
            ports[f"udp/{pkt[UDP].dport}"] += 1
    else:
        proto_count["OTHER"] += 1

def summary(interval=10):
    import time
    while True:
        time.sleep(interval)
        ts = datetime.now().strftime("%H:%M:%S")
        top_src = ", ".join([f"{ip}({c})" for ip,c in src_count.most_common(3)])
        top_dst = ", ".join([f"{ip}({c})" for ip,c in dst_count.most_common(3)])
        top_ports = ", ".join([f"{p}({c})" for p,c in ports.most_common(5)])
        top_dns = ", ".join([f"{d}({c})" for d,c in dns_queries.most_common(5)])
        print(f"[{ts}] proto={dict(proto_count)} | top_src={top_src} | top_dst={top_dst} | ports={top_ports} | dns={top_dns}")

if __name__ == "__main__":
    import threading
    t = threading.Thread(target=summary, daemon=True)
    t.start()
    sniff(prn=handle, store=False)
