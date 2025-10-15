from scapy.all import sniff

IFACE = r"\Device\NPF_{D5F07FBA-9559-4605-9CC3-01B848866313}"
print("Sniffing 10 packets on:", IFACE)
pkts = sniff(iface=IFACE, count=10, timeout=10)
print("Captured:", len(pkts))
for p in pkts[:3]:
    print(p.summary())
