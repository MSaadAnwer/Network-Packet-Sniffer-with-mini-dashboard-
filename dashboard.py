import threading
import time
from collections import Counter, deque
from datetime import datetime

import pandas as pd
import streamlit as st
from scapy.all import sniff, IP, TCP, UDP, DNS
from streamlit_autorefresh import st_autorefresh

# ─────────── Persistent session state ───────────
if "COUNTS" not in st.session_state:
    st.session_state.COUNTS = {
        "proto": Counter(),
        "src": Counter(),
        "dst": Counter(),
        "ports": Counter(),
        "dns": Counter(),
        "total": 0,
        "recent": deque(maxlen=2000),
        "timeline": deque(maxlen=120),  # last 2 minutes of packets/sec
    }

if "STOP_EVENT" not in st.session_state:
    st.session_state.STOP_EVENT = threading.Event()

if "LOCK" not in st.session_state:
    st.session_state.LOCK = threading.Lock()

if "RUNNING" not in st.session_state:
    st.session_state.RUNNING = False

COUNTS = st.session_state.COUNTS
STOP_EVENT = st.session_state.STOP_EVENT
LOCK = st.session_state.LOCK

# ─────────── Streamlit Layout ───────────
st.set_page_config(page_title="Packet Sniffer Dashboard", layout="wide")

st.sidebar.header("Capture settings")
iface = st.sidebar.text_input(
    "Interface (e.g., Wi-Fi, Ethernet, NPF path)",
    value=r"\Device\NPF_{D5F07FBA-9559-4605-9CC3-01B848866313}",
)
bpf = st.sidebar.text_input("BPF filter (optional, e.g., udp port 53)", value="")

colA, colB = st.sidebar.columns(2)

# ─────────── Packet Handler ───────────
def handle(pkt):
    with LOCK:
        COUNTS["total"] += 1
        COUNTS["recent"].append(time.time())

        # Update packets per second for timeline
        now = int(time.time())
        COUNTS["timeline"].append(now)

        if IP in pkt:
            COUNTS["src"][pkt[IP].src] += 1
            COUNTS["dst"][pkt[IP].dst] += 1

        if TCP in pkt:
            COUNTS["proto"]["TCP"] += 1
            COUNTS["ports"][f"tcp/{pkt[TCP].dport}"] += 1
        elif UDP in pkt:
            COUNTS["proto"]["UDP"] += 1
            if DNS in pkt and pkt[DNS].qd:
                COUNTS["proto"]["DNS"] += 1
                try:
                    q = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    if q:
                        COUNTS["dns"][q] += 1
                except Exception:
                    pass
            else:
                COUNTS["ports"][f"udp/{pkt[UDP].dport}"] += 1
        else:
            COUNTS["proto"]["OTHER"] += 1


# ─────────── Capture Loop ───────────
def capture_loop(iface, bpf):
    print(f"[DEBUG] capture_loop started on {iface!r}")
    while not STOP_EVENT.is_set():
        try:
            sniff(
                prn=handle,
                iface=iface,
                store=False,
                count=0,
                timeout=3,
                promisc=True,
                filter=bpf if bpf else None,
            )
        except Exception as e:
            print(f"[DEBUG] sniff error: {e}")
            time.sleep(1)


# ─────────── Start/Stop Buttons ───────────
if colA.button("Start", use_container_width=True):
    if not st.session_state.RUNNING:
        STOP_EVENT.clear()
        t = threading.Thread(target=capture_loop, args=(iface, bpf), daemon=True)
        t.start()
        st.session_state.RUNNING = True
        print("[DEBUG] Capture started")

if colB.button("Stop", use_container_width=True):
    if st.session_state.RUNNING:
        STOP_EVENT.set()
        st.session_state.RUNNING = False
        print("[DEBUG] Capture stopped")

st.sidebar.caption("Run Streamlit as **Administrator** so Scapy can capture packets.")
st.sidebar.markdown("_Auto-refreshing every 3 seconds..._")

# ─────────── Auto-refresh ───────────
st_autorefresh(interval=3000, key="refresh")

# ─────────── Data snapshot for UI ───────────
with LOCK:
    total = COUNTS["total"]
    pps = len(COUNTS["recent"])
    proto_items = list(COUNTS["proto"].items())
    ports_tbl = COUNTS["ports"].most_common(10)
    src_tbl = COUNTS["src"].most_common(10)
    dst_tbl = COUNTS["dst"].most_common(10)
    dns_tbl = COUNTS["dns"].most_common(10)

# ─────────── Layout ───────────
st.write(f"Last update: {datetime.now().strftime('%H:%M:%S')}")
k1, k2, k3 = st.columns(3)
k1.metric("Total packets (session)", f"{total:,}")
k2.metric("Recent packets (buffer)", f"{pps}")
k3.metric(
    "Top protocol",
    (max(COUNTS["proto"], key=COUNTS["proto"].get) if COUNTS["proto"] else "-"),
)

# ─────────── Timeline chart ───────────
if COUNTS["timeline"]:
    timeline_df = pd.Series(COUNTS["timeline"]).value_counts().sort_index()
    st.line_chart(
        pd.DataFrame(
            {"Packets/sec": timeline_df.values},
            index=pd.to_datetime(timeline_df.index, unit="s"),
        )
    )
else:
    st.caption("_No timeline data yet..._")

# ─────────── Main Dashboard ───────────
left, right = st.columns([2, 3])

with left:
    st.subheader("Packets by protocol")
    st.bar_chart(dict(proto_items) if proto_items else {"waiting": 0})

    st.subheader("Top ports (dest)")
    st.table({"port": [p for p, _ in ports_tbl], "count": [n for _, n in ports_tbl]})

with right:
    st.subheader("Top talkers (src)")
    st.table({"ip": [ip for ip, _ in src_tbl], "count": [n for _, n in src_tbl]})

    st.subheader("Top destinations (dst)")
    st.table({"ip": [ip for ip, _ in dst_tbl], "count": [n for _, n in dst_tbl]})

    st.subheader("Top DNS queries")
    st.table({"domain": [d for d, _ in dns_tbl], "count": [n for _, n in dns_tbl]})

# ─────────── Export section ───────────
st.markdown("### 💾 Export Data")
if st.button("Save to CSV"):
    df_export = pd.DataFrame({
        "Protocol": list(COUNTS["proto"].keys()),
        "Count": list(COUNTS["proto"].values()),
    })
    filename = f"packet_summary_{datetime.now().strftime('%H%M%S')}.csv"
    df_export.to_csv(filename, index=False)
    st.success(f"Saved packet summary → `{filename}`")

st.caption("Status: **RUNNING**" if st.session_state.RUNNING else "Status: **STOPPED**")
