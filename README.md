# Network Packet Sniffer Dashboard

This project is a Python-based network packet sniffer that visualizes live network traffic using Scapy and Streamlit.  
It captures packets from a specified network interface, analyzes protocol distributions, and provides real-time dashboards and CSV export capabilities.  
The application serves as a simplified, educational equivalent to Wireshark for traffic monitoring and cybersecurity demonstrations.

---

## Features

- Real-time packet capture from Wi-Fi or Ethernet interfaces  
- Interactive dashboard with charts and metrics  
- Protocol breakdown (TCP, UDP, DNS)  
- Live packets-per-second timeline  
- Berkeley Packet Filter (BPF) syntax support (e.g., `udp port 53`)  
- Export of session summaries to CSV  
- Cross-platform support (Windows with Npcap, Linux/macOS with libpcap)

---

## Techniques and Tools

| Category | Details |
|-----------|----------|
| Language | Python 3.11+ |
| Libraries | scapy, streamlit, pandas, streamlit-autorefresh |
| Key Concepts | Packet sniffing, protocol analysis, data visualization, multithreading, network monitoring |
| Visualization | Streamlit web interface with auto-refreshing dashboards |
| Focus Area | Cybersecurity and network traffic analysis |

---

## Project Overview

This application captures live packets using Scapy, extracts key metadata (IP addresses, ports, protocols, DNS queries), and displays processed statistics in real time using Streamlit.  
The data is safely maintained across refreshes with `st.session_state`, allowing continuous updates to metrics and charts.

Metrics include:
- Protocol distribution  
- Top source and destination IPs  
- Top destination ports  
- DNS queries  
- Packets per second (timeline graph)

---

## Setup and Usage

### Prerequisites

**Windows users:**  
Install [Npcap](https://nmap.org/npcap/) and enable the option:  
“Install Npcap in WinPcap API-compatible mode.”

**Linux/macOS users:**  
Scapy uses `libpcap` by default, no additional installation is required.

---
<img width="890" height="709" alt="image" src="https://github.com/user-attachments/assets/a10c164e-8b4f-4715-8582-00f3223b4308" />

### 1. Create a Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate       # Windows
# or
source venv/bin/activate    # macOS/Linux
```

---

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

If you do not yet have a `requirements.txt`, install manually:

```bash
pip install scapy streamlit pandas streamlit-autorefresh
```

---

### 3. Run the Dashboard

```bash
streamlit run dashboard.py
```

Run the terminal as **Administrator** (on Windows) to allow packet capture.

---

### 4. Generate Traffic to Observe

Open another terminal and run commands such as:

```bash
ping 8.8.8.8
curl http://example.com
```

The dashboard will automatically refresh every few seconds and visualize the live traffic.

---

## File Descriptions

| File | Description |
|------|--------------|
| `dashboard.py` | Main Streamlit dashboard; handles packet capture, statistics, visualization, and CSV export. |
| `sniff_test.py` | Minimal Scapy test script to verify packet capture functionality. |
| `sniffer.py` | Basic command-line sniffer for debugging or demonstration. |
| `list_ifaces.py` | Lists all available network interfaces for Scapy. |
| `list_ifaces_pretty.py` | Lists interfaces with additional metadata such as IP and device description. |
| `show_ifaces.py` | Displays available interfaces in a simplified format. |
| `scapy_ifcheck.py` | Checks which interfaces Scapy can access. |
| `EnhancedSnifferBoard.png`, `PacketSniffing.png`, `SnifferBoard.png` | Screenshot assets for documentation and presentation. |
| `venv/` | Local Python virtual environment (do not include in Git commits). |

---

## Example Use Cases

- Monitor local network traffic on a specific port (e.g., `tcp port 443`)  
- Observe DNS queries in real time  
- Learn about packet-level network analysis  
- Demonstrate cybersecurity and networking fundamentals in a portfolio setting

---

## Example Output

**Metrics:**

```
Total packets (session): 245
Recent packets (buffer): 17
Top protocol: TCP
```

**Dashboard visualizations:**
- Protocol distribution (bar chart)
- Top source and destination IPs (tables)
- Top destination ports
- DNS queries
- Packets-per-second timeline chart

**CSV Export:**
```
packet_summary_210530.csv
```

---

## Future Improvements

- Add live packet log table with source/destination and timestamp  
- Add protocol-based color tagging for readability  
- Add filtering and search capabilities from within the dashboard  

---

## Learning Outcomes

- Understanding of network packet structures  
- Practical application of Scapy for traffic monitoring  
- Building a real-time data visualization pipeline  
- Combining Python-based packet capture with web-based analytics tools  

---

## Author

**Muhammad Saad Anwer**  
University of Connecticut – Master of Science in Computer Science
Focus areas: Cybersecurity
