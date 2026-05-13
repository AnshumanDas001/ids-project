# NetWatch IDS — Network Intrusion Detection System

A production-inspired Python/React network intrusion detection system that captures live packets, analyzes them in real-time, and alerts on suspicious activity like port scans, SYN floods, ICMP floods, and high-frequency IP traffic.

```
   __________ ___   __________________ 
   \\\  ____//\\\\__ \\\  ______\\\  ______\
    \\\ |    /| | \\\ \\\  |____ \\\  |____ 
     \\|  |  |_|  \\\ \\\  ___ \\  ___ \
      |   |   |   \\\ \\\  ___/  \\\  ___/
      |___|   |___ \\\ \\\     |   \\|
                   \\\|_____|    
```

## Features

✅ **Real-time Packet Capture** — Live network traffic analysis  
✅ **4 Attack Detectors** — Port scan, SYN flood, ICMP flood, high-frequency IP  
✅ **SQLite Logging** — Persistent alert and packet storage  
✅ **REST API** — Query alerts, packets, and statistics  
✅ **WebSocket Live Push** — Real-time dashboard updates  
✅ **React Dashboard** — Beautiful, interactive monitoring UI  
✅ **Demo Mode** — No root required; generates synthetic attacks  

---

## Architecture

```
Network Traffic
     ↓
┌─────────────────┐
│  Scapy Sniffer  │  (or Demo mode)
└────────┬────────┘
         ↓
┌─────────────────────┐
│  Packet Parser      │  Extract fields (IP, port, flags)
└────────┬────────────┘
         ↓
┌──────────────────────────────────────┐
│  Detection Engine (4 detectors)      │
│  ├─ PortScanDetector                 │
│  ├─ SynFloodDetector                 │
│  ├─ IcmpFloodDetector                │
│  └─ HighFrequencyIPDetector          │
└────────┬─────────────────────────────┘
         ↓
┌────────────────────────────┐
│  SQLite Database           │
│  ├─ packets table          │
│  ├─ alerts table           │
│  └─ stats table            │
└────────┬───────────────────┘
         ↓
┌──────────────────────────────────────┐
│  Flask REST API + SocketIO           │
│  ├─ /api/alerts                      │
│  ├─ /api/packets                     │
│  ├─ /api/stats                       │
│  └─ WebSocket (live alerts)          │
└────────┬─────────────────────────────┘
         ↓
    React Dashboard
    (Recharts, real-time tables)
```

---

## Quick Start

### 1. Install Dependencies

```bash
cd ids-project
pip install -r requirements.txt
```

### 2. Run the Server (Demo Mode — No Root Required)

```bash
python api/server.py --demo --port 5000
```

**Output:**
```
==================================================
  IDS Server running on http://localhost:5000
  Demo mode: True
  Interface: default
==================================================

[Capture] Demo mode: generating synthetic packets…
[Capture] Attacks will trigger every 30-40 seconds

[DB] Initialized at /home/claude/ids-project/logs/ids.db
```

### 3. Open Dashboard

Navigate to your React app (or use the included React component in `dashboard/App.jsx`).

If using standalone React setup:
```bash
# In dashboard folder
npm install recharts
npm run dev
# Then open http://localhost:5173
```

---

## Running Modes

### Demo Mode (Recommended for Testing)
Generates synthetic traffic with periodic attacks.

```bash
python api/server.py --demo
```

### Live Capture (Requires Root/Admin)
Sniffs real network packets.

```bash
sudo python api/server.py
# or on specific interface:
sudo python api/server.py --interface eth0
```

---

## What Each Detector Does

### 1. **Port Scan Detection**
- **Trigger:** Any single IP probes >15 distinct ports within 15 seconds
- **Severity:** HIGH
- **Example Alert:** "Port scan detected: 10.0.0.99 probed 45 distinct ports in 15s window."

### 2. **SYN Flood Detection**
- **Trigger:** Any IP sends >80 bare SYN packets within 8 seconds
- **Severity:** CRITICAL
- **Example Alert:** "SYN flood detected: 192.168.1.200 sent 120 SYN packets in 8s. Possible DoS attack."

### 3. **ICMP Flood Detection**
- **Trigger:** Any IP sends >35 ICMP packets within 8 seconds
- **Severity:** HIGH
- **Example Alert:** "ICMP flood from 172.16.0.50: 65 pings in 8s window."

### 4. **High-Frequency IP Detection**
- **Trigger:** Any single IP generates >400 packets within 12 seconds
- **Severity:** MEDIUM
- **Example Alert:** "High traffic volume from 203.0.113.42: 520 packets in 12s."

---

## API Endpoints

### GET `/api/status`
Returns server status and live packet counters.

```bash
curl http://localhost:5000/api/status
```

```json
{
  "status": "running",
  "packets": {
    "total": 15234,
    "TCP": 8421,
    "UDP": 4102,
    "ICMP": 1834,
    "DNS": 745
  },
  "time": "2025-05-13T14:22:33.123456"
}
```

### GET `/api/alerts?limit=100&severity=CRITICAL`
Fetch recent alerts.

```bash
curl http://localhost:5000/api/alerts?limit=50
```

### GET `/api/packets?limit=200`
Fetch recent packets.

```bash
curl http://localhost:5000/api/packets
```

### GET `/api/stats`
Get comprehensive statistics.

```bash
curl http://localhost:5000/api/stats
```

### POST `/api/clear`
Clear all alerts and packets.

```bash
curl -X POST http://localhost:5000/api/clear
```

---

## Project Structure

```
ids-project/
├── api/
│   ├── server.py              # Flask + SocketIO server
│   └── database.py            # SQLite manager
├── sniffer/
│   ├── capture.py             # Packet capture + packet callbacks
│   └── parser.py              # Parse Scapy packets → structured dicts
├── detection/
│   ├── engine.py              # Routes packets through detectors
│   ├── port_scan.py           # Port scan detector
│   ├── syn_flood.py           # SYN flood detector
│   └── icmp_flood.py          # ICMP + high-frequency detectors
├── dashboard/
│   └── App.jsx                # React component (Recharts)
├── logs/
│   └── ids.db                 # SQLite database (auto-created)
├── simulate_attacks.py        # Test attack generator
├── requirements.txt
└── README.md
```

---

## Testing with Synthetic Attacks

### Option A: Demo Mode Auto-Attacks
Just run the server in demo mode — it automatically generates realistic attacks every 30–40 seconds.

```bash
python api/server.py --demo
```

Watch the dashboard — you'll see alerts appear like:
- `PORT_SCAN` from `10.0.0.99`
- `SYN_FLOOD` from `192.168.1.200`
- `ICMP_FLOOD` from `172.16.0.50`
- `HIGH_FREQUENCY_IP` from `203.0.113.42`

### Option B: Manual Attack Simulation
Use the simulation script to send crafted packets (requires Scapy + sudo):

```bash
sudo python simulate_attacks.py --target 127.0.0.1 --attack all
```

Or individual attacks:
```bash
sudo python simulate_attacks.py --target 192.168.1.1 --attack port_scan
sudo python simulate_attacks.py --target 192.168.1.1 --attack syn_flood
sudo python simulate_attacks.py --target 192.168.1.1 --attack icmp_flood
```

---

## Dashboard Features

### **Dashboard Tab**
- **Stat Cards:** Total packets, alerts, unique IPs, threat types
- **Live Traffic Chart:** Area chart of TCP/UDP/ICMP over time
- **Protocol Pie:** Distribution of protocols captured
- **Top IPs Bar Chart:** Most active source IPs
- **Alert Severity Bar:** Breakdown by CRITICAL/HIGH/MEDIUM/LOW
- **Recent Alerts Preview:** Last 8 alerts with timestamps

### **Alerts Tab**
- **Full alert list** with severity badges
- **Alert details** including attacker IP, attack type, and explanation
- **Filter by severity** (CRITICAL, HIGH, MEDIUM, LOW)
- **Real-time updates** as new attacks are detected

### **Packets Tab**
- **Live packet feed** with protocol, source, destination, port, size
- **Sortable columns** for deeper inspection
- **Scrollable feed** for recent traffic

---

## Customizing Detectors

Each detector has configurable thresholds. Edit the constants at the top of each file:

**Port Scan** (`detection/port_scan.py`):
```python
PORT_SCAN_THRESHOLD   = 15     # Distinct ports to trigger alert
PORT_SCAN_WINDOW_SECS = 15     # Time window (seconds)
```

**SYN Flood** (`detection/syn_flood.py`):
```python
SYN_FLOOD_THRESHOLD   = 80     # SYN packets to trigger alert
SYN_FLOOD_WINDOW_SECS = 8      # Time window (seconds)
```

**ICMP Flood** (`detection/icmp_flood.py`):
```python
ICMP_THRESHOLD        = 35     # ICMP packets to trigger alert
ICMP_WINDOW_SECS      = 8      # Time window (seconds)

IP_FREQ_THRESHOLD     = 400    # Total packets to trigger alert
IP_FREQ_WINDOW_SECS   = 12     # Time window (seconds)
```

---

## Key Learnings (Interview Questions You'll Get)

This project demonstrates:

1. **Network protocols** — TCP, UDP, ICMP, packet structure
2. **TCP handshake** — SYN, ACK, FIN flags
3. **Port scanning** — How attackers enumerate services
4. **DoS attacks** — SYN flood, ICMP flood mechanics
5. **Packet sniffing** — Raw socket programming
6. **Real-time detection** — Streaming data processing
7. **Database design** — Efficient alert logging
8. **REST APIs** — RESTful design patterns
9. **WebSockets** — Real-time bidirectional communication
10. **Frontend architecture** — React components, Recharts visualization

---

## Common Interview Questions

**Q: What's the difference between IDS and IPS?**  
A: IDS (Intrusion Detection) alerts on threats. IPS (Prevention) actively blocks malicious traffic.

**Q: Why do you track distinct ports instead of total ports?**  
A: Port scanning probes different ports to find open services. A legitimate client might retry the same port.

**Q: How would you handle high-traffic scenarios?**  
A: Add packet sampling, use Redis for in-memory state, or switch to eBPF for kernel-space detection.

**Q: What's a "rolling time window"?**  
A: We only count events in the last N seconds. Older events are discarded automatically.

**Q: Can an attacker evade your detectors?**  
A: Yes. Slow port scans (spread over minutes) would evade. Adding ML for anomaly detection would help.

---

## Resume/Portfolio Tips

### Add These to Stand Out:

1. **Architecture Diagram** (draw in Excalidraw, include in README)
2. **Attack Simulation Screenshots** (run demo, screenshot alerts)
3. **Demo Video** (30-second clip of live detections)
4. **Performance Metrics** (packets/sec, detection latency)
5. **Security Considerations** (mention evasion techniques, improvements)

### Example README Badge:
```markdown
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Scapy](https://img.shields.io/badge/Scapy-packet_analysis-green)
![Flask](https://img.shields.io/badge/Flask-REST_API-lightgrey)
![React](https://img.shields.io/badge/React-Dashboard-cyan)
```

---

## Future Enhancements

- [ ] **GeoIP Lookup** — Map attacker countries
- [ ] **Email Alerts** — SMTP notifications for CRITICAL events
- [ ] **ML Anomaly Detection** — Isolation Forest for unusual traffic
- [ ] **Rate Limiting Rules** — Drop suspicious packets in real-time (IPS mode)
- [ ] **Packet Payload Inspection** — Detect malware signatures
- [ ] **Grafana Integration** — Enterprise-grade dashboards
- [ ] **Kubernetes Deployment** — Run as sidecar in K8s
- [ ] **SIEM Integration** — Send to Splunk, ELK, etc.

---

## Troubleshooting

### Server Won't Start
```bash
# Make sure port 5000 is free
lsof -i :5000
kill -9 <PID>

# Or use different port
python api/server.py --demo --port 8000
```

### No Alerts Appearing
- Check that server is in `--demo` mode or has root privileges
- Verify detectors thresholds in `detection/` files
- Check console for `[DEMO] Simulating...` messages
- Restart server

### Database Errors
```bash
# Clear and reinit database
rm logs/ids.db
python api/server.py --demo
```

### Permission Denied (Live Mode)
```bash
# Need root for real packet capture
sudo python api/server.py
```

---

## License

MIT License — Use freely, modify as needed.

---

## Credits

Built with:
- **Scapy** — Packet manipulation
- **Flask** — Web framework
- **SQLite** — Lightweight database
- **React** — UI library
- **Recharts** — Data visualization

Inspired by production IDS systems like **Snort**, **Suricata**, and **Zeek**.

---

**Happy detecting! 🛡️**