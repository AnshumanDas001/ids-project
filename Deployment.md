# NetWatch IDS — Architecture & Deployment

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NETWORK INTERFACE                           │
│                    (eth0, WiFi, or Simulated)                       │
└─────────────────────────────────────┬───────────────────────────────┘
                                      │
                    ┌─────────────────▼────────────────┐
                    │   SCAPY PACKET SNIFFER           │
                    │  (or Demo Generator in  fallback)│
                    └─────────────────┬────────────────┘
                                      │
         ┌────────────────────────────▼────────────────┐
         │  PACKET PARSER (sniffer/parser.py)         │
         │  Extract: IP, port, protocol, flags       │
         │  Output: Structured dict                  │
         └────────────────────────────┬───────────────┘
                                      │
         ┌────────────────────────────▼──────────────────────┐
         │  DETECTION ENGINE (detection/engine.py)          │
         │  Routes packet through 4 detectors:             │
         │  ┌─────────────────────────────────────────┐    │
         │  │ 1. PortScanDetector                     │    │
         │  │    Tracks {IP: set(ports)} per window   │    │
         │  │    Alert when >15 distinct ports        │    │
         │  └─────────────────────────────────────────┘    │
         │  ┌─────────────────────────────────────────┐    │
         │  │ 2. SynFloodDetector                     │    │
         │  │    Counts bare SYN packets per IP       │    │
         │  │    Alert when >80 in 8s window          │    │
         │  └─────────────────────────────────────────┘    │
         │  ┌─────────────────────────────────────────┐    │
         │  │ 3. IcmpFloodDetector                    │    │
         │  │    Counts ICMP packets per IP           │    │
         │  │    Alert when >35 in 8s window          │    │
         │  └─────────────────────────────────────────┘    │
         │  ┌─────────────────────────────────────────┐    │
         │  │ 4. HighFrequencyIPDetector              │    │
         │  │    Counts all packets per IP            │    │
         │  │    Alert when >400 in 12s window        │    │
         │  └─────────────────────────────────────────┘    │
         └────────────────────────────┬──────────────────────┘
                                      │
         ┌────────────────────────────▼──────────────┐
         │    ALERT + PACKET PERSISTENCE             │
         │    (api/database.py)                      │
         │    ┌──────────────────────────────────┐   │
         │    │ SQLite Database (logs/ids.db)    │   │
         │    │ ├─ packets table (1.5M rows)     │   │
         │    │ ├─ alerts table (5k rows)        │   │
         │    │ └─ stats table                   │   │
         │    └──────────────────────────────────┘   │
         └────────────────────────────┬──────────────┘
                                      │
     ┌────────────────────────────────▼────────────────────────┐
     │   FLASK REST API + SOCKETIO (api/server.py)            │
     │                                                          │
     │  HTTP Endpoints:                                        │
     │  ├─ GET  /api/status         → Live counters           │
     │  ├─ GET  /api/alerts         → Alert list              │
     │  ├─ GET  /api/packets        → Packet feed             │
     │  ├─ GET  /api/stats          → Comprehensive stats     │
     │  └─ POST /api/clear          → Reset all data          │
     │                                                          │
     │  WebSocket Events:                                      │
     │  ├─ new_alert               → Real-time alerts         │
     │  ├─ new_packet              → Lightweight summaries    │
     │  ├─ stats_update            → Periodic stats           │
     │  └─ connected               → Heartbeat                │
     └────────────────────────────────┬────────────────────────┘
                                      │
     ┌────────────────────────────────▼──────────────────────────┐
     │    REACT DASHBOARD (dashboard/App.jsx)                   │
     │                                                           │
     │  Layout:                                                 │
     │  ┌──────────────────────────────────────────────────┐   │
     │  │ Header: Status, CRITICAL alert badge, Clear btn │   │
     │  ├──────────────────────────────────────────────────┤   │
     │  │ Tabs: Dashboard | Alerts | Packets              │   │
     │  ├──────────────────────────────────────────────────┤   │
     │  │ Dashboard:                                       │   │
     │  │  • 4 stat cards (packets, alerts, IPs, types)   │   │
     │  │  • Line chart: Live traffic (TCP/UDP/ICMP)      │   │
     │  │  • Pie chart: Protocol distribution             │   │
     │  │  • Bar chart: Top IPs                           │   │
     │  │  • Bar chart: Alert severity breakdown          │   │
     │  │  • Table: Recent 8 alerts                       │   │
     │  │                                                  │   │
     │  │ Alerts Tab:                                      │   │
     │  │  • Full alert list (all 50+ alerts)             │   │
     │  │  • Severity filter badges                       │   │
     │  │  • Alert details (src IP, type, explanation)    │   │
     │  │  • Real-time updates with flash animation       │   │
     │  │                                                  │   │
     │  │ Packets Tab:                                     │   │
     │  │  • Live packet feed (200+ rows)                 │   │
     │  │  • Columns: time, protocol, src/dst IP, port    │   │
     │  │  • Sortable, scrollable                         │   │
     │  │                                                  │   │
     │  │ Colors:                                          │   │
     │  │  • CRITICAL: #ff2d55 (red)                      │   │
     │  │  • HIGH: #ff9500 (orange)                       │   │
     │  │  • MEDIUM: #ffd60a (yellow)                     │   │
     │  │  • LOW: #30d158 (green)                         │   │
     │  └──────────────────────────────────────────────────┘   │
     └──────────────────────────────────────────────────────────┘
```

---

## Data Flow Examples

### Normal Packet Flow

```
TCP SYN packet arrives from 192.168.1.15 to 10.0.0.5:443

1. Scapy captures: [IP][TCP][Flags=S]
2. Parser extracts:
   {
     src_ip: "192.168.1.15",
     dst_ip: "10.0.0.5",
     protocol: "TCP",
     src_port: 54321,
     dst_port: 443,
     flags: "S",
     is_syn: True,
     size: 64
   }
3. Engine runs all 4 detectors → No alerts (legitimate 3-way handshake)
4. Database stores packet in packets table
5. WebSocket pushes lightweight summary to dashboard
6. Dashboard updates live traffic chart
```

### Attack Flow (Port Scan Example)

```
IP 10.0.0.99 sends SYN packets to ports 1-30 in 5 seconds

For each SYN:
1. Parser extracts src_ip=10.0.0.99, dst_port=N, is_syn=True
2. PortScanDetector.inspect() called:
   - Adds port N to tracker[10.0.0.99]
   - Evicts old entries outside 15s window
   - Counts distinct ports in window
   - When count >= 15 → ALERT!
3. Alert object created:
   {
     alert_type: "PORT_SCAN",
     severity: "HIGH",
     src_ip: "10.0.0.99",
     detail: "Port scan detected: 10.0.0.99 probed 30 distinct ports...",
     raw_data: {"ports": [1,2,3,...,30], "window_secs": 15}
   }
4. Database inserts alert into alerts table
5. WebSocket emits 'new_alert' event
6. Dashboard receives alert → flashes new row, increments HIGH counter
7. Alert appears in Alerts tab with red/orange styling
```

---

## Deployment Scenarios

### Scenario 1: Local Development (Recommended)

```bash
# Terminal 1: Run IDS server
cd ids-project
python api/server.py --demo --port 5000

# Terminal 2: Run React dev server
cd dashboard
npm run dev
# Navigate to http://localhost:5173
```

**Pros:**
- No root required (demo mode)
- Fast iteration
- Easy debugging

**When to use:**
- Portfolio work
- Learning / testing
- Demo presentations

---

### Scenario 2: Production Live Capture (Linux/macOS)

```bash
# Install dependencies
pip install -r requirements.txt

# Start with root (sudo) for real packet capture
sudo python api/server.py --interface eth0 --port 5000

# Frontend: Serve React bundle
npm run build
npx serve -s build -l 5173
```

**Requirements:**
- Linux or macOS (not Windows without WSL2)
- Root/sudo privileges
- Network interface name (eth0, en0, etc.)

**Config:**
```bash
# Specific interface
sudo python api/server.py --interface eth0

# All interfaces (default)
sudo python api/server.py

# Different port
sudo python api/server.py --port 8080
```

---

### Scenario 3: Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy code
COPY . .

# Install Python deps
RUN pip install -r requirements.txt

# Expose port
EXPOSE 5000

# Run server
CMD ["python", "api/server.py", "--demo", "--port", "5000"]
```

Build & run:

```bash
docker build -t ids:latest .
docker run -p 5000:5000 ids:latest
```

For real capture with Docker:

```bash
# Need to run privileged with network access
docker run --privileged -p 5000:5000 ids:latest python api/server.py
```

---

### Scenario 4: Kubernetes (Enterprise)

```yaml
# ids-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ids-server
  labels:
    app: ids
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ids
  template:
    metadata:
      labels:
        app: ids
    spec:
      containers:
      - name: ids-server
        image: ids:latest
        ports:
        - containerPort: 5000
        env:
        - name: DEMO_MODE
          value: "true"
        volumeMounts:
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: logs
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ids-service
spec:
  selector:
    app: ids
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer
```

Deploy:

```bash
kubectl apply -f ids-deployment.yaml
kubectl port-forward svc/ids-service 5000:80
```

---

## Performance Characteristics

### Packet Processing

- **Throughput:** 10,000–50,000 packets/sec (single thread)
- **Latency:** <1ms per packet (parsing + detection)
- **Memory:** ~200MB (1000 unique IPs tracked)
- **Database:** SQLite can handle ~100k inserts/sec (batched)

### Scaling Bottlenecks

1. **Scapy parsing** — Single-threaded, ~10k pps sustainable
2. **SQLite writes** — No concurrent writes; batch inserts for speed
3. **Dashboard WebSocket** — Browser can handle 10+ messages/sec
4. **Detection state** — Memory grows with unique IPs; use Redis for 1M+ IPs

### Optimization Strategies

For high-traffic networks:

1. **Packet Sampling** — Only inspect 1 in N packets
   ```python
   if random.random() > 0.95:  # 5% sample rate
       _handle_packet_parsed(parsed)
   ```

2. **Use Redis** — Replace in-memory detectors with Redis state
   ```python
   # Track in Redis instead of dict
   redis.incr(f"syn_count:{src_ip}")
   redis.expire(f"syn_count:{src_ip}", 8)  # 8s window
   ```

3. **eBPF/XDP** — Kernel-space packet processing (10x faster)
   - Tools: Suricata, Zeek

4. **Batch Inserts** — Write 1000 packets at once, not one-by-one
   ```python
   # Instead of: insert_packet(...)  # per packet
   # Do: conn.executemany(..., batch_of_1000_packets)
   ```

---

## Security Considerations

### What Your IDS Protects Against

✅ Port scanning (slow, stealthy)  
✅ SYN flood DoS attacks  
✅ ICMP flood ping attacks  
✅ Unusual traffic volume from single IPs  

### What It Does NOT Protect Against

❌ Encrypted attacks (HTTPS, VPN payloads)  
❌ Slow distributed attacks (botnet across many IPs)  
❌ Application-layer attacks (HTTP 200 with malware payload)  
❌ Zero-day exploits (unknown vulnerabilities)  
❌ Attacks from inside trusted network  

### Evasion Techniques Attackers Use

1. **Slow Port Scans** — Spread over hours (evade time window)
   - **Fix:** Increase window, use long-term IPs list

2. **Distributed Attacks** — Many IPs sending same attack
   - **Fix:** Detect similar traffic patterns from different IPs

3. **IP Spoofing** — Fake source IP (mostly prevented by ISP)
   - **Fix:** Trust upstream network (assumption of BCP38)

4. **Protocol Obfuscation** — Tunnel attacks over DNS/HTTP
   - **Fix:** Add deep packet inspection (DPI), ML anomaly detection

---

## Monitoring the Monitor

### Health Checks

```bash
# API is up?
curl http://localhost:5000/api/status

# Database is okay?
sqlite3 logs/ids.db "SELECT COUNT(*) FROM alerts;"

# Memory usage growing?
ps aux | grep server.py
# Look at VSIZE, RSS columns

# Disk usage (logs)?
du -sh logs/
```

### Key Metrics to Track

- **Packets/sec** — Processing capacity utilization
- **Alert rate** — Should be <1/sec in normal network
- **Database size** — ids.db should stay <1GB with monthly archival
- **API response time** — /api/stats should return <100ms

### Alerting Rules

```
if packets_per_second > 50000:
    alert("High traffic detected — possible DDoS or sampling needed")

if alerts_per_minute > 10:
    alert("High alert rate — may indicate attack wave or false positives")

if database_size_mb > 1000:
    alert("Archive old alerts (>30 days) and delete")

if api_response_time_ms > 1000:
    alert("Server slow — check database, memory, CPU")
```

---

## Testing Checklist

Before deploying to production:

- [ ] Server starts in demo mode without errors
- [ ] Dashboard loads and connects to API
- [ ] Alerts trigger after 30–40 seconds (demo attacks)
- [ ] Alert appears on dashboard within 1 second
- [ ] Clicking "Clear" removes all data
- [ ] Can switch between Dashboard/Alerts/Packets tabs
- [ ] `/api/status` returns valid JSON
- [ ] `/api/stats` includes packet counts and top IPs
- [ ] Database file is created in `logs/ids.db`
- [ ] No Python errors in console (check stderr)
- [ ] Browser shows no JavaScript errors (F12 > Console)

---

## Maintenance

### Regular Tasks

**Daily:**
- Monitor alert trends
- Check for unusual attack patterns

**Weekly:**
- Review top attacking IPs (block if needed)
- Archive old alerts (>7 days)

**Monthly:**
- Clear database (reset for fresh data)
- Review and adjust detector thresholds
- Update Scapy/Flask libraries

### Archive & Purge

```python
# In database.py
def archive_old_alerts(days=7):
    cutoff = datetime.utcnow() - timedelta(days=days)
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE timestamp < ?", (cutoff.isoformat(),))
    old_alerts = c.fetchall()
    
    # Save to CSV/JSON for long-term storage
    import csv
    with open('archive.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(old_alerts)
    
    # Delete from DB
    c.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff.isoformat(),))
    conn.commit()
    conn.close()
```

---

**Next Steps:**
1. Run locally in demo mode
2. Verify dashboard updates with alerts
3. Adjust thresholds in `detection/` if needed
4. Deploy to server/Docker
5. Set up monitoring & alerting

Good luck! 🛡️