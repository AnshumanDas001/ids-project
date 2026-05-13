"""
capture.py — Live packet capture using Scapy
Runs in a background thread and pushes parsed packets through
the detection engine, persisting everything to SQLite.
"""

import sys
import os
import threading
import time
from collections import deque

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sniffer.parser import parse_packet
from detection.engine import DetectionEngine
from api.database import insert_packet, insert_alert, init_db

try:
    from scapy.all import sniff, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[Capture] Scapy not installed — running in DEMO mode")


# ── Shared state (thread-safe via deque/list) ─────────────────────────────────

recent_packets: deque = deque(maxlen=500)   # last N parsed packets
recent_alerts:  deque = deque(maxlen=200)   # last N alerts
packet_counter: dict  = {
    'total': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0,
    'DNS': 0, 'ARP': 0, 'OTHER': 0
}

_engine = DetectionEngine()
_lock   = threading.Lock()

# Callbacks registered by Flask-SocketIO for live push
_alert_callbacks:  list = []
_packet_callbacks: list = []


def register_alert_callback(fn):
    _alert_callbacks.append(fn)


def register_packet_callback(fn):
    _packet_callbacks.append(fn)


# ── Core packet handler ───────────────────────────────────────────────────────

def _handle_packet(raw_packet):
    parsed = parse_packet(raw_packet)
    if not parsed:
        return

    proto = parsed.get('protocol', 'OTHER')

    with _lock:
        packet_counter['total'] += 1
        packet_counter[proto] = packet_counter.get(proto, 0) + 1
        recent_packets.appendleft(parsed)

    # Persist to DB (every packet — throttle if needed for high traffic)
    insert_packet(
        src_ip   = parsed.get('src_ip'),
        dst_ip   = parsed.get('dst_ip'),
        protocol = proto,
        src_port = parsed.get('src_port'),
        dst_port = parsed.get('dst_port'),
        size     = parsed.get('size', 0),
        flags    = parsed.get('flags'),
    )

    # Fire alert callbacks
    for cb in _packet_callbacks:
        try:
            cb(parsed)
        except Exception:
            pass

    # Run detection
    alerts = _engine.analyze(parsed)
    for alert in alerts:
        with _lock:
            recent_alerts.appendleft(alert)

        insert_alert(
            alert_type = alert['alert_type'],
            severity   = alert['severity'],
            src_ip     = alert.get('src_ip'),
            dst_ip     = alert.get('dst_ip'),
            protocol   = alert.get('protocol'),
            detail     = alert.get('detail'),
            raw_data   = alert.get('raw_data'),
        )
        print(f"[ALERT] {alert['severity']} — {alert['alert_type']}: {alert['detail']}")

        for cb in _alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass


# ── Demo / simulation mode ────────────────────────────────────────────────────

import random
import ipaddress

def _demo_loop():
    """Simulate network traffic when Scapy/root isn't available."""
    print("[Capture] Demo mode: generating synthetic packets…")
    print("[Capture] Attacks will trigger every 30-40 seconds\n")
    
    protocols = ['TCP', 'UDP', 'ICMP', 'DNS']
    attack_ips = ['10.0.0.99', '192.168.1.200', '172.16.0.50', '203.0.113.42']
    normal_ips = [f"192.168.1.{i}" for i in range(1, 120)]
    
    attack_cycle = 0
    
    while True:
        time.sleep(0.02)  # Faster loop = more packets
        attack_cycle += 1
        
        # ── Generate normal background traffic ──────────────────────────────
        for _ in range(random.randint(3, 8)):
            src = random.choice(normal_ips)
            dst = f"10.0.0.{random.randint(1,50)}"
            proto = random.choice(protocols)
            parsed = {
                'src_ip':   src,
                'dst_ip':   dst,
                'protocol': proto,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 53, 8080, 3306, 5432, 27017]),
                'flags':    random.choice(['PA', 'SA', 'A', 'R']) if proto == 'TCP' else None,
                'size':     random.randint(40, 1500),
                'is_syn':   False,
                'is_rst':   False,
                'is_fin':   False,
            }
            _handle_packet_parsed(parsed)
        
        # ── Attack cycles - trigger every 30-40 iterations (~0.6-0.8s) ──────
        if 150 < attack_cycle < 200:  # Port scan
            attacker = random.choice(attack_ips)
            print(f"[DEMO] Simulating PORT SCAN from {attacker}…")
            for port in range(1, 50):  # Needs >20 distinct ports
                p = {
                    'src_ip':   attacker,
                    'dst_ip':   f"10.0.0.{random.randint(1,10)}",
                    'protocol': 'TCP',
                    'src_port': random.randint(1024, 65535),
                    'dst_port': port,
                    'flags':    'S',
                    'size':     64,
                    'is_syn':   True,
                    'is_rst':   False,
                    'is_fin':   False,
                }
                _handle_packet_parsed(p)
                time.sleep(0.002)
            attack_cycle = 0
            
        elif 150 < attack_cycle < 200 and random.random() < 0.3:  # SYN flood
            attacker = random.choice(attack_ips)
            print(f"[DEMO] Simulating SYN FLOOD from {attacker}…")
            for _ in range(120):  # Needs >100 SYN packets
                p = {
                    'src_ip':   attacker,
                    'dst_ip':   f"10.0.0.{random.randint(1,5)}",
                    'protocol': 'TCP',
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 8080]),
                    'flags':    'S',
                    'size':     64,
                    'is_syn':   True,
                    'is_rst':   False,
                    'is_fin':   False,
                }
                _handle_packet_parsed(p)
                time.sleep(0.001)
            attack_cycle = 0
            
        elif 150 < attack_cycle < 200 and random.random() < 0.2:  # ICMP flood
            attacker = random.choice(attack_ips)
            print(f"[DEMO] Simulating ICMP FLOOD from {attacker}…")
            for _ in range(70):  # Needs >50 ICMP packets
                p = {
                    'src_ip':   attacker,
                    'dst_ip':   f"10.0.0.{random.randint(1,5)}",
                    'protocol': 'ICMP',
                    'src_port': None,
                    'dst_port': None,
                    'flags':    '8',
                    'size':     56,
                    'is_syn':   False,
                    'is_rst':   False,
                    'is_fin':   False,
                }
                _handle_packet_parsed(p)
                time.sleep(0.001)
            attack_cycle = 0
            
        elif 150 < attack_cycle < 200 and random.random() < 0.1:  # High frequency
            attacker = random.choice(attack_ips)
            print(f"[DEMO] Simulating HIGH FREQUENCY traffic from {attacker}…")
            for _ in range(520):  # Needs >500 packets
                p = {
                    'src_ip':   attacker,
                    'dst_ip':   f"10.0.0.{random.randint(1,20)}",
                    'protocol': random.choice(['TCP', 'UDP']),
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 53, 8080]),
                    'flags':    'PA' if random.random() < 0.5 else None,
                    'size':     random.randint(40, 200),
                    'is_syn':   False,
                    'is_rst':   False,
                    'is_fin':   False,
                }
                _handle_packet_parsed(p)
                if _ % 50 == 0:
                    time.sleep(0.001)
            attack_cycle = 0


def _handle_packet_parsed(parsed: dict):
    """Same as _handle_packet but accepts already-parsed dict (for demo mode)."""
    proto = parsed.get('protocol', 'OTHER')

    with _lock:
        packet_counter['total'] += 1
        packet_counter[proto] = packet_counter.get(proto, 0) + 1
        recent_packets.appendleft(parsed)

    insert_packet(
        src_ip   = parsed.get('src_ip'),
        dst_ip   = parsed.get('dst_ip'),
        protocol = proto,
        src_port = parsed.get('src_port'),
        dst_port = parsed.get('dst_port'),
        size     = parsed.get('size', 0),
        flags    = parsed.get('flags'),
    )

    for cb in _packet_callbacks:
        try:
            cb(parsed)
        except Exception:
            pass

    alerts = _engine.analyze(parsed)
    for alert in alerts:
        with _lock:
            recent_alerts.appendleft(alert)
        insert_alert(
            alert_type = alert['alert_type'],
            severity   = alert['severity'],
            src_ip     = alert.get('src_ip'),
            dst_ip     = alert.get('dst_ip'),
            protocol   = alert.get('protocol'),
            detail     = alert.get('detail'),
            raw_data   = alert.get('raw_data'),
        )
        print(f"[ALERT] {alert['severity']} — {alert['alert_type']}: {alert['detail']}")
        for cb in _alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass


# ── Public start function ─────────────────────────────────────────────────────

def start_capture(interface=None, demo=False):
    """Start packet capture in a background daemon thread."""
    init_db()

    if demo or not SCAPY_AVAILABLE:
        t = threading.Thread(target=_demo_loop, daemon=True)
        t.start()
        return t

    def _live():
        print(f"[Capture] Starting live capture on interface: {interface or 'default'}")
        try:
            sniff(
                iface  = interface,
                prn    = _handle_packet,
                store  = False,
                filter = "ip or arp",
            )
        except PermissionError:
            print("[Capture] Permission denied — re-run with sudo/root. Falling back to demo mode.")
            _demo_loop()
        except Exception as e:
            print(f"[Capture] Error: {e}. Falling back to demo mode.")
            _demo_loop()

    t = threading.Thread(target=_live, daemon=True)
    t.start()
    return t