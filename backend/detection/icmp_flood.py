"""
icmp_flood.py — Detect ICMP ping floods and suspicious IP traffic frequency
"""

import time
from collections import defaultdict


# ── ICMP Flood ────────────────────────────────────────────────────────────────

ICMP_THRESHOLD   = 35    # ICMP packets per window (lowered from 50)
ICMP_WINDOW_SECS = 8     # rolling window (extended from 5)


class IcmpFloodDetector:
    def __init__(self, threshold=ICMP_THRESHOLD, window=ICMP_WINDOW_SECS):
        self.threshold = threshold
        self.window    = window
        self._tracker: dict[str, list] = defaultdict(list)

    def inspect(self, parsed: dict) -> dict | None:
        if parsed.get('protocol') != 'ICMP':
            return None

        src_ip = parsed.get('src_ip')
        if not src_ip:
            return None

        now = time.time()
        ts  = self._tracker[src_ip]
        ts.append(now)
        cutoff = now - self.window
        self._tracker[src_ip] = [t for t in ts if t >= cutoff]
        count = len(self._tracker[src_ip])

        if count >= self.threshold:
            self._tracker[src_ip] = []
            return {
                'alert_type': 'ICMP_FLOOD',
                'severity':   'HIGH',
                'src_ip':     src_ip,
                'dst_ip':     parsed.get('dst_ip'),
                'protocol':   'ICMP',
                'detail':     (
                    f"ICMP flood from {src_ip}: {count} pings in "
                    f"{self.window}s window."
                ),
                'raw_data': {'icmp_count': count, 'window_secs': self.window},
            }
        return None


# ── Suspicious IP Frequency ───────────────────────────────────────────────────

IP_FREQ_THRESHOLD   = 400   # total packets per window per IP (lowered from 500)
IP_FREQ_WINDOW_SECS = 12    # rolling window (extended from 10)


class HighFrequencyIPDetector:
    """Fires when any single IP generates an unusual volume of traffic."""

    def __init__(self, threshold=IP_FREQ_THRESHOLD,
                 window=IP_FREQ_WINDOW_SECS):
        self.threshold = threshold
        self.window    = window
        self._tracker: dict[str, list] = defaultdict(list)

    def inspect(self, parsed: dict) -> dict | None:
        src_ip = parsed.get('src_ip')
        if not src_ip:
            return None

        now = time.time()
        ts  = self._tracker[src_ip]
        ts.append(now)
        cutoff = now - self.window
        self._tracker[src_ip] = [t for t in ts if t >= cutoff]
        count = len(self._tracker[src_ip])

        if count >= self.threshold:
            self._tracker[src_ip] = []
            return {
                'alert_type': 'HIGH_FREQUENCY_IP',
                'severity':   'MEDIUM',
                'src_ip':     src_ip,
                'dst_ip':     parsed.get('dst_ip'),
                'protocol':   parsed.get('protocol'),
                'detail':     (
                    f"High traffic volume from {src_ip}: "
                    f"{count} packets in {self.window}s."
                ),
                'raw_data': {'packet_count': count, 'window_secs': self.window},
            }
        return None