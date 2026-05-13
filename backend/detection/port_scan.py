"""
port_scan.py — Detect port scanning behaviour
A port scan is identified when a single source IP contacts many distinct
destination ports within a short rolling time window.
"""

import time
from collections import defaultdict

# Tunable thresholds
PORT_SCAN_THRESHOLD   = 15    # distinct ports within window → alert (lowered from 20)
PORT_SCAN_WINDOW_SECS = 15    # rolling window length in seconds (extended from 10)
SEVERITY              = 'HIGH'


class PortScanDetector:
    def __init__(self, threshold=PORT_SCAN_THRESHOLD,
                 window=PORT_SCAN_WINDOW_SECS):
        self.threshold = threshold
        self.window    = window
        # { src_ip: [(timestamp, dst_port), ...] }
        self._tracker: dict[str, list] = defaultdict(list)

    def inspect(self, parsed: dict) -> dict | None:
        """
        Feed a parsed packet dict.
        Returns an alert dict or None.
        """
        if parsed.get('protocol') not in ('TCP', 'UDP'):
            return None

        src_ip   = parsed.get('src_ip')
        dst_port = parsed.get('dst_port')

        if not src_ip or dst_port is None:
            return None

        now = time.time()
        entries = self._tracker[src_ip]

        # Add current event
        entries.append((now, dst_port))

        # Evict old entries outside the window
        cutoff = now - self.window
        self._tracker[src_ip] = [(t, p) for t, p in entries if t >= cutoff]

        # Count distinct ports in window
        ports_in_window = {p for _, p in self._tracker[src_ip]}

        if len(ports_in_window) >= self.threshold:
            # Reset tracker so we don't flood duplicate alerts
            self._tracker[src_ip] = []
            return {
                'alert_type': 'PORT_SCAN',
                'severity':   SEVERITY,
                'src_ip':     src_ip,
                'dst_ip':     parsed.get('dst_ip'),
                'protocol':   parsed.get('protocol'),
                'detail':     (
                    f"Port scan detected: {src_ip} probed "
                    f"{len(ports_in_window)} distinct ports in "
                    f"{self.window}s window. "
                    f"Sample ports: {sorted(ports_in_window)[:10]}"
                ),
                'raw_data': {
                    'ports': sorted(ports_in_window),
                    'window_secs': self.window,
                }
            }
        return None