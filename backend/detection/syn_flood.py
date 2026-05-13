"""
syn_flood.py — Detect TCP SYN flood attacks
A SYN flood is identified when a source IP sends an abnormally high number
of bare SYN packets (no ACK) within a rolling time window.
"""

import time
from collections import defaultdict

SYN_FLOOD_THRESHOLD   = 80    # SYN packets in window → alert (lowered from 100)
SYN_FLOOD_WINDOW_SECS = 8     # rolling window in seconds (extended from 5)
SEVERITY              = 'CRITICAL'


class SynFloodDetector:
    def __init__(self, threshold=SYN_FLOOD_THRESHOLD,
                 window=SYN_FLOOD_WINDOW_SECS):
        self.threshold = threshold
        self.window    = window
        # { src_ip: [timestamp, ...] }
        self._tracker: dict[str, list] = defaultdict(list)

    def inspect(self, parsed: dict) -> dict | None:
        if not parsed.get('is_syn'):
            return None

        src_ip = parsed.get('src_ip')
        if not src_ip:
            return None

        now = time.time()
        timestamps = self._tracker[src_ip]
        timestamps.append(now)

        # Evict stale timestamps
        cutoff = now - self.window
        self._tracker[src_ip] = [t for t in timestamps if t >= cutoff]

        count = len(self._tracker[src_ip])

        if count >= self.threshold:
            # Reset to avoid spam
            self._tracker[src_ip] = []
            return {
                'alert_type': 'SYN_FLOOD',
                'severity':   SEVERITY,
                'src_ip':     src_ip,
                'dst_ip':     parsed.get('dst_ip'),
                'protocol':   'TCP',
                'detail':     (
                    f"SYN flood detected: {src_ip} sent {count} SYN packets "
                    f"in {self.window}s. Possible DoS attack."
                ),
                'raw_data': {
                    'syn_count':  count,
                    'window_secs': self.window,
                }
            }
        return None