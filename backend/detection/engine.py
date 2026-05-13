"""
engine.py — Central detection engine
Routes every parsed packet through all registered detectors and
returns a list of triggered alerts (may be empty).
"""

from detection.port_scan import PortScanDetector
from detection.syn_flood import SynFloodDetector
from detection.icmp_flood import IcmpFloodDetector, HighFrequencyIPDetector


class DetectionEngine:
    def __init__(self):
        self._detectors = [
            PortScanDetector(),
            SynFloodDetector(),
            IcmpFloodDetector(),
            HighFrequencyIPDetector(),
        ]

    def analyze(self, parsed: dict) -> list[dict]:
        """
        Run all detectors against the parsed packet.
        Returns a (possibly empty) list of alert dicts.
        """
        alerts = []
        for detector in self._detectors:
            try:
                result = detector.inspect(parsed)
                if result:
                    alerts.append(result)
            except Exception as exc:
                print(f"[Engine] Detector error: {exc}")
        return alerts