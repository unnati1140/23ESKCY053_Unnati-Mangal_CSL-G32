#!/usr/bin/env python3
"""How should the gratuitous-ARP flood threshold (rule R4) be chosen?

Run from the project folder:

    python tests/threshold_study.py

The normal capture S1 and the flood capture S3 are analysed with
different thresholds.  A threshold that is too low raises false alarms
on S1 (every booting host announces itself twice); a threshold that is
too high detects the flood late or not at all.
The table is also saved as results/threshold_study.csv.
"""

from __future__ import annotations

import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from arpdetect.capture import PcapSource                    # noqa: E402
from arpdetect.config import DetectorConfig                 # noqa: E402
from arpdetect.detector import ArpSpoofDetector             # noqa: E402

THRESHOLDS = (2, 3, 4, 5, 8, 10, 20, 30, 50, 60)


def flood_alerts(file_name: str, threshold: int):
    """All R4 alerts raised on one capture with the given threshold."""
    detector = ArpSpoofDetector(DetectorConfig(flood_threshold=threshold))
    for event in PcapSource(os.path.join(ROOT, "samples", file_name)):
        detector.process(event)
    return [a for a in detector.alerts if a.rule == "R4"]


def main() -> int:
    with open(os.path.join(ROOT, "samples", "scenarios.json"),
              encoding="utf-8") as handle:
        runs = {run["id"]: run for run in json.load(handle)}
    flood = runs["S3"]
    default = DetectorConfig().flood_threshold

    print("Flood threshold study for rule R4 (window %g s)"
          % DetectorConfig().flood_window)
    print("  S1 = normal traffic, S3 = %d forged gratuitous ARPs in 5 s"
          % flood["forged_frames"])
    print("-" * 78)
    print(" %-10s  %-19s  %-15s  %-14s  %s"
          % ("Threshold", "False alarms on S1", "Flood detected",
             "At forged ARP", "Delay"))
    print("-" * 78)
    rows = []
    for threshold in THRESHOLDS:
        false_alarms = len(flood_alerts("s1_normal.pcap", threshold))
        hits = flood_alerts("s3_garp_flood.pcap", threshold)
        if hits:
            first = hits[0]
            position = sum(1 for n in flood["forged_frame_numbers"]
                           if n <= first.frame)
            delay = first.time - flood["first_forged_time"]
            detected, at, delay_text = "yes", "no. %d" % position, "%.1f s" % delay
        else:
            position, delay = "", ""
            detected, at, delay_text = "NO (missed)", "-", "-"
        label = "%d%s" % (threshold, " *" if threshold == default else "")
        print(" %-10s  %-19d  %-15s  %-14s  %s"
              % (label, false_alarms, detected, at, delay_text))
        rows.append([threshold, false_alarms, "yes" if hits else "no",
                     position, "%.1f" % delay if hits else ""])
    print("-" * 78)
    print(" * = default value used by the detector")

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with open(os.path.join(ROOT, "results", "threshold_study.csv"), "w",
              newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["threshold", "false_alarms_s1", "flood_detected_s3",
                         "detected_at_forged_arp", "delay_s"])
        writer.writerows(rows)
    print()
    print("Saved results/threshold_study.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
