#!/usr/bin/env python3
"""Evaluate the detector on all lab scenarios.

Run from the project folder:

    python tests/run_evaluation.py

Every capture listed in samples/scenarios.json is analysed with the
default settings.  The rules that fired are compared with the rules
that are expected to fire (the ground truth), and the delay between
the first forged frame and the first HIGH/CRITICAL alert is measured.
The table is also saved as results/evaluation.csv.
"""

from __future__ import annotations

import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from arpdetect.alerts import CRITICAL, HIGH                 # noqa: E402
from arpdetect.capture import PcapSource                    # noqa: E402
from arpdetect.config import DetectorConfig, load_trusted   # noqa: E402
from arpdetect.detector import ArpSpoofDetector             # noqa: E402

SERIOUS = (HIGH, CRITICAL)


def analyse(run: dict) -> dict:
    """Run the detector over one capture and collect the facts."""
    trusted = {}
    if run["trusted"]:
        trusted = load_trusted(os.path.join(ROOT, run["trusted"]))
    detector = ArpSpoofDetector(DetectorConfig(), trusted)
    for event in PcapSource(os.path.join(ROOT, "samples", run["file"])):
        detector.process(event)

    fired = sorted(detector.alerts_per_rule())
    serious = [a for a in detector.alerts if a.severity in SERIOUS]
    delay = missed = None
    if serious and run["first_forged_time"] is not None:
        first = serious[0]
        delay = first.time - run["first_forged_time"]
        # forged frames that passed before the first serious alert
        missed = sum(1 for n in run["forged_frame_numbers"] if n < first.frame)
    return {
        "fired": fired,
        "alerts": len(detector.alerts),
        "serious": len(serious),
        "suppressed": sum(detector.suppressed.values()),
        "delay": delay,
        "missed": missed,
        "ok": fired == sorted(run["expected_rules"]),
    }


def main() -> int:
    with open(os.path.join(ROOT, "samples", "scenarios.json"),
              encoding="utf-8") as handle:
        runs = json.load(handle)

    print("ARP Spoofing Detector - evaluation on the lab scenarios "
          "(default settings)")
    print("=" * 94)
    print(" %-5s %-28s %-6s %4s %6s  %-12s %-12s %6s %7s  %s"
          % ("Run", "Capture", "Kind", "ARP", "Forged", "Expected",
             "Fired", "Alerts", "Delay", "Check"))
    print("-" * 94)

    rows = []
    tally = {"attack": [0, 0], "benign": [0, 0]}   # [serious alert, none]
    all_ok = True
    for run in runs:
        result = analyse(run)
        all_ok = all_ok and result["ok"]
        tally[run["kind"]][0 if result["serious"] else 1] += 1
        delay = "-" if result["delay"] is None else "%.3f s" % result["delay"]
        name = run["file"].replace(".pcap", "")
        print(" %-5s %-28s %-6s %4d %6d  %-12s %-12s %6d %7s  %s"
              % (run["id"], name[:28], run["kind"], run["arp_frames"],
                 run["forged_frames"],
                 " ".join(run["expected_rules"]) or "none",
                 " ".join(result["fired"]) or "none",
                 result["alerts"], delay,
                 "PASS" if result["ok"] else "FAIL"))
        rows.append([run["id"], run["file"], run["trusted"] or "",
                     run["kind"], run["frames"], run["arp_frames"],
                     run["forged_frames"], " ".join(run["expected_rules"]),
                     " ".join(result["fired"]), result["alerts"],
                     result["serious"], result["suppressed"],
                     "" if result["delay"] is None else "%.3f" % result["delay"],
                     "" if result["missed"] is None else result["missed"],
                     "PASS" if result["ok"] else "FAIL"])
    print("-" * 94)
    print(" Delay = time from the first forged frame to the first HIGH or "
          "CRITICAL alert.")
    print(" S7+T  = scenario 7 analysed again with --trusted "
          "config/trusted_bindings.txt")

    attack_hit, attack_miss = tally["attack"]
    benign_alarm, benign_quiet = tally["benign"]
    print()
    print("Scenario-level result (a run counts as 'alarm' if it raised a "
          "HIGH or CRITICAL alert)")
    print("  %-22s %7s %9s" % ("", "alarm", "no alarm"))
    print("  %-22s %7d %9d" % ("attack runs (%d)" % (attack_hit + attack_miss),
                               attack_hit, attack_miss))
    print("  %-22s %7d %9d" % ("benign runs (%d)" % (benign_alarm + benign_quiet),
                               benign_alarm, benign_quiet))
    if attack_hit + attack_miss:
        print("  Detection rate   : %d / %d attack runs = %.1f %%"
              % (attack_hit, attack_hit + attack_miss,
                 100.0 * attack_hit / (attack_hit + attack_miss)))
    if benign_alarm + benign_quiet:
        print("  False-alarm runs : %d / %d benign runs"
              % (benign_alarm, benign_alarm + benign_quiet))
    print("  Rule check       : %d / %d runs fired exactly the expected rules"
          % (sum(1 for r in rows if r[-1] == "PASS"), len(rows)))

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    out = os.path.join(ROOT, "results", "evaluation.csv")
    with open(out, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["run", "capture", "trusted_file", "kind", "frames",
                         "arp_frames", "forged_frames", "expected_rules",
                         "fired_rules", "alerts_shown", "serious_alerts",
                         "repeats_suppressed", "delay_s",
                         "forged_frames_before_alarm", "check"])
        writer.writerows(rows)
    print()
    print("Saved results/evaluation.csv")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
