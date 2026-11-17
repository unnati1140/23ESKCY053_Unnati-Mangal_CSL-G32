#!/usr/bin/env python3
"""Draw the result graphs of the project (needs matplotlib).

Run from the project folder:

    python tools/plot_results.py

Four PNG files are written to results/:

  fig_binding_timeline.png   which MAC the table holds for the two
                             poisoned IPs during scenario S2
  fig_garp_window.png        gratuitous ARPs inside the 10 s window
                             during the flood of scenario S3
  fig_threshold_study.png    false alarms and detection delay for
                             different flood thresholds
  fig_alerts_per_run.png     alerts per evaluation run, by severity

The graphs use line styles and hatching in addition to colour, so that
they stay readable in a black-and-white print.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "lab"))

try:
    import matplotlib
    matplotlib.use("Agg")                       # draw to files, no window
    import matplotlib.pyplot as plt
except ImportError:
    raise SystemExit("matplotlib is not installed.  Run:  pip install matplotlib")

from arpdetect.alerts import SEVERITY_ORDER                 # noqa: E402
from arpdetect.capture import PcapSource                    # noqa: E402
from arpdetect.config import DetectorConfig, load_trusted   # noqa: E402
from arpdetect.detector import ArpSpoofDetector             # noqa: E402
from lab_network import ATTACKER, GATEWAY, PC_A             # noqa: E402

RESULTS = os.path.join(ROOT, "results")
SAMPLES = os.path.join(ROOT, "samples")

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 9,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.alpha": 0.35,
    "grid.linewidth": 0.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
})
DARK, RED, BLUE, GREY = "#222222", "#b22222", "#1f4e79", "#7f7f7f"


def load_runs():
    with open(os.path.join(SAMPLES, "scenarios.json"), encoding="utf-8") as fh:
        return json.load(fh)


def events_of(file_name):
    return list(PcapSource(os.path.join(SAMPLES, file_name)))


# ----------------------------------------------------------------------
def plot_binding_timeline() -> str:
    """Scenario S2: owner of the gateway's and PC-A's IP over time."""
    events = events_of("s2_mitm_poisoning.pcap")
    t0 = events[0].time
    detector = ArpSpoofDetector()
    watched = [(GATEWAY, "192.168.56.1 (gateway)"), (PC_A, "192.168.56.10 (PC-A)")]
    series = {host.ip: ([], []) for host, _ in watched}
    for event in events:
        detector.process(event)
        for host, _ in watched:
            entry = detector.table.get(host.ip)
            if entry is not None:
                times, values = series[host.ip]
                times.append(event.time - t0)
                values.append(1 if entry.mac == ATTACKER.mac else 0)

    fig, axes = plt.subplots(2, 1, figsize=(6.3, 3.3), sharex=True)
    for axis, (host, label) in zip(axes, watched):
        times, values = series[host.ip]
        axis.step(times, values, where="post", color=DARK, linewidth=1.2)
        axis.set_yticks([0, 1])
        axis.set_yticklabels(["real MAC", "attacker MAC"])
        axis.set_ylim(-0.3, 1.55)
        axis.set_title("Table entry for " + label, loc="left", fontsize=9)
        for alert in detector.alerts:
            if alert.ip == host.ip and alert.rule in ("R1", "R2"):
                x = alert.time - t0
                axis.axvline(x, color=RED, linestyle="--", linewidth=0.9)
                axis.text(x + 0.4, 1.3, alert.rule, color=RED, fontsize=8,
                          fontweight="bold")
    axes[-1].set_xlabel("time since start of capture (s)")
    path = os.path.join(RESULTS, "fig_binding_timeline.png")
    fig.savefig(path)
    plt.close(fig)
    return path


# ----------------------------------------------------------------------
def plot_garp_window() -> str:
    """Scenario S3: gratuitous ARPs inside the sliding window."""
    cfg = DetectorConfig()
    events = events_of("s3_garp_flood.pcap")
    t0 = events[0].time
    stamps = {ATTACKER.mac: [], GATEWAY.mac: []}
    for event in events:
        if event.is_gratuitous and event.sender_mac in stamps:
            stamps[event.sender_mac].append(event.time - t0)

    detector = ArpSpoofDetector(cfg)
    for event in events:
        detector.process(event)
    flood_alert = next(a for a in detector.alerts if a.rule == "R4")

    grid = [i * 0.05 for i in range(0, 701)]              # 0 ... 35 s

    def in_window(times, now):
        return sum(1 for t in times if 0 <= now - t <= cfg.flood_window)

    fig, axis = plt.subplots(figsize=(6.3, 2.7))
    axis.plot(grid, [in_window(stamps[ATTACKER.mac], t) for t in grid],
              color=DARK, linewidth=1.3, label="attacker 02:bb:00:00:00:66")
    axis.plot(grid, [in_window(stamps[GATEWAY.mac], t) for t in grid],
              color=BLUE, linewidth=1.3, linestyle=":",
              label="gateway 02:aa:00:00:00:01")
    axis.axhline(cfg.flood_threshold, color=RED, linestyle="--", linewidth=1.0,
                 label="threshold = %d" % cfg.flood_threshold)
    x = flood_alert.time - t0
    axis.annotate("R4 alert at %.1f s" % x, xy=(x, cfg.flood_threshold),
                  xytext=(x - 11.5, 22), fontsize=8, color=RED,
                  arrowprops=dict(arrowstyle="->", color=RED, linewidth=0.8))
    axis.set_xlabel("time since start of capture (s)")
    axis.set_ylabel("gratuitous ARPs in the last %g s" % cfg.flood_window)
    axis.set_xlim(0, 35)
    axis.set_ylim(0, 55)
    axis.legend(loc="upper left", fontsize=8, frameon=False)
    path = os.path.join(RESULTS, "fig_garp_window.png")
    fig.savefig(path)
    plt.close(fig)
    return path


# ----------------------------------------------------------------------
def plot_threshold_study() -> str:
    """False alarms (S1) and detection delay (S3) against the threshold."""
    thresholds = (2, 3, 4, 5, 8, 10, 20, 30, 50, 60)
    flood = next(run for run in load_runs() if run["id"] == "S3")
    false_alarms, delays = [], []
    for threshold in thresholds:
        cfg = DetectorConfig(flood_threshold=threshold)
        quiet = ArpSpoofDetector(cfg)
        for event in events_of("s1_normal.pcap"):
            quiet.process(event)
        false_alarms.append(sum(1 for a in quiet.alerts if a.rule == "R4"))
        noisy = ArpSpoofDetector(cfg)
        for event in events_of("s3_garp_flood.pcap"):
            noisy.process(event)
        hits = [a for a in noisy.alerts if a.rule == "R4"]
        delays.append(hits[0].time - flood["first_forged_time"] if hits else None)

    labels = [str(t) for t in thresholds]
    positions = list(range(len(thresholds)))
    fig, (left, right) = plt.subplots(1, 2, figsize=(6.3, 2.5))

    left.bar(positions, false_alarms, color="#bdbdbd", edgecolor=DARK,
             hatch="///", linewidth=0.8)
    left.set_xticks(positions)
    left.set_xticklabels(labels)
    left.set_ylim(0, max(false_alarms) + 1)
    left.set_xlabel("flood threshold")
    left.set_ylabel("false R4 alerts on normal traffic (S1)")

    found = [(p, d) for p, d in zip(positions, delays) if d is not None]
    right.plot([p for p, _ in found], [d for _, d in found], color=DARK,
               marker="o", markersize=4, linewidth=1.2)
    for p, d in zip(positions, delays):
        if d is None:
            right.plot([p], [0.15], marker="x", color=RED, markersize=8,
                       markeredgewidth=2, linestyle="none")
            right.text(p - 0.2, 0.75, "missed", color=RED, fontsize=8,
                       ha="right")
    right.set_xticks(positions)
    right.set_xticklabels(labels)
    right.set_ylim(0, 5.5)
    right.set_xlabel("flood threshold")
    right.set_ylabel("delay until the flood alert (s), S3")
    default_pos = thresholds.index(DetectorConfig().flood_threshold)
    for axis in (left, right):
        axis.axvline(default_pos, color=GREY, linestyle=":", linewidth=1.0)
    left.text(default_pos + 0.15, max(false_alarms) + 0.45, "default",
              fontsize=8, color=GREY)
    fig.tight_layout()
    path = os.path.join(RESULTS, "fig_threshold_study.png")
    fig.savefig(path)
    plt.close(fig)
    return path


# ----------------------------------------------------------------------
def plot_alerts_per_run() -> str:
    """Stacked bars: alerts shown in every evaluation run, by severity."""
    runs = load_runs()
    counts = {severity: [] for severity in SEVERITY_ORDER}
    for run in runs:
        trusted = load_trusted(os.path.join(ROOT, run["trusted"])) \
            if run["trusted"] else {}
        detector = ArpSpoofDetector(DetectorConfig(), trusted)
        for event in events_of(run["file"]):
            detector.process(event)
        for severity in SEVERITY_ORDER:
            counts[severity].append(sum(1 for a in detector.alerts
                                        if a.severity == severity))

    style = {"LOW": ("#ffffff", ""), "MEDIUM": ("#d9d9d9", "..."),
             "HIGH": ("#969696", "///"), "CRITICAL": ("#252525", "")}
    positions = list(range(len(runs)))
    bottom = [0] * len(runs)
    fig, axis = plt.subplots(figsize=(6.3, 2.6))
    for severity in reversed(SEVERITY_ORDER):             # LOW at the bottom
        colour, hatch = style[severity]
        axis.bar(positions, counts[severity], bottom=bottom, color=colour,
                 edgecolor=DARK, hatch=hatch, linewidth=0.8, label=severity)
        bottom = [b + c for b, c in zip(bottom, counts[severity])]
    for p, total in zip(positions, bottom):
        axis.text(p, total + 0.15, str(total), ha="center", fontsize=8)
    axis.set_xticks(positions)
    axis.set_xticklabels(["%s\n(%s)" % (run["id"], run["kind"])
                          for run in runs])
    axis.set_ylabel("alerts shown")
    axis.set_ylim(0, max(bottom) + 1.5)
    handles, labels = axis.get_legend_handles_labels()
    axis.legend(handles[::-1], labels[::-1], ncol=4, fontsize=8,
                frameon=False, loc="upper left")
    path = os.path.join(RESULTS, "fig_alerts_per_run.png")
    fig.savefig(path)
    plt.close(fig)
    return path


def main() -> int:
    os.makedirs(RESULTS, exist_ok=True)
    for draw in (plot_binding_timeline, plot_garp_window,
                 plot_threshold_study, plot_alerts_per_run):
        print("wrote", os.path.relpath(draw(), ROOT).replace(os.sep, "/"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
