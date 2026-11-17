"""Plain-text output: banner, alert lines, tables, summary and CSV files.

Only ASCII characters are printed, so the output looks the same in the
Windows Command Prompt, PowerShell, a Linux terminal or a text file.
"""

from __future__ import annotations

import csv
import os
import sys
import textwrap
import time
from typing import Iterable, List, Optional, Sequence

from . import __version__
from .alerts import Alert, CRITICAL, HIGH, LOW, MEDIUM, RULES, SEVERITY_ORDER
from .detector import ArpSpoofDetector

WIDTH = 94                       # width of the rulers
INDENT = " " * 12                # continuation lines are aligned under the text

# ANSI colour codes (only used when the terminal supports them)
_COLOURS = {CRITICAL: "1;31", HIGH: "31", MEDIUM: "33", LOW: "36",
            "note": "32", "title": "1"}


def _enable_windows_ansi() -> bool:
    """Switch the Windows console to ANSI (VT100) mode; False if impossible."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        handle = ctypes.c_void_p(kernel32.GetStdHandle(-11))   # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def colour_supported(choice: str = "auto") -> bool:
    """Decide whether coloured output should be used."""
    if choice == "always":
        if os.name == "nt":
            _enable_windows_ansi()
        return True
    if choice == "never" or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_ansi()
    return True


class Printer:
    """Writes everything the user sees."""

    def __init__(self, use_colour: bool = False, relative_time: bool = True,
                 quiet: bool = False):
        self.use_colour = use_colour
        self.relative_time = relative_time   # +seconds (file) or clock (live)
        self.quiet = quiet                   # hide 'new host' lines
        self._t0: Optional[float] = None

    # -- small helpers --------------------------------------------------
    def paint(self, text: str, kind: str) -> str:
        if not self.use_colour or kind not in _COLOURS:
            return text
        return "\033[%sm%s\033[0m" % (_COLOURS[kind], text)

    def stamp(self, t: float) -> str:
        """Timestamp column: seconds since the first packet, or clock time."""
        if self.relative_time:
            if self._t0 is None:
                self._t0 = t
            return "[+%07.3fs]" % (t - self._t0)
        return "[%s] " % time.strftime("%H:%M:%S", time.localtime(t))

    @staticmethod
    def ruler(char: str = "-") -> None:
        print(char * WIDTH)

    # -- banner ---------------------------------------------------------
    def banner(self, source: str, detector: ArpSpoofDetector) -> None:
        cfg = detector.cfg
        self.ruler("=")
        print(self.paint(" ARP Spoofing Detector v%s  |  Mini Project CSL-032  |"
                         "  Unnati Mangal (23ESKCY053)" % __version__, "title"))
        self.ruler("=")
        print(" Source  : %s" % source)
        print(" Rules   : flood >= %d gratuitous ARPs in %g s | TTL %g s | "
              "multi-IP >= %d | cooldown %g s"
              % (cfg.flood_threshold, cfg.flood_window, cfg.binding_ttl,
                 cfg.multi_ip_threshold, cfg.alert_cooldown))
        if detector.trusted:
            print(" Trusted : %d binding(s) - %s" % (
                len(detector.trusted),
                ", ".join("%s=%s" % item for item in detector.trusted.items())))
        else:
            print(" Trusted : none (bindings are learnt from the traffic)")
        self.ruler()
        sys.stdout.flush()

    # -- per-packet lines -----------------------------------------------
    def note(self, t: float, text: str) -> None:
        """Informational line such as 'new host ...'."""
        stamp = self.stamp(t)                # always advance the time base
        if not self.quiet:
            print("%s %s" % (stamp, self.paint(text, "note")))
            sys.stdout.flush()

    def packet(self, t: float, frame: int, text: str) -> None:
        """Verbose mode: one line per ARP packet."""
        print("%s #%-5d %s" % (self.stamp(t), frame, text))

    def alert(self, alert: Alert) -> None:
        head = "ALERT #%-3d %-8s %s  %s" % (alert.number, alert.severity,
                                             alert.rule, alert.name)
        print("%s %s  (frame %d)" % (self.stamp(alert.time),
                                     self.paint(head, alert.severity),
                                     alert.frame))
        for line in textwrap.wrap(alert.message, WIDTH - len(INDENT)):
            print(INDENT + line)
        sys.stdout.flush()

    # -- summary ----------------------------------------------------------
    def summary(self, detector: ArpSpoofDetector,
                frames: Optional[int] = None) -> None:
        stats = detector.stats
        self.ruler()
        print(self.paint("SUMMARY", "title"))
        if frames is not None:
            print("  Frames read    : %d (%d of them ARP)"
                  % (frames, stats["packets"]))
        print("  ARP packets    : %d = %d requests + %d replies "
              "(%d gratuitous, %d probes)"
              % (stats["packets"], stats["requests"], stats["replies"],
                 stats["gratuitous"], stats["probes"]))
        print("  Hosts in table : %d" % len(detector.table))

        shown = len(detector.alerts)
        hidden = sum(detector.suppressed.values())
        if shown:
            per_sev = ["%s %d" % (sev, sum(1 for a in detector.alerts
                                            if a.severity == sev))
                       for sev in SEVERITY_ORDER
                       if any(a.severity == sev for a in detector.alerts)]
            print("  Alerts         : %d shown (%s), %d repeats suppressed"
                  % (shown, ", ".join(per_sev), hidden))
        else:
            print("  Alerts         : 0")

        print()
        print("IP-MAC TABLE")
        rows = []
        for b in detector.table.rows():
            remark = []
            if b.ip in detector.trusted:
                remark.append("trusted")
            if b.changes:
                remark.append("CHANGED %dx - verify" % b.changes)
            rows.append((b.ip, b.mac, b.packets, b.changes, ", ".join(remark)))
        for ip, mac in sorted(detector.trusted.items()):
            if detector.table.get(ip) is None:
                rows.append((ip, mac, 0, 0, "trusted (not seen yet)"))
        print_table(("IP address", "MAC address", "Packets", "Changes", "Remark"),
                    rows)

        if shown:
            print()
            print("ALERTS BY RULE")
            counts = detector.alerts_per_rule()
            rule_ids = sorted(set(counts) | set(detector.suppressed))
            print_table(("Rule", "Name", "Severity", "Shown", "Suppressed"),
                        [(rid, RULES[rid].name, RULES[rid].severity,
                          counts.get(rid, 0), detector.suppressed.get(rid, 0))
                         for rid in rule_ids])
        print()
        if shown:
            worst = next(sev for sev in SEVERITY_ORDER
                         if any(a.severity == sev for a in detector.alerts))
            verdict = ("RESULT: suspicious ARP activity detected "
                       "(highest severity: %s)" % worst)
            print(self.paint(verdict, worst))
        else:
            print(self.paint("RESULT: no suspicious ARP activity detected",
                             "note"))
        sys.stdout.flush()


def print_table(headers: Sequence[str], rows: Iterable[Sequence]) -> None:
    """Print a simple ASCII table with a border."""
    rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  +" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(cells: Sequence[str]) -> str:
        return "  |" + "|".join(" %-*s " % (w, c)
                                for w, c in zip(widths, cells)) + "|"

    print(line)
    print(fmt(headers))
    print(line)
    for row in rows:
        print(fmt(row))
    print(line)


# ----------------------------------------------------------------------
# CSV files
# ----------------------------------------------------------------------
def write_alert_log(path: str, alerts: List[Alert]) -> None:
    """Save all alerts as a CSV file (opens directly in Excel)."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["alert", "timestamp", "frame", "severity", "rule",
                         "name", "ip", "mac", "previous_mac", "message"])
        for a in alerts:
            writer.writerow([a.number, "%.6f" % a.time, a.frame, a.severity,
                             a.rule, a.name, a.ip, a.mac, a.old_mac, a.message])


def write_table(path: str, detector: ArpSpoofDetector) -> None:
    """Save the learnt IP-MAC table as a CSV file."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "mac", "first_seen", "last_seen", "packets",
                         "changes", "trusted", "previous_macs"])
        for b in detector.table.rows():
            previous = " ".join(dict.fromkeys(mac for _, mac in b.history))
            writer.writerow([b.ip, b.mac, "%.6f" % b.first_seen,
                             "%.6f" % b.last_seen, b.packets, b.changes,
                             "yes" if b.ip in detector.trusted else "no",
                             previous])
