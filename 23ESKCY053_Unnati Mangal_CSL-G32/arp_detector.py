#!/usr/bin/env python3
"""ARP Spoofing Detector - command-line program.

Mini Project CSL-032, Cyber Security Lab (7CS4-22)
Unnati Mangal, Roll No. 23ESKCY053, SKIT Jaipur

Monitors ARP traffic with Scapy, keeps an IP-MAC table and raises an
alert when a binding conflicts with what was seen before or when a
station floods the LAN with gratuitous ARPs.

Examples
--------
  python arp_detector.py --list-interfaces
  python arp_detector.py --iface "Wi-Fi"                 (live capture)
  python arp_detector.py --read samples/s2_mitm_poisoning.pcap
  python arp_detector.py --read samples/s3_garp_flood.pcap --realtime
  python arp_detector.py --read samples/s7_poisoned_before_start.pcap
                         --trusted config/trusted_bindings.txt

Live capture only listens; this program never transmits a packet.
"""

from __future__ import annotations

import argparse
import os
import sys

from arpdetect import __version__
from arpdetect.config import DetectorConfig, load_trusted
from arpdetect.console import (Printer, colour_supported, print_table,
                               write_alert_log, write_table)
from arpdetect.detector import ArpSpoofDetector

DEFAULT_IFACE = "<default>"      # marker: --iface given without a name


def build_parser() -> argparse.ArgumentParser:
    defaults = DetectorConfig()
    parser = argparse.ArgumentParser(
        prog="arp_detector.py",
        description="ARP Spoofing Detector: monitors ARP traffic, keeps an "
                    "IP-MAC table and alerts on conflicts and gratuitous "
                    "ARP floods.")
    parser.add_argument("--version", action="version",
                        version="ARP Spoofing Detector " + __version__)

    source = parser.add_argument_group("packet source (choose one)")
    choice = source.add_mutually_exclusive_group(required=True)
    choice.add_argument("-i", "--iface", nargs="?", const=DEFAULT_IFACE,
                        metavar="NAME",
                        help="capture live from this interface "
                             "(no name = default interface)")
    choice.add_argument("-r", "--read", metavar="FILE",
                        help="analyse a saved capture (.pcap / .pcapng)")
    choice.add_argument("-L", "--list-interfaces", action="store_true",
                        help="list the network interfaces and exit")

    source.add_argument("--realtime", action="store_true",
                        help="with --read: replay the capture with its "
                             "original timing, like live traffic")
    source.add_argument("--speed", type=float, default=1.0, metavar="X",
                        help="with --realtime: replay X times faster "
                             "(default 1)")
    source.add_argument("--count", type=int, default=0, metavar="N",
                        help="with --iface: stop after N ARP packets")
    source.add_argument("--duration", type=float, default=None, metavar="SEC",
                        help="with --iface: stop after SEC seconds")

    rules = parser.add_argument_group("detection settings")
    rules.add_argument("--trusted", metavar="FILE",
                       help="file with trusted 'IP MAC' bindings (rule R3)")
    rules.add_argument("--flood-threshold", type=int, metavar="N",
                       default=defaults.flood_threshold,
                       help="gratuitous ARPs from one MAC that count as a "
                            "flood (default %(default)s)")
    rules.add_argument("--flood-window", type=float, metavar="SEC",
                       default=defaults.flood_window,
                       help="time window for the flood count "
                            "(default %(default)s s)")
    rules.add_argument("--ttl", type=float, metavar="SEC",
                       default=defaults.binding_ttl,
                       help="a binding not seen for SEC seconds may change "
                            "without an alert; 0 = never (default %(default)s)")
    rules.add_argument("--max-ips", type=int, metavar="N",
                       default=defaults.multi_ip_threshold,
                       help="alert when one MAC claims N or more IPs "
                            "(default %(default)s)")
    rules.add_argument("--cooldown", type=float, metavar="SEC",
                       default=defaults.alert_cooldown,
                       help="show the same alert at most once per SEC "
                            "seconds (default %(default)s)")

    output = parser.add_argument_group("output")
    output.add_argument("--log", metavar="FILE",
                        help="save the alerts to a CSV file")
    output.add_argument("--export-table", metavar="FILE",
                        help="save the learnt IP-MAC table to a CSV file")
    output.add_argument("-q", "--quiet", action="store_true",
                        help="show only alerts and the summary")
    output.add_argument("-v", "--verbose", action="store_true",
                        help="show every ARP packet")
    output.add_argument("--color", choices=("auto", "always", "never"),
                        default="auto", help="coloured output (default auto)")
    return parser


def has_admin_rights() -> bool:
    """Live capture normally needs Administrator (Windows) / root (Linux)."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return True                      # unknown: do not print a warning


def show_interfaces() -> int:
    from arpdetect.capture import default_interface, list_interfaces
    rows = list_interfaces()
    print("Network interfaces visible to Scapy:")
    print_table(("Name", "Description", "MAC address", "IPv4 address"), rows)
    print("Default interface: %s" % default_interface())
    print('Use:  python arp_detector.py --iface "<Name>"')
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        from arpdetect import capture
    except ImportError:
        print("Scapy is not installed.  Install it with:  pip install scapy",
              file=sys.stderr)
        return 2

    if args.list_interfaces:
        return show_interfaces()
    if args.read and not os.path.isfile(args.read):
        print("File not found: %s" % args.read, file=sys.stderr)
        return 2

    # ---- build the detector from the command-line settings -------------
    config = DetectorConfig(flood_threshold=args.flood_threshold,
                            flood_window=args.flood_window,
                            binding_ttl=args.ttl,
                            multi_ip_threshold=args.max_ips,
                            alert_cooldown=args.cooldown)
    trusted = {}
    if args.trusted:
        try:
            trusted = load_trusted(args.trusted)
        except (OSError, ValueError) as exc:
            print("Cannot read trusted bindings: %s" % exc, file=sys.stderr)
            return 2
    detector = ArpSpoofDetector(config, trusted)

    live = args.iface is not None
    printer = Printer(use_colour=colour_supported(args.color),
                      relative_time=not live, quiet=args.quiet)

    def on_event(event) -> None:
        """Called for every ARP packet, whatever the source."""
        if args.verbose:
            printer.packet(event.time, event.frame, event.describe())
        alerts = detector.process(event)
        if detector.note:
            printer.note(event.time, detector.note)
        for alert in alerts:
            printer.alert(alert)

    frames = None
    try:
        if live:
            iface = None if args.iface == DEFAULT_IFACE else args.iface
            shown = iface or capture.default_interface()
            printer.banner("live capture on interface '%s' (Ctrl+C to stop)"
                           % shown, detector)
            if not has_admin_rights():
                print("Note: not running as Administrator/root - live "
                      "capture may be refused.")
            capture.sniff_live(iface, on_event, count=args.count,
                               duration=args.duration)
        else:
            mode = "replayed in real time" if args.realtime else "pcap file"
            printer.banner("%s %s" % (mode, args.read), detector)
            source = capture.PcapSource(args.read, realtime=args.realtime,
                                        speed=args.speed)
            for event in source:
                on_event(event)
            frames = source.frames
    except KeyboardInterrupt:
        print()                              # Ctrl+C: finish with the summary
    except Exception as exc:                 # capture could not be started
        print("Capture failed: %s" % exc, file=sys.stderr)
        if live:
            print("Check the interface name (--list-interfaces).  On Windows "
                  "install Npcap (https://npcap.com) and open the terminal "
                  "as Administrator; on Linux run with sudo.", file=sys.stderr)
        else:
            print("Is the file a valid .pcap / .pcapng capture?",
                  file=sys.stderr)
        return 2

    printer.summary(detector, frames)

    if args.log:
        write_alert_log(args.log, detector.alerts)
        print("Alerts saved to %s" % args.log)
    if args.export_table:
        write_table(args.export_table, detector)
        print("IP-MAC table saved to %s" % args.export_table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
