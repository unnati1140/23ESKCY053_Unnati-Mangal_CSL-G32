#!/usr/bin/env python3
"""List the frames of a capture file, similar to Wireshark's packet list.

    python tools/show_pcap.py samples/s2_mitm_poisoning.pcap
    python tools/show_pcap.py samples/s2_mitm_poisoning.pcap --first 19 --last 30
"""

from __future__ import annotations

import argparse
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import IP                   # noqa: E402
from scapy.layers.l2 import ARP, Ether             # noqa: E402
from scapy.utils import PcapReader                 # noqa: E402


def info(pkt) -> str:
    """Text for the Info column (wording close to Wireshark's)."""
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op == 1:
            if arp.psrc == "0.0.0.0":
                return "Who has %s? (ARP Probe)" % arp.pdst
            if arp.psrc == arp.pdst:
                return "ARP Announcement for %s" % arp.psrc
            return "Who has %s? Tell %s" % (arp.pdst, arp.psrc)
        if arp.psrc == arp.pdst:
            return "Gratuitous ARP for %s (Reply): at %s" % (arp.psrc, arp.hwsrc)
        return "%s is at %s" % (arp.psrc, arp.hwsrc)
    if pkt.haslayer(IP):
        return "IPv4 %s -> %s (not ARP)" % (pkt[IP].src, pkt[IP].dst)
    return pkt.summary()


def main() -> int:
    parser = argparse.ArgumentParser(description="List the frames of a capture.")
    parser.add_argument("file")
    parser.add_argument("--first", type=int, default=1, metavar="N",
                        help="first frame number to show (default 1)")
    parser.add_argument("--last", type=int, default=0, metavar="N",
                        help="last frame number to show (default: all)")
    args = parser.parse_args()

    print("%4s  %10s  %-17s  %-17s  %s"
          % ("No.", "Time", "Source", "Destination", "Info"))
    start = None
    with PcapReader(args.file) as reader:
        for number, pkt in enumerate(reader, start=1):
            if start is None:
                start = float(pkt.time)
            if number < args.first:
                continue
            if args.last and number > args.last:
                break
            eth = pkt[Ether]
            print("%4d  %10.6f  %-17s  %-17s  %s"
                  % (number, float(pkt.time) - start, eth.src, eth.dst,
                     info(pkt)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
