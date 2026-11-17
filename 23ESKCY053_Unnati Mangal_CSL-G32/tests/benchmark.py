#!/usr/bin/env python3
"""Measure how many ARP packets per second the detector can handle.

Run from the project folder:

    python tests/benchmark.py

Two figures are printed:
  1. the detection engine alone (ArpEvent objects already in memory);
  2. the complete pipeline: read a capture file, let Scapy decode each
     frame, run the engine.
The numbers depend on the computer; the interesting part is their
ratio, which shows where the time is spent.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from arpdetect.capture import PcapSource                    # noqa: E402
from arpdetect.detector import ArpSpoofDetector             # noqa: E402
from arpdetect.events import (ARP_REPLY, ARP_REQUEST, ArpEvent,   # noqa: E402
                              BROADCAST_MAC, ZERO_MAC)

HOSTS = 50               # size of the simulated LAN
ENGINE_EVENTS = 100000   # packets for the engine-only test
PCAP_FRAMES = 5000       # frames for the full-pipeline test
BAD_MAC = "02:bb:00:00:00:66"


def host(i: int):
    return "192.168.56.%d" % (i + 1), "02:aa:00:00:00:%02x" % (i + 1)


def synthetic_events(count: int):
    """Request/reply pairs between 50 hosts; every 100th reply is forged."""
    events = []
    t = 0.0
    i = 0
    while len(events) < count:
        a_ip, a_mac = host(i % HOSTS)
        b_ip, b_mac = host((i * 7 + 3) % HOSTS)
        t += 0.01
        events.append(ArpEvent(t, ARP_REQUEST, a_mac, BROADCAST_MAC, a_mac,
                               a_ip, ZERO_MAC, b_ip, len(events) + 1))
        mac = BAD_MAC if i % 100 == 99 else b_mac
        events.append(ArpEvent(t + 0.0004, ARP_REPLY, mac, a_mac, mac, b_ip,
                               a_mac, a_ip, len(events) + 1))
        i += 1
    return events[:count]


def main() -> int:
    print("Benchmark of the ARP Spoofing Detector (LAN of %d hosts)" % HOSTS)

    events = synthetic_events(ENGINE_EVENTS)
    detector = ArpSpoofDetector()
    start = time.perf_counter()
    for event in events:
        detector.process(event)
    engine_rate = len(events) / (time.perf_counter() - start)
    print("  1. detection engine only : %8d packets  -> %9.0f packets/s"
          % (len(events), engine_rate))

    from scapy.layers.l2 import ARP, Ether
    from scapy.utils import wrpcap
    packets = []
    for event in events[:PCAP_FRAMES]:
        pkt = (Ether(src=event.eth_src, dst=event.eth_dst)
               / ARP(op=event.op, hwsrc=event.sender_mac, psrc=event.sender_ip,
                     hwdst=event.target_mac, pdst=event.target_ip))
        pkt.time = 1000.0 + event.time
        packets.append(pkt)
    handle = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    handle.close()
    try:
        wrpcap(handle.name, packets)
        detector = ArpSpoofDetector()
        start = time.perf_counter()
        for event in PcapSource(handle.name):
            detector.process(event)
        pipeline_rate = len(packets) / (time.perf_counter() - start)
    finally:
        os.remove(handle.name)
    print("  2. pcap + Scapy + engine : %8d packets  -> %9.0f packets/s"
          % (len(packets), pipeline_rate))
    print("  Decoding the frames with Scapy costs about %.0f times more than"
          % (engine_rate / pipeline_rate))
    print("  the detection rules themselves.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
