#!/usr/bin/env python3
"""Generate the labelled test captures of the virtual lab LAN.

Run from the project folder:

    python lab/generate_scenarios.py

Seven capture files are written to samples/ together with
samples/scenarios.json, which records for every capture which frames
are forged and which detector rules are expected to fire (the "ground
truth" used by tests/run_evaluation.py).

IMPORTANT: this script only writes files.  It contains no code that
sends a packet, so it cannot disturb any network.  The capture files
can be opened in Wireshark like any real capture.
"""

from __future__ import annotations

import calendar
import json
import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP             # noqa: E402
from scapy.layers.l2 import ARP, Ether             # noqa: E402
from scapy.packet import Padding                   # noqa: E402
from scapy.utils import wrpcap                     # noqa: E402

from lab_network import (ATTACKER, BOGUS_MAC, GATEWAY, INTERNET_HOST,  # noqa: E402
                         IOT_NODE, MONITOR, NEW_ROUTER, PC_A, PC_B, PHONE,
                         SERVER)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")

# Every capture starts at the same arbitrary instant, so that the files
# are identical each time the script is run.
BASE_TIME = calendar.timegm((2026, 11, 1, 0, 0, 0))

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
# An ARP packet is 28 bytes; Ethernet pads the frame to its 60-byte minimum.
PAD = b"\x00" * 18


class Trace:
    """Builds one capture as a list of (time offset, frame, is_forged)."""

    def __init__(self) -> None:
        self._frames = []

    def _add(self, t: float, frame, forged: bool = False) -> None:
        self._frames.append((round(t, 6), frame, forged))

    # ---------------- honest ARP traffic --------------------------------
    def request(self, t, asker, wanted_ip, unicast_to=None) -> None:
        """'Who has wanted_ip? Tell asker.'  Broadcast unless unicast_to."""
        dst = unicast_to.mac if unicast_to else BROADCAST
        self._add(t, Ether(src=asker.mac, dst=dst)
                  / ARP(op=1, hwsrc=asker.mac, psrc=asker.ip,
                        hwdst=ZERO_MAC, pdst=wanted_ip)
                  / Padding(load=PAD))

    def reply(self, t, owner, asker) -> None:
        """'owner.ip is at owner.mac', sent only to the asker."""
        self._add(t, Ether(src=owner.mac, dst=asker.mac)
                  / ARP(op=2, hwsrc=owner.mac, psrc=owner.ip,
                        hwdst=asker.mac, pdst=asker.ip)
                  / Padding(load=PAD))

    def resolve(self, t, asker, owner, unicast=False) -> None:
        """A complete address resolution: request, reply 0.4 ms later.

        unicast=True models a cache refresh, where the request goes
        straight to the MAC the asker already knows.
        """
        self.request(t, asker, owner.ip, unicast_to=owner if unicast else None)
        self.reply(t + 0.0004, owner, asker)

    def probe(self, t, host) -> None:
        """RFC 5227 ARP probe (sender IP 0.0.0.0): 'is my address free?'"""
        self._add(t, Ether(src=host.mac, dst=BROADCAST)
                  / ARP(op=1, hwsrc=host.mac, psrc="0.0.0.0",
                        hwdst=ZERO_MAC, pdst=host.ip)
                  / Padding(load=PAD))

    def announce(self, t, host) -> None:
        """RFC 5227 ARP announcement = legitimate gratuitous ARP."""
        self._add(t, Ether(src=host.mac, dst=BROADCAST)
                  / ARP(op=1, hwsrc=host.mac, psrc=host.ip,
                        hwdst=ZERO_MAC, pdst=host.ip)
                  / Padding(load=PAD))

    def boot(self, t, host) -> None:
        """A host joining the LAN as RFC 5227 prescribes:
        three probes one second apart, then two announcements."""
        for i in range(3):
            self.probe(t + i, host)
        self.announce(t + 4.0, host)
        self.announce(t + 6.0, host)

    # ---------------- ordinary IP traffic (ignored by the detector) -----
    def ip_frame(self, t, src_host, dst_ip, eth_dst, eth_src=None) -> None:
        self._add(t, Ether(src=eth_src or src_host.mac, dst=eth_dst)
                  / IP(src=src_host.ip, dst=dst_ip) / ICMP() / b"lab-ping")

    def ping(self, t, a, b) -> None:
        """ICMP echo request a -> b and the reply 0.3 ms later."""
        self.ip_frame(t, a, b.ip, eth_dst=b.mac)
        self._add(t + 0.0003, Ether(src=b.mac, dst=a.mac)
                  / IP(src=b.ip, dst=a.ip) / ICMP(type=0) / b"lab-ping")

    # ---------------- forged ARP frames (labelled as such) --------------
    def forged_reply(self, t, attacker_mac, claimed_ip, victim,
                     arp_sender_mac=None) -> None:
        """Forged unicast reply telling `victim` that `claimed_ip` is at
        the attacker's MAC (or at `arp_sender_mac`, if given)."""
        self._add(t, Ether(src=attacker_mac, dst=victim.mac)
                  / ARP(op=2, hwsrc=arp_sender_mac or attacker_mac,
                        psrc=claimed_ip, hwdst=victim.mac, pdst=victim.ip)
                  / Padding(load=PAD), forged=True)

    def forged_gratuitous(self, t, attacker_mac, claimed_ip) -> None:
        """Forged broadcast gratuitous ARP: everybody is told at once
        that `claimed_ip` is at the attacker's MAC."""
        self._add(t, Ether(src=attacker_mac, dst=BROADCAST)
                  / ARP(op=2, hwsrc=attacker_mac, psrc=claimed_ip,
                        hwdst=BROADCAST, pdst=claimed_ip)
                  / Padding(load=PAD), forged=True)

    # ---------------- output ---------------------------------------------
    def save(self, path: str) -> dict:
        """Write the capture and return its facts for scenarios.json."""
        ordered = sorted(self._frames, key=lambda item: item[0])
        packets, forged = [], []
        for number, (offset, frame, is_forged) in enumerate(ordered, start=1):
            frame.time = BASE_TIME + offset
            packets.append(frame)
            if is_forged:
                forged.append(number)
        wrpcap(path, packets)
        first_forged_time = None
        if forged:
            first_forged_time = BASE_TIME + ordered[forged[0] - 1][0]
        return {
            "frames": len(packets),
            "arp_frames": sum(1 for p in packets if p.haslayer(ARP)),
            "forged_frames": len(forged),
            "forged_frame_numbers": forged,
            "first_forged_frame": forged[0] if forged else None,
            "first_forged_time": first_forged_time,
            "duration": round(ordered[-1][0] - ordered[0][0], 3),
        }


# ======================================================================
# The seven scenarios
# ======================================================================
def s1_normal() -> Trace:
    """Ordinary LAN life: hosts boot, resolve and refresh addresses."""
    t = Trace()
    t.announce(0.00, GATEWAY)
    t.boot(1.00, PC_A)
    t.boot(3.20, PC_B)
    t.boot(5.10, SERVER)
    t.boot(7.40, IOT_NODE)
    t.resolve(14.30, PC_A, GATEWAY)
    t.ping(14.31, PC_A, GATEWAY)
    t.resolve(16.75, PC_B, GATEWAY)
    t.resolve(19.20, IOT_NODE, SERVER)
    t.resolve(22.60, PC_A, SERVER)
    t.ping(22.61, PC_A, SERVER)
    t.resolve(25.05, MONITOR, GATEWAY)
    t.resolve(28.90, SERVER, GATEWAY)
    t.resolve(33.40, GATEWAY, PC_B)
    t.resolve(38.15, PC_B, SERVER)
    t.resolve(44.70, PC_A, GATEWAY, unicast=True)
    t.resolve(49.30, IOT_NODE, SERVER, unicast=True)
    t.resolve(53.80, GATEWAY, PC_A)
    t.resolve(58.20, PC_B, PC_A)
    t.ping(58.21, PC_B, PC_A)
    return t


def s2_mitm_poisoning() -> Trace:
    """Classic man-in-the-middle: the attacker poisons PC-A and the
    gateway in both directions with forged unicast replies every 2 s."""
    t = Trace()
    t.announce(0.00, GATEWAY)
    t.boot(1.10, PC_A)
    t.resolve(8.60, PC_A, GATEWAY)
    t.ping(8.61, PC_A, GATEWAY)
    t.resolve(10.25, PC_B, GATEWAY)
    t.resolve(12.90, SERVER, GATEWAY)
    t.resolve(15.35, PC_A, SERVER)
    t.resolve(17.80, MONITOR, GATEWAY)
    # Reconnaissance: the attacker learns the MACs of its two victims
    # with perfectly ordinary ARP requests.
    t.resolve(20.30, ATTACKER, GATEWAY)
    t.resolve(20.85, ATTACKER, PC_A)
    # Poisoning, repeated so that the victims' caches never recover.
    for i in range(15):                                   # 24.0 s ... 52.0 s
        at = 24.0 + 2.0 * i
        t.forged_reply(at, ATTACKER.mac, GATEWAY.ip, PC_A)
        t.forged_reply(at + 0.001, ATTACKER.mac, PC_A.ip, GATEWAY)
    # Effect: PC-A's Internet traffic is now addressed to the attacker's
    # MAC, and the attacker passes it on to the real gateway.
    t.ip_frame(26.40, PC_A, INTERNET_HOST, eth_dst=ATTACKER.mac)
    t.ip_frame(26.4003, PC_A, INTERNET_HOST, eth_dst=GATEWAY.mac,
               eth_src=ATTACKER.mac)
    # Honest hosts keep talking while the attack runs.
    t.resolve(33.50, PC_B, GATEWAY)       # the real gateway answers
    t.resolve(41.20, SERVER, PC_A)        # the real PC-A answers
    t.resolve(47.80, PC_A, SERVER)
    return t


def s3_garp_flood() -> Trace:
    """The attacker broadcasts 50 gratuitous ARPs in 5 s, each claiming
    the gateway's IP, to poison every host on the LAN at once."""
    t = Trace()
    t.announce(0.00, GATEWAY)
    t.resolve(2.10, PC_A, GATEWAY)
    t.resolve(4.45, PC_B, GATEWAY)
    t.resolve(6.80, SERVER, GATEWAY)
    t.resolve(9.15, IOT_NODE, SERVER)
    t.resolve(11.60, MONITOR, GATEWAY)
    t.resolve(13.90, PC_A, SERVER)
    for i in range(50):                                   # 16.0 s ... 20.9 s
        t.forged_gratuitous(16.0 + 0.1 * i, ATTACKER.mac, GATEWAY.ip)
    t.resolve(18.247, PC_B, GATEWAY)      # honest reply inside the flood
    t.resolve(23.50, PC_A, GATEWAY)       # and one after it
    return t


def s4_dhcp_reassignment() -> Trace:
    """Harmless change: PC-B is switched off; about seven minutes later
    DHCP gives its address to a phone (old entry is older than the TTL)."""
    t = Trace()
    t.announce(0.00, GATEWAY)
    t.boot(1.00, PC_B)
    t.resolve(8.20, PC_B, GATEWAY)        # last packet of PC-B
    t.resolve(9.60, PC_A, GATEWAY)
    for at in (70.4, 131.7, 192.3, 254.9, 316.2, 377.8):
        t.resolve(at, PC_A, GATEWAY, unicast=True)
    t.boot(420.0, PHONE)                  # same IP as PC-B, new MAC
    t.resolve(427.50, PHONE, GATEWAY)
    return t


def s5_router_replaced() -> Trace:
    """Harmless change that looks like an attack: the router is swapped
    for a new one with the same IP while the old entry is still fresh."""
    t = Trace()
    t.announce(0.00, GATEWAY)
    t.resolve(2.40, PC_A, GATEWAY)
    t.resolve(5.10, PC_B, GATEWAY)
    t.resolve(8.75, SERVER, GATEWAY)
    t.resolve(12.20, IOT_NODE, SERVER)
    t.resolve(15.60, PC_A, GATEWAY, unicast=True)
    t.announce(25.00, NEW_ROUTER)
    t.announce(27.00, NEW_ROUTER)
    t.resolve(29.30, PC_A, NEW_ROUTER)
    t.resolve(33.80, PC_B, NEW_ROUTER)
    t.resolve(38.40, SERVER, NEW_ROUTER)
    t.resolve(44.10, NEW_ROUTER, PC_A)
    return t


def s6_blackhole_forged_headers() -> Trace:
    """Denial of service against the IoT node: forged replies say that
    SERVER is at a MAC that does not exist.  The attacker hides its own
    MAC in the ARP payload, but the Ethernet header still shows it."""
    t = Trace()
    t.announce(0.00, GATEWAY)
    t.boot(0.90, IOT_NODE)
    t.resolve(7.50, IOT_NODE, SERVER)
    t.resolve(9.80, SERVER, GATEWAY)
    t.resolve(12.10, PC_A, SERVER)
    t.resolve(14.40, IOT_NODE, SERVER, unicast=True)
    for i in range(6):                                    # 16 s ... 31 s
        t.forged_reply(16.0 + 3.0 * i, ATTACKER.mac, SERVER.ip, IOT_NODE,
                       arp_sender_mac=BOGUS_MAC)
    t.resolve(24.60, PC_A, SERVER)        # the real server answers PC-A
    t.resolve(33.90, PC_B, SERVER)
    return t


def s7_poisoned_before_start() -> Trace:
    """The capture starts while a man-in-the-middle attack is already
    running, so the first binding the detector sees is the forged one."""
    t = Trace()
    for i in range(15):                                   # 0 s ... 28 s
        at = 2.0 * i
        t.forged_reply(at, ATTACKER.mac, GATEWAY.ip, PC_A)
        t.forged_reply(at + 0.001, ATTACKER.mac, PC_A.ip, GATEWAY)
    t.ip_frame(1.10, PC_A, INTERNET_HOST, eth_dst=ATTACKER.mac)
    t.ip_frame(1.1003, PC_A, INTERNET_HOST, eth_dst=GATEWAY.mac,
               eth_src=ATTACKER.mac)
    t.resolve(3.70, SERVER, PC_B)
    t.resolve(5.20, PC_A, SERVER)         # PC-A's real MAC appears
    t.resolve(11.60, IOT_NODE, SERVER)
    t.resolve(18.40, PC_B, GATEWAY)       # the real gateway speaks at last
    t.resolve(24.90, MONITOR, SERVER)
    return t


# (file name, builder, kind, expected rules, title)
SCENARIOS = [
    ("s1_normal.pcap", s1_normal, "benign", [],
     "Normal LAN traffic"),
    ("s2_mitm_poisoning.pcap", s2_mitm_poisoning, "attack",
     ["R1", "R2", "R5", "R7"],
     "Man-in-the-middle poisoning of PC-A and the gateway"),
    ("s3_garp_flood.pcap", s3_garp_flood, "attack", ["R1", "R2", "R4"],
     "Gratuitous ARP flood claiming the gateway address"),
    ("s4_dhcp_reassignment.pcap", s4_dhcp_reassignment, "benign", [],
     "Address re-used by a new device after the TTL"),
    ("s5_router_replaced.pcap", s5_router_replaced, "benign", ["R1"],
     "Router replaced within the TTL (expected false alarm)"),
    ("s6_blackhole_forged_headers.pcap", s6_blackhole_forged_headers,
     "attack", ["R1", "R2", "R6", "R7"],
     "Black-hole attack on the IoT node with forged headers"),
    ("s7_poisoned_before_start.pcap", s7_poisoned_before_start, "attack",
     ["R1", "R2", "R7"],
     "Attack already running when monitoring starts"),
]

# Scenario 7 is evaluated a second time with the trusted table switched on.
TRUSTED_RERUN = {
    "base": "s7_poisoned_before_start.pcap",
    "trusted": "config/trusted_bindings.txt",
    "expected_rules": ["R1", "R2", "R3", "R7"],
    "title": "Scenario 7 again, with the trusted-bindings table",
}


def main() -> int:
    os.makedirs(SAMPLES, exist_ok=True)
    runs = []
    print("Writing lab captures to samples/ (files only - nothing is sent)")
    for file_name, builder, kind, expected, title in SCENARIOS:
        facts = builder().save(os.path.join(SAMPLES, file_name))
        run = {"id": file_name.split("_")[0].upper(), "file": file_name,
               "title": title, "kind": kind, "trusted": None,
               "expected_rules": expected}
        run.update(facts)
        runs.append(run)
        print("  %-34s %3d frames (%3d ARP, %2d forged)  %s"
              % (file_name, facts["frames"], facts["arp_frames"],
                 facts["forged_frames"], kind))

    base = next(r for r in runs if r["file"] == TRUSTED_RERUN["base"])
    rerun = dict(base)
    rerun.update(id=base["id"] + "+T", title=TRUSTED_RERUN["title"],
                 trusted=TRUSTED_RERUN["trusted"],
                 expected_rules=TRUSTED_RERUN["expected_rules"])
    runs.append(rerun)

    with open(os.path.join(SAMPLES, "scenarios.json"), "w",
              encoding="utf-8") as handle:
        json.dump(runs, handle, indent=2)
        handle.write("\n")
    print("Ground truth written to samples/scenarios.json (%d runs)"
          % len(runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
