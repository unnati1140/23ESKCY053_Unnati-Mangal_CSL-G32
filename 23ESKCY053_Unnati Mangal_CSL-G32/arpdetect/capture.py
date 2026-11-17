"""Scapy glue: where the ARP packets come from.

Three sources produce the same stream of ArpEvent objects:

    PcapSource(path)                  a saved capture (.pcap / .pcapng)
    PcapSource(path, realtime=True)   the same capture replayed with its
                                      original timing, like live traffic
    sniff_live(iface, callback)       a network interface (Npcap on
                                      Windows / root rights on Linux)

This is the only module that imports Scapy.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Iterator, List, Optional, Tuple

# Scapy prints a warning at import time when no capture driver is
# found (e.g. Windows without Npcap).  Reading pcap files needs no
# driver, so the warning would only confuse; real capture errors are
# reported later.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.config import conf                      # noqa: E402
from scapy.error import Scapy_Exception            # noqa: E402
from scapy.layers.l2 import ARP, Ether             # noqa: E402
from scapy.sendrecv import sniff                   # noqa: E402
from scapy.utils import PcapReader                 # noqa: E402

from .events import (ARP_REPLY, ARP_REQUEST, ArpEvent,  # noqa: E402
                     normalise_mac)

ETHERNET_HWTYPE = 1        # ARP hardware type for Ethernet
IPV4_PTYPE = 0x0800        # ARP protocol type for IPv4


def packet_to_event(pkt, frame_no: int) -> Optional[ArpEvent]:
    """Convert a Scapy packet to an ArpEvent (None if not IPv4 ARP)."""
    if not pkt.haslayer(ARP):
        return None
    arp = pkt[ARP]
    if arp.hwtype != ETHERNET_HWTYPE or arp.ptype != IPV4_PTYPE:
        return None
    if arp.op not in (ARP_REQUEST, ARP_REPLY):
        return None                                  # e.g. RARP

    sender_mac = normalise_mac(arp.hwsrc)
    target_mac = normalise_mac(arp.hwdst)
    if pkt.haslayer(Ether):
        eth_src = normalise_mac(pkt[Ether].src)
        eth_dst = normalise_mac(pkt[Ether].dst)
    else:
        # capture without an Ethernet header: nothing to compare against
        eth_src, eth_dst = sender_mac, target_mac

    return ArpEvent(time=float(pkt.time), op=int(arp.op),
                    eth_src=eth_src, eth_dst=eth_dst,
                    sender_mac=sender_mac, sender_ip=str(arp.psrc),
                    target_mac=target_mac, target_ip=str(arp.pdst),
                    frame=frame_no)


class PcapSource:
    """Iterate over the ARP packets of a capture file.

    `frames` counts every frame read (ARP or not), so the frame numbers
    in the alerts are the same as the 'No.' column in Wireshark.
    """

    def __init__(self, path: str, realtime: bool = False,
                 speed: float = 1.0, max_gap: float = 2.0):
        self.path = path
        self.realtime = realtime
        self.speed = max(speed, 0.001)
        self.max_gap = max_gap         # longest sleep in seconds
        self.frames = 0

    def __iter__(self) -> Iterator[ArpEvent]:
        previous: Optional[float] = None
        with PcapReader(self.path) as reader:
            for pkt in reader:
                self.frames += 1
                event = packet_to_event(pkt, self.frames)
                if event is None:
                    continue
                if self.realtime and previous is not None:
                    gap = (event.time - previous) / self.speed
                    time.sleep(min(max(gap, 0.0), self.max_gap))
                previous = event.time
                yield event


def sniff_live(iface: Optional[str],
               on_event: Callable[[ArpEvent], None],
               count: int = 0,
               duration: Optional[float] = None) -> int:
    """Capture ARP packets from an interface until Ctrl+C, `count`
    packets or `duration` seconds.  Returns the ARP packet count."""
    seen = 0

    def handle(pkt) -> None:
        nonlocal seen
        event = packet_to_event(pkt, seen + 1)
        if event is not None:
            seen += 1
            on_event(event)

    options = dict(iface=iface, prn=handle, store=False,
                   count=count, timeout=duration)
    try:
        # The capture filter "arp" is applied by the capture driver, so
        # all other traffic is discarded before it reaches Python.
        sniff(filter="arp", **options)
    except Scapy_Exception:
        # No libpcap/tcpdump available to compile the filter (possible
        # on Linux): capture everything and keep only ARP in Python.
        sniff(lfilter=lambda p: p.haslayer(ARP), **options)
    return seen


def default_interface() -> str:
    """Name of the interface Scapy would use by default."""
    return str(getattr(conf.iface, "name", conf.iface))


def list_interfaces() -> List[Tuple[str, str, str, str]]:
    """(name, description, MAC, IPv4) of every interface Scapy sees."""
    rows = []
    for iface in conf.ifaces.values():
        name = str(getattr(iface, "name", iface))
        description = str(getattr(iface, "description", "") or "")
        if description == name:
            description = ""
        rows.append((name, description,
                     str(getattr(iface, "mac", "") or ""),
                     str(getattr(iface, "ip", "") or "")))
    return rows
