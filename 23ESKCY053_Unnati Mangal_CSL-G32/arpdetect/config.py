"""Tunable thresholds of the detector and the trusted-bindings file."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict

from .events import normalise_mac

_MAC_PATTERN = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass
class DetectorConfig:
    """All thresholds in one place (each can be set on the CLI)."""

    # R4 - gratuitous ARP flood: this many gratuitous ARPs from one
    # sender MAC inside `flood_window` seconds raise an alert.  A normal
    # host announces itself two or three times at boot (RFC 5227), so
    # the default of 5 stays quiet for legitimate traffic.
    flood_threshold: int = 5
    flood_window: float = 10.0

    # A binding that was not confirmed for this long is stale: another
    # MAC may then take over the IP without an alert (typical for DHCP
    # handing an address to a new device).  0 = never.
    binding_ttl: float = 300.0

    # R2 - flip-flop: the IP returns to a MAC it had before, within this
    # many seconds.
    flipflop_window: float = 60.0

    # R5 - one MAC claiming at least this many IP addresses.
    multi_ip_threshold: int = 3

    # R7 - a reply is "solicited" if a matching request was seen at most
    # this many seconds earlier.
    request_timeout: float = 5.0

    # The same alert (same rule and same address) is printed at most
    # once per cooldown period; repeats in between are only counted.
    alert_cooldown: float = 30.0


def load_trusted(path: str) -> Dict[str, str]:
    """Read a trusted-bindings file and return {ip: mac}.

    File format - one binding per line, '#' starts a comment:

        192.168.56.1   02:aa:00:00:00:01   # gateway
    """
    trusted: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                raise ValueError("%s line %d: expected 'IP MAC', got %r"
                                 % (path, line_no, raw.strip()))
            ip, mac = parts[0], normalise_mac(parts[1])
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                raise ValueError("%s line %d: %r is not an IPv4 address"
                                 % (path, line_no, ip)) from None
            if not _MAC_PATTERN.match(mac):
                raise ValueError("%s line %d: %r is not a MAC address"
                                 % (path, line_no, parts[1]))
            trusted[ip] = mac
    return trusted
