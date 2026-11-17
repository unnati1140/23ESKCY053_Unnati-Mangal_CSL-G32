"""The IP-MAC binding table - the detector's own copy of the ARP cache.

For every IP address seen on the LAN the table remembers which MAC
address claimed it, when, how often, and whether that ever changed.
A change of MAC for a known IP is the central symptom of ARP spoofing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .events import ip_sort_key

# Result codes of ArpTable.update()
NEW = "new"               # first time this IP is seen
SAME = "same"             # the IP is still at the MAC we knew
CHANGED = "changed"       # the IP moved to another MAC -> suspicious
RELEARNED = "relearned"   # moved, but the old entry had expired

MAX_HISTORY = 20          # previous MACs remembered per IP


@dataclass
class Binding:
    """Everything the detector knows about one IP address."""

    ip: str
    mac: str                 # MAC currently believed to own the IP
    first_seen: float
    last_seen: float
    packets: int = 1         # ARP packets that confirmed/changed it
    changes: int = 0         # number of suspicious MAC changes
    # (time of replacement, MAC that was replaced), oldest first
    history: List[Tuple[float, str]] = field(default_factory=list)

    def held_before(self, mac: str, now: float, window: float) -> bool:
        """Did `mac` own this IP during the last `window` seconds?"""
        return any(old == mac and now - when <= window
                   for when, old in self.history)


class ArpTable:
    """IP -> Binding, plus a reverse index MAC -> IPs it has claimed."""

    def __init__(self, ttl: float = 300.0):
        self.ttl = ttl                     # 0 = entries never expire
        self._by_ip: Dict[str, Binding] = {}
        # MAC -> {IP: time of the most recent claim}
        self._claims: Dict[str, Dict[str, float]] = {}

    def __len__(self) -> int:
        return len(self._by_ip)

    def get(self, ip: str) -> Optional[Binding]:
        return self._by_ip.get(ip)

    def update(self, ip: str, mac: str,
               now: float) -> Tuple[str, Optional[str]]:
        """Record the claim 'ip is at mac' made at time `now`.

        Returns (status, previous MAC); status is NEW, SAME, CHANGED
        or RELEARNED.  The table always follows the newest claim, as
        a real ARP cache does; the caller decides about an alert.
        """
        self._claims.setdefault(mac, {})[ip] = now

        entry = self._by_ip.get(ip)
        if entry is None:
            self._by_ip[ip] = Binding(ip, mac, first_seen=now,
                                      last_seen=now)
            return NEW, None

        if entry.mac == mac:
            entry.last_seen = now
            entry.packets += 1
            return SAME, mac

        # The IP is now claimed by a different MAC.
        old_mac = entry.mac
        expired = self.ttl > 0 and (now - entry.last_seen) > self.ttl
        entry.history.append((now, old_mac))
        del entry.history[:-MAX_HISTORY]
        entry.mac = mac
        entry.last_seen = now
        entry.packets += 1
        if expired:
            # The old owner was silent for longer than the TTL, e.g.
            # its DHCP lease ran out and the address went to another
            # device.
            return RELEARNED, old_mac
        entry.changes += 1
        return CHANGED, old_mac

    def ips_claimed_by(self, mac: str, now: float) -> List[str]:
        """IP addresses that `mac` claimed recently (within the TTL)."""
        claims = self._claims.get(mac, {})
        if self.ttl > 0:
            ips = [ip for ip, when in claims.items()
                   if now - when <= self.ttl]
        else:
            ips = list(claims)
        return sorted(ips, key=ip_sort_key)

    def rows(self) -> List[Binding]:
        """All bindings ordered by IP address (display / export)."""
        return sorted(self._by_ip.values(),
                      key=lambda b: ip_sort_key(b.ip))
