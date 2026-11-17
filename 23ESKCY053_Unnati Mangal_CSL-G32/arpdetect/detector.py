"""The detection engine.

ArpSpoofDetector.process() is called once for every ARP packet.  It
updates the IP-MAC table and applies seven rules:

    R1  IP-MAC CONFLICT           a known IP moves to another MAC
    R2  BINDING FLIP-FLOP         the IP keeps switching between MACs
    R3  TRUSTED BINDING VIOLATED  a protected IP gets a wrong MAC
    R4  GRATUITOUS ARP FLOOD      too many gratuitous ARPs from a MAC
    R5  MAC CLAIMS MANY IPs       one MAC claims several IP addresses
    R6  INCONSISTENT HEADERS      Ethernet source != ARP sender MAC
    R7  UNSOLICITED REPLY         a reply that nobody asked for

All time comparisons use the packet timestamp, never the wall clock,
so a saved capture gives exactly the same alerts as live traffic.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from .alerts import Alert, RULES
from .arp_table import ArpTable, CHANGED, NEW, RELEARNED
from .config import DetectorConfig
from .events import ArpEvent, ZERO_MAC

HOUSEKEEPING_INTERVAL = 1024     # packets between two clean-ups


def _is_station_mac(mac: str) -> bool:
    """A real network card has a unicast, non-zero MAC address.

    The lowest bit of the first byte is the group bit.  It is set in
    broadcast (ff:ff:ff:ff:ff:ff) and multicast addresses, which can
    be a destination but never the address of a sender.
    """
    if mac == ZERO_MAC:
        return False
    try:
        return int(mac[:2], 16) & 1 == 0
    except ValueError:
        return False


class ArpSpoofDetector:
    """Keeps the IP-MAC table and raises alerts on suspicious ARP."""

    def __init__(self, config: Optional[DetectorConfig] = None,
                 trusted: Optional[Dict[str, str]] = None):
        self.cfg = config or DetectorConfig()
        # ip -> MAC that must never change (rule R3)
        self.trusted: Dict[str, str] = dict(trusted or {})
        self.table = ArpTable(ttl=self.cfg.binding_ttl)

        self.alerts: List[Alert] = []     # every alert that was shown
        self.suppressed = Counter()       # rule id -> hidden repeats
        self.stats = Counter()            # packets, requests, ...
        self.note: Optional[str] = None   # info line for last packet

        # R4: sender MAC -> timestamps of its recent gratuitous ARPs
        self._garp_times: Dict[str, Deque[float]] = defaultdict(deque)
        # R7: (requester IP, wanted IP) -> time of the request
        self._pending: Dict[Tuple[str, str], float] = {}
        # cooldown: (rule id, address) -> time the alert was last shown
        self._last_alert: Dict[tuple, float] = {}

    # ------------------------------------------------------------------
    # public interface
    # ------------------------------------------------------------------
    def process(self, ev: ArpEvent) -> List[Alert]:
        """Apply all rules to one ARP packet; return the new alerts."""
        self.note = None
        raised: List[Alert] = []

        self._count(ev)
        if not ev.is_probe:                 # a probe claims no address
            self._rule_binding(ev, raised)  # R3, R1, R2, R5
        self._rule_flood(ev, raised)        # R4
        self._rule_headers(ev, raised)      # R6
        self._rule_unsolicited(ev, raised)  # R7

        if self.stats["packets"] % HOUSEKEEPING_INTERVAL == 0:
            self._housekeeping(ev.time)
        return raised

    def alerts_per_rule(self) -> Dict[str, int]:
        """Number of alerts shown per rule id (rules that fired)."""
        counts = Counter(alert.rule for alert in self.alerts)
        return dict(sorted(counts.items()))

    # ------------------------------------------------------------------
    # statistics
    # ------------------------------------------------------------------
    def _count(self, ev: ArpEvent) -> None:
        self.stats["packets"] += 1
        self.stats["requests" if ev.is_request else "replies"] += 1
        if ev.is_gratuitous:
            self.stats["gratuitous"] += 1
        if ev.is_probe:
            self.stats["probes"] += 1

    # ------------------------------------------------------------------
    # R3, R1, R2, R5 - the IP-MAC table
    # ------------------------------------------------------------------
    def _rule_binding(self, ev: ArpEvent, raised: List[Alert]) -> None:
        ip, mac, now = ev.sender_ip, ev.sender_mac, ev.time

        # R3 - a trusted binding is never overwritten.
        good_mac = self.trusted.get(ip)
        if good_mac is not None and mac != good_mac:
            self._raise("R3", ip, ev, raised, ip, mac,
                        "%s is trusted at %s but claimed by %s"
                        % (ip, good_mac, mac), old_mac=good_mac)
            return                          # do not learn the forgery

        status, old_mac = self.table.update(ip, mac, now)

        if status == NEW:
            self.note = "new host   %-15s is at %s" % (ip, mac)
        elif status == RELEARNED:
            self.note = ("re-learnt  %-15s is at %s (old %s expired)"
                         % (ip, mac, old_mac))
        elif status == CHANGED:
            entry = self.table.get(ip)
            window = self.cfg.flipflop_window
            if entry.held_before(mac, now, window):
                # R2 - the IP went back to a MAC it already had:
                # two stations are fighting over the address.
                self._raise("R2", ip, ev, raised, ip, mac,
                            "%s flips between %s and %s (%d changes)"
                            % (ip, old_mac, mac, entry.changes),
                            old_mac=old_mac)
            else:
                # R1 - first time this IP is seen at another MAC.
                self._raise("R1", ip, ev, raised, ip, mac,
                            "%s moved from %s to %s"
                            % (ip, old_mac, mac), old_mac=old_mac)

        # R5 - how many IP addresses does this MAC claim by now?
        claimed = self.table.ips_claimed_by(mac, now)
        if len(claimed) >= self.cfg.multi_ip_threshold:
            self._raise("R5", mac, ev, raised, ip, mac,
                        "%s claims %d IP addresses: %s"
                        % (mac, len(claimed), ", ".join(claimed)))

    # ------------------------------------------------------------------
    # R4 - gratuitous ARP flood (sliding time window per sender MAC)
    # ------------------------------------------------------------------
    def _rule_flood(self, ev: ArpEvent, raised: List[Alert]) -> None:
        if not ev.is_gratuitous:
            return
        times = self._garp_times[ev.sender_mac]
        times.append(ev.time)
        # forget gratuitous ARPs that have left the window
        while ev.time - times[0] > self.cfg.flood_window:
            times.popleft()
        if len(times) >= self.cfg.flood_threshold:
            self._raise("R4", ev.sender_mac, ev, raised,
                        ev.sender_ip, ev.sender_mac,
                        "%s sent %d gratuitous ARPs for %s within "
                        "%g s (limit %d)"
                        % (ev.sender_mac, len(times), ev.sender_ip,
                           self.cfg.flood_window,
                           self.cfg.flood_threshold))

    # ------------------------------------------------------------------
    # R6 - Ethernet header and ARP payload must agree
    # ------------------------------------------------------------------
    def _rule_headers(self, ev: ArpEvent, raised: List[Alert]) -> None:
        if not _is_station_mac(ev.sender_mac):
            self._raise("R6", ev.eth_src, ev, raised,
                        ev.sender_ip, ev.sender_mac,
                        "ARP sender MAC %s is not a station address "
                        "(frame sent by %s)"
                        % (ev.sender_mac, ev.eth_src))
        elif ev.eth_src != ev.sender_mac:
            # An honest host puts its own MAC into both fields.
            # Forging tools often change only one of them.
            self._raise("R6", ev.eth_src, ev, raised,
                        ev.sender_ip, ev.sender_mac,
                        "frame sent by %s but its ARP sender field "
                        "says %s (claims %s)"
                        % (ev.eth_src, ev.sender_mac, ev.sender_ip))

    # ------------------------------------------------------------------
    # R7 - a reply should answer a request
    # ------------------------------------------------------------------
    def _rule_unsolicited(self, ev: ArpEvent,
                          raised: List[Alert]) -> None:
        if ev.is_gratuitous or ev.is_probe:
            return                          # R4 handles gratuitous ARP
        if ev.is_request:
            # remember "sender_ip asked for target_ip"
            self._pending[(ev.sender_ip, ev.target_ip)] = ev.time
            return
        # A reply "sender_ip is at ..." sent to target_ip is solicited
        # only if target_ip asked for sender_ip a moment ago.  pop():
        # one request permits one reply, so a second (forged) answer
        # to the same request is caught as well.
        asked = self._pending.pop((ev.target_ip, ev.sender_ip), None)
        timeout = self.cfg.request_timeout
        if asked is None or ev.time - asked > timeout:
            self._raise("R7", (ev.sender_ip, ev.sender_mac), ev, raised,
                        ev.sender_ip, ev.sender_mac,
                        "unrequested reply '%s is at %s' sent to %s"
                        % (ev.sender_ip, ev.sender_mac, ev.target_ip))

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _raise(self, rule_id: str, key, ev: ArpEvent,
               raised: List[Alert], ip: str, mac: str, message: str,
               old_mac: str = "") -> None:
        """Create an alert unless the same one was shown recently."""
        cooldown_key = (rule_id, key)
        last = self._last_alert.get(cooldown_key)
        cooldown = self.cfg.alert_cooldown
        if last is not None and ev.time - last < cooldown:
            self.suppressed[rule_id] += 1   # count it, do not show it
            return
        self._last_alert[cooldown_key] = ev.time

        rule = RULES[rule_id]
        alert = Alert(number=len(self.alerts) + 1, time=ev.time,
                      rule=rule.id, name=rule.name,
                      severity=rule.severity, ip=ip, mac=mac,
                      old_mac=old_mac, message=message, frame=ev.frame)
        self.alerts.append(alert)
        raised.append(alert)

    def _housekeeping(self, now: float) -> None:
        """Drop state that can no longer influence a decision.

        Without this an attacker could exhaust the detector's memory
        by sending ARP packets with endless random addresses.
        """
        cfg = self.cfg
        self._pending = {
            key: t for key, t in self._pending.items()
            if now - t <= cfg.request_timeout}
        stale = [mac for mac, times in self._garp_times.items()
                 if not times or now - times[-1] > cfg.flood_window]
        for mac in stale:
            del self._garp_times[mac]
        self._last_alert = {
            key: t for key, t in self._last_alert.items()
            if now - t < cfg.alert_cooldown}
