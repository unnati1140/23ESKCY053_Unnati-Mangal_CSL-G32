"""One ARP packet, reduced to the fields the detector needs.

An ARP packet travels inside an Ethernet frame, so two layers matter:

    Ethernet header :  eth_dst | eth_src | type = 0x0806
    ARP payload     :  op | sender MAC | sender IP | target MAC |
                       target IP

The *sender* pair (sender IP, sender MAC) is the claim "this IP address
lives at this MAC address".  Every host that receives the packet may
store that claim in its ARP cache - this is exactly what ARP spoofing
abuses, and it is the pair this project keeps track of.
"""

from __future__ import annotations

from dataclasses import dataclass

ARP_REQUEST = 1                      # "who has IP x? tell IP y"
ARP_REPLY = 2                        # "IP x is at MAC m"

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
ZERO_IP = "0.0.0.0"


def normalise_mac(mac: str) -> str:
    """Return a MAC address in one canonical form.

    '02-AA-00-00-00-01' and '02:AA:00:00:00:01' both become
    '02:aa:00:00:00:01', so that string comparison is reliable.
    """
    return str(mac).strip().lower().replace("-", ":")


def ip_sort_key(ip: str):
    """Sort key that orders IPv4 addresses numerically (so .2 < .10)."""
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


@dataclass(frozen=True)
class ArpEvent:
    """A single ARP packet as seen on the wire."""

    time: float          # capture timestamp in seconds
    op: int              # 1 = request, 2 = reply
    eth_src: str         # Ethernet source MAC (who really sent it)
    eth_dst: str         # Ethernet destination MAC
    sender_mac: str      # ARP field SHA - sender hardware address
    sender_ip: str       # ARP field SPA - sender protocol address
    target_mac: str      # ARP field THA - target hardware address
    target_ip: str       # ARP field TPA - target protocol address
    frame: int = 0       # frame number in the capture (as in Wireshark)

    @property
    def is_request(self) -> bool:
        return self.op == ARP_REQUEST

    @property
    def is_reply(self) -> bool:
        return self.op == ARP_REPLY

    @property
    def is_probe(self) -> bool:
        """RFC 5227 ARP probe (sender IP 0.0.0.0): 'is this IP free?'

        A probe makes no claim about any address, so nothing is learnt
        from it.
        """
        return self.sender_ip == ZERO_IP

    @property
    def is_gratuitous(self) -> bool:
        """Gratuitous ARP: sender IP == target IP.

        Nobody asked for it; the sender simply announces its own
        binding to everybody.  Normal at boot time, but a stream of
        them is the fastest way to poison a whole LAN.
        """
        return self.sender_ip == self.target_ip and not self.is_probe

    def describe(self) -> str:
        """One-line, human-readable description of the packet."""
        if self.is_probe:
            return "ARP probe: is %s in use? (asked by %s)" % (
                self.target_ip, self.sender_mac)
        if self.is_gratuitous:
            kind = "request" if self.is_request else "reply"
            return "gratuitous ARP %s: %s is at %s" % (
                kind, self.sender_ip, self.sender_mac)
        if self.is_request:
            return "ARP request: who has %s? tell %s" % (
                self.target_ip, self.sender_ip)
        return "ARP reply: %s is at %s (sent to %s)" % (
            self.sender_ip, self.sender_mac, self.target_ip)
