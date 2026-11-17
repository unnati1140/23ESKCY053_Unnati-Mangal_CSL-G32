"""The detection rules and the Alert record.

Each rule has an id (R1..R7), a short name and a severity.  The rules
themselves are implemented in detector.py; this file only describes
them, so that the console, the CSV log and the tests all use the same
names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

LOW, MEDIUM, HIGH, CRITICAL = "LOW", "MEDIUM", "HIGH", "CRITICAL"
SEVERITY_ORDER = (CRITICAL, HIGH, MEDIUM, LOW)


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    meaning: str


RULES: Dict[str, Rule] = {
    rule.id: rule for rule in (
        Rule("R1", "IP-MAC CONFLICT", HIGH,
             "a known IP address is claimed by a different MAC"),
        Rule("R2", "BINDING FLIP-FLOP", CRITICAL,
             "an IP address keeps switching between two MACs "
             "(real owner and attacker both answering)"),
        Rule("R3", "TRUSTED BINDING VIOLATED", CRITICAL,
             "an IP of the trusted table is claimed by another MAC"),
        Rule("R4", "GRATUITOUS ARP FLOOD", HIGH,
             "one station sends too many gratuitous ARPs at once"),
        Rule("R5", "MAC CLAIMS MANY IPs", MEDIUM,
             "one MAC address claims several IP addresses"),
        Rule("R6", "INCONSISTENT HEADERS", MEDIUM,
             "Ethernet source MAC and ARP sender MAC disagree, "
             "or the sender MAC is not a valid station address"),
        Rule("R7", "UNSOLICITED REPLY", LOW,
             "an ARP reply arrived without a matching request"),
    )
}


@dataclass
class Alert:
    """One alert raised by the detector."""

    number: int       # running alert number, starting at 1
    time: float       # timestamp of the packet that triggered it
    rule: str         # "R1" .. "R7"
    name: str         # rule name, e.g. "IP-MAC CONFLICT"
    severity: str     # LOW / MEDIUM / HIGH / CRITICAL
    ip: str           # IP address concerned ("" if not applicable)
    mac: str          # MAC address that made the suspicious claim
    old_mac: str      # MAC previously bound to the IP ("" if none)
    message: str      # full human-readable explanation
    frame: int        # frame number of the triggering packet
