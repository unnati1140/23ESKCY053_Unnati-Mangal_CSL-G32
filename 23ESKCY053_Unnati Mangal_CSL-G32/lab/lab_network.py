"""The virtual lab LAN used to test the detector.

Nothing here exists on a real network.  All MAC addresses start with
02:..., i.e. they have the "locally administered" bit set and belong to
no manufacturer, and 192.168.56.0/24 is a private range (the default of
a VirtualBox host-only network).  The traffic of this LAN is written
straight into capture files - it is never transmitted.
"""

from __future__ import annotations

from dataclasses import dataclass

NETWORK = "192.168.56.0/24"


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    mac: str
    role: str


GATEWAY = Host("GATEWAY", "192.168.56.1", "02:aa:00:00:00:01",
               "router / default gateway")
PC_A = Host("PC-A", "192.168.56.10", "02:aa:00:00:00:10",
            "user PC (victim in the attack scenarios)")
PC_B = Host("PC-B", "192.168.56.11", "02:aa:00:00:00:11", "user PC")
SERVER = Host("SERVER", "192.168.56.20", "02:aa:00:00:00:20",
              "file / data server")
IOT_NODE = Host("IOT-NODE", "192.168.56.30", "02:aa:00:00:00:30",
                "IoT sensor node that reports to SERVER")
MONITOR = Host("MONITOR", "192.168.56.100", "02:aa:00:00:01:00",
               "machine running the detector (listens only)")
ATTACKER = Host("ATTACKER", "192.168.56.66", "02:bb:00:00:00:66",
                "malicious host")

# Devices that appear only in the two harmless "change" scenarios
PHONE = Host("PHONE", "192.168.56.11", "02:aa:00:00:00:40",
             "new device that gets PC-B's old address from DHCP")
NEW_ROUTER = Host("NEW-ROUTER", "192.168.56.1", "02:aa:00:00:00:02",
                  "replacement router with the gateway's IP")

# A MAC address that no host owns (used for the black-hole attack)
BOGUS_MAC = "02:de:ad:00:00:00"

# A host outside the LAN (documentation range, RFC 5737)
INTERNET_HOST = "203.0.113.10"

LAB_HOSTS = (GATEWAY, PC_A, PC_B, SERVER, IOT_NODE, MONITOR, ATTACKER)
