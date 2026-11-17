"""ARP Spoofing Detector - detection package.

Modules
-------
events     one ARP packet reduced to the fields the detector needs
arp_table  the IP-MAC binding table (the detector's own ARP cache)
alerts     the seven detection rules and the Alert record
config     tunable thresholds and the trusted-bindings file
detector   the detection engine (applies the rules to every ARP packet)
capture    Scapy glue: live sniffing, pcap reading, real-time replay
console    plain-text output: alert lines, tables, summary

Only capture.py imports Scapy.  The detection engine itself is plain
Python, so it can be unit-tested without a network or special rights.
"""

__version__ = "1.0"
