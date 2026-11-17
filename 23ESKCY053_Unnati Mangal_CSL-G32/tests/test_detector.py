#!/usr/bin/env python3
"""Unit tests for the ARP Spoofing Detector.

Run from the project folder:

    python tests/test_detector.py            one line per test
    python tests/test_detector.py --brief    one dot per test

The first eleven test classes need only Python (the detection engine
does not depend on Scapy).  The last two also need Scapy and the lab
captures in samples/.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from arpdetect.alerts import CRITICAL, HIGH, LOW, MEDIUM          # noqa: E402
from arpdetect.arp_table import (ArpTable, CHANGED, NEW,           # noqa: E402
                                 RELEARNED, SAME)
from arpdetect.config import DetectorConfig, load_trusted          # noqa: E402
from arpdetect.detector import ArpSpoofDetector                    # noqa: E402
from arpdetect.events import (ARP_REPLY, ARP_REQUEST, ArpEvent,    # noqa: E402
                              BROADCAST_MAC, ZERO_MAC, normalise_mac)

try:
    from arpdetect import capture
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

# Addresses used in the tests
GW_IP, GW_MAC = "192.168.56.1", "02:aa:00:00:00:01"
PC_IP, PC_MAC = "192.168.56.10", "02:aa:00:00:00:10"
SRV_IP, SRV_MAC = "192.168.56.20", "02:aa:00:00:00:20"
BAD_MAC = "02:bb:00:00:00:66"


# ----------------------------------------------------------------------
# helpers that build ARP packets
# ----------------------------------------------------------------------
def request(t, mac, ip, wanted_ip):
    """Broadcast ARP request: 'who has wanted_ip? tell ip'."""
    return ArpEvent(t, ARP_REQUEST, mac, BROADCAST_MAC, mac, ip,
                    ZERO_MAC, wanted_ip)


def reply(t, mac, ip, to_mac, to_ip, eth_src=None):
    """Unicast ARP reply: 'ip is at mac', sent to (to_ip, to_mac)."""
    return ArpEvent(t, ARP_REPLY, eth_src or mac, to_mac, mac, ip,
                    to_mac, to_ip)


def gratuitous(t, mac, ip):
    """Gratuitous ARP: sender IP == target IP, broadcast."""
    return ArpEvent(t, ARP_REQUEST, mac, BROADCAST_MAC, mac, ip, ZERO_MAC, ip)


def rules_of(alerts):
    return [a.rule for a in alerts]


def feed(detector, events):
    """Process several packets; return all alerts they raised."""
    raised = []
    for event in events:
        raised.extend(detector.process(event))
    return raised


# ----------------------------------------------------------------------
class TestArpEvent(unittest.TestCase):

    def test_request_and_reply_flags(self):
        self.assertTrue(request(0, PC_MAC, PC_IP, GW_IP).is_request)
        self.assertTrue(reply(0, GW_MAC, GW_IP, PC_MAC, PC_IP).is_reply)

    def test_gratuitous_means_sender_ip_equals_target_ip(self):
        self.assertTrue(gratuitous(0, GW_MAC, GW_IP).is_gratuitous)
        self.assertFalse(request(0, PC_MAC, PC_IP, GW_IP).is_gratuitous)

    def test_probe_is_not_gratuitous(self):
        probe = request(0, PC_MAC, "0.0.0.0", "0.0.0.0")
        self.assertTrue(probe.is_probe)
        self.assertFalse(probe.is_gratuitous)

    def test_mac_is_normalised(self):
        self.assertEqual(normalise_mac("02-AA-00-00-00-01"), GW_MAC)


class TestArpTable(unittest.TestCase):

    def test_new_same_changed(self):
        table = ArpTable(ttl=300)
        self.assertEqual(table.update(GW_IP, GW_MAC, 0.0), (NEW, None))
        self.assertEqual(table.update(GW_IP, GW_MAC, 1.0), (SAME, GW_MAC))
        self.assertEqual(table.update(GW_IP, BAD_MAC, 2.0), (CHANGED, GW_MAC))
        entry = table.get(GW_IP)
        self.assertEqual((entry.mac, entry.changes, entry.packets),
                         (BAD_MAC, 1, 3))

    def test_expired_binding_is_relearned(self):
        table = ArpTable(ttl=300)
        table.update(PC_IP, PC_MAC, 0.0)
        self.assertEqual(table.update(PC_IP, BAD_MAC, 301.0),
                         (RELEARNED, PC_MAC))
        self.assertEqual(table.get(PC_IP).changes, 0)

    def test_ttl_zero_never_expires(self):
        table = ArpTable(ttl=0)
        table.update(PC_IP, PC_MAC, 0.0)
        self.assertEqual(table.update(PC_IP, BAD_MAC, 99999.0)[0], CHANGED)

    def test_history_remembers_previous_owner(self):
        table = ArpTable(ttl=300)
        table.update(GW_IP, GW_MAC, 0.0)
        table.update(GW_IP, BAD_MAC, 5.0)
        entry = table.get(GW_IP)
        self.assertTrue(entry.held_before(GW_MAC, now=6.0, window=60))
        self.assertFalse(entry.held_before(GW_MAC, now=100.0, window=60))

    def test_reverse_index_and_numeric_order(self):
        table = ArpTable(ttl=300)
        for ip in ("192.168.56.10", "192.168.56.2", "192.168.56.100"):
            table.update(ip, BAD_MAC, 0.0)
        self.assertEqual(table.ips_claimed_by(BAD_MAC, 1.0),
                         ["192.168.56.2", "192.168.56.10", "192.168.56.100"])
        self.assertEqual([b.ip for b in table.rows()],
                         ["192.168.56.2", "192.168.56.10", "192.168.56.100"])


class TestR1Conflict(unittest.TestCase):

    def test_learning_and_confirming_is_silent(self):
        det = ArpSpoofDetector()
        alerts = feed(det, [gratuitous(0, GW_MAC, GW_IP),
                            request(1, PC_MAC, PC_IP, GW_IP),
                            reply(1.001, GW_MAC, GW_IP, PC_MAC, PC_IP)])
        self.assertEqual(alerts, [])
        self.assertEqual(len(det.table), 2)

    def test_known_ip_at_new_mac_raises_high_alert(self):
        det = ArpSpoofDetector()
        det.process(gratuitous(0, GW_MAC, GW_IP))
        alerts = det.process(gratuitous(5, BAD_MAC, GW_IP))
        self.assertEqual(rules_of(alerts), ["R1"])
        self.assertEqual(alerts[0].severity, HIGH)
        self.assertEqual((alerts[0].ip, alerts[0].old_mac, alerts[0].mac),
                         (GW_IP, GW_MAC, BAD_MAC))

    def test_change_after_ttl_is_not_an_alert(self):
        det = ArpSpoofDetector(DetectorConfig(binding_ttl=300))
        det.process(gratuitous(0, PC_MAC, PC_IP))
        self.assertEqual(det.process(gratuitous(400, BAD_MAC, PC_IP)), [])
        self.assertIn("re-learnt", det.note)

    def test_probe_is_not_learnt(self):
        det = ArpSpoofDetector()
        det.process(request(0, PC_MAC, "0.0.0.0", PC_IP))
        self.assertEqual(len(det.table), 0)
        self.assertEqual(det.stats["probes"], 1)


class TestR2FlipFlop(unittest.TestCase):

    def test_return_to_previous_mac_is_critical(self):
        det = ArpSpoofDetector()
        det.process(gratuitous(0, GW_MAC, GW_IP))
        first = det.process(gratuitous(5, BAD_MAC, GW_IP))
        second = det.process(gratuitous(6, GW_MAC, GW_IP))
        self.assertEqual(rules_of(first), ["R1"])
        self.assertEqual(rules_of(second), ["R2"])
        self.assertEqual(second[0].severity, CRITICAL)

    def test_return_after_window_is_a_plain_conflict(self):
        det = ArpSpoofDetector(DetectorConfig(flipflop_window=60))
        det.process(gratuitous(0, GW_MAC, GW_IP))
        det.process(gratuitous(5, BAD_MAC, GW_IP))
        late = det.process(gratuitous(100, GW_MAC, GW_IP))
        self.assertEqual(rules_of(late), ["R1"])


class TestR3Trusted(unittest.TestCase):

    def test_wrong_mac_for_trusted_ip_is_critical_at_once(self):
        det = ArpSpoofDetector(trusted={GW_IP: GW_MAC})
        alerts = det.process(gratuitous(0, BAD_MAC, GW_IP))
        self.assertEqual(rules_of(alerts), ["R3"])
        self.assertEqual(alerts[0].severity, CRITICAL)

    def test_forged_claim_is_not_learnt(self):
        det = ArpSpoofDetector(trusted={GW_IP: GW_MAC})
        det.process(gratuitous(0, BAD_MAC, GW_IP))
        self.assertIsNone(det.table.get(GW_IP))

    def test_correct_mac_for_trusted_ip_is_accepted(self):
        det = ArpSpoofDetector(trusted={GW_IP: GW_MAC})
        self.assertEqual(det.process(gratuitous(0, GW_MAC, GW_IP)), [])
        self.assertEqual(det.table.get(GW_IP).mac, GW_MAC)


class TestR4GratuitousFlood(unittest.TestCase):

    def test_four_gratuitous_arps_are_tolerated(self):
        det = ArpSpoofDetector(DetectorConfig(flood_threshold=5))
        alerts = feed(det, [gratuitous(i * 0.5, PC_MAC, PC_IP)
                            for i in range(4)])
        self.assertEqual(alerts, [])

    def test_fifth_gratuitous_arp_raises_flood(self):
        det = ArpSpoofDetector(DetectorConfig(flood_threshold=5))
        alerts = feed(det, [gratuitous(i * 0.5, PC_MAC, PC_IP)
                            for i in range(5)])
        self.assertEqual(rules_of(alerts), ["R4"])
        self.assertEqual(alerts[0].time, 2.0)

    def test_slow_announcements_are_not_a_flood(self):
        det = ArpSpoofDetector(DetectorConfig(flood_threshold=5,
                                              flood_window=10))
        alerts = feed(det, [gratuitous(i * 4.0, PC_MAC, PC_IP)
                            for i in range(20)])
        self.assertEqual(alerts, [])

    def test_flood_is_counted_per_sender(self):
        det = ArpSpoofDetector(DetectorConfig(flood_threshold=5))
        events = [gratuitous(i * 0.1, "02:aa:00:00:01:%02x" % i,
                             "192.168.56.%d" % (100 + i)) for i in range(8)]
        self.assertEqual(feed(det, events), [])


class TestR5ManyIps(unittest.TestCase):

    def test_third_ip_for_one_mac_raises_alert(self):
        det = ArpSpoofDetector(DetectorConfig(multi_ip_threshold=3))
        self.assertEqual(det.process(gratuitous(0, BAD_MAC, "192.168.56.66")), [])
        self.assertEqual(det.process(gratuitous(1, BAD_MAC, "192.168.56.67")), [])
        alerts = det.process(gratuitous(2, BAD_MAC, "192.168.56.68"))
        self.assertEqual(rules_of(alerts), ["R5"])
        self.assertEqual(alerts[0].severity, MEDIUM)


class TestR6Headers(unittest.TestCase):

    def test_ethernet_source_differs_from_arp_sender(self):
        det = ArpSpoofDetector()
        det.process(request(0, PC_MAC, PC_IP, SRV_IP))
        alerts = det.process(reply(0.001, "02:de:ad:00:00:00", SRV_IP,
                                   PC_MAC, PC_IP, eth_src=BAD_MAC))
        self.assertEqual(rules_of(alerts), ["R6"])

    def test_broadcast_sender_mac_is_invalid(self):
        det = ArpSpoofDetector()
        alerts = det.process(gratuitous(0, BROADCAST_MAC, PC_IP))
        self.assertIn("R6", rules_of(alerts))


class TestR7Unsolicited(unittest.TestCase):

    def test_reply_to_a_request_is_fine(self):
        det = ArpSpoofDetector()
        alerts = feed(det, [request(0, PC_MAC, PC_IP, GW_IP),
                            reply(0.001, GW_MAC, GW_IP, PC_MAC, PC_IP)])
        self.assertEqual(alerts, [])

    def test_reply_without_request_is_flagged(self):
        det = ArpSpoofDetector()
        alerts = det.process(reply(0, GW_MAC, GW_IP, PC_MAC, PC_IP))
        self.assertEqual(rules_of(alerts), ["R7"])
        self.assertEqual(alerts[0].severity, LOW)

    def test_late_reply_is_flagged(self):
        det = ArpSpoofDetector(DetectorConfig(request_timeout=5))
        det.process(request(0, PC_MAC, PC_IP, GW_IP))
        alerts = det.process(reply(6, GW_MAC, GW_IP, PC_MAC, PC_IP))
        self.assertEqual(rules_of(alerts), ["R7"])

    def test_second_reply_to_one_request_is_flagged(self):
        det = ArpSpoofDetector()
        det.process(request(0, PC_MAC, PC_IP, GW_IP))
        det.process(reply(0.001, GW_MAC, GW_IP, PC_MAC, PC_IP))
        alerts = det.process(reply(0.002, GW_MAC, GW_IP, PC_MAC, PC_IP))
        self.assertEqual(rules_of(alerts), ["R7"])


class TestCooldown(unittest.TestCase):

    def test_repeats_are_counted_not_shown(self):
        det = ArpSpoofDetector(DetectorConfig(alert_cooldown=30))
        alerts = feed(det, [reply(t, GW_MAC, GW_IP, PC_MAC, PC_IP)
                            for t in (0, 2, 4, 6)])
        self.assertEqual(rules_of(alerts), ["R7"])
        self.assertEqual(det.suppressed["R7"], 3)

    def test_alert_returns_after_cooldown(self):
        det = ArpSpoofDetector(DetectorConfig(alert_cooldown=30))
        alerts = feed(det, [reply(t, GW_MAC, GW_IP, PC_MAC, PC_IP)
                            for t in (0, 10, 31)])
        self.assertEqual(rules_of(alerts), ["R7", "R7"])


class TestTrustedFile(unittest.TestCase):

    def _write(self, text):
        handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                             encoding="utf-8")
        handle.write(text)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        return handle.name

    def test_file_is_parsed(self):
        path = self._write("# lab\n192.168.56.1  02-AA-00-00-00-01  # gw\n\n")
        self.assertEqual(load_trusted(path), {GW_IP: GW_MAC})

    def test_bad_mac_is_rejected(self):
        path = self._write("192.168.56.1 not-a-mac\n")
        with self.assertRaises(ValueError):
            load_trusted(path)

    def test_bad_ip_is_rejected(self):
        path = self._write("192.168.56.999 02:aa:00:00:00:01\n")
        with self.assertRaises(ValueError):
            load_trusted(path)


@unittest.skipUnless(HAVE_SCAPY, "Scapy is not installed")
class TestScapyConversion(unittest.TestCase):

    def test_arp_packet_becomes_event(self):
        from scapy.layers.l2 import ARP, Ether
        pkt = (Ether(src=BAD_MAC, dst=PC_MAC)
               / ARP(op=2, hwsrc="02:DE:AD:00:00:00", psrc=SRV_IP,
                     hwdst=PC_MAC, pdst=PC_IP))
        pkt.time = 12.5
        event = capture.packet_to_event(pkt, 7)
        self.assertEqual((event.eth_src, event.sender_mac, event.sender_ip,
                          event.target_ip, event.op, event.frame, event.time),
                         (BAD_MAC, "02:de:ad:00:00:00", SRV_IP, PC_IP, 2, 7,
                          12.5))

    def test_non_arp_packet_is_ignored(self):
        from scapy.layers.inet import ICMP, IP
        from scapy.layers.l2 import Ether
        pkt = Ether(src=PC_MAC, dst=GW_MAC) / IP(src=PC_IP, dst=GW_IP) / ICMP()
        self.assertIsNone(capture.packet_to_event(pkt, 1))


@unittest.skipUnless(HAVE_SCAPY and os.path.isfile(
    os.path.join(ROOT, "samples", "scenarios.json")),
    "Scapy or the lab captures are missing")
class TestLabScenarios(unittest.TestCase):
    """Every lab capture must trigger exactly the expected rules."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "samples", "scenarios.json"),
                  encoding="utf-8") as handle:
            cls.runs = {run["id"]: run for run in json.load(handle)}

    def _fired(self, run_id):
        run = self.runs[run_id]
        trusted = {}
        if run["trusted"]:
            trusted = load_trusted(os.path.join(ROOT, run["trusted"]))
        det = ArpSpoofDetector(DetectorConfig(), trusted)
        for event in capture.PcapSource(os.path.join(ROOT, "samples",
                                                     run["file"])):
            det.process(event)
        return sorted(det.alerts_per_rule()), run["expected_rules"]

    def test_s1_normal_traffic_is_silent(self):
        self.assertEqual(*self._fired("S1"))

    def test_s2_mitm_poisoning(self):
        self.assertEqual(*self._fired("S2"))

    def test_s3_gratuitous_flood(self):
        self.assertEqual(*self._fired("S3"))

    def test_s4_dhcp_reassignment_is_silent(self):
        self.assertEqual(*self._fired("S4"))

    def test_s5_router_replaced_gives_one_conflict(self):
        self.assertEqual(*self._fired("S5"))

    def test_s6_blackhole_forged_headers(self):
        self.assertEqual(*self._fired("S6"))

    def test_s7_poisoned_before_start(self):
        self.assertEqual(*self._fired("S7"))

    def test_s7_with_trusted_table(self):
        self.assertEqual(*self._fired("S7+T"))


class ShortResult(unittest.TextTestResult):
    """Print 'Class.test_name ... ok' (the same on every Python version)."""

    def getDescription(self, test):
        return "%s.%s" % (type(test).__name__, test._testMethodName)


if __name__ == "__main__":
    brief = "--brief" in sys.argv
    if brief:
        sys.argv.remove("--brief")
    unittest.main(testRunner=unittest.TextTestRunner(
        stream=sys.stdout, resultclass=ShortResult,
        verbosity=1 if brief else 2))
