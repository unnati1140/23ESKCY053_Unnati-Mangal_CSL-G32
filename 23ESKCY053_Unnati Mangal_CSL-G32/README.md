# ARP Spoofing Detector

**Mini Project CSL-032 - Cyber Security Lab (7CS4-22), B.Tech VII Semester, Session 2026-27**
**Unnati Mangal, Roll No. 23ESKCY053, CSE (IoT), Batch IoT-A-G2, SKIT Jaipur**
Linked syllabus experiment: Experiment 6 - *Perform an Experiment to Sniff Traffic using ARP Poisoning*.

The program monitors ARP traffic with Scapy, keeps an IP-MAC table and
raises an alert when a binding conflicts with what was seen before or
when a station floods the LAN with gratuitous ARPs.

It only **listens**. Nothing in this project transmits a packet.

## 1. Detection rules

| Rule | Name | Severity | Fires when |
|------|------|----------|------------|
| R1 | IP-MAC CONFLICT | HIGH | a known IP address is claimed by a different MAC |
| R2 | BINDING FLIP-FLOP | CRITICAL | the IP keeps switching between two MACs |
| R3 | TRUSTED BINDING VIOLATED | CRITICAL | an IP from the trusted file is claimed by another MAC |
| R4 | GRATUITOUS ARP FLOOD | HIGH | 5 or more gratuitous ARPs from one MAC within 10 s |
| R5 | MAC CLAIMS MANY IPs | MEDIUM | one MAC claims 3 or more IP addresses |
| R6 | INCONSISTENT HEADERS | MEDIUM | Ethernet source MAC differs from the ARP sender MAC |
| R7 | UNSOLICITED REPLY | LOW | an ARP reply arrives without a matching request |

All thresholds can be changed on the command line (`python arp_detector.py --help`).

## 2. Requirements (Windows 10 / 11)

1. **Python 3.10 or newer** from python.org (tick "Add python.exe to PATH").
   If `python` is not recognised in the terminal, type `py` instead.
2. **Scapy**: `pip install -r requirements.txt`
   (matplotlib in that file is only needed for the graphs).
3. **Npcap** from https://npcap.com, installed with the default options.
   Needed only for *live* capture; analysing capture files works without it.
4. Optional: **Wireshark**, to look at the capture files in `samples/`.

The program also runs on Linux and macOS (live capture then needs `sudo`).

## 3. How to run

Open a terminal in the project folder.

```
python arp_detector.py --help
python arp_detector.py --read samples/s1_normal.pcap
python arp_detector.py --read samples/s2_mitm_poisoning.pcap
python arp_detector.py --read samples/s3_garp_flood.pcap --realtime
python arp_detector.py --read samples/s7_poisoned_before_start.pcap --trusted config/trusted_bindings.txt
python arp_detector.py --read samples/s2_mitm_poisoning.pcap --log results/alerts.csv --export-table results/table.csv
```

`--realtime` replays a capture with its original timing, so the alerts
appear one after another exactly as they would during live monitoring.
`-v` shows every ARP packet, `-q` shows only alerts and the summary.

### Live capture

Open the terminal **as Administrator** (Npcap must be installed).

```
python arp_detector.py --list-interfaces
python arp_detector.py --iface "Wi-Fi"
```

Stop with Ctrl+C; the IP-MAC table and the summary are printed.
Use live capture only on a network you own (home Wi-Fi, mobile
hotspot, VirtualBox host-only network) - never on the college network.

## 4. Tests and results

```
python tests/test_detector.py        44 unit tests
python tests/run_evaluation.py       all lab scenarios against the ground truth
python tests/threshold_study.py      choice of the flood threshold
python tests/benchmark.py            packets per second
python tools/plot_results.py         graphs in results/ (needs matplotlib)
python tools/show_pcap.py samples/s2_mitm_poisoning.pcap --first 19 --last 30
```

The outputs of these commands are stored in `results/`.

## 5. The lab captures

`lab/generate_scenarios.py` builds a virtual LAN (192.168.56.0/24, MAC
addresses 02:..., defined in `lab/lab_network.py`) and writes its
traffic into capture files. The script only writes files; it cannot
send a packet. `python lab/generate_scenarios.py` recreates them
byte for byte.

| File in `samples/` | Kind | Content | Expected rules |
|--------------------|------|---------|----------------|
| s1_normal.pcap | benign | hosts boot, resolve and refresh addresses | none |
| s2_mitm_poisoning.pcap | attack | two-way poisoning of PC-A and the gateway | R1 R2 R5 R7 |
| s3_garp_flood.pcap | attack | 50 forged gratuitous ARPs in 5 s | R1 R2 R4 |
| s4_dhcp_reassignment.pcap | benign | address re-used by a new device after the TTL | none |
| s5_router_replaced.pcap | benign | router swapped within the TTL (expected false alarm) | R1 |
| s6_blackhole_forged_headers.pcap | attack | IoT node cut off from the server, forged headers | R1 R2 R6 R7 |
| s7_poisoned_before_start.pcap | attack | attack already running when monitoring starts | R1 R2 R7 (R3 with `--trusted`) |

`samples/scenarios.json` holds the ground truth (forged frame numbers
and expected rules).

## 6. Project structure

```
arp_detector.py            command-line program (live / file / replay)
arpdetect/
    events.py              one ARP packet (ArpEvent)
    arp_table.py           IP-MAC binding table
    alerts.py              the seven rules and the Alert record
    config.py              thresholds, trusted-bindings file
    detector.py            detection engine (rules R1-R7)
    capture.py             Scapy: live sniffing, pcap reading, replay
    console.py             text output and CSV files
config/trusted_bindings.txt   trusted IP-MAC pairs of the lab (rule R3)
lab/                       virtual LAN and capture generator
samples/                   the seven lab captures + ground truth
tests/                     unit tests, evaluation, threshold study, benchmark
tools/                     graphs, capture listing
results/                   outputs of the test runs
```

## 7. Ethical use

All attack traffic in this project is synthetic and exists only inside
capture files. No real network, account or person was targeted.
Unauthorised interception or modification of network traffic is an
offence under the Information Technology Act, 2000 (Sections 43 and 66).
