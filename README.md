# Intrusion Detection System (IDS)

A rule-based Network Intrusion Detection System developed by **Aadarsh Bonthula** as part of a cybersecurity portfolio series focused on network security and ethical hacking fundamentals.

Inspired by the architecture of **Snort IDS** — captures live traffic via raw socket, evaluates each packet against a configurable rule set, and generates timestamped alerts with severity classification.

---

## What It Does

- Captures **live network traffic** at the raw socket level
- Evaluates packets against **Snort-inspired detection rules**
- Detects common attack patterns: **brute force, port scans, ICMP floods, SMB exploits, DDoS indicators**
- **Threshold-based alerting** — prevents alert fatigue from single-packet noise
- Classifies alerts as **HIGH / MED / LOW** severity
- Exports a structured **alert log** for incident response review

---

## Concepts Applied

| Concept | Reference |
|---------|-----------|
| IDS Architecture (NIDS) | Chapter 2.4 — Firewalls, IDS & IPS (CodTech Material) |
| Network Forensics | Chapter 11.4 — Network Forensics & Log Analysis |
| Snort as IDS Tool | Chapter 11.4 — Network Forensic Tools (Snort reference) |
| Brute Force / DDoS Detection | Chapter 5.5 — Password Cracking & Brute Force Attacks |
| SMB Exploit Detection | Chapter 5.2 — Metasploit (EternalBlue / MS17-010) |
| Incident Response | Chapter 11.5 — Incident Response & Threat Hunting |

---

## Requirements

- Python 3.7+
- Linux OS
- **Root / sudo privileges**
- No external libraries

---

## Project Structure

```
ids-snort/
├── ids.py                  # Main IDS engine
├── rules/
│   └── default.rules       # Detection rule set (Snort-compatible syntax)
├── demo/
│   └── sample_alerts.log   # Example alert output
└── README.md
```

---

## Usage

```bash
# Run with default rules
sudo python3 ids.py

# Run with custom rules file
sudo python3 ids.py --rules rules/custom.rules

# Run and save alerts to log
sudo python3 ids.py --rules rules/default.rules --log alerts.log
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `--rules` | Path to `.rules` file | `rules/default.rules` |
| `--log` | Save alert log to file | Console only |

---

## Rule Syntax

Rules follow a simplified Snort format:

```
alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (msg:"..."; threshold:N; sid:N; severity:LEVEL;)
```

**Examples:**
```
# SSH brute force — 5 hits from same source triggers HIGH alert
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; threshold:5; sid:1001; severity:HIGH;)

# ICMP flood detection
alert icmp any any -> any any (msg:"ICMP Flood Detected"; threshold:20; sid:1004; severity:HIGH;)

# Telnet — unencrypted, alerts on first occurrence
alert tcp any any -> any 23 (msg:"Telnet Connection Detected"; threshold:1; sid:1003; severity:MED;)
```

**Rule Fields:**

| Field | Description |
|-------|-------------|
| `proto` | `tcp`, `udp`, `icmp`, or `any` |
| `src_ip` / `dst_ip` | IP address or `any` |
| `src_port` / `dst_port` | Port number or `any` |
| `msg` | Alert description |
| `threshold` | Minimum hits before alert fires |
| `sid` | Unique rule ID |
| `severity` | `HIGH`, `MED`, or `LOW` |
| `content` | Optional payload keyword match |

---

## Sample Output

```
============================================================
  Intrusion Detection System — Aadarsh Bonthula
  Rules    : 11 loaded
  Log      : alerts.log
  Started  : 2025-06-10 15:30:00
============================================================
  Monitoring traffic. Press Ctrl+C to stop.

[ALERT] [2025-06-10 15:30:12] [SID:1001] [HIGH] SSH Brute Force Attempt
         TCP 192.168.1.100:54921 → 192.168.1.10:22 | Hits: 5

[ALERT] [2025-06-10 15:30:45] [SID:1004] [HIGH] ICMP Flood Detected
         ICMP 10.0.0.5 → 192.168.1.10 | Hits: 20

[ALERT] [2025-06-10 15:31:02] [SID:1008] [HIGH] SMB Attack Attempt — EternalBlue Risk
         TCP 192.168.1.200:49150 → 192.168.1.10:445 | Hits: 3

[*] IDS stopped. 3 alert(s) generated.
[*] Alert log saved to: alerts.log
```

---

## How It Works

### Rule Engine
Each packet is evaluated against every loaded rule. A rule matches when protocol, source IP/port, and destination IP/port all satisfy the rule's conditions. Content-based rules also check the packet payload for keyword matches.

### Threshold Logic
Each rule maintains a per-source-IP hit counter. An alert only fires when the counter reaches the configured threshold. This mirrors Snort's threshold directive — preventing a single port scan from generating hundreds of individual alerts.

### Alert Classification
- **HIGH** — Active exploitation attempt or confirmed attack pattern (brute force, EternalBlue, flood)
- **MED** — Suspicious activity requiring investigation (scanning, unusual protocols)
- **LOW** — Informational — unusual but not immediately dangerous

---

## Legal Disclaimer

This tool is developed for **educational purposes and authorized network monitoring only**. Deploy only on networks you own or have explicit written permission to monitor.

---

## Author

**Aadarsh Bonthula**
B.Tech Computer Science (Cybersecurity Specialization)
Manav Rachna International Institute of Research and Studies

GitHub: [NovocaineX](https://github.com/NovocaineX)

*Developed as part of a cybersecurity portfolio series focused on network security and ethical hacking fundamentals.*
