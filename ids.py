#!/usr/bin/env python3
"""
Intrusion Detection System - ids.py
Developed by Aadarsh Bonthula
Reference: Cybersecurity and Ethical Hacking Material, CodTech IT Solutions
           Chapter 2.4 — Firewalls, IDS & IPS
           Chapter 11.4 — Network Forensics & Log Analysis (Snort reference)

This IDS operates similarly to Snort's rule-based detection engine:
  - Loads detection rules from a rules file (snort-style syntax)
  - Captures live traffic via raw socket
  - Matches packets against rules
  - Generates alerts with severity, timestamps, and IOC details
  - Exports an alert log

USAGE (requires root):
  sudo python3 ids.py
  sudo python3 ids.py --rules rules/custom.rules --log alerts.log
"""

import socket
import struct
import argparse
import signal
import sys
import os
import re
from datetime import datetime

# ─── Rule Engine ─────────────────────────────────────────────────────────────
class IDSRule:
    """
    Represents a single detection rule.

    Rule format (simplified Snort syntax):
      alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (msg:"..."; threshold:N; sid:N; severity:N;)

    Examples:
      alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; threshold:5; sid:1001; severity:HIGH;)
      alert tcp any any -> any 80 (msg:"HTTP Port Scan Detected"; threshold:10; sid:1002; severity:MED;)
      alert icmp any any -> any any (msg:"ICMP Flood"; threshold:20; sid:1003; severity:LOW;)
    """

    def __init__(self, action, proto, src_ip, src_port,
                 dst_ip, dst_port, msg, threshold, sid, severity, content=None):
        self.action    = action      # "alert"
        self.proto     = proto       # tcp, udp, icmp, any
        self.src_ip    = src_ip      # IP or "any"
        self.src_port  = src_port    # port number or "any"
        self.dst_ip    = dst_ip      # IP or "any"
        self.dst_port  = dst_port    # port number or "any"
        self.msg       = msg         # Alert message
        self.threshold = threshold   # Minimum hits before alerting
        self.sid       = sid         # Rule ID
        self.severity  = severity    # HIGH / MED / LOW
        self.content   = content     # Optional payload keyword
        self.hit_count = {}          # {src_ip: count} — tracks per-source hits

    def matches(self, proto_name, src_ip, src_port, dst_ip, dst_port, payload=b""):
        """Check whether a captured packet matches this rule."""
        if self.proto not in ("any", proto_name.lower()):
            return False
        if self.src_ip != "any" and self.src_ip != src_ip:
            return False
        if self.src_port != "any" and self.src_port != str(src_port):
            return False
        if self.dst_ip != "any" and self.dst_ip != dst_ip:
            return False
        if self.dst_port != "any" and self.dst_port != str(dst_port):
            return False
        if self.content:
            try:
                if self.content.lower() not in payload.decode(errors="ignore").lower():
                    return False
            except Exception:
                return False
        return True

    def should_alert(self, src_ip: str) -> bool:
        """
        Threshold logic — only alert after N hits from the same source.
        This prevents alert fatigue from single-packet noise.
        """
        self.hit_count[src_ip] = self.hit_count.get(src_ip, 0) + 1
        return self.hit_count[src_ip] >= self.threshold


# ─── Rule Parser ─────────────────────────────────────────────────────────────
def parse_rules(filepath: str) -> list:
    """
    Load and parse rules from a .rules file.
    Lines starting with # are comments. Blank lines are skipped.
    """
    rules = []
    if not os.path.exists(filepath):
        print(f"[WARN] Rules file not found: {filepath}. Using built-in defaults.")
        return load_default_rules()

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rule = parse_rule_line(line)
            if rule:
                rules.append(rule)

    print(f"[*] Loaded {len(rules)} rule(s) from {filepath}")
    return rules


def parse_rule_line(line: str):
    """Parse one rule line into an IDSRule object."""
    try:
        # Match: action proto src_ip src_port -> dst_ip dst_port (options)
        pattern = r'(\w+)\s+(\w+)\s+([\w.]+)\s+([\w]+)\s+->\s+([\w.]+)\s+([\w]+)\s+\((.+)\)'
        m = re.match(pattern, line)
        if not m:
            return None

        action, proto, src_ip, src_port, dst_ip, dst_port, options = m.groups()

        # Parse options block
        def get_opt(key):
            om = re.search(rf'{key}:"?([^";]+)"?', options)
            return om.group(1).strip() if om else None

        msg       = get_opt("msg") or "Unknown alert"
        sid       = get_opt("sid") or "0"
        severity  = get_opt("severity") or "LOW"
        content   = get_opt("content")
        threshold = int(get_opt("threshold") or "1")

        return IDSRule(action, proto, src_ip, src_port,
                       dst_ip, dst_port, msg, threshold,
                       sid, severity.upper(), content)
    except Exception:
        return None


def load_default_rules() -> list:
    """
    Built-in detection rules — covers common attack patterns.
    Based on threat types described in the reference material.
    """
    defaults = [
        # SSH brute force — repeated connections to port 22 (Chapter 5.5)
        "alert tcp any any -> any 22 (msg:\"SSH Brute Force Attempt\"; threshold:5; sid:1001; severity:HIGH;)",
        # HTTP directory scanning — high connection rate to port 80
        "alert tcp any any -> any 80 (msg:\"HTTP Scan / Enumeration\"; threshold:15; sid:1002; severity:MED;)",
        # Telnet connection — unencrypted protocol, suspicious in modern networks
        "alert tcp any any -> any 23 (msg:\"Telnet Connection Detected\"; threshold:1; sid:1003; severity:MED;)",
        # ICMP flood — Chapter 12 (DDoS via ICMP)
        "alert icmp any any -> any any (msg:\"ICMP Flood Detected\"; threshold:20; sid:1004; severity:HIGH;)",
        # RDP brute force — port 3389
        "alert tcp any any -> any 3389 (msg:\"RDP Brute Force Attempt\"; threshold:5; sid:1005; severity:HIGH;)",
        # FTP login attempts
        "alert tcp any any -> any 21 (msg:\"FTP Connection Attempt\"; threshold:3; sid:1006; severity:LOW;)",
        # DNS amplification indicator — high UDP 53 rate
        "alert udp any any -> any 53 (msg:\"High Rate DNS Query\"; threshold:30; sid:1007; severity:MED;)",
        # SMB attack — EternalBlue targets 445 (Chapter 5.2 Metasploit example)
        "alert tcp any any -> any 445 (msg:\"SMB Attack Attempt (EternalBlue Risk)\"; threshold:3; sid:1008; severity:HIGH;)",
    ]
    rules = [parse_rule_line(r) for r in defaults]
    return [r for r in rules if r]


# ─── Alert Logger ────────────────────────────────────────────────────────────
class AlertLogger:
    """Handles alert formatting and log file output."""

    SEVERITY_COLORS = {
        "HIGH": "\033[91m",   # Red
        "MED":  "\033[93m",   # Yellow
        "LOW":  "\033[96m",   # Cyan
        "RESET": "\033[0m"
    }

    def __init__(self, log_file=None):
        self.log_file  = log_file
        self.alerts    = []
        self.alert_count = 0

    def alert(self, rule: IDSRule, src_ip: str, dst_ip: str,
              src_port, dst_port, proto: str):
        """Format and output an alert."""
        self.alert_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        color = self.SEVERITY_COLORS.get(rule.severity, "")
        reset = self.SEVERITY_COLORS["RESET"]

        console_line = (
            f"{color}[ALERT]{reset} [{timestamp}] "
            f"[SID:{rule.sid}] [{rule.severity}] {rule.msg}\n"
            f"         {proto} {src_ip}:{src_port} → {dst_ip}:{dst_port}"
            f" | Hits: {rule.hit_count.get(src_ip, 0)}"
        )
        print(console_line)

        log_line = (
            f"[{timestamp}] [SID:{rule.sid}] [{rule.severity}] {rule.msg} | "
            f"{proto} {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
            f"Hits: {rule.hit_count.get(src_ip, 0)}"
        )
        self.alerts.append(log_line)

    def save(self):
        """Write alerts to log file."""
        if self.log_file and self.alerts:
            with open(self.log_file, "w") as f:
                f.write(f"IDS Alert Log — Aadarsh Bonthula\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")
                f.write("\n".join(self.alerts))
                f.write(f"\n\nTotal Alerts: {self.alert_count}\n")
            print(f"\n[*] Alert log saved to: {self.log_file}")


# ─── Packet Parsing (reused from sniffer architecture) ───────────────────────
def parse_ipv4(raw: bytes):
    ihl = (raw[0] & 0xF) * 4
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", raw[:20])
    return proto, socket.inet_ntoa(src), socket.inet_ntoa(dst), raw[ihl:]

def parse_tcp(raw: bytes):
    src_port, dst_port = struct.unpack("!HH", raw[:4])
    offset = ((raw[12] >> 4) * 4)
    return src_port, dst_port, raw[offset:]

def parse_udp(raw: bytes):
    src_port, dst_port = struct.unpack("!HH", raw[:4])
    return src_port, dst_port, raw[8:]


# ─── Main IDS Engine ─────────────────────────────────────────────────────────
def run_ids(rules_file: str, log_file: str):
    """Main capture and detection loop."""
    if os.geteuid() != 0:
        print("[ERROR] Root privileges required. Run: sudo python3 ids.py")
        sys.exit(1)

    rules  = parse_rules(rules_file)
    logger = AlertLogger(log_file)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(0x0003))
    except PermissionError:
        print("[ERROR] Permission denied.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Intrusion Detection System — Aadarsh Bonthula")
    print(f"  Rules    : {len(rules)} loaded")
    print(f"  Log      : {log_file if log_file else 'Console only'}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print("  Monitoring traffic. Press Ctrl+C to stop.\n")

    def handle_exit(sig, frame):
        print(f"\n[*] IDS stopped. {logger.alert_count} alert(s) generated.")
        logger.save()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    while True:
        try:
            raw_data, _ = sock.recvfrom(65535)
            eth_proto   = struct.unpack("!H", raw_data[12:14])[0]

            if socket.htons(eth_proto) != 8:   # Only IPv4
                continue

            ip_data = raw_data[14:]
            proto_num, src_ip, dst_ip, transport = parse_ipv4(ip_data)

            proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
            proto_name = proto_map.get(proto_num, "other")

            src_port, dst_port, payload = 0, 0, b""

            if proto_num == 6:
                src_port, dst_port, payload = parse_tcp(transport)
            elif proto_num == 17:
                src_port, dst_port, payload = parse_udp(transport)

            # Check each rule against this packet
            for rule in rules:
                if rule.matches(proto_name, src_ip, src_port,
                                dst_ip, dst_port, payload):
                    if rule.should_alert(src_ip):
                        logger.alert(rule, src_ip, dst_ip,
                                     src_port, dst_port, proto_name.upper())

        except Exception:
            continue


# ─── CLI Entry Point ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Python Intrusion Detection System — Developed by Aadarsh Bonthula",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 ids.py
  sudo python3 ids.py --rules rules/custom.rules
  sudo python3 ids.py --rules rules/custom.rules --log alerts.log
        """
    )
    parser.add_argument("--rules",
                        default="rules/default.rules",
                        help="Path to rules file (default: rules/default.rules)")
    parser.add_argument("--log",
                        default=None,
                        help="Save alerts to log file")

    args = parser.parse_args()
    run_ids(args.rules, args.log)


if __name__ == "__main__":
    main()
