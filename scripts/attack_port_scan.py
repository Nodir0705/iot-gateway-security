#!/usr/bin/env python3
"""
Simulates a compromised IoT device scanning the internal network.
A hacked camera scanning for other devices = lateral movement.
Detection: NPU should flag abnormal connection patterns.
"""
from scapy.all import *
import sys
import socket

def stealth_scan(target, ports=range(1, 1025)):
    print(f"[Port Scan] SYN stealth scan -> {target}")
    print(f"  Scanning ports 1-1024...")
    open_ports = []
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=0.5, verbose=False)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            open_ports.append(port)
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=False)
    print(f"  Open ports: {open_ports if open_ports else 'none found'}")
    return open_ports

def quick_scan(target, ports=[22, 23, 80, 443, 554, 1900, 2323, 5000, 8080, 8443, 8554, 9000]):
    """Quick scan of common IoT ports only"""
    print(f"[Quick Scan] Common IoT ports -> {target}")
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"  Port {port}: OPEN")
            s.close()
        except:
            pass
    print(f"  Open IoT ports: {open_ports}")
    return open_ports

def service_fingerprint(target, ports):
    print(f"\n[Service Fingerprint] Probing {target}")
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((target, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(256).decode(errors='ignore').strip()[:80]
            print(f"  Port {port}: {banner}")
            s.close()
        except:
            print(f"  Port {port}: no banner")

def subnet_sweep(subnet):
    """ARP sweep to find alive hosts — like Mirai worm spreading"""
    print(f"\n[Subnet Sweep] ARP scan {subnet}")
    ans, _ = arping(subnet, timeout=2, verbose=False)
    alive = [(r[1].psrc, r[1].hwsrc) for r in ans]
    for ip, mac in alive:
        print(f"  Alive: {ip} ({mac})")
    print(f"  Total hosts: {len(alive)}")
    return alive

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    mode = sys.argv[2] if len(sys.argv) > 2 else "quick"

    print(f"=== Lateral Movement Simulation ===")
    print(f"(Simulating compromised IoT device scanning network)\n")

    if mode == "quick":
        open_ports = quick_scan(target)
    elif mode == "stealth":
        open_ports = stealth_scan(target)
    elif mode == "sweep":
        subnet_sweep(target)  # pass subnet like 192.168.3.0/24
        sys.exit(0)
    else:
        print(f"Usage: {sys.argv[0]} <target> [quick|stealth|sweep]")
        sys.exit(1)

    if open_ports:
        service_fingerprint(target, open_ports)
    print("\n=== Scan complete ===")
