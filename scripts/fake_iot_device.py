#!/usr/bin/env python3
"""
Simulates a vulnerable IoT device with:
- HTTP web interface on port 8080 (like a smart camera)
- Telnet on port 2323 (like Mirai target)
- UPnP/SSDP listener on port 1900
"""
import socket
import threading
import sys

def http_server(port=8080):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    print(f"[IoT HTTP] Listening on :{port}")
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><body><h1>Smart Camera v1.0</h1>"
            "<form>Login: <input name='user'> Pass: <input name='pass' type='password'>"
            "<button>Login</button></form></body></html>"
        )
        conn.send(response.encode())
        conn.close()

def telnet_server(port=2323):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    print(f"[IoT Telnet] Listening on :{port}")
    while True:
        conn, addr = s.accept()
        conn.send(b"\r\nLogin: ")
        try:
            user = conn.recv(256)
            conn.send(b"Password: ")
            pwd = conn.recv(256)
            conn.send(b"\r\nLogin incorrect\r\n")
            print(f"  [Telnet] Login attempt from {addr}: {user.strip()}/{pwd.strip()}")
        except:
            pass
        conn.close()

def upnp_listener(port=1900):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    print(f"[IoT UPnP] Listening on UDP :{port}")
    while True:
        data, addr = s.recvfrom(1024)
        if b"M-SEARCH" in data:
            response = (
                "HTTP/1.1 200 OK\r\n"
                "ST: urn:schemas-upnp-org:device:Basic:1\r\n"
                "USN: uuid:fake-iot-camera-001\r\n"
                "LOCATION: http://{}:8080/desc.xml\r\n\r\n"
            ).format(socket.gethostbyname(socket.gethostname()))
            s.sendto(response.encode(), addr)
            print(f"  [UPnP] Discovery from {addr}")

if __name__ == '__main__':
    print("=== Fake IoT Device Simulator ===")
    print("Simulating: Smart Camera with HTTP + Telnet + UPnP")
    print("Ctrl+C to stop\n")
    threads = [
        threading.Thread(target=http_server, daemon=True),
        threading.Thread(target=telnet_server, daemon=True),
        threading.Thread(target=upnp_listener, daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\nStopped.")
