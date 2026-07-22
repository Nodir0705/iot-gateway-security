#!/bin/bash
IFACE=${1:-eth0}
CAPTURE_DIR=/home/orangepi/iot-gateway/captures
SCRIPT_DIR=/home/orangepi/iot-gateway/scripts

echo "=========================================="
echo " IoT Security Gateway — Full Test Suite"
echo " Interface: $IFACE"
echo " $(date)"
echo "=========================================="

echo ""
echo "[1/7] Starting fake IoT device..."
python3 $SCRIPT_DIR/fake_iot_device.py &
IOT_PID=$!
sleep 2

echo "[2/7] Starting packet capture..."
sudo tcpdump -i lo -w $CAPTURE_DIR/test_full_suite.pcap &
CAP_PID=$!
sleep 1

echo ""
echo "[3/7] Attack: Credential Stuffing"
python3 $SCRIPT_DIR/attack_credential_stuffing.py 127.0.0.1 2>&1 | tail -5
sleep 2

echo ""
echo "[4/7] Attack: C2 Beacon (DNS only, 5 packets)"
sudo python3 $SCRIPT_DIR/attack_c2_beacon.py dns 2>&1 | tail -5
sleep 2

echo ""
echo "[5/7] Attack: UPnP Abuse"
sudo python3 $SCRIPT_DIR/attack_upnp_abuse.py 127.0.0.1 2>&1 | tail -5
sleep 2

echo ""
echo "[6/7] Attack: ARP Spoofing (5 packets)"
sudo python3 $SCRIPT_DIR/attack_arp_spoof.py 127.0.0.1 192.168.3.1 spoof 2>&1 | tail -5
sleep 2

echo ""
echo "[7/7] Attack: SYN Flood (1000 packets)"
sudo $SCRIPT_DIR/attack_flood.sh syn 127.0.0.1 8080 1000 2>&1 | tail -3
sleep 2

echo ""
echo "=========================================="
echo " Stopping captures and services..."
echo "=========================================="
kill $IOT_PID 2>/dev/null
sudo kill $CAP_PID 2>/dev/null
sleep 2

echo ""
echo "=== Capture Summary ==="
echo "Total packets: $(tcpdump -r $CAPTURE_DIR/test_full_suite.pcap 2>/dev/null | wc -l)"

echo ""
echo "=== Protocol Breakdown ==="
tshark -r $CAPTURE_DIR/test_full_suite.pcap -z io,phs -q 2>/dev/null | head -20

echo ""
echo "=== Unique Source IPs ==="
tshark -r $CAPTURE_DIR/test_full_suite.pcap -T fields -e ip.src 2>/dev/null | sort -u | wc -l

echo ""
echo "Full capture: $CAPTURE_DIR/test_full_suite.pcap"
