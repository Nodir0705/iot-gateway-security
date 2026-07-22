#!/bin/bash
# Volumetric flood simulation for XDP/eBPF testing
TYPE=${1:-syn}
TARGET=${2:-127.0.0.1}
PORT=${3:-8080}
COUNT=${4:-5000}

echo "=== Volumetric Flood Test ==="
echo "Type: $TYPE | Target: $TARGET:$PORT | Packets: $COUNT"
echo "Starting in 3 seconds... (Ctrl+C to abort)"
sleep 3

case $TYPE in
    syn)  sudo hping3 -S -p $PORT --fast -c $COUNT $TARGET 2>&1 ;;
    udp)  sudo hping3 --udp -p $PORT --fast -c $COUNT $TARGET 2>&1 ;;
    icmp) sudo hping3 --icmp --fast -c $COUNT $TARGET 2>&1 ;;
    *)    echo "Unknown type: $TYPE (use: syn, udp, icmp)"; exit 1 ;;
esac
echo "Flood test complete."
