#!/bin/bash
# Build eBPF programs for IoT Security Gateway
# Run on Orange Pi (aarch64) — requires clang, libbpf-dev
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="/etc/suricata/ebpf"

echo "── Building eBPF programs ──"

# 1. Suricata bypass filter
echo "  [1/2] suricata_bypass.bpf ..."
clang -O2 -g -target bpf \
    -c "$SCRIPT_DIR/suricata_bypass.c" \
    -o "$SCRIPT_DIR/suricata_bypass.bpf" \
    -I/usr/include -I/usr/include/bpf \
    -D__TARGET_ARCH_arm64

echo "  [2/2] xdp_filter.bpf ..."
clang -O2 -g -target bpf \
    -c "$SCRIPT_DIR/xdp_filter.c" \
    -o "$SCRIPT_DIR/xdp_filter.bpf" \
    -I/usr/include -I/usr/include/bpf \
    -D__TARGET_ARCH_arm64

echo ""
echo "── Installing ──"
sudo mkdir -p "$OUT_DIR"
sudo cp "$SCRIPT_DIR/suricata_bypass.bpf" "$OUT_DIR/"
sudo cp "$SCRIPT_DIR/xdp_filter.bpf" "$OUT_DIR/"

echo "  Installed to $OUT_DIR/"
ls -la "$OUT_DIR/"

echo ""
echo "── Configuration ──"
echo ""
echo "1. Add to /etc/suricata/suricata-iot.yaml under af-packet:"
echo "   ebpf-filter-file: $OUT_DIR/suricata_bypass.bpf"
echo ""
echo "2. Load XDP filter:"
echo "   sudo ip link set dev eth0 xdp obj $OUT_DIR/xdp_filter.bpf sec xdp"
echo ""
echo "3. Manage XDP whitelist (example: whitelist 192.168.3.1):"
echo "   sudo bpftool map update pinned /sys/fs/bpf/xdp_whitelist_ips \\"
echo "     key 0xC0 0xA8 0x03 0x01  value 0x01 0x00 0x00 0x00"
echo ""
echo "Done."
