#!/bin/bash
# XDP Filter Management — IoT Security Gateway
# Manages whitelist/blacklist/stats for the XDP L4 pre-filter
set -e

XDP_OBJ="/etc/suricata/ebpf/xdp_filter.bpf"
IFACE="${IFACE:-eth0}"

ip_to_hex() {
    # Convert IP like 192.168.3.1 to "0xC0 0xA8 0x03 0x01"
    printf '%s' "$1" | awk -F. '{printf "0x%02X 0x%02X 0x%02X 0x%02X", $1, $2, $3, $4}'
}

port_to_hex() {
    # Convert port to 2-byte little-endian hex
    printf "0x%02X 0x%02X" $(($1 & 0xFF)) $(($1 >> 8 & 0xFF))
}

case "$1" in
    load)
        echo "Loading XDP filter on $IFACE ..."
        sudo ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp
        echo "Done. XDP filter active on $IFACE"
        ;;

    unload)
        echo "Unloading XDP filter from $IFACE ..."
        sudo ip link set dev "$IFACE" xdp off
        echo "Done."
        ;;

    status)
        echo "=== XDP status on $IFACE ==="
        ip link show dev "$IFACE" | grep -i xdp || echo "No XDP program loaded"
        echo ""
        if command -v bpftool &>/dev/null; then
            echo "=== Pinned maps ==="
            ls /sys/fs/bpf/xdp_* 2>/dev/null || echo "No pinned maps found"
        fi
        ;;

    whitelist-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 whitelist-ip <IP>"; exit 1
        fi
        KEY=$(ip_to_hex "$2")
        echo "Whitelisting IP $2 ..."
        sudo bpftool map update pinned /sys/fs/bpf/xdp_whitelist_ips \
            key $KEY  value 0x01 0x00 0x00 0x00
        echo "Done."
        ;;

    blacklist-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 blacklist-ip <IP>"; exit 1
        fi
        KEY=$(ip_to_hex "$2")
        echo "Blacklisting IP $2 ..."
        sudo bpftool map update pinned /sys/fs/bpf/xdp_blacklist_ips \
            key $KEY  value 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        echo "Done."
        ;;

    whitelist-port)
        if [ -z "$2" ]; then
            echo "Usage: $0 whitelist-port <PORT>"; exit 1
        fi
        KEY=$(port_to_hex "$2")
        echo "Whitelisting port $2 ..."
        sudo bpftool map update pinned /sys/fs/bpf/xdp_whitelist_ports \
            key $KEY  value 0x01 0x00 0x00 0x00
        echo "Done."
        ;;

    remove-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 remove-ip <IP>"; exit 1
        fi
        KEY=$(ip_to_hex "$2")
        echo "Removing IP $2 from whitelist and blacklist ..."
        sudo bpftool map delete pinned /sys/fs/bpf/xdp_whitelist_ips key $KEY 2>/dev/null || true
        sudo bpftool map delete pinned /sys/fs/bpf/xdp_blacklist_ips key $KEY 2>/dev/null || true
        echo "Done."
        ;;

    stats)
        echo "=== XDP Filter Stats ==="
        if [ -f /sys/fs/bpf/xdp_stats ]; then
            sudo bpftool map dump pinned /sys/fs/bpf/xdp_stats 2>/dev/null
        else
            echo "Stats map not found — is XDP loaded?"
        fi
        ;;

    *)
        echo "XDP Filter Management — IoT Security Gateway"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  load                  Load XDP filter on $IFACE"
        echo "  unload                Unload XDP filter from $IFACE"
        echo "  status                Show XDP status"
        echo "  whitelist-ip <IP>     Add IP to whitelist (bypass inspection)"
        echo "  blacklist-ip <IP>     Add IP to blacklist (drop at NIC level)"
        echo "  whitelist-port <PORT> Add port to whitelist (e.g., 443 for HTTPS)"
        echo "  remove-ip <IP>        Remove IP from whitelist and blacklist"
        echo "  stats                 Show packet counters"
        echo ""
        echo "Examples:"
        echo "  $0 load"
        echo "  $0 whitelist-ip 192.168.3.1      # trust the gateway"
        echo "  $0 whitelist-port 443             # bypass HTTPS streaming"
        echo "  $0 blacklist-ip 45.33.32.156      # block malicious IP"
        ;;
esac
