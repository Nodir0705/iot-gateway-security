#!/bin/bash
IFACE=${IFACE:-eth0}
OBJ_DIR=/home/orangepi/iot-gateway/xdp/obj

ip_to_hex() {
    printf '%02x ' $(echo $1 | tr '.' ' ')
}

case $1 in
    load)
        PROG=${2:-xdp_gateway}
        echo "Loading $PROG on $IFACE..."
        sudo ip link set dev $IFACE xdpgeneric obj $OBJ_DIR/${PROG}.o sec xdp
        ip link show $IFACE | grep xdp && echo "OK" || echo "FAILED"
        ;;
    unload)
        echo "Unloading XDP from $IFACE..."
        sudo ip link set dev $IFACE xdpgeneric off
        echo "OK"
        ;;
    stats)
        echo "=== XDP Gateway Stats ==="
        sudo bpftool map dump name gw_stats 2>/dev/null
        ;;
    flows)
        echo "=== Active Flows (first 20) ==="
        sudo bpftool map dump name flow_table 2>/dev/null | head -80
        ;;
    block)
        if [ -z "$2" ]; then echo "Usage: $0 block <IP> [reason]"; exit 1; fi
        HEX=$(ip_to_hex $2)
        REASON=${3:-1}
        sudo bpftool map update name blacklist key hex $HEX value hex $(printf '%02x' $REASON) 00 00 00
        echo "BLOCKED: $2 (reason: $REASON)"
        ;;
    unblock)
        if [ -z "$2" ]; then echo "Usage: $0 unblock <IP>"; exit 1; fi
        HEX=$(ip_to_hex $2)
        sudo bpftool map delete name blacklist key hex $HEX
        echo "UNBLOCKED: $2"
        ;;
    status)
        echo "=== XDP Status ==="
        ip link show $IFACE | grep xdp
        echo ""
        echo "=== Loaded BPF Programs ==="
        sudo bpftool prog list 2>/dev/null | grep -A2 xdp
        ;;
    *)
        echo "XDP Gateway Control"
        echo "  $0 load [program]  — Load XDP (default: xdp_gateway)"
        echo "  $0 unload          — Remove XDP"
        echo "  $0 stats           — Show packet stats"
        echo "  $0 flows           — Show flow table"
        echo "  $0 block <IP>      — Blacklist an IP"
        echo "  $0 unblock <IP>    — Remove from blacklist"
        echo "  $0 status          — Show status"
        ;;
esac
