#!/bin/bash
IFACE=${1:-eth0}

while true; do
    clear
    echo "=========================================="
    echo " IoT Security Gateway Monitor"
    echo " $(date '+%Y-%m-%d %H:%M:%S') | $IFACE"
    echo "=========================================="

    RX1=$(cat /sys/class/net/$IFACE/statistics/rx_packets)
    TX1=$(cat /sys/class/net/$IFACE/statistics/tx_packets)
    RXB1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
    sleep 1
    RX2=$(cat /sys/class/net/$IFACE/statistics/rx_packets)
    TX2=$(cat /sys/class/net/$IFACE/statistics/tx_packets)
    RXB2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)

    BPS=$(( (RXB2 - RXB1) * 8 ))
    echo ""
    echo "Packets/sec  — RX: $((RX2-RX1))  TX: $((TX2-TX1))"
    if [ $BPS -gt 1000000 ]; then
        echo "Bandwidth    — $(echo "scale=2; $BPS/1000000" | bc) Mbps"
    else
        echo "Bandwidth    — $(echo "scale=2; $BPS/1000" | bc) Kbps"
    fi

    echo ""
    echo "Connection States:"
    ss -tan | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn | head -5

    SYN_COUNT=$(ss -tan state syn-recv | wc -l)
    ESTAB_COUNT=$(ss -tan state established | wc -l)
    ARP_COUNT=$(arp -n 2>/dev/null | grep -v incomplete | wc -l)

    echo ""
    if [ "$SYN_COUNT" -gt 50 ]; then
        echo "!! WARNING: $SYN_COUNT half-open connections (SYN flood?)"
    fi
    if [ "$ESTAB_COUNT" -gt 200 ]; then
        echo "!! WARNING: $ESTAB_COUNT established connections (Slowloris?)"
    fi
    echo "ARP entries  — $ARP_COUNT"

    sleep 3
done
