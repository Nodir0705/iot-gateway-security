#!/bin/bash
# Quarantine / release IoT devices via nftables
# Usage: quarantine.sh {add|remove|list|flush} [IP] [timeout]

NFT_TABLE="inet iot_gateway"
NFT_SET="quarantine_v4"

case $1 in
    add)
        if [ -z "$2" ]; then echo "Usage: $0 add <IP> [timeout_sec]"; exit 1; fi
        TIMEOUT=${3:-3600}  # Default 1 hour
        sudo nft add element $NFT_TABLE $NFT_SET "{ $2 timeout ${TIMEOUT}s }"
        echo "[QUARANTINE] $2 isolated for ${TIMEOUT}s"
        logger -t iot-gateway "QUARANTINE: $2 isolated for ${TIMEOUT}s"
        ;;
    remove)
        if [ -z "$2" ]; then echo "Usage: $0 remove <IP>"; exit 1; fi
        sudo nft delete element $NFT_TABLE $NFT_SET "{ $2 }"
        echo "[RELEASED] $2 back online"
        logger -t iot-gateway "RELEASED: $2 back online"
        ;;
    list)
        echo "=== Quarantined Devices ==="
        sudo nft list set $NFT_TABLE $NFT_SET
        ;;
    flush)
        sudo nft flush set $NFT_TABLE $NFT_SET
        echo "All devices released"
        ;;
    *)
        echo "Usage: $0 {add|remove|list|flush} [IP] [timeout_sec]"
        ;;
esac
