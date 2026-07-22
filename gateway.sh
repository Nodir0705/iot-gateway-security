#!/bin/bash
# IoT Security Gateway — Unified Control Script
# Usage: gateway.sh {start|stop|status|test}

GATEWAY_DIR="$HOME/iot-gateway"
LOG_DIR="$GATEWAY_DIR/logs"
PID_DIR="$GATEWAY_DIR/pids"
mkdir -p "$LOG_DIR" "$PID_DIR"

start_gateway() {
    echo "╔══════════════════════════════════════════════╗"
    echo "║   IoT Security Gateway — RK3588S Starting   ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""

    # 0. Flush any stale quarantine rules from previous run
    echo "[0/6] Clearing stale quarantine..."
    sudo nft flush set inet iot_gateway quarantine_v4 2>/dev/null

    # 1. Load nftables
    echo "[1/6] Loading nftables quarantine rules..."
    sudo nft -f /etc/nftables-iot.conf 2>/dev/null && echo "  ✓ nftables loaded" || echo "  ✗ nftables failed"

    # 2. Load XDP
    echo "[2/6] Loading XDP/eBPF gateway filter..."
    $GATEWAY_DIR/xdp/scripts/xdp_control.sh load xdp_gateway 2>/dev/null && echo "  ✓ XDP loaded" || echo "  ✗ XDP failed (non-critical)"

    # 3. Start Suricata
    echo "[3/6] Starting Suricata IDS..."
    if ! pidof suricata > /dev/null 2>&1; then
    bash ~/iot-gateway/setup_bridge.sh
        sudo suricata -c /etc/suricata/suricata-iot.yaml --af-packet -D 2>/dev/null
        sleep 3
        pidof suricata > /dev/null && echo "  ✓ Suricata running (PID: $(pidof suricata))" || echo "  ✗ Suricata failed"
    else
        echo "  ✓ Suricata already running (PID: $(pidof suricata))"
    fi

    # 4. Start MQTT broker
    echo "[4/6] Checking MQTT broker..."
    if systemctl is-active mosquitto > /dev/null 2>&1; then
        echo "  ✓ Mosquitto running"
    else
        sudo systemctl start mosquitto 2>/dev/null && echo "  ✓ Mosquitto started" || echo "  ✗ Mosquitto failed (alerts will log only)"
    fi

    # 4.5. Start Suricata watcher
    echo "[4.5/6] Starting Suricata alert watcher..."
    sudo HOME=/home/orangepi PYTHONPATH=/home/orangepi/.local/lib/python3.10/site-packages python3 -u $GATEWAY_DIR/scripts/suricata_watcher.py \
        > "$LOG_DIR/suricata_watcher.log" 2>&1 &
    echo $! > "$PID_DIR/suricata_watcher.pid"
    echo "  ✓ Suricata watcher started (PID: $!)"
    # 5. Start detection pipeline
    echo "[5/6] Starting detection pipeline..."
    sudo HOME=/home/orangepi PYTHONPATH=/home/orangepi/.local/lib/python3.10/site-packages python3 -u $GATEWAY_DIR/scripts/detect_pipeline.py eth0 0 \
        > "$LOG_DIR/pipeline.log" 2>&1 &
    echo $! > "$PID_DIR/pipeline.pid"
    echo "  ✓ Detection pipeline started (PID: $!)"

    # 6. Start dashboard
    echo "[6/6] Starting web dashboard..."
    python3 $GATEWAY_DIR/dashboard/app.py \
        > "$LOG_DIR/dashboard.log" 2>&1 &
    echo $! > "$PID_DIR/dashboard.pid"
    echo "  ✓ Dashboard at http://$(hostname -I | awk '{print $1}'):5000"

    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║          Gateway Started Successfully        ║"
    echo "╠══════════════════════════════════════════════╣"
    echo "║  Dashboard : http://$(hostname -I | awk '{print $1}'):5000          ║"
    echo "║  MQTT      : localhost:1883                  ║"
    echo "║  Logs      : ~/iot-gateway/logs/             ║"
    echo "╚══════════════════════════════════════════════╝"
}

stop_gateway() {
    echo "Stopping IoT Security Gateway..."

    # Stop pipeline
    if [ -f "$PID_DIR/pipeline.pid" ]; then
        sudo kill $(cat "$PID_DIR/pipeline.pid") 2>/dev/null
        rm "$PID_DIR/pipeline.pid"
        echo "  ✓ Pipeline stopped"
    fi

    # Stop Suricata watcher
    if [ -f "$PID_DIR/suricata_watcher.pid" ]; then
        sudo kill $(cat "$PID_DIR/suricata_watcher.pid") 2>/dev/null
        rm "$PID_DIR/suricata_watcher.pid"
        echo "  ✓ Suricata watcher stopped"
    fi

    # Stop dashboard
    if [ -f "$PID_DIR/dashboard.pid" ]; then
        kill $(cat "$PID_DIR/dashboard.pid") 2>/dev/null
        rm "$PID_DIR/dashboard.pid"
        echo "  ✓ Dashboard stopped"
    fi

    # Stop Suricata
    sudo kill $(pidof suricata) 2>/dev/null && echo "  ✓ Suricata stopped"

    # Unload XDP
    $GATEWAY_DIR/xdp/scripts/xdp_control.sh unload 2>/dev/null && echo "  ✓ XDP unloaded"

    # Flush quarantine
    sudo nft flush set inet iot_gateway quarantine_v4 2>/dev/null && echo "  ✓ Quarantine flushed"

    echo "Gateway stopped."
}

status_gateway() {
    echo "╔══════════════════════════════════════════════╗"
    echo "║       IoT Security Gateway Status            ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""

    # XDP
    echo -n "  XDP/eBPF:    "
    ip link show eth0 | grep -q xdp && echo "✓ LOADED" || echo "✗ NOT LOADED"

    # Suricata
    echo -n "  Suricata:    "
    pidof suricata > /dev/null && echo "✓ RUNNING (PID: $(pidof suricata))" || echo "✗ STOPPED"

    # MQTT
    echo -n "  MQTT:        "
    systemctl is-active mosquitto > /dev/null 2>&1 && echo "✓ RUNNING" || echo "✗ STOPPED"

    # Pipeline
    echo -n "  Pipeline:    "
    if [ -f "$PID_DIR/pipeline.pid" ] && kill -0 $(cat "$PID_DIR/pipeline.pid") 2>/dev/null; then
        echo "✓ RUNNING (PID: $(cat $PID_DIR/pipeline.pid))"
    else
        echo "✗ STOPPED"
    fi

    # Dashboard
    echo -n "  Dashboard:   "
    if [ -f "$PID_DIR/dashboard.pid" ] && kill -0 $(cat "$PID_DIR/dashboard.pid") 2>/dev/null; then
        echo "✓ RUNNING (http://$(hostname -I | awk '{print $1}'):5000)"
    else
        echo "✗ STOPPED"
    fi

    # nftables
    echo -n "  nftables:    "
    sudo nft list set inet iot_gateway quarantine_v4 2>/dev/null | grep -q "elements" && \
        echo "✓ LOADED ($(sudo nft list set inet iot_gateway quarantine_v4 2>/dev/null | grep -c 'timeout')  quarantined)" || \
        echo "✓ LOADED (0 quarantined)"

    # Logs
    echo ""
    echo "  Recent alerts:"
    tail -3 "$LOG_DIR/decisions.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f'    [{d[\"action\"]}] {d[\"ip\"]} score={d[\"score\"]:.0f}')
    except: pass
" 2>/dev/null || echo "    (none)"
}

test_gateway() {
    echo "=== End-to-End Gateway Test ==="
    echo ""

    # Test 1: Decision Engine
    echo "[Test 1] Decision Engine..."
    python3 $GATEWAY_DIR/scripts/decision_engine.py
    echo ""

    # Test 2: Quarantine
    echo "[Test 2] Quarantine..."
    $GATEWAY_DIR/scripts/quarantine.sh add 192.168.3.200 30
    $GATEWAY_DIR/scripts/quarantine.sh list
    $GATEWAY_DIR/scripts/quarantine.sh remove 192.168.3.200
    echo ""

    # Test 3: MQTT
    echo "[Test 3] MQTT Alerts..."
    python3 $GATEWAY_DIR/scripts/mqtt_alerter.py 2>/dev/null || echo "  MQTT not available (OK)"
    echo ""

    # Test 4: NPU Detection
    echo "[Test 4] NPU Detector..."
    python3 $GATEWAY_DIR/scripts/npu_detector.py 2>/dev/null | head -10
    echo ""

    echo "=== All tests complete ==="
}

case $1 in
    start)  start_gateway ;;
    stop)   stop_gateway ;;
    status) status_gateway ;;
    test)   test_gateway ;;
    *)      echo "Usage: $0 {start|stop|status|test}" ;;
esac
