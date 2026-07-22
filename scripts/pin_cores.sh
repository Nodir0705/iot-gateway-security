#!/bin/bash
# pin_cores.sh — Assign IoT Gateway processes to CPU cores
#
# RK3588S topology:
#   Cortex-A55 LITTLE:  cores 0-3  @ 1.8 GHz  (efficient)
#   Cortex-A76 BIG:     cores 4-7  @ 2.4 GHz  (performance)
#
# Assignment:
#   4-5  →  detect_pipeline + rknn_server  (NPU inference, latency-critical)
#   6-7  →  suricata                       (packet inspection, compute-heavy)
#   2-3  →  influxd + grafana              (analytics stack, IO-bound bursts)
#   0-1  →  dashboard + metrics_exporter + mosquitto  (light services)

pin() {
    local label="$1"
    local pattern="$2"
    local cores="$3"
    local pids
    pids=$(pgrep -f "$pattern" 2>/dev/null)
    if [ -z "$pids" ]; then
        echo "  [SKIP] $label — not running"
        return
    fi
    for pid in $pids; do
        if taskset -cp "$cores" "$pid" > /dev/null 2>&1; then
            echo "  [OK]   $label (pid=$pid) → cores $cores"
        else
            echo "  [FAIL] $label (pid=$pid) → cores $cores (permission denied?)"
        fi
    done
}

echo "========================================"
echo "  IoT Gateway — CPU Affinity Pinning"
echo "  A55 LITTLE: 0-3 @ 1.8GHz"
echo "  A76 BIG:    4-7 @ 2.4GHz"
echo "========================================"

echo ""
echo "[ BIG cores 4-5 — NPU pipeline ]"
pin "detect_pipeline" "detect_pipeline.py"  "4-5"
pin "rknn_server"     "rknn_server"          "4-5"

echo ""
echo "[ BIG cores 6-7 — Suricata IDS ]"
pin "suricata"        "suricata"             "6-7"

echo ""
echo "[ LITTLE cores 2-3 — Analytics stack ]"
pin "influxd"         "influxd"              "2-3"
pin "grafana"         "grafana"              "2-3"

echo ""
echo "[ LITTLE cores 0-1 — Light services ]"
pin "dashboard"       "dashboard/app.py"     "0-1"
pin "metrics_export"  "metrics_exporter.py"  "0-1"
pin "mosquitto"       "mosquitto"            "0-1"

echo ""
echo "========================================"
echo "  Verification"
echo "========================================"
for pattern in "detect_pipeline" "suricata" "influxd" "grafana" "app.py" "metrics_exporter" "mosquitto" "rknn_server"; do
    pid=$(pgrep -f "$pattern" 2>/dev/null | head -1)
    [ -z "$pid" ] && continue
    affinity=$(taskset -cp "$pid" 2>/dev/null | awk -F': ' '{print $2}')
    printf "  %-22s pid=%-7s cores=%s\n" "$pattern" "$pid" "$affinity"
done
echo ""
