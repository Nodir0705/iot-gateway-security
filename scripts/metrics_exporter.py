#!/usr/bin/env python3
"""
metrics_exporter.py — JSONL log → InfluxDB 2.x exporter
Reads npu_alerts.jsonl and decisions.jsonl every 5s,
polls Flask /api/status for gateway health, writes to InfluxDB.
"""

import json
import os
import time
import requests
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Config ──────────────────────────────────────────────────────────────────
INFLUX_URL    = "http://localhost:8086"
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN", "")   # REQUIRED: set via env / gateway.env — never hardcode
INFLUX_ORG    = "iotgw"
INFLUX_BUCKET = "security"

LOG_DIR       = os.path.expanduser("~/iot-gateway/logs")
NPU_LOG       = os.path.join(LOG_DIR, "npu_alerts.jsonl")
DEC_LOG       = os.path.join(LOG_DIR, "decisions.jsonl")
FLASK_STATUS  = "http://localhost:5000/api/status"

POS_FILE      = "/tmp/metrics_exporter_pos.json"
INTERVAL      = 5   # seconds

# ── Position tracking ────────────────────────────────────────────────────────
def load_positions():
    if os.path.exists(POS_FILE):
        try:
            with open(POS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_positions(pos):
    with open(POS_FILE, "w") as f:
        json.dump(pos, f)

def read_new_lines(filepath, positions):
    """Yield new JSON objects from filepath since last read position."""
    key = filepath
    offset = positions.get(key, 0)
    if not os.path.exists(filepath):
        return
    with open(filepath, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        if end < offset:
            # file rotated
            offset = 0
        f.seek(offset)
        for raw in f:
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
        positions[key] = f.tell()

# ── InfluxDB write ────────────────────────────────────────────────────────────
def build_npu_point(record):
    ts = int(record["timestamp"] * 1e9)  # nanoseconds
    return (
        Point("npu_alert")
        .tag("src_ip", record.get("src_ip", "unknown"))
        .tag("dst_ip", record.get("dst_ip", "unknown"))
        .tag("protocol", str(record.get("protocol", 0)))
        .field("score", float(record.get("score", 0)))
        .field("src_port", int(record.get("src_port", 0)))
        .field("dst_port", int(record.get("dst_port", 0)))
        .time(ts, WritePrecision.NS)
    )

def build_decision_point(record):
    ts = int(record["timestamp"] * 1e9)
    return (
        Point("threat_decision")
        .tag("ip", record.get("ip", "unknown"))
        .tag("action", record.get("action", "UNKNOWN"))
        .field("score", float(record.get("score", 0)))
        .field("alert_count", int(record.get("alert_count", 0)))
        .time(ts, WritePrecision.NS)
    )

def build_health_point(status):
    quarantined = status.get("quarantined", [])
    return (
        Point("gateway_health")
        .field("packet_count", int(status.get("packet_count", 0)))
        .field("flow_count", int(status.get("flow_count", 0)))
        .field("alert_count", int(status.get("total_decisions", status.get("alert_count", 0))))
        .field("quarantine_count", len(quarantined) if isinstance(quarantined, list) else int(quarantined))
        .time(int(time.time() * 1e9), WritePrecision.NS)
    )

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    print(f"[metrics_exporter] Starting. InfluxDB={INFLUX_URL} org={INFLUX_ORG} bucket={INFLUX_BUCKET}")
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)

    positions = load_positions()

    while True:
        points = []

        # NPU alerts
        for rec in read_new_lines(NPU_LOG, positions):
            try:
                points.append(build_npu_point(rec))
            except Exception as e:
                print(f"[metrics_exporter] npu parse error: {e}")

        # Decision engine
        for rec in read_new_lines(DEC_LOG, positions):
            try:
                points.append(build_decision_point(rec))
            except Exception as e:
                print(f"[metrics_exporter] decision parse error: {e}")

        # Gateway health from Flask
        try:
            r = requests.get(FLASK_STATUS, timeout=3)
            if r.ok:
                status = r.json()
                points.append(build_health_point(status))
        except Exception as e:
            print(f"[metrics_exporter] flask status error: {e}")

        # Write batch
        if points:
            try:
                write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=points)
                print(f"[metrics_exporter] wrote {len(points)} points")
            except Exception as e:
                print(f"[metrics_exporter] write error: {e}")

        save_positions(positions)
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
