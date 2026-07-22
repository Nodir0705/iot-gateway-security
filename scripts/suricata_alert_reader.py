#!/usr/bin/env python3
"""
suricata_alert_reader.py — Tail Suricata eve.json and feed alerts to decision_engine.

Efficiently tails /var/log/suricata/eve.json using seek/tell,
filters for event_type=="alert", maps relevant fields, and calls
decision_engine.process_suricata_alert() for each alert.
"""

import json
import os
import sys
import time

# Allow importing decision_engine from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decision_engine import process_suricata_alert

# ── Config ──────────────────────────────────────────────────────────────────
EVE_JSON      = "/var/log/suricata/eve.json"
POS_FILE      = "/tmp/suricata_eve_pos.json"
POLL_INTERVAL = 2   # seconds

# ── Position tracking ──────────────────────────────────────────────────────
def load_position():
    if os.path.exists(POS_FILE):
        try:
            with open(POS_FILE) as f:
                data = json.load(f)
                return data.get("offset", 0)
        except Exception:
            pass
    return 0

def save_position(offset):
    with open(POS_FILE, "w") as f:
        json.dump({"offset": offset}, f)

# ── Tail and process ──────────────────────────────────────────────────────
def process_new_events(filepath, offset):
    """Read new lines from filepath starting at offset, process alerts.
    Returns updated offset."""
    if not os.path.exists(filepath):
        return offset

    with open(filepath, "rb") as f:
        # Check file size for rotation detection
        f.seek(0, 2)
        end = f.tell()
        if end < offset:
            print(f"[suricata_reader] File shrunk ({offset} -> {end}), resetting to 0 (rotation?)")
            offset = 0

        f.seek(offset)
        for raw in f:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            # Map Suricata eve.json fields to what decision_engine expects
            alert_data = {
                "src_ip":    event.get("src_ip", "unknown"),
                "severity":  event.get("alert", {}).get("severity", 3),
                "signature": event.get("alert", {}).get("signature", "unknown"),
            }

            try:
                result = process_suricata_alert(alert_data)
                print(
                    f"[suricata_reader] Alert: src={alert_data['src_ip']} "
                    f"sev={alert_data['severity']} sig=\"{alert_data['signature']}\" "
                    f"result={result}"
                )
            except Exception as e:
                print(f"[suricata_reader] Error processing alert: {e}")

        offset = f.tell()

    return offset

# ── Main loop ─────────────────────────────────────────────────────────────
def main():
    print(f"[suricata_reader] Starting. Tailing {EVE_JSON}, poll every {POLL_INTERVAL}s")
    offset = load_position()
    print(f"[suricata_reader] Resuming from offset {offset}")

    while True:
        try:
            offset = process_new_events(EVE_JSON, offset)
            save_position(offset)
        except Exception as e:
            print(f"[suricata_reader] Error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
