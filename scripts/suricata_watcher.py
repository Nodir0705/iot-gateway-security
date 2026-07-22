#!/usr/bin/env python3
"""Watch Suricata eve.json and feed alerts into decision engine + dashboard"""
import json, time, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decision_engine import process_suricata_alert, get_status

LOG_DIR = os.path.expanduser("~/iot-gateway/logs")
# Must match the eve-log filename in /etc/suricata/suricata-iot.yaml, which writes
# eve.json into the gateway's own logs dir (NOT /var/log/suricata). Overridable via env.
EVE_LOG = os.environ.get("EVE_LOG", os.path.join(LOG_DIR, "eve.json"))

def tail_eve(duration=0):
    """Tail eve.json and process new alerts"""
    print("=== Suricata Alert Watcher ===")
    print(f"Watching: {EVE_LOG}")

    if not os.path.exists(EVE_LOG):
        print(f"ERROR: {EVE_LOG} not found. Is Suricata running?")
        return

    # Seek to end of file
    f = open(EVE_LOG, "r")
    f.seek(0, 2)
    print("Tailing for new alerts...\n")

    start = time.time()
    alert_count = 0
    try:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                if duration > 0 and (time.time() - start) > duration:
                    break
                continue

            try:
                event = json.loads(line.strip())
            except:
                continue

            # Only process alert events
            if event.get("event_type") != "alert":
                continue

            alert = {
                "src_ip": event.get("src_ip", "unknown"),
                "dst_ip": event.get("dest_ip", "unknown"),
                "src_port": event.get("src_port", 0),
                "dst_port": event.get("dest_port", 0),
                "severity": event.get("alert", {}).get("severity", 3),
                "signature": event.get("alert", {}).get("signature", "unknown"),
                "category": event.get("alert", {}).get("category", ""),
                "proto": event.get("proto", ""),
            }

            action = process_suricata_alert(alert)
            alert_count += 1
            print(f"  [{time.strftime('%H:%M:%S')}] {alert['signature']}")
            print(f"    {alert['src_ip']}:{alert.get('src_port',0)} -> {alert['dst_ip']}:{alert.get('dst_port',0)}")
            if action:
                print(f"    Action: {action}")

    except KeyboardInterrupt:
        pass

    print(f"\nProcessed {alert_count} Suricata alerts")
    status = get_status()
    print(f"Active threats: {status['devices_active_threat']}")
    print(f"Quarantined: {status['devices_quarantined']}")

if __name__ == '__main__':
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    tail_eve(dur)
