#!/usr/bin/env python3
"""
Decision Engine — combines Suricata alerts + NPU anomaly scores + behavioral signals.

Uses evidence accumulation: weak signals within a sliding time window accumulate
before triggering actions. A single weak signal is ignored; repeated or diverse
signals within the window escalate to alert/quarantine.

Evidence weights:
  - Suricata severity 1 (high)     → 50 pts
  - Suricata severity 2 (medium)   → 30 pts
  - Suricata severity 3 (low)      → 10 pts
  - NPU anomaly                    → 40 pts
  - NPU high confidence (>2x thr)  → 60 pts
  - Periodic beaconing             → 35 pts
  - Long connection                → 25 pts
  - DNS anomaly                    → 20 pts

Action thresholds (accumulated evidence within window):
  - score >= 80  → AUTO-QUARANTINE + alert
  - score >= 50  → ALERT (no quarantine)
  - score >= 20  → LOG (monitor)
  - score < 20   → IGNORE
"""
import json
import time
import os
import subprocess
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Evidence accumulation window — only evidence within this window counts
EVIDENCE_WINDOW = 60  # seconds

EVIDENCE_WEIGHTS = {
    "suricata_high":       50,
    "suricata_medium":     30,
    "suricata_low":        10,
    "npu_anomaly":         40,
    "npu_high_confidence": 60,
    "beaconing":           35,
    "long_connection":     25,
    "dns_anomaly":         20,
}

QUARANTINE_THRESHOLD = 80
ALERT_THRESHOLD = 50
LOG_THRESHOLD = 20
AUTO_QUARANTINE_TIMEOUT = 3600  # 1 hour

# Critical IPs that must NEVER be quarantined
NEVER_QUARANTINE = {
    "192.168.3.1",      # default gateway / router / DNS
    "192.168.3.15",     # trusted workstation
    "192.168.3.64",     # this device (gateway itself)
    "255.255.255.255",  # broadcast
    "224.0.0.1",        # multicast all-hosts
    "0.0.0.0",          # unspecified
}

# Only monitor and quarantine this host
MONITOR_ONLY = {"192.168.13.48"}

LOG_DIR = os.path.expanduser("~/iot-gateway/logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Per-device state
device_scores = defaultdict(lambda: {
    "evidence": [],      # list of {time, weight, source, detail}
    "quarantined": False,
    "alert_count": 0,
})

# Try MQTT
mqtt_alerter = None
try:
    from mqtt_alerter import MQTTAlerter
    mqtt_alerter = MQTTAlerter()
    if not mqtt_alerter.connected:
        mqtt_alerter = None
except Exception:
    pass


def compute_score(ip):
    """Compute current threat score from evidence within the sliding window."""
    now = time.time()
    cutoff = now - EVIDENCE_WINDOW
    device = device_scores[ip]
    # Expire old evidence
    device["evidence"] = [e for e in device["evidence"] if e["time"] > cutoff]
    return sum(e["weight"] for e in device["evidence"])


def add_evidence(ip, weight, source, detail=None):
    """Append an evidence item for an IP."""
    device = device_scores[ip]
    device["evidence"].append({
        "time": time.time(),
        "weight": weight,
        "source": source,
        "detail": detail or {},
    })
    device["alert_count"] += 1
    # Cap at 50 items to prevent unbounded memory growth
    if len(device["evidence"]) > 50:
        device["evidence"] = device["evidence"][-50:]


def process_suricata_alert(alert):
    """Process a Suricata IDS alert."""
    src_ip = alert.get("src_ip", "unknown")
    if src_ip not in MONITOR_ONLY:
        return None
    severity = alert.get("severity", 3)
    signature = alert.get("signature", "unknown")

    key = {1: "suricata_high", 2: "suricata_medium", 3: "suricata_low"}.get(severity, "suricata_low")
    add_evidence(src_ip, EVIDENCE_WEIGHTS[key], key, {"signature": signature, "severity": severity})
    return evaluate_device(src_ip)


def process_npu_result(flow_info, is_anomaly, score, threshold):
    """Process NPU anomaly detection result."""
    src_ip = flow_info.get("src_ip", "unknown")
    if src_ip not in MONITOR_ONLY:
        return None
    if not is_anomaly:
        return None

    signal = "npu_high_confidence" if score > threshold * 2 else "npu_anomaly"
    add_evidence(src_ip, EVIDENCE_WEIGHTS[signal], signal, {"score": score, "threshold": threshold})
    return evaluate_device(src_ip)


def process_behavioral_signal(ip, signal_type, detail=None):
    """Process a behavioral detection signal (beaconing, long_connection, dns_anomaly)."""
    if ip not in MONITOR_ONLY:
        return None
    weight = EVIDENCE_WEIGHTS.get(signal_type, 20)
    add_evidence(ip, weight, signal_type, detail or {})
    return evaluate_device(ip)


def evaluate_device(ip):
    """Evaluate device threat level and take action based on accumulated evidence."""
    device = device_scores[ip]
    score = compute_score(ip)
    action = None

    if score >= QUARANTINE_THRESHOLD and not device["quarantined"]:
        if ip in NEVER_QUARANTINE:
            action = "ALERT"
            print(f"  [!] Skipping quarantine for critical IP {ip} (score={score:.0f})")
        else:
            action = "QUARANTINE"
            quarantine_device(ip)
            device["quarantined"] = True

    elif score >= ALERT_THRESHOLD:
        action = "ALERT"

    elif score >= LOG_THRESHOLD:
        action = "LOG"

    if action:
        recent = device["evidence"][-3:] if device["evidence"] else []
        record = {
            "timestamp": time.time(),
            "ip": ip,
            "score": score,
            "action": action,
            "alert_count": device["alert_count"],
            "recent_evidence": recent,
        }

        with open(f"{LOG_DIR}/decisions.jsonl", "a") as f:
            f.write(json.dumps(record) + "\n")

        if mqtt_alerter and action in ("QUARANTINE", "ALERT"):
            mqtt_alerter.send_alert(record)

        icon = {"QUARANTINE": "🔴", "ALERT": "🟡", "LOG": "⚪"}.get(action, "")
        print(f"  {icon} [{action}] {ip} — score: {score:.0f}, alerts: {device['alert_count']}")

    return action


def quarantine_device(ip):
    """Auto-quarantine via nftables."""
    print(f"  >>> AUTO-QUARANTINE: {ip} for {AUTO_QUARANTINE_TIMEOUT}s")
    try:
        subprocess.run([
            "sudo", "nft", "add", "element", "inet", "iot_gateway",
            "quarantine_v4", f"{{ {ip} timeout {AUTO_QUARANTINE_TIMEOUT}s }}"
        ], check=True, capture_output=True)

        if mqtt_alerter:
            mqtt_alerter.send_quarantine(ip, "isolated", f"Threat score exceeded {QUARANTINE_THRESHOLD}")

        with open(f"{LOG_DIR}/quarantine.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} QUARANTINE {ip} timeout={AUTO_QUARANTINE_TIMEOUT}s\n")

    except subprocess.CalledProcessError as e:
        print(f"  !!! Quarantine failed for {ip}: {e.stderr.decode()}")


def get_status():
    """Get current gateway status."""
    scores = {ip: compute_score(ip) for ip in device_scores}
    active = {ip: s for ip, s in scores.items() if s > 0}
    quarantined = {ip: info for ip, info in device_scores.items() if info["quarantined"]}
    return {
        "devices_monitored": len(device_scores),
        "devices_active_threat": len(active),
        "devices_quarantined": len(quarantined),
        "top_threats": sorted(active.items(), key=lambda x: -x[1])[:10],
    }


if __name__ == '__main__':
    print("=== Decision Engine Test (Evidence Accumulation) ===\n")

    print("Simulating Suricata alerts...")
    process_suricata_alert({"src_ip": "192.168.13.48", "severity": 1,
        "signature": "IOT Mirai credential - admin/admin"})
    process_suricata_alert({"src_ip": "192.168.13.48", "severity": 1,
        "signature": "IOT Telnet brute-force"})

    print("\nSimulating NPU detections...")
    process_npu_result({"src_ip": "192.168.13.48"}, True, 0.15, 0.05)

    print("\nSimulating behavioral signals...")
    process_behavioral_signal("192.168.13.48", "beaconing",
        {"dst_ip": "10.0.0.1", "mean_interval": 30.2, "cv": 0.04, "samples": 8})
    process_behavioral_signal("192.168.13.48", "dns_anomaly",
        {"reason": "burst", "unique_domains": 25, "window_s": 60})

    print(f"\n=== Gateway Status ===")
    status = get_status()
    print(f"  Monitored: {status['devices_monitored']}")
    print(f"  Active threats: {status['devices_active_threat']}")
    print(f"  Quarantined: {status['devices_quarantined']}")
    print(f"  Top threats:")
    for ip, score in status['top_threats']:
        q = " [QUARANTINED]" if device_scores[ip]["quarantined"] else ""
        print(f"    {ip}: {score:.0f}{q}")

    if mqtt_alerter:
        mqtt_alerter.close()
