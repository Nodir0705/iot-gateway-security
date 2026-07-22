#!/usr/bin/env python3
"""Full pipeline: Packets → Flow Extraction → Detection → Behavioral Analysis → Alert"""
import math
import time
import sys
import os
import json
from collections import defaultdict

import numpy as np
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import FEATURE_NAMES, NUM_FEATURES
from npu_detector import NPUDetector
from decision_engine import process_npu_result, process_behavioral_signal, MONITOR_ONLY

# Whitelist: skip NPU detection for these IPs/ports
WHITELIST_IPS = {
    "192.168.3.1",     # default gateway / router / DNS
    "192.168.15.255",  # cross-subnet broadcast
    "169.254.169.254", # link-local metadata
    "224.0.0.22",      # IGMP multicast
    "224.0.0.251",     # mDNS
    "224.0.0.252",     # LLMNR
    "255.255.255.255", # broadcast
}
WHITELIST_PORTS = {22}   # SSH management only; DNS captured separately for behavioral analysis
GATEWAY_IP = "192.168.3.64"
TARGET_IP = "192.168.13.48"  # only monitor/quarantine this host


class BehavioralAnalyzer:
    """
    Detects behavioral attack patterns not captured by NPU anomaly scores:
      - Periodic beaconing (C&C check-in)
      - Long-lived connections (exfiltration / persistent access)
      - DNS anomalies (burst querying, high-entropy DGA domains)
    """

    BEACON_MIN_SAMPLES   = 5      # min connection events to evaluate
    BEACON_CV_THRESHOLD  = 0.15   # coefficient of variation < 15% → periodic
    BEACON_MIN_INTERVAL  = 10     # seconds (faster → noise/scan, not beaconing)
    BEACON_MAX_INTERVAL  = 600    # seconds (slower → too infrequent to be C&C)

    LONG_CONN_THRESHOLD  = 300    # seconds (5 minutes)
    LONG_CONN_MIN_BYTES  = 1000   # must have moved some data

    DNS_WINDOW           = 60     # seconds for burst detection
    DNS_BURST_THRESHOLD  = 20     # unique domains in window → suspicious
    DNS_ENTROPY_THRESHOLD = 3.5   # Shannon entropy → DGA candidate

    def __init__(self):
        # {(src_ip, dst_ip): [timestamps of new connections]}
        self.conn_history = defaultdict(list)
        # {src_ip: [(timestamp, domain)]}
        self.dns_history = defaultdict(list)
        # Avoid re-reporting the same detection repeatedly
        self._reported_beacons = set()
        self._reported_long    = set()

    def track_connection(self, src_ip, dst_ip, timestamp):
        """Record a new connection event (first packet of a flow)."""
        key = (src_ip, dst_ip)
        self.conn_history[key].append(timestamp)
        if len(self.conn_history[key]) > 20:
            self.conn_history[key] = self.conn_history[key][-20:]

    def track_dns(self, src_ip, domain, timestamp):
        """Record a DNS query."""
        self.dns_history[src_ip].append((timestamp, domain))
        if len(self.dns_history[src_ip]) > 100:
            self.dns_history[src_ip] = self.dns_history[src_ip][-100:]

    def analyze(self, flows, now):
        """
        Run all behavioral checks.
        Returns list of (ip, signal_type, detail) tuples to feed into the decision engine.
        """
        signals = []
        signals.extend(self._check_beaconing(now))
        signals.extend(self._check_long_connections(flows, now))
        signals.extend(self._check_dns_anomalies(now))
        return signals

    # ------------------------------------------------------------------ #
    #  Internal checks                                                     #
    # ------------------------------------------------------------------ #

    def _check_beaconing(self, now):
        signals = []
        cutoff = now - 1800  # look back 30 min
        for (src_ip, dst_ip), timestamps in self.conn_history.items():
            ts = [t for t in timestamps if t > cutoff]
            if len(ts) < self.BEACON_MIN_SAMPLES:
                continue
            intervals = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
            mean_iv = np.mean(intervals)
            if mean_iv < self.BEACON_MIN_INTERVAL or mean_iv > self.BEACON_MAX_INTERVAL:
                continue
            cv = np.std(intervals) / mean_iv if mean_iv > 0 else 1.0
            if cv < self.BEACON_CV_THRESHOLD:
                key = (src_ip, dst_ip)
                if key not in self._reported_beacons:
                    self._reported_beacons.add(key)
                    signals.append((src_ip, "beaconing", {
                        "dst_ip": dst_ip,
                        "mean_interval_s": round(mean_iv, 1),
                        "cv": round(cv, 3),
                        "samples": len(ts),
                    }))
        return signals

    def _check_long_connections(self, flows, now):
        signals = []
        for key, f in flows.items():
            src_ip, dst_ip, sp, dp, proto = key
            if src_ip not in MONITOR_ONLY and dst_ip not in MONITOR_ONLY:
                continue
            duration = now - f["start"]
            total_bytes = f["fwd_bytes"] + f["bwd_bytes"]
            if duration > self.LONG_CONN_THRESHOLD and total_bytes > self.LONG_CONN_MIN_BYTES:
                if key not in self._reported_long:
                    self._reported_long.add(key)
                    ip = src_ip if src_ip in MONITOR_ONLY else dst_ip
                    signals.append((ip, "long_connection", {
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "dst_port": dp, "duration_s": round(duration),
                        "bytes": total_bytes,
                    }))
        return signals

    def _check_dns_anomalies(self, now):
        signals = []
        cutoff = now - self.DNS_WINDOW
        for src_ip, queries in self.dns_history.items():
            if src_ip not in MONITOR_ONLY:
                continue
            recent_domains = [d for t, d in queries if t > cutoff]
            if not recent_domains:
                continue
            unique = set(recent_domains)

            # Burst: too many unique domains in the window
            if len(unique) > self.DNS_BURST_THRESHOLD:
                signals.append((src_ip, "dns_anomaly", {
                    "reason": "burst",
                    "unique_domains": len(unique),
                    "window_s": self.DNS_WINDOW,
                }))
                continue

            # DGA: high-entropy first label
            for domain in unique:
                label = domain.split(".")[0]
                if len(label) > 8:
                    entropy = self._shannon_entropy(label)
                    if entropy > self.DNS_ENTROPY_THRESHOLD:
                        signals.append((src_ip, "dns_anomaly", {
                            "reason": "high_entropy",
                            "domain": domain,
                            "entropy": round(entropy, 2),
                        }))
                        break  # one report per IP per analysis cycle

        return signals

    @staticmethod
    def _shannon_entropy(s):
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())


class DetectionPipeline:
    def __init__(self, iface="eth0"):
        self.iface = iface
        self.detector = NPUDetector()
        self.behavioral = BehavioralAnalyzer()
        self.flows = {}
        self.alert_log = os.path.expanduser("~/iot-gateway/logs/npu_alerts.jsonl")
        self.batch_interval = 5
        self.flow_timeout = 30
        self.alert_count = 0
        self.pkt_count = 0
        self.last_batch = time.time()
        os.makedirs(os.path.dirname(self.alert_log), exist_ok=True)

    def _flow_key(self, pkt):
        if IP not in pkt:
            return None
        src, dst, proto = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        sp = dp = 0
        if TCP in pkt:
            sp, dp = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sp, dp = pkt[UDP].sport, pkt[UDP].dport
        return (src, dst, sp, dp, proto) if (src, sp) < (dst, dp) else (dst, src, dp, sp, proto)

    def _is_whitelisted(self, key):
        src, dst, sp, dp, proto = key
        # Only process traffic involving the target IP
        if src != TARGET_IP and dst != TARGET_IP:
            return True
        if dst in WHITELIST_IPS or src in WHITELIST_IPS:
            return True
        if dst.startswith("224.") or dst.startswith("239.") or dst.endswith(".255") or src.endswith(".255"):
            return True
        # Skip SSH to gateway
        if dst == GATEWAY_IP and dp in WHITELIST_PORTS:
            return True
        if src == GATEWAY_IP and sp in WHITELIST_PORTS:
            return True
        # DNS is tracked separately — skip NPU analysis
        if dp == 53 or sp == 53:
            return True
        return False

    def _extract_dns(self, pkt):
        """Extract DNS query domain if present."""
        try:
            if DNSQR in pkt and pkt[DNS].qr == 0:  # DNS query (not response)
                return pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            pass
        return None

    def process_packet(self, pkt):
        if IP not in pkt:
            return
        self.pkt_count += 1

        src_ip = pkt[IP].src
        now = time.time()

        # Capture DNS queries for behavioral analysis (before flow key check)
        if UDP in pkt and pkt[UDP].dport == 53:
            domain = self._extract_dns(pkt)
            if domain and domain != ".":
                self.behavioral.track_dns(src_ip, domain, now)

        key = self._flow_key(pkt)
        if not key:
            return

        is_fwd = pkt[IP].src == key[0]
        syn = 1 if TCP in pkt and pkt[TCP].flags & 0x02 else 0

        is_new_flow = key not in self.flows
        if is_new_flow:
            self.flows[key] = {
                "start": now, "last": now, "proto": pkt[IP].proto,
                "dst_port": key[3], "fwd_pkts": 0, "bwd_pkts": 0,
                "fwd_bytes": 0, "bwd_bytes": 0,
                "fwd_lens": [], "bwd_lens": [], "times": [], "syns": 0,
            }
            # Track connection event for beaconing analysis
            if src_ip in MONITOR_ONLY or pkt[IP].dst in MONITOR_ONLY:
                self.behavioral.track_connection(key[0], key[1], now)

        f = self.flows[key]
        f["last"] = now
        f["times"].append(now)
        f["syns"] += syn
        if is_fwd:
            f["fwd_pkts"] += 1
            f["fwd_bytes"] += len(pkt)
            f["fwd_lens"].append(len(pkt))
        else:
            f["bwd_pkts"] += 1
            f["bwd_bytes"] += len(pkt)
            f["bwd_lens"].append(len(pkt))

        if now - self.last_batch >= self.batch_interval:
            self.last_batch = now
            self._run_detection()

    def _extract_features(self, key):
        f = self.flows[key]
        dur = max((f["last"] - f["start"]) * 1000, 1)
        total_pkts = f["fwd_pkts"] + f["bwd_pkts"]
        total_bytes = f["fwd_bytes"] + f["bwd_bytes"]
        fwd_mean = np.mean(f["fwd_lens"]) if f["fwd_lens"] else 0
        bwd_mean = np.mean(f["bwd_lens"]) if f["bwd_lens"] else 0
        ts = f["times"]
        iat = np.mean([(ts[i] - ts[i - 1]) * 1000 for i in range(1, len(ts))]) if len(ts) > 1 else 0
        return np.array([
            f["proto"], f["dst_port"], dur, f["fwd_pkts"], f["bwd_pkts"],
            f["fwd_bytes"], f["bwd_bytes"], fwd_mean, bwd_mean,
            total_bytes / max(dur / 1000, 0.001), total_pkts / max(dur / 1000, 0.001),
            iat, f["syns"],
        ], dtype=np.float32)

    def _run_detection(self):
        now = time.time()

        # --- NPU anomaly detection ---
        keys = [k for k in self.flows if not self._is_whitelisted(k)]
        if keys:
            features = np.array([self._extract_features(k) for k in keys])
            results = self.detector.predict(features)

            anomalies = []
            for key, (is_anom, score) in zip(keys, results):
                if is_anom:
                    alert = {
                        "timestamp": now, "src_ip": key[0], "dst_ip": key[1],
                        "src_port": key[2], "dst_port": key[3],
                        "protocol": key[4], "score": score,
                    }
                    anomalies.append(alert)
                    self.alert_count += 1
                    with open(self.alert_log, "a") as fout:
                        fout.write(json.dumps(alert) + "\n")
                    process_npu_result(
                        {"src_ip": key[0], "dst_ip": key[1]},
                        True, score, self.detector.threshold
                    )

            if anomalies:
                print(f"  [!] {len(anomalies)} NPU anomalies:")
                for a in anomalies[:5]:
                    print(f"      {a['src_ip']}:{a['src_port']} -> {a['dst_ip']}:{a['dst_port']} score={a['score']:.6f}")
        else:
            if not self.flows:
                print(f"  [{time.strftime('%H:%M:%S')}] pkts={self.pkt_count} flows=0 alerts={self.alert_count}")
                return

        # --- Behavioral analysis ---
        behavioral_signals = self.behavioral.analyze(self.flows, now)
        for ip, signal_type, detail in behavioral_signals:
            print(f"  [BEHAVIORAL] {signal_type} detected for {ip}: {detail}")
            process_behavioral_signal(ip, signal_type, detail)

        # --- Clean expired flows ---
        expired = [k for k in list(self.flows.keys()) if now - self.flows[k]["last"] > self.flow_timeout]
        for k in expired:
            del self.flows[k]

        print(f"  [{time.strftime('%H:%M:%S')}] pkts={self.pkt_count} flows={len(self.flows)} "
              f"alerts={self.alert_count} behavioral={len(behavioral_signals)}")

    def run(self, duration=60):
        print(f"=== IoT Security Gateway — Detection Pipeline ===")
        print(f"Interface: {self.iface} | Backend: {self.detector.backend}")
        dur_str = f"{duration}s" if duration > 0 else "continuous"
        print(f"Duration: {dur_str} | Batch: {self.batch_interval}s")
        print(f"Modules: NPU anomaly, beaconing, long connections, DNS anomaly\n")
        try:
            timeout = duration if duration > 0 else None
            sniff(iface=self.iface, prn=self.process_packet, timeout=timeout, store=False)
        except KeyboardInterrupt:
            pass
        self._run_detection()
        print(f"\n=== Done: {self.pkt_count} packets, {self.alert_count} alerts ===")
        print(f"Alert log: {self.alert_log}")


if __name__ == '__main__':
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    DetectionPipeline(iface=iface).run(dur)
