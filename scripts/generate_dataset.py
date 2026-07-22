#!/usr/bin/env python3
"""Generate labeled training dataset for NPU model"""
import numpy as np
import csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import FEATURE_NAMES, NUM_FEATURES

def generate_normal(n=300):
    samples = []
    for _ in range(n):
        proto = np.random.choice([6, 17], p=[0.4, 0.6])
        dst_port = np.random.choice([80, 443, 53, 1883, 8080, 5353])
        duration = np.random.exponential(5000)
        fwd_pkts = max(np.random.poisson(10), 1)
        bwd_pkts = max(np.random.poisson(8), 1)
        fwd_bytes = max(fwd_pkts * np.random.normal(200, 50), 1)
        bwd_bytes = max(bwd_pkts * np.random.normal(300, 100), 1)
        total = fwd_bytes + bwd_bytes
        total_pkts = fwd_pkts + bwd_pkts
        samples.append(([proto, dst_port, max(duration,1), fwd_pkts, bwd_pkts,
            fwd_bytes, bwd_bytes, fwd_bytes/fwd_pkts, bwd_bytes/bwd_pkts,
            total/max(duration/1000,0.001), total_pkts/max(duration/1000,0.001),
            max(duration/total_pkts,0), np.random.choice([0,1], p=[0.7,0.3])], 0))
    return samples

def generate_attacks(n=60):
    samples = []
    # SYN Flood
    for _ in range(n):
        samples.append(([6, np.random.choice([80,8080,2323]),
            np.random.uniform(100,2000), np.random.randint(500,5000),
            np.random.randint(0,5), np.random.randint(20000,200000),
            np.random.randint(0,500), np.random.uniform(40,60), 0,
            np.random.uniform(50000,500000), np.random.uniform(1000,50000),
            np.random.uniform(0.01,1), np.random.randint(100,5000)], 1))
    # Credential Stuffing
    for _ in range(n):
        samples.append(([6, np.random.choice([23,2323,22]),
            np.random.uniform(5000,30000), np.random.randint(20,100),
            np.random.randint(20,100), np.random.randint(1000,10000),
            np.random.randint(1000,5000), np.random.uniform(50,200),
            np.random.uniform(20,100), np.random.uniform(100,5000),
            np.random.uniform(1,20), np.random.uniform(100,1000),
            np.random.randint(10,50)], 1))
    # Port Scan
    for _ in range(n):
        samples.append(([6, np.random.randint(1,1024),
            np.random.uniform(1000,10000), np.random.randint(100,1000),
            np.random.randint(0,50), np.random.randint(4000,50000),
            np.random.randint(0,5000), np.random.uniform(40,60),
            np.random.uniform(0,60), np.random.uniform(1000,50000),
            np.random.uniform(50,500), np.random.uniform(1,50),
            np.random.randint(100,1000)], 1))
    # C2 Beacon
    for _ in range(n):
        samples.append(([np.random.choice([6,17]),
            np.random.choice([80,443,53,4444,8888]),
            np.random.uniform(30000,120000), np.random.randint(5,30),
            np.random.randint(5,30), np.random.randint(500,5000),
            np.random.randint(200,2000), np.random.uniform(50,200),
            np.random.uniform(50,150), np.random.uniform(10,500),
            np.random.uniform(0.1,2), np.random.uniform(2000,10000),
            np.random.randint(1,10)], 1))
    # Exfiltration
    for _ in range(n):
        samples.append(([6, np.random.choice([443,80,8443]),
            np.random.uniform(1000,10000), np.random.randint(50,500),
            np.random.randint(5,30), np.random.randint(50000,500000),
            np.random.randint(1000,10000), np.random.uniform(500,1400),
            np.random.uniform(40,100), np.random.uniform(10000,200000),
            np.random.uniform(10,200), np.random.uniform(5,100),
            np.random.randint(1,5)], 1))
    return samples

if __name__ == '__main__':
    print("=== Training Dataset Generator ===\n")
    normal = generate_normal(300)
    attacks = generate_attacks(60)
    all_samples = normal + attacks
    np.random.shuffle(all_samples)

    out = os.path.expanduser("~/iot-gateway/models/training_data.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(FEATURE_NAMES + ["label"])
        for features, label in all_samples:
            w.writerow([f"{v:.4f}" for v in features] + [label])

    n0 = sum(1 for _,l in all_samples if l==0)
    n1 = sum(1 for _,l in all_samples if l==1)
    print(f"Saved: {out}")
    print(f"  Total: {len(all_samples)} | Normal: {n0} | Attack: {n1}")
