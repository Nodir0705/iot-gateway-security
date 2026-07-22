#!/usr/bin/env python3
"""13-feature vector definition for NPU anomaly detection"""
import numpy as np

FEATURE_NAMES = [
    "protocol", "dst_port", "flow_duration_ms",
    "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean",
    "flow_bytes_per_sec", "flow_pkts_per_sec",
    "flow_iat_mean_ms", "syn_flag_count",
]
NUM_FEATURES = len(FEATURE_NAMES)

FEATURE_RANGES = {
    "protocol": (0, 255), "dst_port": (0, 65535),
    "flow_duration_ms": (0, 120000), "total_fwd_packets": (0, 10000),
    "total_bwd_packets": (0, 10000), "total_fwd_bytes": (0, 1000000),
    "total_bwd_bytes": (0, 1000000), "fwd_pkt_len_mean": (0, 1500),
    "bwd_pkt_len_mean": (0, 1500), "flow_bytes_per_sec": (0, 125000000),
    "flow_pkts_per_sec": (0, 100000), "flow_iat_mean_ms": (0, 60000),
    "syn_flag_count": (0, 100),
}

def normalize_features(features):
    normalized = np.zeros(NUM_FEATURES, dtype=np.float32)
    for i, name in enumerate(FEATURE_NAMES):
        lo, hi = FEATURE_RANGES[name]
        normalized[i] = max(0.0, min(1.0, (features[i] - lo) / (hi - lo + 1e-9)))
    return normalized

if __name__ == '__main__':
    print(f"Feature vector: {NUM_FEATURES} features")
    for i, name in enumerate(FEATURE_NAMES):
        print(f"  [{i:2d}] {name}")
