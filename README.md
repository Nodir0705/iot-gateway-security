# IoT Security Gateway (Orange Pi 5 / RK3588)

A multi-layer network security gateway for IoT devices, built on an Orange Pi 5
(RK3588, ARM64). It combines kernel-level packet filtering (XDP/eBPF), a
signature-based IDS (Suricata 7.0.8), ML anomaly detection accelerated on the
RK3588's 3-core NPU, behavioral analysis, and automated response (nftables
quarantine + MQTT alerts), with a Flask web dashboard for monitoring and attack
simulation.

> Development history and the current unfinished items are documented in
> [`docs/DEVELOPMENT_STAGES.md`](docs/DEVELOPMENT_STAGES.md).
> Earlier long-form documentation and slides are in `docs/` (docx/pptx/pdf).

## Architecture

```
                    NIC (eth0)
                        │
        ┌───────────────▼────────────────┐
Layer 1 │ XDP (xdp/obj/xdp_gateway.o)    │  blacklist drop → SYN/UDP rate-limit
        │ runs in NIC driver, pre-skb    │  → flow tracking → whitelist bypass
        └───────────────┬────────────────┘
                        │ XDP_PASS
        ┌───────────────▼────────────────┐
Layer 2 │ Suricata 7.0.8 (af-packet)     │  signature IDS; optional eBPF bypass
        │ + ebpf/suricata_bypass.c       │  filter for known-good flows
        └──────┬─────────────────────────┘
               │ alerts → /var/log/suricata/eve.json
               │              │
               │       scripts/suricata_watcher.py
               │              │
        ┌──────▼─────────────────────────┐
Layer 3 │ scripts/detect_pipeline.py     │  scapy sniffer → per-flow 13-feature
        │  ├─ flow_features.py           │  vectors → NPU inference
        │  ├─ npu_detector.py            │  RKNN (NPU) → ONNX (CPU) → sklearn RF
        │  └─ behavioral analysis        │  beaconing / long-conn / DNS anomalies
        └──────┬─────────────────────────┘
               │ npu_alerts.jsonl
        ┌──────▼─────────────────────────┐
Layer 4 │ scripts/decision_engine.py     │  evidence accumulation per device IP,
        │                                │  60 s window, score decay 5 pts/min
        │  score ≥ 80 → QUARANTINE       │  → nftables set (1 h timeout)
        │  score ≥ 50 → ALERT            │  → MQTT iot-gateway/alerts
        │  score ≥ 20 → LOG              │  → decisions.jsonl
        └──────┬─────────────────────────┘
               │
        ┌──────▼─────────────────────────┐
Layer 5 │ dashboard/app.py (Flask :5000) │  live metrics, quarantine view,
        │ scripts/metrics_exporter.py    │  9 attack simulators; InfluxDB export
        └────────────────────────────────┘
```

**Evidence scoring** (decision_engine.py): Suricata severity 1/2/3 → 50/30/10 pts;
NPU anomaly → 40 pts (+20 if score ≥ 2× threshold); behavioral: beaconing 35,
long connection 25, DNS anomaly 20 pts. Trusted IPs in `NEVER_QUARANTINE` are
exempt from quarantine.

**ML models** (`models/`): a 13-feature autoencoder (threshold MSE ≈ 0.00193,
trained on NSL-KDD; `autoencoder.rknn` INT8 for the NPU) plus a supervised
classifier (`classifier.rknn`, softmax [normal, attack]) and a sklearn
RandomForest (`rf_model.joblib`) as CPU fallback. `npu_detector.py` selects
RKNN → ONNX → sklearn in that order. The ONNX→RKNN conversion is done on an
x86 host (see the `rknn-convert` folder on the dev PC) because rknn-toolkit2
does not run on the device; the device only needs `rknn-toolkit-lite2`.

## Usage

```bash
./gateway.sh start     # nftables flush → XDP load → Suricata → mosquitto
                       # → suricata_watcher → detect_pipeline → dashboard
./gateway.sh status    # per-component status
./gateway.sh test      # end-to-end integration test
./gateway.sh stop
```

Dashboard: `http://<gateway-ip>:5000` — live alerts, per-device threat scores,
quarantine status, and buttons to launch the attack simulators against the test
device.

XDP management:

```bash
xdp/scripts/xdp_control.sh load|unload|stats|flows|status
xdp/scripts/xdp_control.sh block <IP> [reason]     # NIC-level drop
ebpf/xdp_manage.sh whitelist-ip <IP> | whitelist-port <PORT>
```

Quarantine management: `scripts/quarantine.sh add|remove|list|flush <IP>`.

## Repository layout

| Path | Contents |
|---|---|
| `gateway.sh` | Master start/stop/status/test orchestrator |
| `scripts/` | Detection pipeline, decision engine, watchers, metrics exporter, MQTT alerter, attack simulators (`attack_*.py/sh`), utilities (`quarantine.sh`, `pin_cores.sh`), model training (`train_autoencoder.py`, `train_random_forest.py`, `convert_to_rknn.py`), native NPU bridge (`npu_infer.c` → `libnpu_infer.so`) |
| `dashboard/` | Flask web UI (`app.py`, port 5000) |
| `xdp/` | XDP programs: `src/xdp_gateway.c` (production: blacklist → rate-limit → flow-track → whitelist), `xdp_blacklist.c`, `xdp_hello.c`; compiled objects in `obj/`; `scripts/xdp_control.sh` |
| `ebpf/` | Suricata-side eBPF: `suricata_bypass.c` (flow bypass filter), `xdp_filter.c`, `build_ebpf.sh` (installs to `/etc/suricata/ebpf/`) |
| `models/` | Trained models + configs (see above); `models.bak_20260309/` is a dated backup |
| `captures/` | `baseline_normal.pcap`, `test_full_suite.pcap` for offline replay |
| `logs/` | Runtime output: `npu_alerts.jsonl`, `decisions.jsonl`, component logs |
| `pids/` | PID files written by `gateway.sh` |
| `configs/` | Reference copies of the live system configs: `suricata-iot.yaml`, `nftables-iot.conf`, `iot-gateway.service`, `metrics-exporter.service`, `logrotate_suricata.conf` (authoritative versions live in `/etc` — see below) |
| `rules/` | Reference copies of the 16 **custom IoT Suricata rule files** loaded by `suricata-iot.yaml`: iot-attacks, mirai-variants, firmware-exploits, protocol-abuse, c2-indicators, dns-lateral, network-anomaly, evasion-techniques, tls-fingerprints, iot-advanced, ics-modbus, mqtt-deep, device-fingerprints, coap-deep, anomaly-baseline, local (authoritative: `/etc/suricata/rules/`) |
| `docs/` | This project's documentation, slides, and development-stage history |

## External dependencies (not in this repo)

These live on the system, outside the project directory (reference copies are kept in
`configs/` and `rules/`; all were verified present on the device):

- `/etc/suricata/suricata-iot.yaml` — Suricata config (af-packet; HOME_NET
  192.168.0.0/20 + 10.0.0.0/24; HTTP/TLS/DNS/MQTT app layers; `midstream: true`
  and `exception-policy: pass-packet` tuned so XMAS/FIN/NULL scan evasion rules
  fire; eve.json written to `iot-gateway/logs/eve.json`, fast/stats to
  `~/suricata/`). Note: the yaml does **not** enable the eBPF bypass.
- `/etc/suricata/rules/` — the 16 custom rule files (mirrored in `rules/`)
- `/etc/suricata/ebpf/` — installed eBPF bypass objects (`ebpf/build_ebpf.sh`)
- `/etc/nftables-iot.conf` + nftables set `inet iot_gateway quarantine_v4`
- `/etc/systemd/system/iot-gateway.service` (runs `gateway.sh`; ordered after
  mosquitto, influxdb, grafana-server) and `metrics-exporter.service`
- `~/logrotate_suricata.conf` — caps eve.json at 50 MB (stats.log once grew to 7.8 GB)
- Built from source in `~`: `suricata-7.0.8/`, `libbpf/`, `xdp-tools/`,
  `rknn-toolkit2/`, and `kernel-build/` (kernel + r8125 NIC driver rebuild for
  XDP support; original module backed up as `~/r8125.ko.backup`)
- `~/npu_stress_test.py` — standalone NPU load/throughput test

## Network assumptions (current test setup)

| Item | Value |
|---|---|
| Monitored interface | `eth0` (bridge `br0` was trialed; see stages doc) |
| Gateway | `192.168.13.1` (LAN side), `192.168.3.64/20` (uplink) |
| Test IoT device | `192.168.13.48` |
| Never-quarantine | router `192.168.3.1`, workstation `192.168.3.15` |
| Dashboard / MQTT / InfluxDB | :5000 / localhost:1883 / localhost:8086 |

## Known gaps

The project was paused mid-integration; the honest state is ~80 %:

- **Watcher path** — *fixed*: `scripts/suricata_watcher.py` now reads eve.json
  from `iot-gateway/logs/eve.json` (matching `suricata-iot.yaml`) instead of
  `/var/log/suricata/eve.json`, so Suricata alerts now reach the decision engine.
  Overridable with the `EVE_LOG` env var.
- `setup_bridge.sh` referenced by `gateway.sh:31` is intentionally kept but not
  yet written; the eth0-vs-br0 capture strategy is a resume item (see stages doc).
- **eBPF bypass cannot be enabled as-is**: the objects are built and installed to
  `/etc/suricata/ebpf/`, but the running Suricata was configured with only
  `--enable-nfqueue --enable-nflog`, **not `--enable-ebpf`**. Adding
  `ebpf-filter-file`/`bypass` to the yaml would make Suricata fatally fail at
  startup. Activating the bypass requires rebuilding Suricata first — tracked as a
  resume stage. The yaml is deliberately left without the bypass keys.
- `metrics_exporter.py` → InfluxDB works but has a hardcoded token; no Grafana.
- Dashboard has no authentication (test-bench only).
- Models trained on NSL-KDD only; no post-quantization accuracy validation.
- Logs under `logs/` grew to ~2.3 GB — safe to truncate.

Full detail per stage in [`docs/DEVELOPMENT_STAGES.md`](docs/DEVELOPMENT_STAGES.md).
