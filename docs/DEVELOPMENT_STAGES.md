# Development Stages — IoT Security Gateway

Reconstructed from the build history and artifacts on the Orange Pi (development ran
~March 2026, then paused). Stages are grouped by concern; they overlapped in time
rather than running strictly one after another.

## Stage 0 — Environment & platform setup
- OS packages: `nftables`, `mosquitto`(+clients), `nodejs`/`npm`.
- Python stack: `scapy`, `numpy`, `pandas`, `scikit-learn`, `torch`, `onnx`,
  `paho-mqtt`, `flask`.
- Toolchains: Rust (`~/.rustup`, `~/.cargo`), Claude CLI.
- Hardware baseline: RK3588 (4×A76 + 4×A55), 3-core NPU at
  `/sys/kernel/debug/rknpu/load`, dual NIC (`eth0` + Realtek `enP4p65s0`/r8125),
  thermal at `/sys/class/thermal/thermal_zone0/temp`.

## Stage 1 — Kernel & NIC driver
- Linux kernel source for RK3588 in `~/kernel-build/` configured for BPF
  (`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`).
- Rebuilt the Realtek **r8125** driver as a loadable module to get XDP-capable
  packet handling; original kept as `~/r8125.ko.backup`.
- **Status:** kernel object compilation was still in progress at the last activity
  (mid-March); final Image not confirmed. `CONFIG_XDP_SOCKETS` was left unset —
  XDP is used in driver/native mode, not AF_XDP sockets.

## Stage 2 — ML model development
- Autoencoder (PyTorch) for network-flow anomaly detection, 13 input features
  (`scripts/flow_features.py`): protocol, dst_port, flow_duration_ms,
  fwd/bwd packet & byte counts, fwd/bwd mean packet length, bytes/sec, pkts/sec,
  mean IAT, SYN count. Min-max normalized to [0, 1].
- Trained on **NSL-KDD**; anomaly = reconstruction MSE above threshold
  (`autoencoder_config.json`: **0.0019333**).
- Also trained a supervised classifier (softmax [normal, attack], threshold 0.5)
  and a sklearn RandomForest (`rf_model.joblib`) as a CPU fallback.
- `scripts/generate_dataset.py` builds training data; `training_data.csv` is the set.
- Iterations v1→v2→v3: v1 exported with external weight data (needed the
  `fix_onnx.py` inline fix on the host), v2 restructured, **v3 is a simplified
  graph that quantizes cleanly**.

## Stage 3 — NPU toolkit & conversion
- Vendor `rknn-toolkit2` cloned (RK3588 support). ONNX→RKNN INT8 conversion runs
  on an **x86 host** (see the `rknn-convert` folder on the dev PC), because the
  full toolkit isn't ARM64; the device runs only `rknn-toolkit-lite2` for inference.
- `scripts/convert_to_rknn.py` (on-device copy) / host `convert.py` build the
  calibration set from normal samples and emit `autoencoder.rknn`.
- `~/npu_stress_test.py` validates NPU throughput and per-core load.
- `scripts/npu_infer.c` → `libnpu_infer.so`: a native C bridge to the rknpu2 API,
  wrapped by `scripts/npu_infer_wrapper.py` (ctypes) as an alternative to the
  Python lite runtime.

## Stage 4 — XDP / eBPF data path
- `libbpf` (HEAD) and `xdp-tools` v1.4.2 cloned and built.
- **XDP programs** (`xdp/src/`):
  - `xdp_gateway.c` (production): blacklist drop → SYN/UDP rate-limit (per-IP LRU,
    configurable via `config` map) → flow tracking (`flow_table`, 100k LRU with
    packets/bytes/timestamps) → whitelist bypass → `XDP_PASS`. Exposes `gw_stats`.
  - `xdp_blacklist.c` (blacklist-only), `xdp_hello.c` (counter demo).
- **eBPF for Suricata** (`ebpf/`): `suricata_bypass.c` — a `"filter"`-section program
  with IPv4/IPv6 flow tables (VLAN-aware) that lets Suricata skip already-seen flows;
  `xdp_filter.c` (whitelist/blacklist/rate-limit variant); `build_ebpf.sh` compiles
  for ARM64 and installs to `/etc/suricata/ebpf/`.
- Management: `xdp/scripts/xdp_control.sh` (load/unload/stats/flows/block via
  `bpftool`), `ebpf/xdp_manage.sh` (whitelist/blacklist IP & port with hex helpers).
- **Status:** objects compiled; XDP load is marked *non-critical* in `gateway.sh`
  and the Suricata↔eBPF bypass was not confirmed wired into the final Suricata build.

## Stage 5 — Suricata IDS
- Built Suricata **7.0.8** from source (`~/suricata-7.0.8/`, configured with
  `--enable-nfqueue --enable-nflog`).
- IoT config `/etc/suricata/suricata-iot.yaml`, af-packet capture. HOME_NET is
  `192.168.0.0/20` + `10.0.0.0/24`; HTTP/TLS/DNS/MQTT app-layer parsers enabled;
  `midstream: true` + `exception-policy: pass-packet` were set specifically so the
  evasion rules (XMAS/FIN/NULL scans that arrive without a SYN) actually fire.
- **16 custom IoT rule files** in `/etc/suricata/rules/` (mirrored into `rules/`):
  iot-attacks, mirai-variants, firmware-exploits, protocol-abuse, c2-indicators,
  dns-lateral, network-anomaly, evasion-techniques, tls-fingerprints, iot-advanced,
  ics-modbus, mqtt-deep, device-fingerprints, coap-deep, anomaly-baseline, local —
  this was substantial hand-written detection content, not stock ET rules.
- `logrotate_suricata.conf` caps eve.json at 50 MB (stats.log had ballooned to ~7.8 GB).
- `scripts/suricata_watcher.py` tails eve.json (with `suricata_alert_reader.py` as
  an earlier variant). **Bug:** it reads `/var/log/suricata/eve.json`, but the yaml
  writes eve.json to `iot-gateway/logs/eve.json` — the two disagree.

## Stage 6 — Detection pipeline
- `scripts/detect_pipeline.py`: scapy live sniffer → assembles flows → 13-feature
  vectors → batch NPU inference (~5 s intervals) → `npu_alerts.jsonl`. Whitelists
  multicast/broadcast/management traffic.
- Backend selection in `npu_detector.py`: **RKNN (NPU) → ONNX (CPU) → sklearn RF**.
- Behavioral analysis layered on top: beaconing (low-CV periodic connections),
  long connections (>5 min, >1 KB), DNS anomalies (domain bursts / high-entropy DGA).

## Stage 7 — Decision engine & response
- `scripts/decision_engine.py`: per-IP evidence accumulation over a **60 s window**
  with **5 pts/min decay**. Scoring: Suricata sev 1/2/3 = 50/30/10; NPU anomaly = 40
  (+20 if ≥ 2× threshold); beaconing 35 / long-conn 25 / DNS 20.
- Thresholds: **≥80 QUARANTINE**, **≥50 ALERT**, **≥20 LOG** → `decisions.jsonl`.
- Quarantine via nftables set `inet iot_gateway quarantine_v4`, 1 h timeout
  (`quarantine.sh`, `quarantine.log`); `NEVER_QUARANTINE` protects router/workstation.
- `scripts/mqtt_alerter.py` publishes to `iot-gateway/alerts|quarantine|status`.

## Stage 8 — Dashboard & metrics
- `dashboard/app.py`: Flask on **:5000**, embedded dark-theme UI — live alerts,
  per-device threat scores, quarantine view, and controls to launch the 9 attack
  simulators. Endpoints `/api/status`, `/api/logs`, `/api/start_attack/<id>`,
  `/api/stop_attack/<id>`. No auth (test bench).
- `scripts/metrics_exporter.py`: polls the JSONL logs + `/api/status` every 5 s and
  writes to InfluxDB (`localhost:8086`, bucket `security`). Token is hardcoded —
  fix before any real deployment.

## Stage 9 — Attack simulation & testing
- `scripts/attack_*` suite: `attack_port_scan.py`, `attack_flood.sh`,
  `attack_c2_beacon.py`, `attack_arp_spoof.py`, `attack_credential_stuffing.py`,
  `attack_upnp_abuse.py`; `fake_iot_device.py` for baseline traffic;
  `run_all_tests.sh` orchestrator. Targets the test device `192.168.13.48`.
- Captures saved for offline replay: `captures/baseline_normal.pcap`,
  `captures/test_full_suite.pcap`.

## Stage 10 — Orchestration & service
- `gateway.sh {start|stop|status|test}` sequences: nftables flush → XDP load →
  Suricata → mosquitto → suricata_watcher → detect_pipeline → dashboard, writing
  PIDs to `pids/`. `pin_cores.sh` sets CPU affinity for the A55/A76 split.
- systemd units: `iot-gateway.service`, `metrics-exporter.service`.

## Where it stopped / open items
- **Networking not settled**: `setup_bridge.sh` (called by `gateway.sh:31`) is not
  yet written — the call is kept as a placeholder; work oscillated between capturing
  on `eth0` and a `br0` bridge/tap. Gateway IP moved around (192.168.3.64 ↔
  192.168.13.x). See resume stage R1.
- **Suricata → decision engine** — *fixed*: `suricata_watcher.py` was tailing
  `/var/log/suricata/eve.json` while the yaml writes `iot-gateway/logs/eve.json`;
  the watcher now reads the correct path (env-overridable via `EVE_LOG`).
- **eBPF bypass blocked on a rebuild**: the `.bpf` objects are installed to
  `/etc/suricata/ebpf/`, but the running Suricata binary was configured
  `--enable-nfqueue --enable-nflog` only — **no `--enable-ebpf`**. The yaml is
  deliberately left without `ebpf-filter-file`/`bypass` because adding them to a
  non-eBPF build makes Suricata fatal-error on startup. See resume stage R2.
- **Kernel/r8125 build** not finalized.
- **Metrics/Grafana** stack incomplete; InfluxDB token hardcoded.
- **Model validation**: no post-quantization accuracy check; NSL-KDD (2009) only.
- **Housekeeping**: `logs/` ~2.3 GB (truncate freely); `models.bak_20260309/`
  is an older model snapshot; `dashboard/app.py.bak*` are prior UI revisions.

## Resume stages
Concrete next tasks, in order. R1/R2 are the two that were deferred with code/config
left in place rather than removed.

**R1 — Write `setup_bridge.sh` and settle the capture path.**
`gateway.sh:31` calls `bash ~/iot-gateway/setup_bridge.sh` before starting Suricata,
but the script was never written (the call is intentionally kept). Decide between:
(a) capture directly on `eth0` — then delete the `setup_bridge.sh` call; or
(b) a `br0` bridge/tap mirror — then implement the script to create the bridge,
enslave the NIC(s), and point Suricata + `detect_pipeline.py` at `br0`. Until then,
`gateway.sh start` will print a bridge error but continue.

**R2 — Rebuild Suricata with eBPF to activate the bypass.**
The `suricata_bypass.bpf` / `xdp_filter.bpf` objects are built and installed to
`/etc/suricata/ebpf/`, but the current binary lacks eBPF support. To enable:
```bash
cd ~/suricata-7.0.8
./configure --enable-nfqueue --enable-nflog --enable-ebpf \
            --enable-ebpf-build && make -j$(nproc) && sudo make install
```
Then add an `af-packet` section to `suricata-iot.yaml` with
`ebpf-filter-file: /etc/suricata/ebpf/suricata_bypass.bpf` and `bypass: yes`, and
point Suricata at the chosen interface from R1. **Do not add those yaml keys before
rebuilding** — the current binary will fatal-error on them.

**R3 — Verify the detection path end-to-end.**
Confirm the watcher now delivers alerts (R1 running), then check the NPU path with
`~/npu_stress_test.py` and live via `detect_pipeline.py`, ensuring RKNN loads and
doesn't silently fall back to CPU.

**R4 — Validate with captures.** Replay `captures/baseline_normal.pcap` and
`captures/test_full_suite.pcap` through the pipeline to confirm detection + scoring.

**R5 — Finalize kernel/r8125 build** if the XDP driver path is needed.

**R6 — Housekeeping.** Truncate `logs/` (~2.3 GB); move the InfluxDB token in
`metrics_exporter.py` to an env var; add auth to the dashboard before exposing it.
