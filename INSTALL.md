# Installation & Setup

> **This is a hardware appliance, not a portable app.** It runs on an
> **Orange Pi 5 (RK3588/RK3588S, ARM64)** and depends on that board's 3-core NPU,
> plus several components built from source on the device. It will *not* run on a
> generic PC. The steps below reproduce it on the target hardware.

## 1. Hardware & OS prerequisites

- Orange Pi 5 / 5B / 5 Plus (RK3588 or RK3588S), running a Debian/Ubuntu-based
  aarch64 image (the project was developed on Python 3.10).
- Root/sudo access. At least one wired NIC used as the monitored interface.
- Recommended: a second NIC or a mirror/tap port if you want a bridge (`br0`) setup.

## 2. System packages

```bash
sudo apt update
sudo apt install -y nftables mosquitto mosquitto-clients \
                    python3-pip python3-venv build-essential \
                    clang llvm libbpf-dev bpftool linux-headers-$(uname -r)
```

## 3. Components built from source (not included in this repo)

These are large upstream projects; build them on the device per their own docs:

| Component | Why | Notes |
|---|---|---|
| **Suricata 7.0.8** | IDS layer | Build with eBPF support if you want the bypass: `./configure --enable-nfqueue --enable-nflog --enable-ebpf --enable-ebpf-build` (see `docs/DEVELOPMENT_STAGES.md` R2). Install the IoT config + rules from `configs/` and `rules/` (below). |
| **rknn-toolkit-lite2** | NPU inference | Install the aarch64 wheel from <https://github.com/airockchip/rknn-toolkit2> (`rknn_toolkit_lite2/packages/`). Device-only; not on PyPI. |
| **rknn-toolkit2** (x86 host) | ONNX→RKNN conversion | Only needed to *regenerate* `models/autoencoder.rknn` on an x86 PC. The prebuilt `.rknn` is already in `models/`. |
| Kernel / r8125 driver | XDP on the Realtek NIC | Optional; only if your NIC needs an XDP-capable driver rebuild. |

## 4. Python dependencies

```bash
pip install --user -r requirements.txt
# then the NPU wheel (device only):
pip install --user rknn_toolkit_lite2-*-cp310-cp310-linux_aarch64.whl
```

If the RKNN or ONNX backends are missing, `npu_detector.py` automatically falls back
to the sklearn RandomForest (`models/rf_model.joblib`) — so the gateway still runs,
just on CPU.

## 5. Configuration

```bash
cp configs/gateway.env.example gateway.env
# edit gateway.env: set MONITOR_IFACE, GATEWAY_IP, TARGET_IP, INFLUX_TOKEN
source gateway.env
```

Install the system-side config (reference copies live in this repo):

```bash
sudo cp configs/suricata-iot.yaml   /etc/suricata/suricata-iot.yaml
sudo mkdir -p /etc/suricata/rules   && sudo cp rules/*.rules /etc/suricata/rules/
sudo cp configs/nftables-iot.conf   /etc/nftables-iot.conf
sudo cp configs/iot-gateway.service /etc/systemd/system/
sudo cp configs/metrics-exporter.service /etc/systemd/system/
sudo cp configs/logrotate_suricata.conf  /etc/logrotate.d/suricata-iot
```

Create the nftables quarantine set expected by the decision engine:

```bash
sudo nft -f /etc/nftables-iot.conf
```

### Passwordless sudo for the dashboard attack simulators
The dashboard launches the attack scripts with `sudo -n`. Allow only those
scripts, not `python3` or `bash` in general (that would give the dashboard user
full root). In `/etc/sudoers.d/iot-gateway` (edit with `sudo visudo -f`):

```
Cmnd_Alias IOTGW_ATTACKS = \
    /usr/bin/python3 -u /home/orangepi/iot-gateway/scripts/attack_*.py *, \
    /bin/bash /home/orangepi/iot-gateway/scripts/attack_flood.sh *
orangepi ALL=(root) NOPASSWD: IOTGW_ATTACKS
```

Make the scripts root-owned and not writable by `orangepi`, otherwise the user
could edit a script and run anything as root.

## 6. Build native / eBPF artifacts

```bash
bash scripts/build_npu_infer.sh     # → scripts/libnpu_infer.so
bash ebpf/build_ebpf.sh             # → /etc/suricata/ebpf/*.bpf  (needs eBPF-enabled Suricata)
```

## 7. Run

```bash
./gateway.sh start      # start everything
./gateway.sh status
./gateway.sh stop
# or as a service:
sudo systemctl enable --now iot-gateway
```

Dashboard: `http://<GATEWAY_IP>:5000`.

## Known setup gaps (see `docs/DEVELOPMENT_STAGES.md`)

- **R1** — `gateway.sh` calls `setup_bridge.sh`, which isn't written yet. If you
  capture directly on `eth0`, remove that line from `gateway.sh`; if you want a
  `br0` bridge/tap, write the script first.
- **R2** — the eBPF bypass needs a Suricata rebuilt with `--enable-ebpf`. Do **not**
  add `ebpf-filter-file`/`bypass` to the yaml before that rebuild — it will crash
  Suricata at startup.

## Security notes

- The dashboard has **no authentication** — bind it to a trusted LAN only.
- It ships **live attack tooling** (port scans, floods, ARP spoof, C2 sim). Run it
  only against devices/networks you own and are authorized to test.
- Set `INFLUX_TOKEN` via `gateway.env`; never commit real tokens.
