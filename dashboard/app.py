#!/usr/bin/env python3
"""Lightweight monitoring dashboard for IoT Security Gateway"""
from flask import Flask, jsonify, render_template_string, request
import json, os, re, time, subprocess, threading, psutil
from collections import defaultdict, deque

app = Flask(__name__)
LOG_DIR = os.path.expanduser("~/iot-gateway/logs")
SCRIPTS_DIR = os.path.expanduser("~/iot-gateway/scripts")

TARGET_IP = os.environ.get("TARGET_IP", "192.168.13.48")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "192.168.13.1")

ATTACKS = {
    "port_scan_quick":   {"label": "Port Scan",      "icon": "🔍", "sub": "Quick",            "category": "recon",
                          "cmd": f"sudo python3 -u {SCRIPTS_DIR}/attack_port_scan.py {TARGET_IP} quick"},
    "port_scan_stealth": {"label": "Port Scan",      "icon": "👁",  "sub": "Stealth",          "category": "recon",
                          "cmd": f"sudo python3 -u {SCRIPTS_DIR}/attack_port_scan.py {TARGET_IP} stealth"},
    "flood_syn":         {"label": "SYN Flood",      "icon": "⚡", "sub": "TCP SYN",           "category": "flood",
                          "cmd": f"sudo bash {SCRIPTS_DIR}/attack_flood.sh syn {TARGET_IP} 80 2000"},
    "flood_udp":         {"label": "UDP Flood",      "icon": "⚡", "sub": "UDP",               "category": "flood",
                          "cmd": f"sudo bash {SCRIPTS_DIR}/attack_flood.sh udp {TARGET_IP} 80 2000"},
    "flood_icmp":        {"label": "ICMP Flood",     "icon": "⚡", "sub": "Ping flood",        "category": "flood",
                          "cmd": f"sudo bash {SCRIPTS_DIR}/attack_flood.sh icmp {TARGET_IP} 80 2000"},
    "arp_spoof":         {"label": "ARP Spoof",      "icon": "🎭", "sub": "MitM / poison",     "category": "mitm",
                          "cmd": f"sudo python3 -u {SCRIPTS_DIR}/attack_arp_spoof.py {TARGET_IP} {GATEWAY_IP} spoof"},
    "c2_beacon":         {"label": "C2 Beacon",      "icon": "📡", "sub": "DNS + HTTP + exfil","category": "c2",
                          "cmd": f"sudo python3 -u {SCRIPTS_DIR}/attack_c2_beacon.py all"},
    "upnp_abuse":        {"label": "UPnP Abuse",     "icon": "🔓", "sub": "SSDP + port map",  "category": "discovery",
                          "cmd": f"sudo python3 -u {SCRIPTS_DIR}/attack_upnp_abuse.py {TARGET_IP}"},
    "cred_stuffing":     {"label": "Cred Stuffing",  "icon": "🔑", "sub": "Telnet + HTTP",     "category": "bruteforce",
                          "cmd": f"sudo python3 -u {SCRIPTS_DIR}/attack_credential_stuffing.py {TARGET_IP}"},
}

# Runtime state
_procs = {}
_output = {}
_attack_log = deque(maxlen=500)
_lock = threading.Lock()

def _read_proc_output(attack_id, proc):
    buf = _output[attack_id]
    label = ATTACKS[attack_id]["label"]
    sub   = ATTACKS[attack_id]["sub"]
    prefix = f"[{label} / {sub}]"
    _attack_log.append(f"{'─'*60}")
    _attack_log.append(f"{prefix} started")
    for line in iter(proc.stdout.readline, b''):
        decoded = line.decode(errors='replace').rstrip()
        buf.append(decoded)
        _attack_log.append(f"{prefix} {decoded}")
    _attack_log.append(f"{prefix} finished")
    proc.stdout.close()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IoT Security Gateway</title>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #05080f;
  --bg2:     #080d18;
  --bg3:     #0b1220;
  --sidebar: #060a12;
  --amber:   #f5a623;
  --amber2:  #ff7b00;
  --neon:    #39ff87;
  --red:     #ff2d55;
  --cyan:    #00d9ff;
  --muted:   #1e2d3d;
  --border:  #121e2e;
  --text:    #bdd4e4;
  --dim:     #3d5266;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { height: 100%; overflow: hidden; }
body {
  font-family: 'JetBrains Mono', monospace;
  background: var(--bg);
  color: var(--text);
  display: flex;
  flex-direction: column;
}
body::before {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  pointer-events: none; z-index: 9000;
}

/* ── HEADER ── */
.hdr {
  display: flex; align-items: center;
  height: 52px; flex-shrink: 0;
  background: var(--bg2);
  border-bottom: 1px solid var(--amber);
  padding: 0 24px; gap: 18px;
  position: relative; z-index: 100;
}
.hdr::after {
  content: '';
  position: absolute; bottom: -4px; left: 0; right: 0; height: 3px;
  background: linear-gradient(90deg, var(--amber), var(--amber2) 30%, transparent 70%);
  opacity: 0.2;
}
.hdr-brand {
  display: flex; align-items: center; gap: 12px;
}
.hdr-logo {
  width: 28px; height: 28px;
  border: 1px solid var(--amber);
  border-radius: 2px;
  display: flex; align-items: center; justify-content: center;
  font-size: 20px; color: var(--amber);
  flex-shrink: 0;
}
.hdr-title {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 21px; font-weight: 700;
  letter-spacing: 3px; text-transform: uppercase;
  color: var(--amber); white-space: nowrap;
}
.hdr-sep { width: 1px; height: 22px; background: var(--border); flex-shrink: 0; }
.hdr-sub {
  font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase;
  color: var(--dim);
}
.hdr-spacer { flex: 1; }
.hdr-pill {
  display: flex; align-items: center; gap: 6px;
  padding: 4px 12px;
  border: 1px solid var(--border); border-radius: 2px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
  color: var(--dim);
}
.dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
.dot-g { background: var(--neon);  box-shadow: 0 0 7px var(--neon);  animation: blink 2s infinite; }
.dot-a { background: var(--amber); box-shadow: 0 0 7px var(--amber); animation: blink 2.5s infinite; }
.dot-r { background: var(--red);   box-shadow: 0 0 7px var(--red);   animation: blink 1.6s infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
.hdr-clock {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 15px; color: var(--amber); opacity: .7; letter-spacing: 1px;
  white-space: nowrap;
}

/* ── LAYOUT ── */
.layout { display: flex; flex: 1; overflow: hidden; }

/* ── SIDEBAR ── */
.sidebar {
  width: 188px; flex-shrink: 0;
  background: var(--sidebar);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  padding: 20px 0 0;
}
.nav-section-label {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 3px; text-transform: uppercase;
  color: var(--dim); padding: 0 20px 10px;
}
.nav-item {
  display: flex; align-items: center; gap: 11px;
  padding: 11px 20px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 15px; letter-spacing: 1.5px; text-transform: uppercase;
  color: var(--dim); cursor: pointer;
  border-left: 2px solid transparent;
  transition: color .15s, background .15s;
}
.nav-item:hover { color: var(--text); background: rgba(255,255,255,.025); }
.nav-item.active {
  color: var(--amber);
  border-left-color: var(--amber);
  background: rgba(245,166,35,.05);
}
.nav-icon { font-size: 21px; width: 20px; text-align: center; line-height: 1; }
.sidebar-spacer { flex: 1; }
.sidebar-footer {
  padding: 14px 20px;
  font-size: 12px; color: var(--dim); letter-spacing: 1px;
  border-top: 1px solid var(--border);
  line-height: 1.8;
}

/* ── MAIN ── */
.main { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
.page { display: none; flex-direction: column; flex: 1; overflow: hidden; }
.page.active { display: flex; }

/* ── PAGE HEADER ── */
.page-hdr {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 28px;
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.page-title {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 14px; letter-spacing: 3px; text-transform: uppercase;
  color: var(--dim); display: flex; align-items: center; gap: 8px;
}
.page-title::before { content: '//'; color: var(--amber); opacity: .5; font-size: 14px; }
.page-meta { font-size: 12px; color: var(--dim); letter-spacing: 1px; }

/* ── STAT CARDS ── */
.stats-row {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 1px; background: var(--border);
  flex-shrink: 0;
}
.stat-card {
  background: var(--bg2); padding: 18px 22px;
  position: relative; overflow: hidden;
}
.stat-bg-num {
  position: absolute; right: 10px; bottom: 4px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 90px; font-weight: 700;
  opacity: .04; line-height: 1; pointer-events: none; color: white;
}
.stat-lbl {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 2.5px; text-transform: uppercase;
  color: var(--dim); margin-bottom: 8px;
}
.stat-num {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 51px; font-weight: 700; line-height: 1;
}
.stat-bar { height: 2px; margin-top: 10px; background: var(--border); }
.stat-bar-fill { height: 100%; }
.c-red   { color: var(--red);   }
.c-amber { color: var(--amber); }
.c-cyan  { color: var(--cyan);  }
.c-neon  { color: var(--neon);  }

/* ── PIPELINE STRIP ── */
.pipeline {
  display: flex; align-items: center;
  padding: 7px 28px; gap: 0;
  background: var(--bg3);
  border-bottom: 1px solid var(--border);
  overflow-x: auto; flex-shrink: 0;
}
.pipe-node {
  display: flex; align-items: center; gap: 6px;
  padding: 4px 11px;
  border: 1px solid var(--muted); border-radius: 2px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
  color: var(--cyan); white-space: nowrap; background: var(--bg2);
}
.pipe-dot { width: 4px; height: 4px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 5px var(--cyan); animation: blink 1.8s infinite; }
.pipe-arr { width: 20px; height: 1px; background: var(--muted); flex-shrink: 0; position: relative; }
.pipe-arr::after { content: '▸'; position: absolute; right: -3px; top: -5px; color: var(--muted); font-size: 10px; }

/* ── OVERVIEW GRID ── */
.ov-grid {
  display: grid; grid-template-columns: 1fr 1fr;
  gap: 1px; background: var(--border);
  flex: 1; overflow: hidden;
}
.ov-panel { background: var(--bg2); padding: 18px 22px; overflow-y: auto; }
.panel-hd {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px; letter-spacing: 2.5px; text-transform: uppercase;
  color: var(--dim); margin-bottom: 14px;
  display: flex; align-items: center; gap: 8px;
}
.panel-hd::before { content: '//'; color: var(--amber); opacity: .4; }

table { width: 100%; border-collapse: collapse; }
th {
  text-align: left; padding: 0 8px 8px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--dim); border-bottom: 1px solid var(--border);
}
td { padding: 7px 8px; font-size: 15px; border-bottom: 1px solid rgba(255,255,255,.03); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,.015); }
.td-ip { color: var(--cyan); }
.td-ts { color: var(--dim); font-size: 14px; }
.no-data { color: var(--dim); font-size: 15px; padding: 14px 8px; }

.badge {
  display: inline-flex; align-items: center;
  padding: 1px 7px; border-radius: 2px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 1px; text-transform: uppercase;
}
.b-red   { background: rgba(255,45,85,.1);   color: var(--red);   border: 1px solid rgba(255,45,85,.25); }
.b-amber { background: rgba(245,166,35,.1);  color: var(--amber); border: 1px solid rgba(245,166,35,.25); }
.b-neon  { background: rgba(57,255,135,.1);  color: var(--neon);  border: 1px solid rgba(57,255,135,.25); }

/* ── ATTACKS PAGE ── */
.atk-grid {
  display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 12px; padding: 22px 28px;
  overflow-y: auto; align-content: start;
}
.atk-card {
  background: var(--bg2);
  border: 1px solid var(--border); border-radius: 3px;
  padding: 18px 18px 16px;
  transition: border-color .15s, background .15s;
}
.atk-card:hover { border-color: var(--muted); }
.atk-card.running { border-color: var(--red); background: rgba(255,45,85,.05); }

.atk-card-top {
  display: flex; align-items: flex-start; justify-content: space-between;
  margin-bottom: 12px;
}
.atk-icon { font-size: 33px; line-height: 1; }
.atk-ind {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--border);
  transition: background .2s, box-shadow .2s;
  margin-top: 3px; flex-shrink: 0;
}
.atk-card.running .atk-ind { background: var(--red); box-shadow: 0 0 10px var(--red); animation: blink .8s infinite; }

.atk-name {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 16px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase;
  color: var(--text); margin-bottom: 4px;
}
.atk-sub { font-size: 14px; color: var(--dim); margin-bottom: 12px; }
.atk-cat {
  display: inline-block;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 1px; text-transform: uppercase;
  padding: 2px 8px; border-radius: 2px; margin-bottom: 14px;
}
.cat-recon     { background: rgba(0,217,255,.08);   color: var(--cyan);  border: 1px solid rgba(0,217,255,.2); }
.cat-flood     { background: rgba(255,45,85,.08);   color: var(--red);   border: 1px solid rgba(255,45,85,.2); }
.cat-mitm      { background: rgba(245,166,35,.08);  color: var(--amber); border: 1px solid rgba(245,166,35,.2); }
.cat-c2        { background: rgba(57,255,135,.08);  color: var(--neon);  border: 1px solid rgba(57,255,135,.2); }
.cat-discovery { background: rgba(160,110,255,.08); color: #a78bff;      border: 1px solid rgba(160,110,255,.2); }
.cat-bruteforce{ background: rgba(255,120,50,.08);  color: #ff7832;      border: 1px solid rgba(255,120,50,.2); }

.atk-btns { display: flex; gap: 6px; }
.btn-launch {
  flex: 1;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase;
  background: transparent; color: var(--text);
  border: 1px solid var(--muted); border-radius: 2px;
  padding: 7px; cursor: pointer;
  transition: background .15s, border-color .15s;
}
.btn-launch:hover { background: rgba(255,255,255,.04); border-color: var(--text); }
.atk-card.running .btn-launch { color: var(--red); border-color: rgba(255,45,85,.4); background: rgba(255,45,85,.08); }
.btn-stop {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px; letter-spacing: 1px; text-transform: uppercase;
  background: rgba(255,45,85,.1); color: var(--red);
  border: 1px solid rgba(255,45,85,.3); border-radius: 2px;
  padding: 7px 12px; cursor: pointer; display: none;
  transition: background .15s;
}
.btn-stop:hover { background: rgba(255,45,85,.25); }
.atk-card.running .btn-stop { display: block; }

.btn-stop-all {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px; letter-spacing: 2px; text-transform: uppercase;
  background: rgba(255,45,85,.1); color: var(--red);
  border: 1px solid rgba(255,45,85,.3); border-radius: 2px;
  padding: 6px 14px; cursor: pointer;
  transition: background .15s;
}
.btn-stop-all:hover { background: rgba(255,45,85,.25); }

.atk-target-badge {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px; letter-spacing: 1.5px;
  color: var(--dim); border: 1px solid var(--border);
  padding: 5px 14px; border-radius: 2px;
}
.atk-target-badge span { color: var(--amber); }

/* ── ANALYTICS PAGE ── */
.ana-inner { flex: 1; overflow-y: auto; padding: 20px 28px; }
.ana-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.ana-full { grid-column: 1 / -1; }
.ana-frame {
  border: 1px solid var(--border); border-radius: 3px;
  overflow: hidden; background: var(--bg3);
}
.ana-lbl {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--dim); padding: 7px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--bg2);
}
.ana-frame iframe { width: 100%; display: block; border: none; }
.ana-range-btn {
  background: var(--bg3); color: var(--dim); border: 1px solid var(--border);
  border-radius: 3px; padding: 4px 14px; font-size: 12px; cursor: pointer;
  font-family: 'Chakra Petch', sans-serif; letter-spacing: 1px;
}
.ana-range-btn:hover { border-color: var(--accent); color: var(--fg); }
.ana-range-btn.active { background: var(--accent); color: #000; border-color: var(--accent); }

/* ── LOGS PAGE ── */
.log-tabs {
  display: flex; background: var(--bg2);
  border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.log-tab {
  padding: 10px 20px;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--dim); cursor: pointer;
  border-right: 1px solid var(--border);
  transition: color .15s;
}
.log-tab:hover { color: var(--text); }
.log-tab.active {
  color: var(--amber); background: var(--bg);
  border-bottom: 2px solid var(--amber); margin-bottom: -1px;
}
.log-body {
  flex: 1; overflow-y: auto;
  padding: 12px 20px; font-size: 15px; line-height: 1.8;
}
.log-hidden { display: none; }
.log-line { padding: 1px 0; border-bottom: 1px solid rgba(255,255,255,.02); }
.log-ts  { color: var(--dim); }
.log-q   { color: var(--red); }
.log-a   { color: var(--amber); }
.log-ok  { color: var(--neon); }
.log-num { color: var(--cyan); }
.log-sep { color: var(--muted); }
.log-ip  { color: var(--cyan); }

/* ── SYSTEM PAGE ── */
.sys-inner { flex: 1; overflow-y: auto; padding: 22px 28px; display: flex; flex-direction: column; gap: 14px; }
.sys-row   { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.sys-card  { background: var(--bg2); border: 1px solid var(--border); border-radius: 3px; padding: 18px 20px; }
.sys-card-hd {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px; letter-spacing: 2.5px; text-transform: uppercase;
  color: var(--dim); margin-bottom: 16px;
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
}
.sys-card-hd::before { content: '//'; color: var(--amber); opacity: .4; }
.sys-badge {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 1px;
  padding: 2px 8px; border-radius: 2px;
  background: rgba(0,217,255,.08); color: var(--cyan); border: 1px solid rgba(0,217,255,.2);
}
.sys-big-val {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 72px; font-weight: 700; line-height: 1;
  margin-bottom: 10px;
}
.sys-bar-wrap { background: var(--border); border-radius: 1px; height: 6px; margin-bottom: 6px; }
.sys-bar      { height: 100%; border-radius: 1px; transition: width .6s ease; }
.sys-bar-label {
  display: flex; justify-content: space-between; align-items: center;
  font-size: 14px; color: var(--dim); margin-bottom: 10px;
}
.sys-bar-label span { color: var(--text); }

.core-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px 14px; }
.core-item { }
.core-label {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px; letter-spacing: 1px; text-transform: uppercase;
  color: var(--dim); margin-bottom: 5px;
  display: flex; justify-content: space-between;
}
.core-label span { color: var(--cyan); }
.core-bar-wrap { background: var(--border); border-radius: 1px; height: 4px; }
.core-bar      { height: 100%; border-radius: 1px; transition: width .5s ease; background: var(--cyan); }
.core-procs    { margin-top: 5px; min-height: 28px; }
.core-proc     { display: flex; justify-content: space-between; align-items: center; gap: 4px; }
.core-proc-name { font-size: 12px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 90px; }
.core-proc-name.core-proc-idle { color: var(--dim); }
.core-proc-cpu  { font-size: 10px; color: var(--dim); flex-shrink: 0; }

.npu-freq {
  font-family: 'Chakra Petch', sans-serif;
  font-size: 15px; color: var(--dim); margin-top: 10px; letter-spacing: 1px;
}
.npu-freq span { color: var(--neon); }

::-webkit-scrollbar { width: 3px; height: 3px; }
::-webkit-scrollbar-track { background: var(--bg3); }
::-webkit-scrollbar-thumb { background: var(--muted); }
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-brand">
    <div class="hdr-logo">⬡</div>
    <div class="hdr-title">IoT Security Gateway</div>
  </div>
  <div class="hdr-sep"></div>
  <div class="hdr-sub">RK3588S &nbsp;·&nbsp; NPU Threat Detection &nbsp;·&nbsp; 192.168.3.64</div>
  <div class="hdr-spacer"></div>
  <div class="hdr-pill"><div class="dot dot-g"></div>Pipeline</div>
  <div class="hdr-pill"><div class="dot dot-a"></div>eth0</div>
  <div class="hdr-pill"><div class="dot dot-r"></div>Threat Engine</div>
  <div style="width:12px"></div>
  <div class="hdr-clock" id="clock"></div>
</div>

<!-- LAYOUT -->
<div class="layout">

  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="nav-section-label">Navigation</div>
    <div class="nav-item active" onclick="nav('overview', this)">
      <span class="nav-icon">◈</span>Overview
    </div>
    <div class="nav-item" onclick="nav('attacks', this)">
      <span class="nav-icon">⚔</span>Attacks
    </div>
    <div class="nav-item" onclick="nav('analytics', this)">
      <span class="nav-icon">◉</span>Analytics
    </div>
    <div class="nav-item" onclick="nav('logs', this)">
      <span class="nav-icon">≡</span>Logs
    </div>
    <div class="nav-item" onclick="nav('system', this)">
      <span class="nav-icon">◌</span>System
    </div>
    <div class="sidebar-spacer"></div>
    <div class="sidebar-footer">
      IoT Sec Gateway<br>
      Build 2026.03
    </div>
  </div>

  <!-- MAIN CONTENT -->
  <div class="main">

    <!-- ══════════ OVERVIEW ══════════ -->
    <div class="page active" id="page-overview">

      <!-- Stat cards -->
      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-bg-num" id="stat-bg-total">{{ stats.total_alerts }}</div>
          <div class="stat-lbl">Total Alerts</div>
          <div class="stat-num c-red" id="stat-total">{{ stats.total_alerts }}</div>
          <div class="stat-bar"><div class="stat-bar-fill" style="background:var(--red);width:80%"></div></div>
        </div>
        <div class="stat-card">
          <div class="stat-bg-num" id="stat-bg-quar">{{ stats.quarantined }}</div>
          <div class="stat-lbl">Quarantined</div>
          <div class="stat-num c-amber" id="stat-quar">{{ stats.quarantined }}</div>
          <div class="stat-bar"><div class="stat-bar-fill" style="background:var(--amber);width:40%"></div></div>
        </div>
        <div class="stat-card">
          <div class="stat-bg-num" id="stat-bg-suri">{{ stats.suricata_alerts }}</div>
          <div class="stat-lbl">Suricata Alerts</div>
          <div class="stat-num c-cyan" id="stat-suri">{{ stats.suricata_alerts }}</div>
          <div class="stat-bar"><div class="stat-bar-fill" style="background:var(--cyan);width:55%"></div></div>
        </div>
        <div class="stat-card">
          <div class="stat-bg-num" id="stat-bg-npu">{{ stats.npu_alerts }}</div>
          <div class="stat-lbl">NPU Detections</div>
          <div class="stat-num c-neon" id="stat-npu">{{ stats.npu_alerts }}</div>
          <div class="stat-bar"><div class="stat-bar-fill" style="background:var(--neon);width:70%"></div></div>
        </div>
      </div>

      <!-- Pipeline strip -->
      <div class="pipeline">
        <div class="pipe-node"><div class="pipe-dot"></div>NIC 1Gbps</div>
        <div class="pipe-arr"></div>
        <div class="pipe-node"><div class="pipe-dot"></div>XDP / eBPF</div>
        <div class="pipe-arr"></div>
        <div class="pipe-node"><div class="pipe-dot"></div>Suricata IDS</div>
        <div class="pipe-arr"></div>
        <div class="pipe-node"><div class="pipe-dot"></div>Flow Extractor</div>
        <div class="pipe-arr"></div>
        <div class="pipe-node"><div class="pipe-dot"></div>NPU Detector</div>
        <div class="pipe-arr"></div>
        <div class="pipe-node"><div class="pipe-dot"></div>Decision Engine</div>
        <div class="pipe-arr"></div>
        <div class="pipe-node"><div class="pipe-dot"></div>nftables / MQTT</div>
      </div>

      <!-- Tables -->
      <div class="ov-grid">
        <div class="ov-panel">
          <div class="panel-hd">Recent Alerts</div>
          <table>
            <tr><th>Time</th><th>Source IP</th><th>Score</th><th>Action</th></tr>
            {% for a in alerts %}
            <tr>
              <td class="td-ts">{{ a.time }}</td>
              <td class="td-ip">{{ a.ip }}</td>
              <td class="{% if a.severity==1 %}c-red{% elif a.severity==2 %}c-amber{% else %}c-neon{% endif %}">{{ a.score }}</td>
              <td>
                {% if a.action == 'QUARANTINE' %}<span class="badge b-red">{{ a.action }}</span>
                {% elif a.action == 'ALERT' %}<span class="badge b-amber">{{ a.action }}</span>
                {% else %}<span class="badge b-neon">{{ a.action }}</span>{% endif %}
              </td>
            </tr>
            {% endfor %}
            {% if not alerts %}<tr><td colspan="4" class="no-data">No alerts recorded</td></tr>{% endif %}
          </table>
        </div>
        <div class="ov-panel">
          <div class="panel-hd">Quarantined Devices</div>
          <table>
            <tr><th>IP Address</th><th>Threat Score</th><th>Status</th></tr>
            {% for q in quarantined %}
            <tr>
              <td class="td-ip">{{ q.ip }}</td>
              <td class="c-red">{{ q.score }}</td>
              <td><span class="badge b-red">ISOLATED</span></td>
            </tr>
            {% endfor %}
            {% if not quarantined %}<tr><td colspan="3" class="no-data">No active quarantines</td></tr>{% endif %}
          </table>
        </div>
      </div>
    </div><!-- /overview -->

    <!-- ══════════ ATTACKS ══════════ -->
    <div class="page" id="page-attacks">
      <div class="page-hdr">
        <div class="page-title">Attack Simulation</div>
        <div style="display:flex;align-items:center;gap:10px">
          <div class="atk-target-badge">TARGET &nbsp;<span>{{ target_ip }}</span></div>
          <button class="btn-stop-all" onclick="stopAllAttacks()">■ STOP ALL</button>
        </div>
      </div>
      <div class="atk-grid">

        <div class="atk-card" id="card-port_scan_quick">
          <div class="atk-card-top">
            <div class="atk-icon">🔍</div>
            <div class="atk-ind" id="ind-port_scan_quick"></div>
          </div>
          <div class="atk-name">Port Scan</div>
          <div class="atk-sub">Quick recon — all TCP ports</div>
          <div class="atk-cat cat-recon">recon</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('port_scan_quick')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('port_scan_quick')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-port_scan_stealth">
          <div class="atk-card-top">
            <div class="atk-icon">👁</div>
            <div class="atk-ind" id="ind-port_scan_stealth"></div>
          </div>
          <div class="atk-name">Stealth Scan</div>
          <div class="atk-sub">Low-noise TCP SYN probe</div>
          <div class="atk-cat cat-recon">recon</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('port_scan_stealth')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('port_scan_stealth')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-flood_syn">
          <div class="atk-card-top">
            <div class="atk-icon">⚡</div>
            <div class="atk-ind" id="ind-flood_syn"></div>
          </div>
          <div class="atk-name">SYN Flood</div>
          <div class="atk-sub">TCP SYN packet saturation</div>
          <div class="atk-cat cat-flood">flood</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('flood_syn')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('flood_syn')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-flood_udp">
          <div class="atk-card-top">
            <div class="atk-icon">⚡</div>
            <div class="atk-ind" id="ind-flood_udp"></div>
          </div>
          <div class="atk-name">UDP Flood</div>
          <div class="atk-sub">UDP packet storm</div>
          <div class="atk-cat cat-flood">flood</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('flood_udp')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('flood_udp')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-flood_icmp">
          <div class="atk-card-top">
            <div class="atk-icon">⚡</div>
            <div class="atk-ind" id="ind-flood_icmp"></div>
          </div>
          <div class="atk-name">ICMP Flood</div>
          <div class="atk-sub">Ping flood / ICMP storm</div>
          <div class="atk-cat cat-flood">flood</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('flood_icmp')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('flood_icmp')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-arp_spoof">
          <div class="atk-card-top">
            <div class="atk-icon">🎭</div>
            <div class="atk-ind" id="ind-arp_spoof"></div>
          </div>
          <div class="atk-name">ARP Spoof</div>
          <div class="atk-sub">MitM / ARP cache poison</div>
          <div class="atk-cat cat-mitm">mitm</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('arp_spoof')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('arp_spoof')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-c2_beacon">
          <div class="atk-card-top">
            <div class="atk-icon">📡</div>
            <div class="atk-ind" id="ind-c2_beacon"></div>
          </div>
          <div class="atk-name">C2 Beacon</div>
          <div class="atk-sub">DNS + HTTP + data exfil</div>
          <div class="atk-cat cat-c2">c2</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('c2_beacon')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('c2_beacon')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-upnp_abuse">
          <div class="atk-card-top">
            <div class="atk-icon">🔓</div>
            <div class="atk-ind" id="ind-upnp_abuse"></div>
          </div>
          <div class="atk-name">UPnP Abuse</div>
          <div class="atk-sub">SSDP discovery + port map</div>
          <div class="atk-cat cat-discovery">discovery</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('upnp_abuse')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('upnp_abuse')">■ Stop</button>
          </div>
        </div>

        <div class="atk-card" id="card-cred_stuffing">
          <div class="atk-card-top">
            <div class="atk-icon">🔑</div>
            <div class="atk-ind" id="ind-cred_stuffing"></div>
          </div>
          <div class="atk-name">Cred Stuffing</div>
          <div class="atk-sub">Telnet + HTTP brute-force</div>
          <div class="atk-cat cat-bruteforce">bruteforce</div>
          <div class="atk-btns">
            <button class="btn-launch" onclick="startAttack('cred_stuffing')">▶ Launch</button>
            <button class="btn-stop" onclick="stopAttack('cred_stuffing')">■ Stop</button>
          </div>
        </div>

      </div>
    </div><!-- /attacks -->

    <!-- ══════════ ANALYTICS ══════════ -->
    <div class="page" id="page-analytics">
      <div class="page-hdr">
        <div class="page-title">Historical Analytics</div>
        <div class="page-meta" id="ana-meta">Grafana · last 7d · refresh 30s</div>
      </div>
      <div style="padding:0 24px 8px;display:flex;gap:8px;flex-wrap:wrap;">
        <button class="ana-range-btn" onclick="setAnaRange('now-1h','Last 1h',this)">1h</button>
        <button class="ana-range-btn" onclick="setAnaRange('now-6h','Last 6h',this)">6h</button>
        <button class="ana-range-btn" onclick="setAnaRange('now-24h','Last 24h',this)">24h</button>
        <button class="ana-range-btn active" onclick="setAnaRange('now-7d','Last 7d',this)">7d</button>
        <button class="ana-range-btn" onclick="setAnaRange('now-30d','Last 30d',this)">30d</button>
      </div>
      <div class="ana-inner">
        <div class="ana-grid" id="ana-grid">
          <div class="ana-frame ana-full">
            <div class="ana-lbl">Threat Score Over Time (per IP)</div>
            <iframe class="ana-iframe" data-panel="5" src="http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics?orgId=1&panelId=5&from=now-7d&to=now&refresh=30s&theme=dark" height="230"></iframe>
          </div>
          <div class="ana-frame ana-full">
            <div class="ana-lbl">NPU Anomaly Score Over Time</div>
            <iframe class="ana-iframe" data-panel="6" src="http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics?orgId=1&panelId=6&from=now-7d&to=now&refresh=30s&theme=dark" height="230"></iframe>
          </div>
          <div class="ana-frame">
            <div class="ana-lbl">Alert Rate (detections/min)</div>
            <iframe class="ana-iframe" data-panel="7" src="http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics?orgId=1&panelId=7&from=now-7d&to=now&refresh=30s&theme=dark" height="230"></iframe>
          </div>
          <div class="ana-frame">
            <div class="ana-lbl">Action Breakdown</div>
            <iframe class="ana-iframe" data-panel="8" src="http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics?orgId=1&panelId=8&from=now-7d&to=now&refresh=30s&theme=dark" height="230"></iframe>
          </div>
          <div class="ana-frame">
            <div class="ana-lbl">NPU Score Distribution</div>
            <iframe class="ana-iframe" data-panel="9" src="http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics?orgId=1&panelId=9&from=now-7d&to=now&refresh=30s&theme=dark" height="230"></iframe>
          </div>
          <div class="ana-frame">
            <div class="ana-lbl">Recent Threat Decisions</div>
            <iframe class="ana-iframe" data-panel="10" src="http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics?orgId=1&panelId=10&from=now-7d&to=now&refresh=30s&theme=dark" height="230"></iframe>
          </div>
        </div>
      </div>
    </div><!-- /analytics -->

    <!-- ══════════ LOGS ══════════ -->
    <div class="page" id="page-logs">
      <div class="log-tabs">
        <div class="log-tab active" onclick="showLog('pipeline', this)">Pipeline</div>
        <div class="log-tab" onclick="showLog('decisions', this)">Decisions</div>
        <div class="log-tab" onclick="showLog('quarantine', this)">Quarantine</div>
        <div class="log-tab" onclick="showLog('npu', this)">NPU Alerts</div>
        <div class="log-tab" onclick="showLog('attacks', this)">Attacks</div>
      </div>
      <div class="log-body" id="log-pipeline">
        {% for line in logs.pipeline %}<div class="log-line">{{ line }}</div>{% endfor %}
        {% if not logs.pipeline %}<div class="log-line" style="color:var(--dim)">(empty)</div>{% endif %}
      </div>
      <div class="log-body log-hidden" id="log-decisions">
        {% for e in logs.decisions %}<div class="log-line"><span class="log-ts">{{ e.time }}</span>&nbsp;&nbsp;{% if e.action=='QUARANTINE' %}<span class="log-q">{{ e.action }}</span>{% elif e.action=='ALERT' %}<span class="log-a">{{ e.action }}</span>{% else %}<span class="log-ok">{{ e.action }}</span>{% endif %}&nbsp;&nbsp;<span class="log-ip">{{ e.ip }}</span>&nbsp;&nbsp;score=<span class="log-num">{{ e.score }}</span>&nbsp;&nbsp;alerts={{ e.alert_count }}</div>{% endfor %}
        {% if not logs.decisions %}<div class="log-line" style="color:var(--dim)">(empty)</div>{% endif %}
      </div>
      <div class="log-body log-hidden" id="log-quarantine">
        {% for line in logs.quarantine %}<div class="log-line"><span class="log-q">{{ line }}</span></div>{% endfor %}
        {% if not logs.quarantine %}<div class="log-line" style="color:var(--dim)">(empty)</div>{% endif %}
      </div>
      <div class="log-body log-hidden" id="log-npu">
        {% for e in logs.npu %}<div class="log-line"><span class="log-ts">{{ e.time }}</span>&nbsp;&nbsp;<span class="log-ip">{{ e.src_ip }}:{{ e.src_port }}</span> → <span class="log-ip">{{ e.dst_ip }}:{{ e.dst_port }}</span>&nbsp;&nbsp;score=<span class="log-num">{{ e.score }}</span></div>{% endfor %}
        {% if not logs.npu %}<div class="log-line" style="color:var(--dim)">(empty)</div>{% endif %}
      </div>
      <div class="log-body log-hidden" id="log-attacks">
        <div id="log-attacks-content" style="color:var(--dim)">(no attacks run yet)</div>
      </div>
    </div><!-- /logs -->

    <!-- ══════════ SYSTEM ══════════ -->
    <div class="page" id="page-system">
      <div class="page-hdr">
        <div class="page-title">System Resources</div>
        <div class="page-meta" id="sys-updated">—</div>
      </div>
      <div class="sys-inner">

        <!-- Row 1: CPU overall + NPU -->
        <div class="sys-row">
          <div class="sys-card">
            <div class="sys-card-hd">CPU Overall</div>
            <div class="sys-big-val c-cyan" id="cpu-total">—</div>
            <div class="sys-bar-wrap">
              <div class="sys-bar" id="cpu-bar" style="width:0%;background:var(--cyan)"></div>
            </div>
            <div class="sys-bar-label">utilization <span id="cpu-cores-lbl">8 cores</span></div>
          </div>
          <div class="sys-card">
            <div class="sys-card-hd">NPU Load <div class="sys-badge" id="npu-state-badge">—</div></div>
            <div class="sys-big-val c-neon" id="npu-total">—</div>
            <div class="sys-bar-wrap">
              <div class="sys-bar" id="npu-bar" style="width:0%;background:var(--neon)"></div>
            </div>
            <div class="sys-bar-label">avg utilization <span>RK3588S NPU · 3 cores</span></div>
            <div style="margin-top:10px">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                <span style="width:48px;font-size:13px;color:var(--dim)">Core 0</span>
                <div class="sys-bar-wrap" style="flex:1"><div class="sys-bar" id="npu-bar-c0" style="width:0%;background:var(--neon)"></div></div>
                <span style="width:36px;text-align:right;font-size:13px" id="npu-c0">0%</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                <span style="width:48px;font-size:13px;color:var(--dim)">Core 1</span>
                <div class="sys-bar-wrap" style="flex:1"><div class="sys-bar" id="npu-bar-c1" style="width:0%;background:var(--neon)"></div></div>
                <span style="width:36px;text-align:right;font-size:13px" id="npu-c1">0%</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px">
                <span style="width:48px;font-size:13px;color:var(--dim)">Core 2</span>
                <div class="sys-bar-wrap" style="flex:1"><div class="sys-bar" id="npu-bar-c2" style="width:0%;background:var(--neon)"></div></div>
                <span style="width:36px;text-align:right;font-size:13px" id="npu-c2">0%</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Row 2: CPU per-core -->
        <div class="sys-card">
          <div class="sys-card-hd">CPU Per Core</div>
          <div class="core-grid" id="core-grid">
            <!-- filled by JS -->
          </div>
        </div>

        <!-- Row 3: Memory -->
        <div class="sys-card">
          <div class="sys-card-hd">Memory</div>
          <div class="sys-bar-label">used <span id="mem-label">— / —</span></div>
          <div class="sys-bar-wrap" style="height:10px;margin-bottom:10px">
            <div class="sys-bar" id="mem-bar" style="width:0%;background:var(--amber)"></div>
          </div>
          <div class="sys-bar-label">available <span id="mem-avail">—</span></div>
        </div>

      </div>
    </div><!-- /system -->

  </div><!-- /main -->
</div><!-- /layout -->

<script>
// Clock
function tick() {
  var n = new Date();
  document.getElementById('clock').textContent = n.toLocaleString('sv-SE', {timeZone:'Asia/Seoul'}).replace('T',' ') + ' KST';
}
setInterval(tick, 1000); tick();

// Navigation
function nav(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  el.classList.add('active');
  if (page === 'logs') showLog('pipeline', document.querySelector('.log-tab'));
}

// Attack controls
function startAttack(id) {
  fetch('/api/attack/start/' + id, {method:'POST'})
    .then(r => r.json())
    .then(d => { if (d.error) alert(d.error); else updateStatus(); });
}
function stopAttack(id) {
  fetch('/api/attack/stop/' + id, {method:'POST'}).then(() => updateStatus());
}
function stopAllAttacks() {
  fetch('/api/attack/stop_all', {method:'POST'}).then(() => updateStatus());
}
function updateStatus() {
  fetch('/api/attack/status')
    .then(r => r.json())
    .then(data => {
      Object.keys(data).forEach(id => {
        var card = document.getElementById('card-' + id);
        if (!card) return;
        if (data[id].running) card.classList.add('running');
        else card.classList.remove('running');
      });
    });
}

// Log tabs
var attackLogTimer = null;
function showLog(name, el) {
  document.querySelectorAll('.log-body').forEach(p => p.classList.add('log-hidden'));
  document.querySelectorAll('.log-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('log-' + name).classList.remove('log-hidden');
  if (el) el.classList.add('active');
  clearInterval(attackLogTimer);
  if (name === 'attacks') {
    refreshAttackLog();
    attackLogTimer = setInterval(refreshAttackLog, 2000);
  }
}
function refreshAttackLog() {
  fetch('/api/attack/log').then(r => r.json()).then(data => {
    var el = document.getElementById('log-attacks-content');
    if (!data.lines.length) {
      el.style.color = 'var(--dim)';
      el.textContent = '(no attacks run yet)';
    } else {
      el.style.color = '';
      el.innerHTML = data.lines.map(l => {
        var cls = '';
        if (l.startsWith('─'))           cls = 'log-sep';
        else if (l.includes('finished')) cls = 'log-ok';
        else if (l.includes('started'))  cls = 'log-a';
        else if (/error/i.test(l))       cls = 'log-q';
        return '<div class="log-line">' + (cls ? '<span class="'+cls+'">'+esc(l)+'</span>' : esc(l)) + '</div>';
      }).join('');
      document.getElementById('log-attacks').scrollTop = 99999;
    }
  });
}
function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

setInterval(updateStatus, 3000);
updateStatus();

function refreshStats() {
  fetch('/api/status')
    .then(r => r.json())
    .then(d => {
      var total = d.total_alerts !== undefined ? d.total_alerts : d.total_decisions;
      var npu   = d.npu_alerts  !== undefined ? d.npu_alerts  : 0;
      var suri  = d.suricata_alerts !== undefined ? d.suricata_alerts : 0;
      var quar  = d.quarantined_count !== undefined ? d.quarantined_count : (d.quarantined || []).length;
      document.getElementById('stat-total').textContent    = total;
      document.getElementById('stat-bg-total').textContent = total;
      document.getElementById('stat-npu').textContent      = npu;
      document.getElementById('stat-bg-npu').textContent   = npu;
      document.getElementById('stat-suri').textContent     = suri;
      document.getElementById('stat-bg-suri').textContent  = suri;
      document.getElementById('stat-quar').textContent     = quar;
      document.getElementById('stat-bg-quar').textContent  = quar;
    });
}
setInterval(refreshStats, 5000);
refreshStats();

// System metrics
var sysTimer = null;
function refreshSystem() {
  fetch('/api/system')
    .then(r => r.json())
    .then(d => {
      // CPU overall
      var cpu = d.cpu_percent.toFixed(1);
      document.getElementById('cpu-total').textContent = cpu + '%';
      document.getElementById('cpu-bar').style.width = cpu + '%';

      // CPU per-core
      var grid = document.getElementById('core-grid');
      var procs = d.cpu_core_procs || {};
      grid.innerHTML = d.cpu_per_core.map(function(v, i) {
        var col = v > 80 ? 'var(--red)' : v > 50 ? 'var(--amber)' : 'var(--cyan)';
        var plist = (procs[i] || []).slice(0, 2);
        var procHtml = plist.length
          ? plist.map(function(p) {
              return '<div class="core-proc">' +
                '<span class="core-proc-name">' + esc(p.name) + '</span>' +
                (p.cpu > 0 ? '<span class="core-proc-cpu">' + p.cpu + '%</span>' : '') +
                '</div>';
            }).join('')
          : '<div class="core-proc"><span class="core-proc-name core-proc-idle">idle</span></div>';
        return '<div class="core-item">' +
          '<div class="core-label">Core ' + i + ' <span>' + v.toFixed(0) + '%</span></div>' +
          '<div class="core-bar-wrap"><div class="core-bar" style="width:' + v + '%;background:' + col + '"></div></div>' +
          '<div class="core-procs">' + procHtml + '</div>' +
          '</div>';
      }).join('');

      // NPU — real utilization from /sys/kernel/debug/rknpu/load
      var npu_avg = d.npu_avg || 0;
      var npu_cores = d.npu_cores || [0, 0, 0];
      document.getElementById('npu-total').textContent = npu_avg + '%';
      document.getElementById('npu-bar').style.width = npu_avg + '%';
      var state = npu_avg > 50 ? 'active' : npu_avg > 0 ? 'partial' : 'idle';
      document.getElementById('npu-state-badge').textContent = state;
      [0,1,2].forEach(function(i) {
        var pct = npu_cores[i] || 0;
        document.getElementById('npu-c'+i).textContent = pct + '%';
        document.getElementById('npu-bar-c'+i).style.width = pct + '%';
      });

      // Memory
      var mem = d.memory;
      document.getElementById('mem-label').textContent =
        mem.used_mb + ' MB / ' + mem.total_mb + ' MB (' + mem.percent + '%)';
      document.getElementById('mem-avail').textContent = mem.available_mb + ' MB free';
      document.getElementById('mem-bar').style.width = mem.percent + '%';

      // Timestamp
      document.getElementById('sys-updated').textContent =
        'updated ' + new Date().toLocaleString('sv-SE', {timeZone:'Asia/Seoul'}).slice(11,19) + ' KST';
    });
}

// Auto-poll system when on system page
var _activePage = 'overview';
var _origNav = nav;
nav = function(page, el) {
  _origNav(page, el);
  _activePage = page;
  clearInterval(sysTimer);
  if (page === 'system') {
    refreshSystem();
    sysTimer = setInterval(refreshSystem, 2000);
  }
};

function setAnaRange(from, label, btn) {
  const base = 'http://192.168.3.64:3000/d-solo/914a78ae-8b95-4b1d-ad7c-3726af0d1089/iot-security-gateway-analytics';
  document.querySelectorAll('.ana-range-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('ana-meta').textContent = 'Grafana · ' + label + ' · refresh 30s';
  document.querySelectorAll('.ana-iframe').forEach(iframe => {
    const pid = iframe.dataset.panel;
    iframe.src = base + '?orgId=1&panelId=' + pid + '&from=' + from + '&to=now&refresh=30s&theme=dark';
  });
}
</script>
</body>
</html>
"""


def read_decisions(limit=20):
    path = f"{LOG_DIR}/decisions.jsonl"
    if not os.path.exists(path):
        return []
    alerts = []
    with open(path) as f:
        for line in f:
            try:
                alerts.append(json.loads(line.strip()))
            except:
                continue
    return alerts[-limit:]

def read_npu_alerts(limit=20):
    path = f"{LOG_DIR}/npu_alerts.jsonl"
    if not os.path.exists(path):
        return []
    alerts = []
    with open(path) as f:
        for line in f:
            try:
                alerts.append(json.loads(line.strip()))
            except:
                continue
    return alerts[-limit:]

def read_log_file(filename, limit=50):
    path = f"{LOG_DIR}/{filename}"
    if not os.path.exists(path):
        return []
    with open(path) as f:
        lines = f.readlines()
    return [line.rstrip() for line in lines[-limit:]]

def read_logs_for_dashboard():
    pipeline = read_log_file("pipeline.log", 50)

    decisions_raw = read_decisions(50)
    decisions = []
    for d in decisions_raw:
        decisions.append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(d.get("timestamp", 0))),
            "ip": d.get("ip", "?"),
            "action": d.get("action", "LOG"),
            "score": f"{d.get('score', 0):.0f}",
            "alert_count": d.get("alert_count", 0),
        })

    quarantine = read_log_file("quarantine.log", 50)

    npu_raw = read_npu_alerts(50)
    npu = []
    for a in npu_raw:
        npu.append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a.get("timestamp", 0))),
            "src_ip": a.get("src_ip", "?"),
            "dst_ip": a.get("dst_ip", "?"),
            "src_port": a.get("src_port", 0),
            "dst_port": a.get("dst_port", 0),
            "score": f"{a.get('score', 0):.6f}",
        })

    return {
        "pipeline": pipeline,
        "decisions": decisions,
        "quarantine": quarantine,
        "npu": npu,
    }

@app.route('/')
def dashboard():
    decisions = read_decisions(50)
    npu = read_npu_alerts(50)

    # Count Suricata alerts from eve.json
    eve_path = "/var/log/suricata/eve.json"
    suricata_count = 0
    try:
        import subprocess
        result = subprocess.run(["grep", "-c", '"event_type":"alert"', eve_path],
                                capture_output=True, text=True, timeout=5)
        suricata_count = int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception:
        pass
    npu_count = len(npu)
    quarantined = [d for d in decisions if d.get("action") == "QUARANTINE"]

    seen = set()
    unique_q = []
    for q in reversed(quarantined):
        if q["ip"] not in seen:
            seen.add(q["ip"])
            unique_q.append(q)

    stats = {
        "total_alerts": len(decisions) + npu_count,
        "quarantined": len(unique_q),
        "suricata_alerts": suricata_count,
        "npu_alerts": npu_count,
    }

    formatted_alerts = []
    for d in reversed(decisions[-20:]):
        formatted_alerts.append({
            "time": time.strftime('%H:%M:%S', time.localtime(d.get("timestamp", 0))),
            "ip": d.get("ip", "?"),
            "source": "combined",
            "severity": 1 if d.get("action") == "QUARANTINE" else 2,
            "score": f"{d.get('score', 0):.0f}",
            "action": d.get("action", "LOG"),
        })

    quarantined_list = [{"ip": q["ip"], "score": f"{q.get('score',0):.0f}"} for q in unique_q]
    logs = read_logs_for_dashboard()

    return render_template_string(DASHBOARD_HTML,
                                  stats=stats,
                                  alerts=formatted_alerts[:15],
                                  quarantined=quarantined_list,
                                  logs=logs,
                                  target_ip=TARGET_IP)

# ── Attack API ────────────────────────────────────────────────────────────────

@app.route('/api/attack/start/<attack_id>', methods=['POST'])
def attack_start(attack_id):
    if attack_id not in ATTACKS:
        return jsonify({"error": "Unknown attack"}), 400

    with _lock:
        if attack_id in _procs and _procs[attack_id].poll() is None:
            _procs[attack_id].terminate()

        atk = ATTACKS[attack_id]
        _output[attack_id] = deque(maxlen=200)
        proc = subprocess.Popen(
            atk["cmd"], shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=os.path.expanduser("~/iot-gateway"),
            env=dict(os.environ, PYTHONUNBUFFERED='1')
        )
        _procs[attack_id] = proc

        t = threading.Thread(target=_read_proc_output, args=(attack_id, proc), daemon=True)
        t.start()

    return jsonify({"ok": True, "label": f"{atk['icon']} {atk['label']} ({atk['sub']})"})

@app.route('/api/attack/stop/<attack_id>', methods=['POST'])
def attack_stop(attack_id):
    with _lock:
        proc = _procs.get(attack_id)
        if proc and proc.poll() is None:
            proc.terminate()
    return jsonify({"ok": True})

@app.route('/api/attack/stop_all', methods=['POST'])
def attack_stop_all():
    with _lock:
        for proc in _procs.values():
            if proc and proc.poll() is None:
                proc.terminate()
    return jsonify({"ok": True})

@app.route('/api/attack/status')
def attack_status():
    with _lock:
        return jsonify({
            aid: {"running": proc.poll() is None}
            for aid, proc in _procs.items()
        })

@app.route('/api/attack/output/<attack_id>')
def attack_output(attack_id):
    with _lock:
        proc = _procs.get(attack_id)
        lines = list(_output.get(attack_id, []))
        running = proc is not None and proc.poll() is None
    return jsonify({"lines": lines, "running": running})

@app.route('/api/attack/log')
def attack_log():
    with _lock:
        lines = list(_attack_log)
    return jsonify({"lines": lines})

# ── Existing API ──────────────────────────────────────────────────────────────

def count_jsonl_lines(filename):
    path = f"{LOG_DIR}/{filename}"
    if not os.path.exists(path):
        return 0
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except:
        return 0

@app.route('/api/status')
def api_status():
    decisions = read_decisions(200)
    quarantined = list(dict.fromkeys(
        d["ip"] for d in decisions if d.get("action") == "QUARANTINE"
    ))
    total_decisions = count_jsonl_lines("decisions.jsonl")
    total_npu = count_jsonl_lines("npu_alerts.jsonl")
    # Count Suricata alerts from eve.json
    eve_path = "/var/log/suricata/eve.json"
    suricata_count = 0
    try:
        import subprocess
        result = subprocess.run(["grep", "-c", '"event_type":"alert"', eve_path],
                                capture_output=True, text=True, timeout=5)
        suricata_count = int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception:
        pass
    return jsonify({
        "status": "running",
        "total_decisions": total_decisions,
        "quarantined": quarantined,
        "total_alerts": total_decisions + total_npu,
        "npu_alerts": total_npu,
        "suricata_alerts": suricata_count,
        "quarantined_count": len(quarantined),
    })

@app.route('/api/alerts')
def api_alerts():
    return jsonify(read_decisions(50))

@app.route('/api/system')
def api_system():
    # CPU
    cpu_total = psutil.cpu_percent(interval=0.5)
    cpu_cores = psutil.cpu_percent(interval=None, percpu=True)

    # Per-core process map using cpu_affinity().
    # Processes pinned to [4,5] appear under both core 4 and core 5.
    # System daemons pinned to all cores with 0% cpu are filtered out.
    n_cores = len(cpu_cores)
    core_procs = {i: [] for i in range(n_cores)}
    try:
        for p in psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent']):
            try:
                info = p.info
                if (info['pid'] or 0) <= 2 or (info['ppid'] or 0) == 2:
                    continue
                name = info['name'] or '?'
                if name in ('python3', 'python', 'python3.10'):
                    try:
                        cmd = p.cmdline()
                        script = next((os.path.basename(a) for a in cmd[1:] if a.endswith('.py')), None)
                        if script:
                            name = script.replace('.py', '')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                affinity = p.cpu_affinity()
                cpu_pct = round(info.get('cpu_percent') or 0, 1)
                pinned_all = len(affinity) == n_cores
                entry = {'name': name[:22], 'pid': info['pid'], 'cpu': cpu_pct, '_all': pinned_all}
                for core in affinity:
                    if core in core_procs:
                        core_procs[core].append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for i in core_procs:
            seen = set()
            pinned, system_wide = [], []
            for e in sorted(core_procs[i], key=lambda x: -x['cpu']):
                if e['pid'] in seen:
                    continue
                seen.add(e['pid'])
                out = {'name': e['name'], 'pid': e['pid'], 'cpu': e['cpu']}
                if e['_all']:
                    # System-wide daemon — only include if meaningfully busy
                    if e['cpu'] >= 2.0:
                        system_wide.append(out)
                else:
                    pinned.append(out)
            # Pinned processes take priority; fill remaining slots with busy system-wide ones
            combined = pinned + system_wide
            core_procs[i] = combined[:3]
    except Exception:
        pass

    # Memory
    mem = psutil.virtual_memory()

    # NPU real utilization from RKNPU kernel debug interface
    # /sys/kernel/debug/rknpu/load → "NPU load:  Core0:  45%, Core1:  30%, Core2:  12%,"
    npu_cores = [0, 0, 0]
    try:
        import subprocess
        raw = subprocess.check_output(['sudo', '-n', 'cat', '/sys/kernel/debug/rknpu/load'],
                                      stderr=subprocess.DEVNULL).decode()
        pcts = re.findall(r'Core\d+:\s*(\d+)%', raw)
        npu_cores = [int(p) for p in pcts[:3]]
    except Exception:
        pass
    npu_avg = round(sum(npu_cores) / len(npu_cores)) if npu_cores else 0

    return jsonify({
        'cpu_percent': cpu_total,
        'cpu_per_core': cpu_cores,
        'cpu_core_procs': core_procs,
        'npu_cores': npu_cores,
        'npu_avg': npu_avg,
        'memory': {
            'percent': round(mem.percent, 1),
            'total_mb': mem.total // 1024 // 1024,
            'used_mb': (mem.total - mem.available) // 1024 // 1024,
            'available_mb': mem.available // 1024 // 1024,
        },
    })

if __name__ == '__main__':
    print("Dashboard: http://192.168.3.64:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
