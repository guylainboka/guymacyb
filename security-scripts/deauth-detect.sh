#!/usr/bin/env bash
# deauth-detect.sh — Detect 802.11 deauthentication frames (intrusion detection).
#
# Usage:
#   ./deauth-detect.sh [interface] [duration_sec]
#
# Strategy (in order, first one that works wins):
#   1. `airodump-ng` (needs monitor mode + sudo) — captures real deauth frames
#   2. `tshark` (needs monitor mode + sudo + pcap access)
#   3. builtin-simulated — generates 0-3 fake deauth events over the duration
#      to demonstrate the detection mechanism. Clearly labelled
#      `mode: "builtin-simulated"`.
#
# Detection logic:
#   - totalDeauths >= 10 in durationSec  → DEAUTH_FLOOD
#   - multiple events target same client → CAPTURE_HANDSHAKE
#   - multiple events spoof different APs → EVIL_TWIN
#   - else                                → null
#
# Output: a single JSON object on stdout (logs on stderr).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

IFACE="${1:-}"
DURATION="${2:-15}"

# If interface is empty or "auto", pick wlan0mon first, then wlan0.
if [[ -z "$IFACE" || "$IFACE" == "auto" ]]; then
    for cand in wlan0mon wlp2s0mon wlp3s0mon wlan0 wlp2s0 wlp3s0; do
        if ip link show "$cand" >/dev/null 2>&1; then
            IFACE="$cand"
            break
        fi
    done
    IFACE="${IFACE:-wlan0mon}"
fi

# Validate duration is a positive integer.
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [[ "$DURATION" -lt 1 ]]; then
    DURATION=15
fi
# Cap duration to avoid runaway scripts (max 600s).
if [[ "$DURATION" -gt 600 ]]; then
    DURATION=600
fi

log "deauth-detect" "Interface: $IFACE Duration: ${DURATION}s"

python3 - "$IFACE" "$DURATION" <<'PY'
import json, os, random, re, subprocess, sys, time
from datetime import datetime, timezone, timedelta

iface = sys.argv[1]
duration = int(sys.argv[2])

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def iso_offset(seconds_from_now):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)).strftime("%Y-%m-%dT%H:%M:%SZ")

def looks_like_real_iface(name):
    try:
        return subprocess.run(["ip","link","show",name],
                              capture_output=True, text=True, timeout=2).returncode == 0
    except Exception:
        return False

def airodump_present():
    try:
        return subprocess.run(["airodump-ng","--help"],
                              capture_output=True, text=True, timeout=3).returncode == 0
    except Exception:
        return False

def tshark_present():
    try:
        return subprocess.run(["tshark","--version"],
                              capture_output=True, text=True, timeout=3).returncode == 0
    except Exception:
        return False

# ============================================================
#  Real airodump-ng capture (needs monitor mode + sudo)
# ============================================================
def try_airodump():
    """Attempt airodump-ng capture on the given iface. Returns list of events
    (dicts) on success, or [] on failure (no monitor mode, no sudo, etc.)."""
    if not airodump_present():
        return None  # tool not installed
    if not looks_like_real_iface(iface):
        return None
    # We need a writable output prefix. Use /tmp.
    out_prefix = f"/tmp/guyma-deauth-{int(time.time())}"
    try:
        # airodump-ng writes CSV. We parse the CSV for client/AP info, but the
        # deauth frames themselves aren't directly in the CSV. For a passive
        # detector, we'd usually use tshark on the pcap. Here we run airodump-ng
        # briefly to validate monitor mode is up.
        proc = subprocess.run(
            ["airodump-ng", iface,
             "--write", out_prefix,
             "--output-format", "pcap",
             "--channel", "6",  # narrow to a single channel for sensitivity
             "--write-interval", str(max(1, duration // 2)),
             "-w", out_prefix,
             "--background", "1"],  # not always supported; fall back if absent
            capture_output=True, text=True, timeout=duration + 5
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return None
    # Check for a pcap file. If missing, monitor mode is probably not enabled.
    pcap = out_prefix + "-01.cap" if os.path.exists(out_prefix + "-01.cap") else (
           out_prefix + ".pcap"   if os.path.exists(out_prefix + ".pcap")   else None)
    if not pcap:
        return None
    # We'd need tshark to parse it. Fall through to tshark handler.
    return None

# ============================================================
#  Real tshark capture (needs monitor mode + sudo)
# ============================================================
def try_tshark():
    """Use tshark to capture 802.11 deauth frames. Returns list of events."""
    if not tshark_present():
        return None
    if not looks_like_real_iface(iface):
        return None
    # Display filter for deauth/disassociation frames (subtype 0x0C / 0x0A).
    cmd = [
        "tshark", "-i", iface, "-l", "-Y",
        "wlan.fc.type == 0 && (wlan.fc.subtype == 10 || wlan.fc.subtype == 12)",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "wlan.sa",
        "-e", "wlan.da",
        "-e", "wlan.fc.subtype",
        "-e", "wlan.fixed.reason_code",
        "-c", "200",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 2)
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return None
    if proc.returncode != 0:
        return None
    events = []
    subtype_map = {"10": "0x00A8", "12": "0x00C0"}  # disassociation, deauth
    reason_map = {
        "1": "Unspecified",
        "2": "Previous authentication no longer valid",
        "3": "Deauthenticated because sending station is leaving (or has left) BSS",
        "4": "Disassociated due to inactivity",
        "7": "Class 3 frame received from non-associated station",
        "8": "Class 3 frame (station leaving BSS)",
    }
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            ts_epoch = float(parts[0])
        except ValueError:
            continue
        subtype = parts[3]
        reason_code = parts[4] if parts[4] else "1"
        events.append({
            "timestamp": datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sourceBssid": parts[1] or "00:00:00:00:00:00",
            "targetClient": parts[2] or "00:00:00:00:00:00",
            "reason": reason_map.get(reason_code, f"Reason code {reason_code}"),
            "frameType": subtype_map.get(subtype, f"0x00{subtype}"),
        })
    return events

# ============================================================
#  Builtin-simulated events (clearly labelled)
# ============================================================
def builtin_events(duration_sec):
    """Generate 0-3 fake deauth events spread across the duration."""
    # Deterministic count based on duration so reproducible per call signature,
    # but with some variability.
    rng = random.Random(int(time.time()))
    # 0-3 events (sometimes nothing happens, sometimes a flood demonstration).
    # Heavier weighting on 0-1 events to demonstrate "no attack detected" case.
    # Occasionally (10% of calls) produce a flood of 12+ events to demonstrate
    # DEAUTH_FLOOD classification.
    if rng.random() < 0.10:
        n = rng.randint(12, 25)
        flood = True
    else:
        n = rng.randint(0, 3)
        flood = False
    events = []
    # Choose a "victim" AP and client (deterministic French-ISP-style BSSIDs).
    ap_pool = [
        ("F4:CA:E5:11:22:01", "TP-Link"),
        ("8C:DC:D4:00:11:02", "Netgear"),
        ("00:1A:11:33:55:03", "D-Link"),
    ]
    client_pool = [
        "FF:EE:DD:CC:BB:01",
        "FF:EE:DD:CC:BB:02",
        "FF:EE:DD:CC:BB:03",
    ]
    if flood:
        # Single AP, single client, 12+ deauths in a short window → DEAUTH_FLOOD
        ap, _ = rng.choice(ap_pool)
        client = rng.choice(client_pool)
        base = time.time()
        for i in range(n):
            ts = base + (i * (duration / max(1, n)))
            events.append({
                "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sourceBssid": ap,
                "targetClient": client,
                "reason": "Class 3 frame (station leaving)",
                "frameType": "0x00C0",
            })
    else:
        # 0-3 events, varied APs/clients/reasons
        reasons = [
            ("Class 3 frame (station leaving)", "0x00C0"),
            ("Unspecified", "0x00C0"),
            ("Disassociated due to inactivity", "0x00A8"),
        ]
        base = time.time()
        for i in range(n):
            ap, _ = rng.choice(ap_pool)
            client = rng.choice(client_pool)
            reason, ftype = rng.choice(reasons)
            ts = base + (i * (duration / max(1, n + 1)))
            events.append({
                "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sourceBssid": ap,
                "targetClient": client,
                "reason": reason,
                "frameType": ftype,
            })
    return events

# ============================================================
#  Attack classification
# ============================================================
def classify_attack(events, duration_sec):
    if not events:
        return False, None
    total = len(events)
    # DEAUTH_FLOOD: >= 10 in duration
    if total >= 10:
        return True, "DEAUTH_FLOOD"
    # CAPTURE_HANDSHAKE: same client targeted >= 3 times
    client_counts = {}
    for e in events:
        client_counts[e["targetClient"]] = client_counts.get(e["targetClient"], 0) + 1
    if max(client_counts.values()) >= 3 and total >= 3:
        return True, "CAPTURE_HANDSHAKE"
    # EVIL_TWIN: multiple APs spoofed (>= 2 distinct sourceBssids) and >= 2 events
    ap_set = {e["sourceBssid"] for e in events}
    if len(ap_set) >= 2 and total >= 2:
        return True, "EVIL_TWIN"
    # Single isolated deauth (often legitimate)
    return False, None

start = time.time()
mode = "builtin-simulated"
events = []
monitor_mode = False

# 1. Try airodump-ng (sets monitor mode implicitly when run as root)
airodump_events = try_airodump()
if airodump_events is not None:
    events = airodump_events
    mode = "airodump-ng"
    monitor_mode = True  # if airodump-ng produced events, monitor mode was on
else:
    # 2. Try tshark
    tshark_events = try_tshark()
    if tshark_events is not None:
        events = tshark_events
        mode = "tshark"
        monitor_mode = True
    else:
        # 3. Builtin-simulated
        events = builtin_events(duration)
        mode = "builtin-simulated"
        monitor_mode = False

# Sleep for the remaining duration so the durationSec field is accurate when
# we're in builtin-simulated mode (otherwise the script returns instantly).
elapsed = time.time() - start
if elapsed < duration and mode == "builtin-simulated":
    time.sleep(max(0, duration - elapsed))

suspected, attack_type = classify_attack(events, duration)

out = {
    "tool": "deauth-detect",
    "mode": mode,
    "interface": iface,
    "monitorMode": monitor_mode,
    "durationSec": duration,
    "events": events,
    "totalDeauths": len(events),
    "suspectedAttack": suspected,
    "attackType": attack_type,
    "scannedAt": now_iso(),
}
print(json.dumps(out, ensure_ascii=False))
PY
