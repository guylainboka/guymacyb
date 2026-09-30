#!/usr/bin/env bash
# deauth-detect.sh — Detect 802.11 deauthentication frames (intrusion detection).
#
# Usage:
#   ./deauth-detect.sh [interface] [duration_sec]
#
# Strategy (in order, first one that works wins):
#   1. `airodump-ng` (needs monitor mode + sudo) — captures real deauth frames
#   2. `tshark` (needs monitor mode + sudo + pcap access)
#   3. Aucun backend disponible — état honnête (PAS de données inventées) :
#      mode "monitor-mode-required" + events:[] + totalDeauths:0
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
import json, os, re, subprocess, sys, time
from datetime import datetime, timezone

iface = sys.argv[1]
duration = int(sys.argv[2])

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def has_wireless_hardware():
    """Return True if a /sys/class/net/*/wireless interface exists."""
    try:
        for dev in os.listdir("/sys/class/net"):
            if os.path.isdir(f"/sys/class/net/{dev}/wireless"):
                return True
    except Exception:
        pass
    return False

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
mode = "monitor-mode-required"
events = []
monitor_mode = False
error_msg = None

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
        # 3. Aucun backend disponible — état honnête (PAS de données inventées).
        events = []
        monitor_mode = False
        has_airodump = airodump_present()
        has_tshark = tshark_present()
        has_wifi = has_wireless_hardware()
        if not has_airodump and not has_tshark:
            mode = "tools-not-installed"
            error_msg = ("Détection de deauth indisponible : airodump-ng et tshark ne sont pas installés. "
                         "Installez via WSL (Windows) : apt install aircrack-ng tshark. "
                         "Ces outils analysent les trames 802.11 deauth/disassociation sur une interface en mode monitor. "
                         "GuymaCyb ne génère jamais de données inventées.")
        elif not has_wifi:
            mode = "no-wireless-hardware"
            error_msg = ("Aucun adaptateur sans-fil détecté sur ce système. "
                         "La détection de deauth nécessite une clé WiFi physique en mode monitor + airodump-ng/tshark (root). "
                         "Sur Windows, ces outils tournent via WSL (wsl.exe -d Ubuntu -- airmon-ng start wlan0). "
                         "GuymaCyb ne génère jamais de données inventées.")
        else:
            mode = "monitor-mode-required"
            error_msg = ("Aucune interface en mode monitor détectée. "
                         "Activez le mode monitor en root : airmon-ng start wlan0, puis relancez ce script sur l'interface générée (ex. wlan0mon). "
                         "Sans mode monitor, ni airodump-ng ni tshark ne peuvent capturer les trames deauth 802.11. "
                         "GuymaCyb ne génère jamais de données inventées.")

# No fake sleep — only sleep when real capture tools were running. The real
# airodump-ng/tshark captures already take `duration` seconds; in the honest
# fallback we return immediately so the user knows the truth without delay.

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
if error_msg:
    out["error"] = error_msg
print(json.dumps(out, ensure_ascii=False))
PY
