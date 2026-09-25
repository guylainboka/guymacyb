#!/usr/bin/env bash
# wifi-scan.sh — Scan WiFi networks for Guyma Cyb.
#
# Usage:
#   ./wifi-scan.sh [interface]
#
# Strategy (in order, first one that works wins):
#   1. `iw dev <iface> scan`        (passive/direct, nl80211)
#   2. `iwlist <iface> scan`        (wireless-tools legacy)
#   3. `aircrack-ng` (airmon-ng + airodump-ng)  — NOT typically available here
#   4. builtin-simulated            (realistic French SSIDs, clearly labelled)
#
# The script ALSO tries to parse real `iw`/`iwlist` output even when a real
# WiFi interface is missing (it will just produce no rows). The fallback
# builtin-simulated mode produces 6-8 realistic networks.
#
# Output: a single JSON object on stdout (logs on stderr).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

IFACE="${1:-}"

# Auto-detect a wireless interface if none provided.
detect_iface() {
    if [[ -n "$IFACE" ]]; then
        printf '%s' "$IFACE"
        return 0
    fi
    # /sys/class/net/*/wireless presence is a strong signal for a Wi-Fi iface.
    if [[ -d /sys/class/net ]]; then
        for dev in /sys/class/net/*; do
            [[ -d "${dev}/wireless" ]] || continue
            local name
            name="$(basename "$dev")"
            printf '%s' "$name"
            return 0
        done
    fi
    # Fallback: try common names in order.
    for cand in wlan0 wlp2s0 wlp3s0 wlp4s0 wlan1; do
        if ip link show "$cand" >/dev/null 2>&1; then
            printf '%s' "$cand"
            return 0
        fi
    done
    printf 'wlan0'
}

IFACE="$(detect_iface)"
log "wifi-scan" "Interface: $IFACE"

# Try real backends in order, write JSON to stdout.
python3 - "$IFACE" "$SCRIPT_DIR" <<'PY'
import json, os, re, subprocess, sys, time
from datetime import datetime, timezone

iface = sys.argv[1]
scripts_dir = sys.argv[2]

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def iso_offset(seconds_from_now):
    dt = datetime.now(timezone.utc) - __import__("datetime").timedelta(seconds=seconds_from_now)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

# ---- OUI lookup (small embedded table of common vendors) ----
OUI_PREFIXES = {
    "00:11:22": "Cisco",
    "00:1A:11": "D-Link",
    "00:24:B2": "Apple",
    "14:EB:B6": "Asus",
    "8C:DC:D4": "Netgear",
    "F4:CA:E5": "TP-Link",
    "EC:08:6B": "TP-Link",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:0C:E6": "Belkin",
    "C0:4A:00": "Netgear",
    "00:1F:33": "D-Link",
    "AC:84:C6": "Huawei",
    "04:F0:21": "Huawei",
    "B0:BE:76": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:32:B1": "D-Link",
    "F8:1A:67": "D-Link",
    "00:19:70": "Zyxel",
    "A4:2B:B0": "Cisco-Meraki",
    "00:50:56": "VMware",
    "00:15:5D": "Hyper-V",
    "C4:04:15": "Aruba",
    "24:A4:3C": "Aruba",
    "00:0B:86": "Aruba",
    "00:1B:54": "Netgear",
}

def lookup_vendor(bssid):
    if not bssid:
        return "Unknown"
    prefix = bssid.upper()[:8]
    return OUI_PREFIXES.get(prefix, "Unknown")

def channel_from_freq(freq_mhz):
    """Convert a frequency in MHz to a channel number (2.4 GHz + 5 GHz)."""
    try:
        f = int(freq_mhz)
    except (ValueError, TypeError):
        return 0
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5160 <= f <= 5885:
        return (f - 5000) // 5
    return 0

def quality_from_dbm(dbm):
    """Map dBm (negative, often -30..-100) to 0-100 quality."""
    try:
        s = int(dbm)
    except (ValueError, TypeError):
        return 0
    if s <= -100:
        return 0
    if s >= -50:
        return 100
    return int(2 * (s + 100))

# ============================================================
#  Parser: `iw dev <iface> scan`
# ============================================================
def parse_iw_scan(text):
    """Parse `iw dev <iface> scan` output. Returns list of network dicts."""
    nets = []
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("BSS ") and ":" in line:
            if cur:
                nets.append(cur)
            bssid = line.split()[1]
            cur = {
                "bssid": bssid, "ssid": "", "channel": 0, "frequency": 0,
                "signalDbm": -80, "quality": 30, "encryption": "UNKNOWN",
                "cipher": "", "authMode": "", "securityFlags": [],
                "vendor": lookup_vendor(bssid), "isHidden": True,
                "clients": 0, "firstSeen": now_iso(), "lastSeen": now_iso(),
            }
            continue
        if cur is None:
            continue
        if line.startswith("freq:"):
            try:
                cur["frequency"] = int(line.split(":",1)[1].strip())
                cur["channel"] = channel_from_freq(cur["frequency"])
            except ValueError:
                pass
        elif line.startswith("signal:"):
            try:
                v = line.split(":",1)[1].strip().split()[0]
                cur["signalDbm"] = int(v)
                cur["quality"] = quality_from_dbm(v)
            except (ValueError, IndexError):
                pass
        elif line.startswith("SSID:"):
            cur["ssid"] = line.split(":",1)[1].strip()
            cur["isHidden"] = (cur["ssid"] == "" or cur["ssid"].lower() == "\\x00")
        elif "capability:" in line.lower():
            # e.g. "capability: ESS Privacy ShortPreamble ShortSlotTime"
            cap = line.lower()
            if "privacy" in cap:
                # Some encryption present; refined by RSN/WPA blocks below
                if cur["encryption"] == "UNKNOWN":
                    cur["encryption"] = "WPA2"  # default if RSN present later
        elif line.startswith("* station count:"):
            try:
                cur["clients"] = int(line.split(":",1)[1].strip())
            except ValueError:
                pass
        # RSN block — WPA2/3
        # Lines look like: "* WPA:     * Group cipher: CCMP     * Pairwise ciphers: CCMP     * Authentication suites: PSK"
        # and similarly for RSN. We keep a small state machine.
    if cur:
        nets.append(cur)
    # Second pass for encryption: re-scan the text per-BSS is complex; do a heuristic on whole block instead.
    # Simpler: scan groups of RSN: blocks.
    blocks = re.split(r"^BSS\s+([0-9A-Fa-f:]{17})\s+on\s+\S+", text, flags=re.M)
    # blocks[0] = preamble, then pairs (bssid, body)
    for i in range(1, len(blocks)-1, 2):
        bssid = blocks[i].strip()
        body = blocks[i+1]
        for n in nets:
            if n["bssid"].lower() == bssid.lower():
                # Encryption
                if "RSN:" in body:
                    # WPA2 or WPA3
                    if "SAE" in body:
                        n["encryption"] = "WPA3"
                        n["authMode"] = "SAE"
                        if "SAE" not in n["securityFlags"]: n["securityFlags"].append("SAE")
                    elif "WPA2/WPA3" in body or ("WPA-PSK" in body and "SAE" in body):
                        n["encryption"] = "WPA2/WPA3"
                        n["authMode"] = "PSK/SAE"
                    else:
                        n["encryption"] = "WPA2"
                        if "PSK" not in n["authMode"]:
                            n["authMode"] = ("PSK" if "PSK" in body else
                                             ("SAE" if "SAE" in body else "PSK"))
                elif "WPA:" in body:
                    n["encryption"] = "WPA"
                    n["authMode"] = "PSK"
                else:
                    # No RSN/WPA block but privacy was set => WEP (rare today)
                    if n["encryption"] == "UNKNOWN" or n["encryption"] == "WPA2":
                        # If privacy NOT present either, treat as OPEN
                        if "Privacy" in body or "privacy" in body:
                            n["encryption"] = "WEP"
                            n["cipher"] = "WEP-40"
                        else:
                            n["encryption"] = "OPEN"
                            n["authMode"] = ""
                # Cipher
                m = re.search(r"Pairwise ciphers?:\s*(\S+)", body)
                if m:
                    n["cipher"] = m.group(1)
                # PMF flags
                if "BIP-CMAC-128" in body or "MFPR" in body or "MFPREQUIRED" in body.upper():
                    if "PMF_ENABLED" not in n["securityFlags"]: n["securityFlags"].append("PMF_ENABLED")
                elif "MFPC" in body:
                    if "PMF_CAPABLE" not in n["securityFlags"]: n["securityFlags"].append("PMF_CAPABLE")
                # AES-CCMP / TKIP / GCMP tags
                if "CCMP" in (n["cipher"] or body):
                    if "AES-CCMP" not in n["securityFlags"]: n["securityFlags"].append("AES-CCMP")
                if "TKIP" in (n["cipher"] or body):
                    if "TKIP" not in n["securityFlags"]: n["securityFlags"].append("TKIP")
                if "GCMP" in (n["cipher"] or body):
                    if "GCMP" not in n["securityFlags"]: n["securityFlags"].append("GCMP")
                if "EAP" in body:
                    if "EAP" not in n["securityFlags"]: n["securityFlags"].append("EAP")
                if n["authMode"] == "PSK" and "PSK" not in n["securityFlags"]:
                    n["securityFlags"].append("PSK")
                # Hidden
                if n["isHidden"]:
                    if "HIDDEN_SSID" not in n["securityFlags"]:
                        n["securityFlags"].append("HIDDEN_SSID")
                break
    # Filter out empty BSS lines (sometimes iw emits BSS lines for stale entries).
    return [n for n in nets if n["bssid"]]

# ============================================================
#  Parser: `iwlist <iface> scan`
# ============================================================
def parse_iwlist(text):
    nets = []
    # Each cell starts with 'Cell 01 - Address: AA:BB:CC:DD:EE:FF'
    cells = re.split(r"Cell\s+\d+\s+-\s+Address:\s*([0-9A-Fa-f:]{17})", text)
    # cells[0] = preamble, then (bssid, body) pairs
    for i in range(1, len(cells)-1, 2):
        bssid = cells[i].strip()
        body = cells[i+1]
        n = {
            "bssid": bssid, "ssid": "", "channel": 0, "frequency": 0,
            "signalDbm": -80, "quality": 30, "encryption": "OPEN",
            "cipher": "", "authMode": "", "securityFlags": [],
            "vendor": lookup_vendor(bssid), "isHidden": True,
            "clients": 0, "firstSeen": now_iso(), "lastSeen": now_iso(),
        }
        # SSID
        m = re.search(r'ESSID:"([^"]*)"', body)
        if m:
            n["ssid"] = m.group(1)
            n["isHidden"] = (n["ssid"] == "")
        # Channel
        m = re.search(r"Channel[=: ]+(\d+)", body)
        if m:
            n["channel"] = int(m.group(1))
            # Approximate frequency from channel
            if n["channel"] == 14:
                n["frequency"] = 2484
            elif 1 <= n["channel"] <= 13:
                n["frequency"] = 2407 + 5*n["channel"]
            elif 36 <= n["channel"] <= 173:
                n["frequency"] = 5000 + 5*n["channel"]
        # Quality + signal
        m = re.search(r"Quality[=: ]+(\d+)/(\d+)\s+Signal level[=: ]+(-?\d+)\s*dBm", body)
        if m:
            try:
                q_num, q_den = int(m.group(1)), int(m.group(2))
                n["quality"] = int(100 * q_num / q_den) if q_den else 0
                n["signalDbm"] = int(m.group(3))
            except (ValueError, ZeroDivisionError):
                pass
        else:
            m = re.search(r"Signal level[=: ]+(-?\d+)\s*dBm", body)
            if m:
                n["signalDbm"] = int(m.group(1))
                n["quality"] = quality_from_dbm(n["signalDbm"])
        # Encryption
        if "Encryption key:on" in body or "Encryption key: on" in body:
            n["encryption"] = "WPA2"  # default, refined below
        else:
            n["encryption"] = "OPEN"
        # IE: IEEE 802.11i/WPA2
        if "IEEE 802.11i/WPA2" in body or "WPA2" in body:
            n["encryption"] = "WPA2"
            n["authMode"] = "PSK"
            n["securityFlags"].append("AES-CCMP")
            n["securityFlags"].append("PSK")
            m = re.search(r"Group Cipher\s*:\s*(\S+)", body)
            if m: n["cipher"] = m.group(1)
        if "WPA3" in body or "SAE" in body:
            n["encryption"] = "WPA3"
            n["authMode"] = "SAE"
            if "SAE" not in n["securityFlags"]: n["securityFlags"].append("SAE")
        if "TKIP" in body:
            if "TKIP" not in n["securityFlags"]: n["securityFlags"].append("TKIP")
            if n["encryption"] == "WPA2": n["cipher"] = "TKIP"
        if "WEP" in body and n["encryption"] not in ("WPA2","WPA3","WPA"):
            n["encryption"] = "WEP"
            n["cipher"] = "WEP-40"
        if n["isHidden"] and "HIDDEN_SSID" not in n["securityFlags"]:
            n["securityFlags"].append("HIDDEN_SSID")
        nets.append(n)
    return nets

# ============================================================
#  Builtin-simulated networks (clearly labelled)
# ============================================================
def builtin_networks():
    """Return 6-8 realistic French WiFi networks."""
    # Realistic OUI prefixes mapped to known vendors so lookup_vendor works.
    base = now_iso()
    return [
        {
            "bssid": "F4:CA:E5:11:22:01", "ssid": "FreeWifi_secure", "channel": 6,
            "frequency": 2437, "signalDbm": -55, "quality": 90,
            "encryption": "WPA2", "cipher": "CCMP", "authMode": "PSK",
            "securityFlags": ["AES-CCMP","PSK","PMF_CAPABLE"],
            "vendor": "TP-Link", "isHidden": False, "clients": 3,
            "firstSeen": iso_offset(120), "lastSeen": base,
        },
        {
            "bssid": "8C:DC:D4:00:11:02", "ssid": "Livebox-AB12", "channel": 11,
            "frequency": 2462, "signalDbm": -62, "quality": 76,
            "encryption": "WPA2", "cipher": "CCMP", "authMode": "PSK",
            "securityFlags": ["AES-CCMP","PSK","WPS_ENABLED"],
            "vendor": "Netgear", "isHidden": False, "clients": 5,
            "firstSeen": iso_offset(180), "lastSeen": base,
        },
        {
            "bssid": "00:1A:11:33:55:03", "ssid": "Bbox-A1B2C3", "channel": 1,
            "frequency": 2412, "signalDbm": -68, "quality": 64,
            "encryption": "WPA2/WPA3", "cipher": "CCMP", "authMode": "PSK/SAE",
            "securityFlags": ["AES-CCMP","PSK","SAE","PMF_ENABLED"],
            "vendor": "D-Link", "isHidden": False, "clients": 2,
            "firstSeen": iso_offset(60), "lastSeen": base,
        },
        {
            "bssid": "00:11:22:7A:8B:04", "ssid": "NETGEAR_5G", "channel": 44,
            "frequency": 5220, "signalDbm": -71, "quality": 58,
            "encryption": "WPA3", "cipher": "GCMP", "authMode": "SAE",
            "securityFlags": ["GCMP","SAE","PMF_ENABLED"],
            "vendor": "Cisco", "isHidden": False, "clients": 1,
            "firstSeen": iso_offset(90), "lastSeen": base,
        },
        {
            "bssid": "14:EB:B6:99:88:05", "ssid": "eduroam", "channel": 36,
            "frequency": 5180, "signalDbm": -75, "quality": 50,
            "encryption": "WPA2", "cipher": "CCMP", "authMode": "802.1X",
            "securityFlags": ["AES-CCMP","EAP","PMF_ENABLED"],
            "vendor": "Asus", "isHidden": False, "clients": 12,
            "firstSeen": iso_offset(300), "lastSeen": base,
        },
        {
            "bssid": "AC:84:C6:AA:BB:06", "ssid": "Guest-WiFi", "channel": 6,
            "frequency": 2437, "signalDbm": -80, "quality": 40,
            "encryption": "OPEN", "cipher": "", "authMode": "",
            "securityFlags": [],
            "vendor": "Huawei", "isHidden": False, "clients": 7,
            "firstSeen": iso_offset(45), "lastSeen": base,
        },
        {
            "bssid": "B8:27:EB:12:34:07", "ssid": "", "channel": 4,
            "frequency": 2427, "signalDbm": -85, "quality": 30,
            "encryption": "WPA", "cipher": "TKIP", "authMode": "PSK",
            "securityFlags": ["TKIP","PSK","HIDDEN_SSID"],
            "vendor": "Raspberry Pi", "isHidden": True, "clients": 0,
            "firstSeen": iso_offset(150), "lastSeen": base,
        },
        {
            "bssid": "00:0C:E6:DE:AD:08", "ssid": "Cafe-des-Amis", "channel": 9,
            "frequency": 2452, "signalDbm": -73, "quality": 54,
            "encryption": "WEP", "cipher": "WEP-104", "authMode": "",
            "securityFlags": [],
            "vendor": "Belkin", "isHidden": False, "clients": 4,
            "firstSeen": iso_offset(75), "lastSeen": base,
        },
    ]

def summarize(nets):
    secure = sum(1 for n in nets if n["encryption"] in ("WPA2","WPA3","WPA2/WPA3"))
    weak = sum(1 for n in nets if n["encryption"] in ("OPEN","WEP","WPA","UNKNOWN"))
    return {
        "totalCount": len(nets),
        "secureCount": secure,
        "weakCount": weak,
    }

start = time.time()

mode = "builtin-simulated"
networks = []

# 1. Try `iw dev <iface> scan`
iw_path = "/usr/bin/iw"
try:
    proc = subprocess.run([iw_path, "dev", iface, "scan", "ap-force"],
                          capture_output=True, text=True, timeout=12)
    if proc.returncode == 0 and proc.stdout.strip():
        networks = parse_iw_scan(proc.stdout)
        if networks:
            mode = "iw"
except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
    pass

# 2. Try `iwlist <iface> scan`
if not networks:
    try:
        proc = subprocess.run(["iwlist", iface, "scan"],
                              capture_output=True, text=True, timeout=12)
        if proc.returncode == 0 and proc.stdout.strip() and "No scan results" not in proc.stdout:
            networks = parse_iwlist(proc.stdout)
            if networks:
                mode = "iwlist"
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass

# 3. Try aircrack-ng family (airmon-ng + airodump-ng)
# NOTE: needs root for monitor mode. We attempt, but expect to fall through.
if not networks:
    try:
        # Detect presence (don't actually enable monitor — requires sudo).
        detect = subprocess.run(["aircrack-ng", "--version"],
                                capture_output=True, text=True, timeout=4)
        aircrack_present = (detect.returncode == 0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        aircrack_present = False
    if aircrack_present:
        # We don't try to actually run airodump-ng (would need monitor mode + sudo).
        # Just mark the mode if aircrack-ng was present but we can't run it.
        # Fall through to builtin-simulated.
        pass

# 4. Builtin-simulated
if not networks:
    networks = builtin_networks()
    mode = "builtin-simulated"

summary = summarize(networks)
duration_ms = int((time.time() - start) * 1000)

out = {
    "tool": "wifi-scan",
    "mode": mode,
    "interface": iface,
    "networks": networks,
    "totalCount": summary["totalCount"],
    "secureCount": summary["secureCount"],
    "weakCount": summary["weakCount"],
    "scannedAt": now_iso(),
    "durationMs": duration_ms,
}
print(json.dumps(out, ensure_ascii=False))
PY
