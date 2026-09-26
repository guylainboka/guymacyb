#!/usr/bin/env bash
# wifi-handshake-capture.sh — Capture un 4-way handshake WiFi via airodump-ng.
#
# Usage: ./wifi-handshake-capture.sh <bssid> <channel> <interface> [duration_sec]
#
# Linux+aircrack-ng : timeout <dur> airodump-ng <iface> --bssid <mac> -c <ch> -w /tmp/hs
# Vérifie la présence du handshake via aircreck-ng <cap>
#
# Strategy:
#   1. airodump-ng (root + monitor mode) → capture réelle + vérification aircrack-ng
#   2. Aucun backend disponible — état honnête (PAS de données simulées) :
#      captured:false + mode "airodump-ng-required" / "root-required" / "no-wireless-hardware"
#
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

BSSID="${1:-}"; CH="${2:-6}"; IFACE="${3:-wlan0mon}"; DUR="${4:-30}"
[ -z "$BSSID" ] && { fail_json "usage: wifi-handshake-capture.sh <bssid> <channel> <interface> [duration]"; exit 1; }
log "wifi-hs" "BSSID=$BSSID ch=$CH iface=$IFACE dur=${DUR}s"

python3 - "$BSSID" "$CH" "$IFACE" "$DUR" <<'PY'
import json, os, subprocess, sys, time, glob
from datetime import datetime, timezone

bssid, ch, iface, dur = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
ts = int(time.time())
outdir = f"/tmp/guymacyb-hs-{ts}"
os.makedirs(outdir, exist_ok=True)
cap_prefix = f"{outdir}/hs"

result = {"tool":"wifi-handshake-capture","bssid":bssid,"channel":ch,"interface":iface,
          "durationSec":dur,"capFile":"","handshakeFound":False,"packetsCaptured":0,
          "mode":"","error":"","scannedAt":now}

is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
has_airodump = __import__("shutil").which("airodump-ng") is not None
has_aircrack = __import__("shutil").which("aircrack-ng") is not None

def has_wireless_hardware():
    """Return True if a /sys/class/net/*/wireless interface exists."""
    try:
        for dev in os.listdir("/sys/class/net"):
            if os.path.isdir(f"/sys/class/net/{dev}/wireless"):
                return True
    except Exception:
        pass
    return False

# État honnête : aucun backend temps réel disponible (PAS de données simulées).
if sys.platform != "linux":
    result["mode"] = "linux-required"
    result["error"] = ("La capture de handshake nécessite Linux (WSL sur Windows). "
                      "Lancez wsl.exe -d Ubuntu -- bash security-scripts/wifi-handshake-capture.sh <bssid> <ch> <iface> <dur>. "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

if not has_wireless_hardware():
    result["mode"] = "no-wireless-hardware"
    result["error"] = ("Aucun adaptateur sans-fil détecté sur ce système. "
                      "La capture d'un 4-way handshake nécessite une clé WiFi physique compatible mode monitor + airodump-ng (root). "
                      "Sur Windows, ces outils tournent via WSL (wsl.exe -d Ubuntu -- airmon-ng start wlan0). "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

if not has_airodump:
    result["mode"] = "airodump-ng-required"
    result["error"] = ("Capture indisponible : airodump-ng n'est pas installé. "
                      "Installez via WSL (Windows) : apt install aircrack-ng, puis airmon-ng start wlan0. "
                      "airodump-ng capture les trames EAPOL du 4-way handshake sur l'interface monitor. "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

if not is_root:
    result["mode"] = "root-required"
    result["error"] = ("Capture indisponible : privilèges root requis. "
                      "Le mode monitor (airmon-ng) et airodump-ng nécessitent les droits d'accès à l'interface réseau brute. "
                      "Relancez via : sudo bash security-scripts/wifi-handshake-capture.sh <bssid> <ch> <iface> <dur>, "
                      "ou sous WSL : wsl.exe -d Ubuntu -u root -- bash ... "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Capture réelle
try:
    proc = subprocess.run(
        ["timeout",str(dur),"airodump-ng",iface,"--bssid",bssid,"-c",str(ch),"-w",cap_prefix,"--write-interval","1"],
        capture_output=True, text=True, timeout=dur+10
    )
    # Trouver le fichier .cap produit
    caps = glob.glob(f"{cap_prefix}*.cap")
    if caps:
        result["capFile"] = caps[0]
        # Vérifier handshake avec aircrack-ng
        if has_aircrack:
            chk = subprocess.run(["aircrack-ng",caps[0]],capture_output=True,text=True,timeout=10)
            out = chk.stdout + chk.stderr
            if "1 handshake" in out or "KEY FOUND" in out:
                result["handshakeFound"] = True
            # Compter les paquets (approx via taille du fichier)
            result["packetsCaptured"] = os.path.getsize(caps[0]) // 50
        result["mode"] = "aircrack-ng"
    else:
        result["error"] = "Aucun fichier .cap produit par airodump-ng"
except subprocess.TimeoutExpired:
    result["mode"] = "aircrack-ng"
    caps = glob.glob(f"{cap_prefix}*.cap")
    if caps:
        result["capFile"] = caps[0]
        result["note"] = "Capture terminée (timeout)"
    else:
        result["error"] = "Timeout et aucun .cap produit"
except Exception as e:
    result["error"] = str(e)

print(json.dumps(result, ensure_ascii=False))
PY
