#!/usr/bin/env bash
# wifi-monitor-mode.sh — Active le mode monitor sur une interface WiFi.
#
# Usage: ./wifi-monitor-mode.sh <interface>
#
# Linux : ip link set down + iw dev set type monitor + ip link set up (sudo)
#         ou airmon-ng start <iface>
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

IFACE="${1:-wlan0}"
log "wifi-monitor" "Interface: $IFACE"

python3 - "$IFACE" <<'PY'
import json, os, subprocess, sys
from datetime import datetime, timezone

iface = sys.argv[1]
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
result = {"tool":"wifi-monitor-mode","interface":iface,"monitorInterface":"",
          "enabled":False,"method":"","originalMac":"","newMac":"","error":"","scannedAt":now}

def have(c): 
    try: subprocess.run(["command","-v",c],capture_output=True,check=True); return True
    except: return c in os.environ.get("PATH","")

# Vérifier qu'on est sous Linux avec une interface wlan
is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
if sys.platform != "linux":
    result["error"] = "Mode monitor non supporté sur " + sys.platform + " (Linux requis avec carte WiFi USB compatible)"
    result["mode"] = "unsupported-platform"
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Vérifier iw
has_iw = __import__("shutil").which("iw") is not None
has_airmon = __import__("shutil").which("airmon-ng") is not None

if not is_root:
    result["error"] = "Privilèges root requis (sudo). Relancez avec : sudo ./wifi-monitor-mode.sh " + iface
    result["mode"] = "needs-sudo"
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Sauvegarder la MAC originale
try:
    mac_out = subprocess.run(["cat",f"/sys/class/net/{iface}/address"],capture_output=True,text=True).stdout.strip()
    result["originalMac"] = mac_out
except Exception:
    pass

# Méthode 1 : airmon-ng
if has_airmon:
    try:
        r = subprocess.run(["airmon-ng","start",iface],capture_output=True,text=True,timeout=15)
        # Chercher le nom de l'interface monitor dans la sortie
        mon_iface = iface + "mon"
        for line in r.stdout.splitlines():
            if "mon" in line and iface in line:
                parts = line.split()
                for p in parts:
                    if p.endswith("mon"):
                        mon_iface = p; break
        # Vérifier que l'interface monitor existe
        if os.path.exists(f"/sys/class/net/{mon_iface}"):
            result["enabled"] = True
            result["method"] = "airmon-ng"
            result["monitorInterface"] = mon_iface
        else:
            result["error"] = "airmon-ng n'a pas créé l'interface monitor. " + r.stderr[:200]
    except Exception as e:
        result["error"] = f"airmon-ng a échoué: {e}"

# Méthode 2 : iw (si airmon-ng a échoué ou absent)
if not result["enabled"] and has_iw:
    try:
        subprocess.run(["ip","link","set",iface,"down"],check=True,capture_output=True,timeout=10)
        subprocess.run(["iw","dev",iface,"set","type","monitor"],check=True,capture_output=True,timeout=10)
        subprocess.run(["ip","link","set",iface,"up"],check=True,capture_output=True,timeout=10)
        result["enabled"] = True
        result["method"] = "iw"
        result["monitorInterface"] = iface
    except subprocess.CalledProcessError as e:
        result["error"] = f"iw a échoué: {e.stderr.decode() if e.stderr else str(e)}"
    except Exception as e:
        result["error"] = f"iw a échoué: {e}"

if not result["enabled"] and not result["error"]:
    result["error"] = "Aucune méthode disponible (iw ni airmon-ng installé). Installez aircrack-ng."
    result["mode"] = "missing-tools"

print(json.dumps(result, ensure_ascii=False))
PY
