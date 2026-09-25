#!/usr/bin/env bash
# wifi-mac-changer.sh — Change l'adresse MAC d'une interface (macchanger).
#
# Usage: ./wifi-mac-changer.sh <interface> [new_mac]
#
# Sans new_mac : génère une MAC aléatoire.
# Linux+macchanger : sudo ip link set <iface> down; macchanger -m <mac> <iface>; ip link set <iface> up
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

IFACE="${1:-wlan0}"; NEW_MAC="${2:-}"
log "wifi-mac" "iface=$IFACE new=${NEW_MAC:-auto}"

python3 - "$IFACE" "$NEW_MAC" <<'PY'
import json, os, random, re, subprocess, sys
from datetime import datetime, timezone

iface, new_mac = sys.argv[1], sys.argv[2]
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
result = {"tool":"wifi-mac-changer","interface":iface,"originalMac":"","newMac":"",
          "changed":False,"method":"","error":"","scannedAt":now}

# Lire MAC actuelle
try:
    with open(f"/sys/class/net/{iface}/address") as f:
        result["originalMac"] = f.read().strip()
except Exception:
    pass

# Générer MAC aléatoire si non fournie
if not new_mac:
    # OUI aléatoire + 3 octets aléatoires (MAC localement administrée → 2e bit du 1er octet à 1)
    first = random.randint(0, 255) | 0x02  # bit locally administered
    first = first & 0xFE  # unicast
    octets = [first] + [random.randint(0,255) for _ in range(5)]
    new_mac = ":".join(f"{o:02x}" for o in octets)
result["newMac"] = new_mac

has_macchanger = __import__("shutil").which("macchanger") is not None
is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

if sys.platform != "linux" or not is_root:
    result["method"] = "builtin-simulated"
    result["error"] = "Privilèges root requis pour changer la MAC (sudo). " + result["newMac"] + " est la MAC demandée."
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Changement réel
try:
    subprocess.run(["ip","link","set",iface,"down"],check=True,capture_output=True,timeout=10)
    if has_macchanger:
        r = subprocess.run(["macchanger","-m",new_mac,iface],capture_output=True,text=True,timeout=10)
        result["method"] = "macchanger"
    else:
        # Fallback iw
        subprocess.run(["ip","link","set",iface,"address",new_mac],check=True,capture_output=True,timeout=10)
        result["method"] = "ip-link"
    subprocess.run(["ip","link","set",iface,"up"],check=True,capture_output=True,timeout=10)
    # Vérifier
    with open(f"/sys/class/net/{iface}/address") as f:
        actual = f.read().strip()
    result["changed"] = (actual.lower() == new_mac.lower())
    if not result["changed"]:
        result["error"] = f"MAC actuelle après changement: {actual} (attendue: {new_mac})"
except subprocess.CalledProcessError as e:
    result["error"] = e.stderr.decode() if e.stderr else str(e)
except Exception as e:
    result["error"] = str(e)

print(json.dumps(result, ensure_ascii=False))
PY
