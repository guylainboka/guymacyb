#!/usr/bin/env bash
# wifi-mac-changer.sh — Change l'adresse MAC d'une interface (macchanger).
#
# Usage: ./wifi-mac-changer.sh <interface> [new_mac]
#
# Sans new_mac : génère une MAC aléatoire localement administrée.
# Linux+macchanger (ou ip link fallback) : sudo ip link set <iface> down;
#   macchanger -m <mac> <iface> (ou: ip link set <iface> address <mac>); ip link set <iface> up
#
# Strategy:
#   1. macchanger (root) → changement réel
#   2. ip link set address (root, fallback si macchanger absent) → changement réel
#   3. Aucun backend disponible — état honnête (PAS de données simulées) :
#      method "failed" + changed:false / mode "root-required" / "linux-required"
#
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

# Lire MAC actuelle (réelle) depuis /sys/class/net
try:
    with open(f"/sys/class/net/{iface}/address") as f:
        result["originalMac"] = f.read().strip()
except Exception:
    result["method"] = "failed"
    result["error"] = (f"Interface {iface} introuvable sur ce système. "
                      "Le changement de MAC nécessite une interface réseau existante et un pilote qui supporte l'adressage arbitraire. "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Générer MAC aléatoire localement administrée si non fournie (juste la valeur demandée)
if not new_mac:
    first = random.randint(0, 255) | 0x02  # bit locally administered
    first = first & 0xFE  # unicast
    octets = [first] + [random.randint(0,255) for _ in range(5)]
    new_mac = ":".join(f"{o:02x}" for o in octets)
result["newMac"] = new_mac

is_linux = sys.platform == "linux"
is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
has_macchanger = __import__("shutil").which("macchanger") is not None

# État honnête : aucun backend temps réel disponible (PAS de données simulées).
if not is_linux:
    result["method"] = "failed"
    result["error"] = ("Changement de MAC indisponible : Linux requis (WSL sur Windows). "
                      f"Lancez wsl.exe -d Ubuntu -u root -- bash security-scripts/wifi-mac-changer.sh {iface} {new_mac}. "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

if not is_root:
    result["method"] = "failed"
    result["error"] = ("Changement de MAC indisponible : privilèges root requis. "
                      "`ip link set` et `macchanger` modifient l'interface réseau brute (CAP_NET_ADMIN). "
                      f"Relancez via : sudo bash security-scripts/wifi-mac-changer.sh {iface} {new_mac}, "
                      "ou sous WSL : wsl.exe -d Ubuntu -u root -- bash ... "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Changement réel
try:
    subprocess.run(["ip","link","set",iface,"down"],check=True,capture_output=True,timeout=10)
    if has_macchanger:
        subprocess.run(["macchanger","-m",new_mac,iface],capture_output=True,text=True,timeout=10)
        result["method"] = "macchanger"
    else:
        # Fallback ip-link (fonctionne sans macchanger installé)
        subprocess.run(["ip","link","set",iface,"address",new_mac],check=True,capture_output=True,timeout=10)
        result["method"] = "ip-link"
    subprocess.run(["ip","link","set",iface,"up"],check=True,capture_output=True,timeout=10)
    # Vérifier la nouvelle MAC réelle
    with open(f"/sys/class/net/{iface}/address") as f:
        actual = f.read().strip()
    result["changed"] = (actual.lower() == new_mac.lower())
    if not result["changed"]:
        result["method"] = "failed"
        result["error"] = (f"MAC actuelle après tentative: {actual} (attendue: {new_mac}). "
                           f"Le pilote de {iface} a peut-être refusé l'adressage arbitraire "
                           f"(certaines cartes WiFi ne supportent pas le spoofing MAC). "
                           f"Essayez `macchanger -A {iface}`.")
except subprocess.CalledProcessError as e:
    result["method"] = "failed"
    result["error"] = (f"Échec du changement réel de MAC : "
                       f"{e.stderr.decode() if e.stderr else str(e)}. "
                       f"Le pilote de l'interface {iface} peut ne pas supporter l'adressage MAC arbitraire "
                       f"(certaines cartes WiFi refusent). Essayez `macchanger -A {iface}`.")
except Exception as e:
    result["method"] = "failed"
    result["error"] = f"Erreur inattendue : {e}"

print(json.dumps(result, ensure_ascii=False))
PY
