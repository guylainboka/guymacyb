#!/usr/bin/env bash
# wifi-crack-handshake.sh — Casser un handshake capturé offline (aircrack-ng/hashcat).
#
# Usage: ./wifi-crack-handshake.sh <cap_file> [wordlist]
#
# Strategy:
#   1. aircrack-ng + wordlist fournie ou découverte sur /usr/share/wordlists → cassage réel
#   2. Aucun backend disponible — état honnête (PAS de données simulées) :
#      cracked:false + mode "aircrack-ng-required" / "cap-file-missing" / "wordlist-missing"
#
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

CAP="${1:-}"; WL="${2:-}"
[ -z "$CAP" ] && { fail_json "usage: wifi-crack-handshake.sh <cap_file> [wordlist]"; exit 1; }
log "wifi-crack" "cap=$CAP wordlist=${WL:-auto}"

python3 - "$CAP" "$WL" <<'PY'
import json, os, subprocess, sys, time
from datetime import datetime, timezone

cap, wl = sys.argv[1], sys.argv[2]
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
result = {"tool":"wifi-crack-handshake","capFile":cap,"wordlist":wl or "","mode":"",
          "cracked":False,"password":"","keysTried":0,"durationMs":0,"error":"","scannedAt":now}

has_aircrack = __import__("shutil").which("aircrack-ng") is not None

# Vérifier d'abord que le fichier .cap existe réellement.
if not os.path.exists(cap):
    result["mode"] = "cap-file-missing"
    result["error"] = (f"Fichier de capture introuvable : {cap}. "
                      "Le cassage hors-ligne nécessite un fichier .cap contenant un vrai 4-way handshake capturé "
                      "(via wifi-handshake-capture.sh avec airodump-ng en mode monitor). "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

if not has_aircrack:
    result["mode"] = "aircrack-ng-required"
    result["error"] = ("Cassage indisponible : aircrack-ng n'est pas installé. "
                      "Installez via WSL (Windows) : apt install aircrack-ng. "
                      "Le cassage réel combine aircrack-ng + une capture .cap valide + une wordlist (ex. rockyou.txt). "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Trouver une wordlist réelle sur le système (aucune wordlist démo n'est générée).
if not wl:
    for cand in ["/usr/share/wordlists/rockyou.txt",
                 "/usr/share/wordlists/fasttrack.txt",
                 "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"]:
        if os.path.exists(cand):
            wl = cand; break
result["wordlist"] = wl or ""

if not wl or not os.path.exists(wl):
    result["mode"] = "wordlist-missing"
    result["error"] = ("Aucune wordlist fournie ou trouvée sur le système. "
                      "Fournissez une wordlist en 2e argument (ex. /usr/share/wordlists/rockyou.txt), "
                      "ou installez-en une : apt install wordlists / seclists. "
                      "Le cassage réel aircrack-ng fait correspondre chaque mot de la wordlist aux EAPOL capturés. "
                      "GuymaCyb ne génère jamais de données simulées.")
    print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Cassage réel avec aircrack-ng
start = time.monotonic()
try:
    proc = subprocess.run(["aircrack-ng","-w",wl,cap],capture_output=True,text=True,timeout=300)
    out = proc.stdout + proc.stderr
    result["durationMs"] = int((time.monotonic()-start)*1000)
    result["mode"] = "aircrack-ng"
    # Chercher "KEY FOUND! [ password ]"
    import re
    m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out)
    if m:
        result["cracked"] = True
        result["password"] = m.group(1)
    # Compter les clés testées
    km = re.search(r"(\d+)\s*keys?\s*tried", out)
    if km: result["keysTried"] = int(km.group(1))
    if not result["cracked"]:
        result["error"] = "Handshake non cassé avec cette wordlist"
except subprocess.TimeoutExpired:
    result["error"] = "Timeout (5min) — wordlist trop grande ou PC trop lent"
    result["mode"] = "aircrack-ng"
except Exception as e:
    result["error"] = str(e)

print(json.dumps(result, ensure_ascii=False))
PY
