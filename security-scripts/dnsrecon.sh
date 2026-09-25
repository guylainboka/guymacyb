#!/usr/bin/env bash
# dnsrecon.sh — Reconnaissance DNS pour Guyma Cyb.
#
# Usage:
#   ./dnsrecon.sh <url|host>
#
# Utilise `dig` (disponible) pour requêter A, AAAA, MX, NS, TXT, CNAME, SOA.
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: dnsrecon.sh <url|host>"
    exit 1
fi

HOST="$(extract_host "$1")"
log "dnsrecon" "Hôte: $HOST"

if ! tool_installed dig; then
    fail_json "outil introuvable: dig"
    exit 1
fi

python3 - "$HOST" <<'PY'
import json, subprocess, sys
from datetime import datetime, timezone

host = sys.argv[1]
records = []
note = ""

def dig(rrtype):
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=2", host, rrtype],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        return [l for l in out.splitlines() if l] if out else []
    except Exception:
        return []

a = dig("A")
aaaa = dig("AAAA")
mx = dig("MX")
ns = dig("NS")
txt = dig("TXT")
cname = dig("CNAME")
soa = dig("SOA")

for v in a:    records.append({"type":"A","value":v})
for v in aaaa: records.append({"type":"AAAA","value":v})
for v in cname:records.append({"type":"CNAME","value":v})
for v in mx:   records.append({"type":"MX","value":v})
for v in ns:   records.append({"type":"NS","value":v})
for v in txt:  records.append({"type":"TXT","value":v})
for v in soa:  records.append({"type":"SOA","value":v})

if not a and not aaaa and not cname:
    note = "Aucun enregistrement trouvé (NXDOMAIN ou domaine inexistant)."

# Détection de wildcard DNS : si A renvoie une IP même pour un sous-domaine aléatoire.
if a:
    rnd = "guymacyb-wildcard-test-xyz123." + host
    wa = dig_call = None
    try:
        r = subprocess.run(["dig","+short","+time=2","+tries=1",rnd,"A"],
                           capture_output=True,text=True,timeout=8).stdout.strip()
        if r and r in a:
            note = (note + " " if note else "") + "Wildcard DNS détecté : le domaine répond pour des sous-domaines aléatoires."
    except Exception:
        pass

print(json.dumps({
    "tool":"dnsrecon",
    "target":host,
    "records":records,
    "note":note.strip(),
    "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
}, ensure_ascii=False))
PY
