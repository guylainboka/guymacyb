#!/usr/bin/env bash
# dirbrute.sh — Découverte de chemins/dossiers web pour Guyma Cyb.
#
# Usage:
#   ./dirbrute.sh <url> [--wordlist path]
#
# - gobuster > dirb > builtin_dirbrute.py
# - Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: dirbrute.sh <url> [--wordlist path]"
    exit 1
fi

RAW_TARGET="$1"; shift
WORDLIST=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wordlist) WORDLIST="${2:-}"; shift 2 ;;
        --wordlist=*) WORDLIST="${1#--wordlist=}"; shift ;;
        -h|--help) echo "Usage: $0 <url> [--wordlist path]" >&2; exit 0 ;;
        *) shift ;;
    esac
done

normalize_target "$RAW_TARGET" >/dev/null
URL="$TARGET_URL"
log "dirbrute" "Cible: $URL"

WL_ARG=""
if [[ -n "$WORDLIST" ]]; then
    WL_ARG="$WORDLIST"
fi

if tool_installed gobuster; then
    log "dirbrute" "gobuster détecté"
    if [[ -z "$WORDLIST" ]]; then
        # Chercher une wordlist système courante.
        for wl in /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/seclists/Discovery/Web-Content/common.txt; do
            if [[ -r "$wl" ]]; then WORDLIST="$wl"; break; fi
        done
    fi
    if [[ -z "$WORDLIST" ]]; then
        log "dirbrute" "aucune wordlist système → builtin"
        python3 "$SCRIPT_DIR/builtin_dirbrute.py" "$URL"
        exit 0
    fi
    TMP="$(mktemp)"
    if gobuster dir -u "$URL" -w "$WORDLIST" -q -z --no-status -t 16 -o "$TMP" 2>/dev/null; then
        python3 - "$URL" "$TMP" <<'PY'
import json, sys, re
from datetime import datetime, timezone
url, path = sys.argv[1], sys.argv[2]
found = []
try:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            m = re.match(r'^(\S+)\s*\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]', line)
            if m:
                found.append({"path": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})
            else:
                parts = line.split()
                if parts:
                    found.append({"path": parts[0], "status": 0, "size": 0})
except Exception:
    pass
print(json.dumps({"tool":"dirbrute","target":url,"mode":"gobuster",
                  "discovered":found,"testedCount":0,"foundCount":len(found),
                  "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                 ensure_ascii=False))
PY
        rm -f "$TMP"
        exit 0
    fi
    rm -f "$TMP"
    log "dirbrute" "gobuster a échoué → builtin"
fi

if tool_installed dirb; then
    log "dirbrute" "dirb détecté (non implémenté en natif) → builtin"
fi

# Repli builtin-python.
if [[ -n "$WL_ARG" ]]; then
    python3 "$SCRIPT_DIR/builtin_dirbrute.py" "$URL" "$WL_ARG"
else
    python3 "$SCRIPT_DIR/builtin_dirbrute.py" "$URL"
fi
