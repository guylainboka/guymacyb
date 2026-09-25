#!/usr/bin/env bash
# netcat-probe.sh — Sonde de connectivité TCP (netcat-like) pour Guyma Cyb.
#
# Usage:
#   ./netcat-probe.sh <url|host> [--port N] [--data "payload"]
#
# - nc/ncat > socat > builtin python (socket TCP)
# - Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: netcat-probe.sh <url|host> [--port N] [--data payload]"
    exit 1
fi

RAW="$1"; shift
PORT=""
DATA=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="${2:-}"; shift 2 ;;
        --port=*) PORT="${1#--port=}"; shift ;;
        --data) DATA="${2:-}"; shift 2 ;;
        --data=*) DATA="${1#--data=}"; shift ;;
        *) shift ;;
    esac
done

HOST="$(extract_host "$RAW")"
[[ -z "$PORT" ]] && PORT="$(extract_port "$RAW")"

log "netcat-probe" "Hôte: $HOST Port: $PORT"

if tool_installed nc; then
    log "netcat-probe" "nc détecté"
    if [[ -n "$DATA" ]]; then
        RES="$(printf '%s' "$DATA" | timeout 6 nc -w 5 "$HOST" "$PORT" 2>/dev/null | head -c 4000)"
    else
        # Juste un test de connectivité
        if timeout 6 nc -z -w 5 "$HOST" "$PORT" 2>/dev/null; then
            printf '{"tool":"netcat-probe","target":"%s","port":%s,"mode":"nc","connected":true,"banner":"","scannedAt":"%s"}\n' \
                "$HOST" "$PORT" "$(iso_now)"
            exit 0
        else
            printf '{"tool":"netcat-probe","target":"%s","port":%s,"mode":"nc","connected":false,"error":"connexion refusée/timeout","scannedAt":"%s"}\n' \
                "$HOST" "$PORT" "$(iso_now)"
            exit 0
        fi
    fi
    BANNER_ESC="$(json_escape "$(printf '%s' "$RES" | head -c 2000)")"
    printf '{"tool":"netcat-probe","target":"%s","port":%s,"mode":"nc","connected":true,"banner":"%s","scannedAt":"%s"}\n' \
        "$HOST" "$PORT" "$BANNER_ESC" "$(iso_now)"
    exit 0
fi

# Repli builtin python
log "netcat-probe" "nc absent → builtin python"
python3 - "$HOST" "$PORT" "$DATA" <<'PY'
import json, socket, sys
from datetime import datetime, timezone
host, port, data = sys.argv[1], int(sys.argv[2]), sys.argv[3]
banner = ""
connected = False
err = ""
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect((host, port))
    connected = True
    if data:
        s.sendall(data.encode("utf-8","replace"))
        try:
            banner = s.recv(4096).decode("utf-8","replace")
        except socket.timeout:
            banner = ""
    else:
        # Tenter de lire une bannière (services qui saluent : SSH, FTP, SMTP)
        s.settimeout(2)
        try:
            banner = s.recv(4096).decode("utf-8","replace")
        except socket.timeout:
            banner = ""
    s.close()
except Exception as e:
    err = str(e)
print(json.dumps({
    "tool":"netcat-probe","target":host,"port":port,"mode":"builtin-python",
    "connected":connected,"banner":banner[:2000],"error":err,
    "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
}, ensure_ascii=False))
PY
