#!/usr/bin/env bash
# iperf3-client.sh — Client de mesure de bande passante iperf3 pour Guyma Cyb.
#
# Usage:
#   ./iperf3-client.sh <server_host> [--port N] [--udp] [--time 10] [--reverse]
#
# - Nécessite iperf3 installé ET un serveur iperf3 distant en écoute.
# - Si iperf3 absent : renvoie une erreur JSON claire (impossible de fallback
#   car iperf3 est un protocole binaire spécifique).
# - Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: iperf3-client.sh <server_host> [--port N] [--udp] [--time 10] [--reverse]"
    exit 1
fi

SERVER="$1"; shift
PORT="5201"
PROTO="tcp"
TIME="10"
REVERSE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="${2:-5201}"; shift 2 ;;
        --port=*) PORT="${1#--port=}"; shift ;;
        --udp) PROTO="udp"; shift ;;
        --time) TIME="${2:-10}"; shift 2 ;;
        --time=*) TIME="${1#--time=}"; shift ;;
        --reverse) REVERSE="--reverse"; shift ;;
        *) shift ;;
    esac
done

log "iperf3" "Serveur: $SERVER Port: $PORT Proto: $PROTO"

if ! tool_installed iperf3; then
    fail_json "outil introuvable: iperf3 (installez avec : sudo apt install iperf3)"
    exit 1
fi

ARGS=(iperf3 -c "$SERVER" -p "$PORT" -t "$TIME" -J)
[[ "$PROTO" == "udp" ]] && ARGS+=(-u)
[[ -n "$REVERSE" ]] && ARGS+=("$REVERSE")

if ! RAW="$(timeout $((TIME + 15)) "${ARGS[@]}" 2>/dev/null)"; then
    fail_json "iperf3 a échoué (serveur injoignable ou non démarré sur $SERVER:$PORT)"
    exit 1
fi

# iperf3 -J produit déjà du JSON. On l'enrichit.
echo "$RAW" | python3 -c '
import json, sys
from datetime import datetime, timezone
try:
    d = json.load(sys.stdin)
except Exception as e:
    print(json.dumps({"error":f"parse iperf3 json: {e}"}))
    sys.exit(1)
end = d.get("end", {})
if "sum_sent" in end:
    s = end["sum_sent"]
    r = end.get("sum_received", end.get("sum", {}))
    out = {
        "tool":"iperf3","mode":"iperf3","protocol":d.get("test",{}).get("protocol",""),
        "server":d.get("start",{}).get("connecting_to",{}).get("host",""),
        "port":d.get("start",{}).get("connecting_to",{}).get("port",0),
        "sent": {"bytes":s.get("bytes",0),"bps":s.get("bits_per_second",0),"retransmits":s.get("retransmits",0)},
        "received": {"bytes":r.get("bytes",0),"bps":r.get("bits_per_second",0)},
        "durationSec": d.get("start",{}).get("test_start",{}).get("duration",0),
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
else:
    s = end.get("sum", {})
    out = {
        "tool":"iperf3","mode":"iperf3","protocol":d.get("test",{}).get("protocol",""),
        "server":d.get("start",{}).get("connecting_to",{}).get("host",""),
        "port":d.get("start",{}).get("connecting_to",{}).get("port",0),
        "summary": {"bytes":s.get("bytes",0),"bps":s.get("bits_per_second",0),"jitterMs":s.get("jitter_ms",0),"lostPackets":s.get("lost_packets",0)},
        "durationSec": d.get("start",{}).get("test_start",{}).get("duration",0),
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
print(json.dumps(out, ensure_ascii=False))
'
