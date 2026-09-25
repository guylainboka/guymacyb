#!/usr/bin/env bash
# nmap-scan.sh — Port scan wrapper for Guyma Cyb.
#
# Usage:
#   ./nmap-scan.sh <url> [--ports 1-1000] [--timeout 2]
#
# Behaviour:
#   - If `nmap` is installed: runs `nmap -sT -Pn -T4 --top-ports 100 -oX - <host>`
#     and parses the XML into JSON via python3.
#   - Else: FALLBACK to builtin_portscan.py (pure-Python TCP connect scanner).
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
# Exit:   0 on success, 1 on hard failure (still emits {"error":...} on stdout).
set -euo pipefail

# Locate the scripts dir even when invoked via PATH.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: nmap-scan.sh <url> [--ports spec] [--timeout N]"
    exit 1
fi

RAW_TARGET="$1"; shift
PORTS_SPEC=""
TIMEOUT_SEC="2"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ports)
            PORTS_SPEC="${2:-}"; shift 2 ;;
        --ports=*)
            PORTS_SPEC="${1#--ports=}"; shift ;;
        --timeout)
            TIMEOUT_SEC="${2:-2}"; shift 2 ;;
        --timeout=*)
            TIMEOUT_SEC="${1#--timeout=}"; shift ;;
        -h|--help)
            echo "Usage: $0 <url> [--ports spec] [--timeout N]" >&2
            exit 0 ;;
        *)
            log "nmap" "ignoring unknown arg: $1"
            shift ;;
    esac
done

normalize_target "$RAW_TARGET" >/dev/null
HOST="$TARGET_HOST"
PORT="$TARGET_PORT"
URL="$TARGET_URL"

log "nmap" "target=$HOST url=$URL port=$PORT ports_spec=${PORTS_SPEC:-<default>}"

# ---------------------------------------------------------------------------
# Branch 1: real nmap is installed.
# ---------------------------------------------------------------------------
if tool_installed nmap; then
    log "nmap" "nmap found — running native scan"
    TMPXML="$(mktemp)"
    trap 'rm -f "$TMPXML"' EXIT
    NMAP_ARGS=(-sT -Pn -T4 --top-ports 100 -oX -)
    if [[ -n "$PORTS_SPEC" ]]; then
        NMAP_ARGS=(-sT -Pn -T4 -p "$PORTS_SPEC" -oX -)
    fi
    if ! nmap "${NMAP_ARGS[@]}" "$HOST" >"$TMPXML" 2>"$SCRIPT_DIR/.nmap-stderr.$$"; then
        log "nmap" "nmap exit non-zero — see stderr file"
    fi
    rm -f "$SCRIPT_DIR/.nmap-stderr.$$" 2>/dev/null || true

    python3 - "$HOST" "$TMPXML" <<'PY'
import json, sys, os, re
from datetime import datetime, timezone

host_arg = sys.argv[1]
xml_path = sys.argv[2]
try:
    with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
        xml = fh.read()
except OSError as exc:
    sys.stdout.write(json.dumps({"error": f"nmap xml read failed: {exc}"}) + "\n")
    sys.exit(1)

# Lightweight regex parser (no lxml dependency). nmap XML is simple enough.
def find_all(pattern, text):
    return re.findall(pattern, text, re.DOTALL)

ports = []
# <port protocol="tcp" portid="80"><state state="open" reason="syn-ack" ...
for m in re.finditer(
    r'<port\s+protocol="[^"]*"\s+portid="(\d+)"[^>]*>(.*?)</port>',
    xml, re.DOTALL):
    portid = int(m.group(1))
    body = m.group(2)
    state_m = re.search(r'<state\s+state="([^"]+)"[^>]*reason="([^"]*)"', body)
    svc_m = re.search(r'<service\s+name="([^"]*)"', body)
    ports.append({
        "port": portid,
        "state": state_m.group(1) if state_m else "unknown",
        "service": svc_m.group(1) if svc_m else "unknown",
        "reason": state_m.group(2) if state_m else "unknown",
    })
ports.sort(key=lambda p: p["port"])

# Duration: scaninfo start/end if available, else 0.
start_m = re.search(r'starttime="(\d+)"', xml)
end_m = re.search(r'endtimestr="[^"]*"\s+endtime="(\d+)"', xml) or re.search(r'endtime="(\d+)"', xml)
duration_ms = 0
if start_m and end_m:
    try:
        duration_ms = int((float(end_m.group(1)) - float(start_m.group(1))) * 1000)
        if duration_ms < 0: duration_ms = 0
    except ValueError:
        duration_ms = 0

payload = {
    "tool": "nmap",
    "target": host_arg,
    "mode": "nmap",
    "ports": ports,
    "summary": {
        "open": len([p for p in ports if p["state"] == "open"]),
        "closed": len([p for p in ports if p["state"] == "closed"]),
        "filtered": len([p for p in ports if p["state"] == "filtered"]),
        "totalScanned": len(ports),
    },
    "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "durationMs": duration_ms,
}
sys.stdout.write(json.dumps(payload) + "\n")
PY
    exit 0
fi

# ---------------------------------------------------------------------------
# Branch 2: FALLBACK to builtin python portscan.
# ---------------------------------------------------------------------------
log "nmap" "nmap NOT installed — falling back to builtin_portscan.py"
if [[ ! -x "$SCRIPT_DIR/builtin_portscan.py" ]]; then
    fail_json "tool not installed: nmap (and builtin fallback missing)"
    exit 1
fi

# builtin_portscan.py prints exactly one JSON object on stdout.
if python3 "$SCRIPT_DIR/builtin_portscan.py" "$HOST" \
        ${PORTS_SPEC:+--ports "$PORTS_SPEC"} \
        --timeout "$TIMEOUT_SEC"; then
    exit 0
else
    # The python script already emitted {"error":...}; just propagate the exit code.
    exit 1
fi
