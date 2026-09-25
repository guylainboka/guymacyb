#!/usr/bin/env bash
# nikto-scan.sh — Web-server vulnerability scanner wrapper for Guyma Cyb.
#
# Usage:
#   ./nikto-scan.sh <url> [--maxtime 60] [--tuning 1,2,3,4,b]
#
# Behaviour:
#   - Invokes the locally-installed nikto 2.6.1 (Perl) at
#     $SCRIPTS_DIR/../tools/nikto/program/nikto.pl with the user-space Perl
#     libs at $SCRIPTS_DIR/../tools/perl5/lib/perl5.
#   - Forces JSON output (-Format json -o -).
#   - Wraps nikto's output into a single JSON object on stdout.
#   - If SSL support is missing in the Perl install AND the target is HTTPS,
#     falls back to HTTP (port 80) on the same host.
#   - If nikto.pl is missing, emits {"error":"nikto not installed","tool":"nikto"}.
#   - If JSON parsing fails, emits a "rawOutput" fallback object.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
# Exit:   0 on success, 1 on hard failure (still emits {"error":...} on stdout).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIKTO_PL="$SCRIPT_DIR/../tools/nikto/program/nikto.pl"
PERL5_LIB="$SCRIPT_DIR/../tools/perl5/lib/perl5"
PERL5_BIN="$SCRIPT_DIR/../tools/perl5/bin"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: nikto-scan.sh <url> [--maxtime N] [--tuning spec]"
    exit 1
fi

RAW_TARGET="$1"; shift
MAXTIME="30"
TUNING="1,2,3,4,b"
TIMEOUT="8"
USERAGENT="GuymaCyb-Security-Auditor/1.0 (+security-research)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --maxtime) MAXTIME="${2:-60}"; shift 2 ;;
        --maxtime=*) MAXTIME="${1#--maxtime=}"; shift ;;
        --tuning) TUNING="${2:-}"; shift 2 ;;
        --tuning=*) TUNING="${1#--tuning=}"; shift ;;
        --timeout) TIMEOUT="${2:-8}"; shift 2 ;;
        --timeout=*) TIMEOUT="${1#--timeout=}"; shift ;;
        -h|--help) echo "Usage: $0 <url> [--maxtime N] [--tuning spec] [--timeout N]" >&2; exit 0 ;;
        *) log "nikto" "ignoring unknown arg: $1"; shift ;;
    esac
done

# Resolve the absolute path of nikto.pl (handles the `../` form).
NIKTO_PL_ABS="$(cd "$(dirname "$NIKTO_PL")" 2>/dev/null && pwd)/$(basename "$NIKTO_PL")"
if [[ ! -f "$NIKTO_PL_ABS" ]]; then
    log "nikto" "nikto.pl not found at $NIKTO_PL_ABS"
    python3 -c '
import json, sys
sys.stdout.write(json.dumps({"error": "nikto not installed", "tool": "nikto"}) + "\n")
'
    exit 1
fi

normalize_target "$RAW_TARGET" >/dev/null
HOST="$TARGET_HOST"
PORT="$TARGET_PORT"
SCHEME="$(printf '%s' "$TARGET_URL" | sed -nE 's|^([a-zA-Z]+)://.*|\1|p')"
[[ -z "$SCHEME" ]] && SCHEME="https"

log "nikto" "target=$HOST url=$TARGET_URL scheme=$SCHEME port=$PORT"

# Detect SSL support in the Perl install.
SSL_OK=0
if PATH="$PERL5_BIN:$PATH" perl -I "$PERL5_LIB" -MNet::SSLeay -e 'exit 0' >/dev/null 2>&1; then
    SSL_OK=1
elif PATH="$PERL5_BIN:$PATH" perl -I "$PERL5_LIB" -MIO::Socket::SSL -e 'exit 0' >/dev/null 2>&1; then
    SSL_OK=1
fi

NIKTO_PORT="$PORT"
NIKTO_SSL_FLAG=()
if [[ "$SCHEME" == "https" ]]; then
    if [[ "$SSL_OK" -eq 1 ]]; then
        NIKTO_SSL_FLAG=(-ssl)
    else
        log "nikto" "HTTPS target but Perl SSL modules unavailable — falling back to HTTP port 80"
        NIKTO_PORT="80"
        SCHEME="http"
    fi
fi

# Build the nikto argument list. Note: nikto's `-o -` (stdout) buffer is NOT
# flushed when nikto is killed by -maxtime, so we write to a temp file and
# read it back.
RAW_OUT="$(mktemp)"
RAW_ERR="$(mktemp)"
RAW_USEROUT="$(mktemp)"
trap 'rm -f "$RAW_OUT" "$RAW_ERR" "$RAW_USEROUT"' EXIT

NIKTO_ARGS=(
    -h "$HOST"
    -port "$NIKTO_PORT"
    -Tuning "$TUNING"
    -maxtime "$MAXTIME"
    -timeout "$TIMEOUT"
    -ask no
    -useragent "$USERAGENT"
    -Format json
    -o "$RAW_OUT"
)
if [[ ${#NIKTO_SSL_FLAG[@]} -gt 0 ]]; then
    NIKTO_ARGS+=("${NIKTO_SSL_FLAG[@]}")
fi

log "nikto" "running: nikto ${NIKTO_ARGS[*]}"

# Wrap the perl invocation with `timeout` to guarantee nikto cannot hang
# longer than (maxtime + 20) seconds. nikto's own -maxtime should fire first,
# but the outer timeout is a safety net for update-check / DNS stalls.
HARD_TIMEOUT=$(( MAXTIME + 25 ))

# nikto sometimes returns non-zero even with valid output; capture exit code
# but continue to parse whatever JSON it produced. Disable pipefail/errexit
# for this single command via `set +e` to be safe.
set +e
PATH="$PERL5_BIN:$PATH" timeout --kill-after=5 "${HARD_TIMEOUT}s" \
    perl -I "$PERL5_LIB" "$NIKTO_PL_ABS" "${NIKTO_ARGS[@]}" \
    >"$RAW_USEROUT" 2>"$RAW_ERR"
NIKTO_RC=$?
set -e
# nikto writes nothing useful to its own stdout; the JSON goes to $RAW_OUT.

# Echo a short tail of stderr for debug.
JSON_SIZE="$(wc -c <"$RAW_OUT" 2>/dev/null || echo 0)"
ERR_SIZE="$(wc -c <"$RAW_ERR" 2>/dev/null || echo 0)"
log "nikto" "exit=$NIKTO_RC, json_file_size=${JSON_SIZE} bytes, stderr_size=${ERR_SIZE} bytes"

# Hand off parsing to python3.
python3 - "$HOST" "$RAW_OUT" "$RAW_ERR" "$NIKTO_RC" <<'PY'
import json, sys, os, re
from datetime import datetime, timezone

host_arg = sys.argv[1]
out_path = sys.argv[2]
err_path = sys.argv[3]
nikto_rc = int(sys.argv[4] or 0)

try:
    with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
except OSError as exc:
    sys.stdout.write(json.dumps({"error": f"nikto output read failed: {exc}", "tool": "nikto", "target": host_arg}) + "\n")
    sys.exit(1)

try:
    with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
        err_tail = fh.read()[-2000:]
except OSError:
    err_tail = ""

def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Strip any leading non-JSON noise (nikto prints "+ ..." lines on stdout in
# some configs even with -Format json). Find the first "[" or "{" and parse
# from there.
stripped = raw.lstrip()
json_start = -1
for i, ch in enumerate(stripped):
    if ch in "[{":
        json_start = i
        break

parsed = None
parse_error = None
if json_start >= 0:
    candidate = stripped[json_start:]
    try:
        parsed = json.loads(candidate)
    except Exception as exc:  # noqa: BLE001
        parse_error = str(exc)
else:
    parse_error = "no JSON array/object found in nikto output"

if parsed is None:
    # Fallback: raw output (first 4000 chars, escaped).
    snippet = raw[:4000]
    payload = {
        "tool": "nikto",
        "target": host_arg,
        "rawOutput": snippet,
        "scannedAt": iso_now(),
        "niktoExit": nikto_rc,
        "parseError": parse_error,
        "stderrTail": err_tail[-800:],
    }
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.exit(0)

# Normalize: nikto JSON is either a list of host objects or a single object.
if isinstance(parsed, list):
    host_objs = parsed
elif isinstance(parsed, dict) and "vulnerabilities" in parsed:
    host_objs = [parsed]
else:
    host_objs = [parsed] if isinstance(parsed, dict) else []

# Pick the first host object matching the target host (or just the first).
chosen = None
for ho in host_objs:
    if isinstance(ho, dict) and ho.get("host", "").lower() == host_arg.lower():
        chosen = ho
        break
if chosen is None and host_objs:
    chosen = host_objs[0] if isinstance(host_objs[0], dict) else {}
if chosen is None:
    chosen = {}

vulns_raw = chosen.get("vulnerabilities", []) or []
vulns = []
for v in vulns_raw:
    if not isinstance(v, dict):
        continue
    vulns.append({
        "id": v.get("id"),
        "method": v.get("method"),
        "url": v.get("url"),
        "msg": v.get("msg"),
        "references": v.get("references"),
        "category": v.get("category") or v.get("OSVDB") or None,
    })

# Compute scan duration in seconds from start_time / end_time if present.
def parse_nikto_ts(s):
    if not s or not isinstance(s, str):
        return None
    # Example: "2026-09-25 10:36:53 +0000"
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None

start_ts = parse_nikto_ts(chosen.get("start_time"))
end_ts = parse_nikto_ts(chosen.get("end_time"))
scan_duration = None
if start_ts and end_ts:
    scan_duration = int((end_ts - start_ts).total_seconds())

banner = chosen.get("server_banner")
if not banner:
    # Try to extract from stderr if needed.
    m = re.search(r"Server:\s*(\S+)", err_tail)
    banner = m.group(1) if m else None

payload = {
    "tool": "nikto",
    "target": host_arg,
    "ip": chosen.get("ip"),
    "port": chosen.get("port"),
    "banner": banner,
    "vulnerabilities": vulns,
    "rawCount": len(vulns),
    "scanDuration": scan_duration,
    "scannedAt": iso_now(),
    "niktoExit": nikto_rc,
}
sys.stdout.write(json.dumps(payload) + "\n")
PY
