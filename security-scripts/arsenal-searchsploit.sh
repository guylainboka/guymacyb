#!/usr/bin/env bash
# arsenal-searchsploit.sh — searchsploit wrapper for Guyma Cyb (module "Arsenal").
#
# Usage:
#   ./arsenal-searchsploit.sh <query>
#
# Behaviour:
#   - If `searchsploit` is on PATH: runs `searchsploit --json <query>` and
#     normalises the response into a flat list of {id,title,type,platform,date}.
#   - Else: returns an HONEST error field "searchsploit non installé
#     (apt install exploitdb)" with `results:[]`. NEVER fabricates exploits.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

QUERY="${1:-}"
if [[ -z "$QUERY" ]]; then
    fail_json "usage: arsenal-searchsploit.sh <query>"
    exit 1
fi

log "searchsploit" "query=$QUERY"

python3 - "$QUERY" <<'PY'
import json, subprocess, sys, time
query = sys.argv[1]
START = time.time()

def has(cmd):
    try:
        # `searchsploit -h` exits 0 on the help screen.
        proc = subprocess.run([cmd, "-h"], capture_output=True, timeout=4)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False

if not has("searchsploit"):
    print(json.dumps({
        "tool": "searchsploit",
        "query": query,
        "results": [],
        "totalCount": 0,
        "durationMs": int((time.time() - START) * 1000),
        "error": "searchsploit non installé (apt install exploitdb)",
    }, ensure_ascii=False))
    sys.exit(0)

try:
    proc = subprocess.run(["searchsploit", "--json", query],
                          capture_output=True, text=True, timeout=30)
except (subprocess.TimeoutExpired, OSError) as e:
    print(json.dumps({
        "tool": "searchsploit", "query": query, "results": [],
        "totalCount": 0,
        "durationMs": int((time.time() - START) * 1000),
        "error": f"exécution searchsploit impossible: {e}",
    }, ensure_ascii=False))
    sys.exit(0)

raw = proc.stdout or ""
try:
    data = json.loads(raw)
except (ValueError, TypeError):
    print(json.dumps({
        "tool": "searchsploit", "query": query, "results": [],
        "totalCount": 0,
        "durationMs": int((time.time() - START) * 1000),
        "error": f"sortie searchsploit non-JSON: {raw[:200]}",
    }, ensure_ascii=False))
    sys.exit(0)

# searchsploit --json schema: {"RESULTS":[{"Title":...,"Exploit ID":"...","Type":...,"Platform":...,"Date":...}]}
results = []
items = data.get("RESULTS") or data.get("results") or data.get("EXPLOITS") or []
if isinstance(items, list):
    for v in items:
        if isinstance(v, dict):
            results.append({
                "id": str(v.get("Exploit ID") or v.get("EDB-ID") or v.get("id") or ""),
                "title": str(v.get("Title") or v.get("title") or ""),
                "type": str(v.get("Type") or v.get("type") or ""),
                "platform": str(v.get("Platform") or v.get("platform") or ""),
                "date": str(v.get("Date") or v.get("date") or ""),
            })

print(json.dumps({
    "tool": "searchsploit",
    "query": query,
    "results": results,
    "totalCount": len(results),
    "durationMs": int((time.time() - START) * 1000),
    "error": None if results else (proc.stderr.strip()[:200] or None),
}, ensure_ascii=False))
PY
