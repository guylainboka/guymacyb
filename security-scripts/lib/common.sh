#!/usr/bin/env bash
# common.sh — Shared helpers for the Guyma Cyb security-scripts wrappers.
#
# Provides:
#   normalize_target <url>   → echoes normalized URL (adds https:// if missing);
#                              sets globals TARGET_URL, TARGET_HOST, TARGET_PORT.
#   extract_host <url>       → echoes host (without port/path).
#   extract_port <url>       → echoes port (defaults 443 for https, 80 for http).
#   tool_installed <name>    → returns 0 if command exists on PATH, 1 otherwise.
#   json_escape <string>     → escapes a string for JSON (uses python3).
#   emit_json <jsonstring>   → prints json to stdout (and nothing else).
#   log <tag> <msg>          → prints "[TAG] msg" to stderr.
#   iso_now                  → echoes current UTC ISO-8601 timestamp.
#   fail_json <msg>          → prints {"error":...} on stdout, exit 1.
#
# Source this file from another script:
#   source "$(dirname "$0")/lib/common.sh"
#
# NOTE: This file is a library — it does NOT execute anything on its own.
#       Safe to source under `set -euo pipefail`.

# Resolve the directory of this library (so callers can locate sibling python
# fallbacks relative to the security-scripts root).
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
export SCRIPTS_DIR

# Emit a log line to stderr (never stdout — stdout is reserved for JSON).
log() {
    local tag="$1"
    shift
    local msg="$*"
    # Uppercase tag for visual consistency.
    local utag
    utag="$(printf '%s' "$tag" | tr '[:lower:]' '[:upper:]')"
    printf '[%s] %s\n' "$utag" "$msg" >&2
}

# Print current UTC time as ISO-8601 (e.g. 2025-09-25T10:19:42Z).
iso_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Check whether a command exists on PATH.
tool_installed() {
    local name="$1"
    command -v "$name" >/dev/null 2>&1
}

# Escape a string for safe inclusion inside a JSON string literal.
# Uses python3 to handle UTF-8 / control chars / quotes correctly.
json_escape() {
    python3 -c '
import json, sys
s = sys.argv[1] if len(sys.argv) > 1 else ""
sys.stdout.write(json.dumps(s)[1:-1])
' "$1"
}

# Print exactly one JSON object to stdout. Trailing newline included.
emit_json() {
    printf '%s\n' "$1"
}

# Print a single-line {"error":"..."} JSON to stdout, then exit 1.
# Useful as the LAST thing a script does on a hard failure.
fail_json() {
    local msg="$1"
    python3 -c '
import json, sys
sys.stdout.write(json.dumps({"error": sys.argv[1]}) + "\n")
' "$msg"
}

# Extract the host portion (no port, no path, no scheme) from a URL or bare host.
extract_host() {
    local url="$1"
    python3 -c '
import sys, re
raw = sys.argv[1] if len(sys.argv) > 1 else ""
s = raw.strip()
# Strip scheme if present.
if "://" in s:
    s = s.split("://", 1)[1]
# Strip userinfo.
if "@" in s.split("/", 1)[0]:
    s = s.split("@", 1)[1]
# Strip path/query/fragment.
s = re.split(r"[/?#]", s, 1)[0]
# Strip port.
host = s.rsplit(":", 1)[0] if ":" in s else s
# IPv6 literal like [::1].
if host.startswith("[") and "]" in host:
    host = host[1:host.index("]")]
print(host)
' "$url"
}

# Extract the port from a URL or bare host:port. Defaults: 443 for https, 80 otherwise.
extract_port() {
    local url="$1"
    python3 -c '
import sys, re
raw = sys.argv[1] if len(sys.argv) > 1 else ""
s = raw.strip()
scheme = "http"
if "://" in s:
    scheme, rest = s.split("://", 1)
    s = rest
# IPv6: leave as-is (we won'"'"'t parse port from IPv6 in this trivial helper).
if s.startswith("["):
    # find closing bracket
    end = s.find("]")
    if end != -1 and end + 1 < len(s) and s[end+1] == ":":
        print(s[end+2:].split("/", 1)[0])
    elif scheme == "https":
        print(443)
    else:
        print(80)
    sys.exit(0)
# Strip path/query/fragment.
s = re.split(r"[/?#]", s, 1)[0]
if ":" in s.rsplit(":", 1)[-1] and s.count(":") == 1:
    port = s.rsplit(":", 1)[1]
    if port.isdigit():
        print(port)
        sys.exit(0)
if scheme == "https":
    print(443)
else:
    print(80)
' "$url"
}

# Normalize a target: ensure it has a scheme, set globals TARGET_URL,
# TARGET_HOST, TARGET_PORT.
#
# - If the input has no scheme, "https://" is prepended.
# - The resulting URL is the canonical TARGET_URL (path/query stripped).
# - TARGET_HOST = bare hostname (no port, no scheme, no path).
# - TARGET_PORT = integer port (default 443 for https, 80 for http).
normalize_target() {
    local raw="$1"
    local scheme=""
    local rest="$raw"

    if [[ "$raw" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
        scheme="${raw%%://*}"
        rest="${raw#*://}"
    else
        scheme="https"
        rest="$raw"
    fi

    # Strip leading user@ if present.
    if [[ "$rest" == *@* ]]; then
        rest="${rest#*@}"
    fi

    # Strip path/query/fragment (keep host[:port] only).
    local hostport
    hostport="$(printf '%s' "$rest" | sed -E 's|[/?#].*$||')"

    # Extract host and (optional) port, accounting for IPv6 [::1] literals.
    local host="$hostport"
    local port=""
    if [[ "$hostport" == \[*\]* ]]; then
        # IPv6 with optional :port after ]
        local after="${hostport#*\]}"
        host="${hostport%%\]*}"
        host="${host#\[}"
        if [[ "$after" == :* ]]; then
            port="${after#:}"
        fi
    elif [[ "$hostport" == *:* ]]; then
        host="${hostport%:*}"
        port="${hostport##*:}"
    fi

    # Default port by scheme.
    if [[ -z "$port" ]]; then
        if [[ "$scheme" == "https" ]]; then
            port="443"
        else
            port="80"
        fi
    fi

    # Validate port is numeric; if not, drop it and apply default.
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        if [[ "$scheme" == "https" ]]; then
            port="443"
        else
            port="80"
        fi
    fi

    # Reconstruct canonical URL: scheme://host[:port] (port omitted if default).
    local canonical="$scheme://$host"
    if [[ "$scheme" == "https" && "$port" != "443" ]]; then
        canonical="$scheme://$host:$port"
    elif [[ "$scheme" == "http" && "$port" != "80" ]]; then
        canonical="$scheme://$host:$port"
    fi

    TARGET_URL="$canonical"
    TARGET_HOST="$host"
    TARGET_PORT="$port"
    export TARGET_URL TARGET_HOST TARGET_PORT

    printf '%s' "$TARGET_URL"
}
