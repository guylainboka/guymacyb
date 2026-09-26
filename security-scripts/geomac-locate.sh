#!/usr/bin/env bash
# geomac-locate.sh — MAC geolocation for Guyma Cyb (module "GeoMac").
#
# Usage:
#   ./geomac-locate.sh <mac>
#
# Strategy:
#   1. Always: lookup the OUI vendor from an embedded table (subset reused
#      from wifi-scan.sh). This needs no network call and no API key.
#   2. Optional: if WIGLE_API_KEY env var is set (Basic-Auth token), query
#      WiGLE's network/geocode endpoint for lat/lng/accuracy.
#   3. If no API key is set: return vendor only with `lat:null, lng:null,
#      accuracy:null, source:"oui-only"` and an HONEST note. NEVER fabricate
#      coordinates — Mac-to-GPS is not derivable from OUI alone.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

MAC_RAW="${1:-}"
if [[ -z "$MAC_RAW" ]]; then
    fail_json "usage: geomac-locate.sh <mac>"
    exit 1
fi

# Normalize: uppercase hex only, then re-format as XX:XX:XX:XX:XX:XX.
# Dash placed at the end of the tr set to avoid a "reverse collating order" error.
MAC_HEX="$(printf '%s' "$MAC_RAW" | tr '[:lower:]' '[:upper:]' | tr -d ' :.-' | tr -cd '0-9A-F')"
if [[ ${#MAC_HEX} -ne 12 ]]; then
    fail_json "MAC invalide: $MAC_RAW (attendu 12 hex, ex: F4:CA:E5:11:22:33)"
    exit 1
fi
OUI_FMT="$(printf '%s:%s:%s' "${MAC_HEX:0:2}" "${MAC_HEX:2:2}" "${MAC_HEX:4:2}")"
MAC_FMT="$(printf '%s:%s:%s:%s:%s:%s' "${MAC_HEX:0:2}" "${MAC_HEX:2:2}" "${MAC_HEX:4:2}" "${MAC_HEX:6:2}" "${MAC_HEX:8:2}" "${MAC_HEX:10:2}")"
log "geomac" "mac=$MAC_FMT oui=$OUI_FMT"

python3 - "$MAC_FMT" "$OUI_FMT" <<'PY'
import json, os, subprocess, sys, time
mac = sys.argv[1]
oui = sys.argv[2]
START = time.time()

# Embedded OUI table (subset reused from wifi-scan.sh / localnetwork-scan.sh).
OUI_PREFIXES = {
    "00:11:22": "Cisco", "00:1A:11": "D-Link", "00:24:B2": "Apple",
    "14:EB:B6": "Asus", "8C:DC:D4": "Netgear", "F4:CA:E5": "TP-Link",
    "EC:08:6B": "TP-Link", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:0C:E6": "Belkin", "C0:4A:00": "Netgear", "00:1F:33": "D-Link",
    "AC:84:C6": "Huawei", "04:F0:21": "Huawei", "B0:BE:76": "TP-Link",
    "50:C7:BF": "TP-Link", "60:32:B1": "D-Link", "F8:1A:67": "D-Link",
    "00:19:70": "Zyxel", "A4:2B:B0": "Cisco-Meraki", "00:50:56": "VMware",
    "00:15:5D": "Hyper-V", "C4:04:15": "Aruba", "24:A4:3C": "Aruba",
    "00:0B:86": "Aruba", "00:1B:54": "Netgear", "00:0C:29": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
}

vendor = OUI_PREFIXES.get(oui.upper(), "Unknown")
api_key = os.environ.get("WIGLE_API_KEY", "").strip()

lat = None
lng = None
accuracy = None
source = "oui-only"
note = ("Géolocalisation WiGLE désactivée : WIGLE_API_KEY non défini. "
        "Seul le fabricant OUI est retourné. Définissez WIGLE_API_KEY "
        "(Basic-Auth token) pour activer la résolution WiGLE network/geocode.")
error = None

if api_key:
    # WiGLE v2 API: GET https://api.wigle.net/api/v2/network/geocode?mac=...
    # Auth: HTTP Basic with the API name + token (we accept either a raw
    # base64 string or an "name:token" pair; if it has no ':' and no '=' we
    # assume it's already base64).
    if ":" in api_key and "=" not in api_key:
        import base64
        token = base64.b64encode(api_key.encode("utf-8")).decode("ascii")
    else:
        token = api_key
    try:
        proc = subprocess.run(
            ["curl", "-s", "-G",
             "https://api.wigle.net/api/v2/network/geocode",
             "-H", f"Authorization: Basic {token}",
             "--data-urlencode", f"mac={mac}",
             "--max-time", "10"],
            capture_output=True, text=True, timeout=12,
        )
        if proc.returncode == 0 and proc.stdout:
            try:
                data = json.loads(proc.stdout)
            except ValueError:
                data = {}
            if data.get("success") and isinstance(data.get("results"), list) and data["results"]:
                r = data["results"][0]
                lat = r.get("lat")
                lng = r.get("lng")
                accuracy = r.get("accuracy")
                if lat is not None and lng is not None:
                    source = "wigle-api"
                    note = None
                else:
                    note = f"WiGLE : coordonnées absentes dans la réponse ({data.get('message', '')})"
            else:
                note = f"WiGLE : {data.get('message', 'réponse vide ou non-autorisée')}"
        else:
            note = f"curl exit {proc.returncode}: {proc.stderr[:200]}"
    except (subprocess.TimeoutExpired, OSError) as e:
        note = f"WiGLE indisponible : {e}"

print(json.dumps({
    "tool": "geomac",
    "mac": mac,
    "oui": oui.upper(),
    "vendor": vendor,
    "lat": lat,
    "lng": lng,
    "accuracy": accuracy,
    "source": source,
    "note": note,
    "durationMs": int((time.time() - START) * 1000),
    "error": error,
}, ensure_ascii=False))
PY
