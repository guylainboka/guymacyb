#!/usr/bin/env bash
# whatweb-scan.sh — Empreinte technologique web pour Guyma Cyb.
#
# Usage:
#   ./whatweb-scan.sh <url>
#
# - Si `whatweb` est installé : l'utilise (sortie JSON).
# - Sinon : repli sur builtin_fingerprint.py (analyse headers + HTML).
# - Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: whatweb-scan.sh <url>"
    exit 1
fi

RAW_TARGET="$1"; shift
normalize_target "$RAW_TARGET" >/dev/null
HOST="$TARGET_HOST"
URL="$TARGET_URL"

log "whatweb" "Cible: $URL (hôte: $HOST)"

if tool_installed whatweb; then
    log "whatweb" "whatweb détecté, lancement..."
    # whatweb --log-json=- écrit du JSON sur stdout (un objet par ligne).
    if RAW="$(whatweb -q --no-errors --log-json=- "$URL" 2>/dev/null | head -1)"; then
        # whatweb produit un objet JSON par ligne ; on l'enveloppe.
        python3 - "$RAW" "$URL" <<'PY'
import json, sys
from datetime import datetime, timezone
raw, url = sys.argv[1], sys.argv[2]
try:
    data = json.loads(raw)
except Exception:
    print(json.dumps({"tool":"whatweb","target":url,"mode":"whatweb",
                      "error":"parse-error","rawOutput":raw[:2000],
                      "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}))
    sys.exit(0)
# Normaliser les champs whatweb vers notre schéma.
techs = []
if isinstance(data.get("plugins"), dict):
    for name, info in data["plugins"].items():
        if isinstance(info, list) and info:
            ver = info[0].get("version") if isinstance(info[0], dict) else None
            techs.append(f"{name} {ver}" if ver else name)
        else:
            techs.append(str(name))
out = {
    "tool": "whatweb",
    "target": url,
    "mode": "whatweb",
    "technologies": techs,
    "title": data.get("title",""),
    "statusCode": data.get("status_code",0),
    "server": (data.get("plugins",{}).get("IP") or [{}])[0].get("string","") if False else "",
    "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
print(json.dumps(out, ensure_ascii=False))
PY
        exit 0
    fi
    log "whatweb" "whatweb a échoué, repli builtin..."
fi

# Repli builtin-python.
log "whatweb" "whatweb absent → builtin_fingerprint.py"
python3 "$SCRIPT_DIR/builtin_fingerprint.py" "$URL"
