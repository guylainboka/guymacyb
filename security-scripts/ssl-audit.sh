#!/usr/bin/env bash
# ssl-audit.sh — Audit TLS/SSL et certificat X.509 pour Guyma Cyb.
#
# Usage:
#   ./ssl-audit.sh <url> [--port N]
#
# Utilise `openssl s_client` (disponible) pour :
#  - récupérer le certificat (sujet, émetteur, validité, n° de série)
#  - tester les versions TLS supportées (1.0, 1.1, 1.2, 1.3)
#  - vérifier HSTS via curl HEAD
# Calcule une note de A+ à F.
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: ssl-audit.sh <url> [--port N]"
    exit 1
fi

RAW_TARGET="$1"; shift
PORT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="${2:-}"; shift 2 ;;
        --port=*) PORT="${1#--port=}"; shift ;;
        *) shift ;;
    esac
done

normalize_target "$RAW_TARGET" >/dev/null
HOST="$TARGET_HOST"
[[ -z "$PORT" ]] && PORT="$TARGET_PORT"
# ssl-audit n'a de sens qu'en 443 ; forcer 443 si la cible est HTTP.
[[ "$PORT" == "80" ]] && PORT="443"

log "ssl-audit" "Hôte: $HOST Port: $PORT"

if ! tool_installed openssl; then
    fail_json "outil introuvable: openssl"
    exit 1
fi

python3 - "$HOST" "$PORT" <<'PY'
import json, subprocess, sys, ssl, socket
from datetime import datetime, timezone, timedelta

host, port = sys.argv[1], int(sys.argv[2])
issues = []
cert_info = {"subject":"", "issuer":"", "notBefore":"", "notAfter":"",
             "daysRemaining":0, "serial":""}
tls_versions = []
hsts = False
grade = "F"

# 1. Récupération du certificat via openssl s_client
try:
    out = subprocess.run(
        ["openssl","s_client","-connect",f"{host}:{port}","-servername",host,"-showcerts"],
        input=b"", capture_output=True, timeout=10
    ).stdout.decode("utf-8","replace")
    # Extraire le bloc certificat
    import re
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if m:
        pem = m.group(0)
        cert = subprocess.run(["openssl","x509","-noout","-subject","-issuer",
                               "-dates","-serial","-fingerprint","-sha256"],
                              input=pem.encode(), capture_output=True, timeout=8)
        ctext = cert.stdout.decode("utf-8","replace")
        for line in ctext.splitlines():
            if line.startswith("subject="): cert_info["subject"]=line[len("subject="):].strip()
            elif line.startswith("issuer="): cert_info["issuer"]=line[len("issuer="):].strip()
            elif line.startswith("notBefore="): cert_info["notBefore"]=line[len("notBefore="):].strip()
            elif line.startswith("notAfter="): cert_info["notAfter"]=line[len("notAfter="):].strip()
            elif line.startswith("serial="): cert_info["serial"]=line[len("serial="):].strip()
        # Calcul jours restants
        if cert_info["notAfter"]:
            try:
                # Format : Sep 25 12:00:00 2026 GMT
                na = datetime.strptime(cert_info["notAfter"], "%b %d %H:%M:%S %Y %Z")
                cert_info["daysRemaining"] = (na - datetime.utcnow()).days
                if cert_info["daysRemaining"] < 0:
                    issues.append("Certificat EXPIRÉ")
                    grade = "F"
                elif cert_info["daysRemaining"] < 30:
                    issues.append(f"Certificat expire bientôt ({cert_info['daysRemaining']} jours)")
            except Exception:
                pass
    else:
        issues.append("Aucun certificat récupéré (TLS absent ?)")
except subprocess.TimeoutExpired:
    issues.append("Timeout openssl s_client")
except Exception as e:
    issues.append(f"Erreur certificat: {e}")

# 2. Test des versions TLS
for ver, flag in [("TLSv1.0","-tls1"),("TLSv1.1","-tls1_1"),
                  ("TLSv1.2","-tls1_2"),("TLSv1.3","-tls1_3")]:
    supported = False
    try:
        r = subprocess.run(
            ["openssl","s_client","-connect",f"{host}:{port}","-servername",host,flag],
            input=b"", capture_output=True, timeout=8
        )
        supported = (r.returncode == 0) or (b"BEGIN CERTIFICATE" in r.stdout)
    except Exception:
        supported = False
    tls_versions.append({"version":ver,"supported":supported})
    if supported and ver in ("TLSv1.0","TLSv1.1"):
        issues.append(f"{ver} encore supporté (faible)")

# 3. HSTS via curl
try:
    r = subprocess.run(
        ["curl","-sI","--max-time","6",f"https://{host}/"],
        capture_output=True, text=True, timeout=8
    )
    hsts = "strict-transport-security" in r.stdout.lower()
except Exception:
    hsts = False
if not hsts:
    issues.append("HSTS manquant")

# 4. Note
if "Certificat EXPIRÉ" in str(issues) or "Aucun certificat" in str(issues):
    grade = "F"
elif any("TLSv1.0" in i or "TLSv1.1" in i for i in issues):
    grade = "C"
elif not hsts:
    grade = "B"
else:
    v3 = any(v["version"]=="TLSv1.3" and v["supported"] for v in tls_versions)
    v12 = any(v["version"]=="TLSv1.2" and v["supported"] for v in tls_versions)
    if v3 and not any(v["supported"] and v["version"] in ("TLSv1.0","TLSv1.1") for v in tls_versions):
        grade = "A+"
    elif v12:
        grade = "A"
    else:
        grade = "B"

print(json.dumps({
    "tool":"ssl-audit",
    "target":host,
    "port":port,
    "certificate":cert_info,
    "tlsVersions":tls_versions,
    "hsts":hsts,
    "grade":grade,
    "issues":issues,
    "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
}, ensure_ascii=False))
PY
