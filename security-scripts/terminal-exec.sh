#!/usr/bin/env bash
# terminal-exec.sh — Exécute une commande dans un shell donné (bash/powershell/cmd/python).
#
# Usage: ./terminal-exec.sh <shell> <command> [cwd]
#
# shell = bash | powershell | cmd | python
# Timeout 30s. Refuse commandes dangereuses (rm -rf /, fork bomb).
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SHELL_NAME="${1:-bash}"; CMD="${2:-}"; CWD="${3:-}"
[ -z "$CMD" ] && { fail_json "usage: terminal-exec.sh <bash|powershell|cmd|python> <command> [cwd]"; exit 1; }

log "terminal" "shell=$SHELL_NAME cmd=${CMD:0:80}"

python3 - "$SHELL_NAME" "$CMD" "$CWD" <<'PY'
import json, os, subprocess, sys, platform
from datetime import datetime, timezone

shell_name, cmd, cwd = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
result = {"tool":"terminal","shell":shell_name,"command":cmd,"stdout":"","stderr":"",
          "exitCode":-1,"durationMs":0,"cwd":cwd or os.getcwd(),"scannedAt":now}

# Sécurité : refuser commandes manifestement dangereuses
DANGEROUS = [r"rm\s+-rf\s+/( |$)", r":\(\)\s*\{\s*:\|:\&\s*\}\s*;", r"mkfs\.", r"dd\s+.*of=/dev/sd", r">\s*/dev/sda"]
import re
for pat in DANGEROUS:
    if re.search(pat, cmd):
        result["error"] = "Commande refusée (pattern dangereux détecté)"
        result["exitCode"] = -2
        print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

# Construire la commande selon le shell
is_win = platform.system() == "Windows"
try:
    start = __import__("time").monotonic()
    if shell_name == "bash":
        # Sur Windows, chercher git-bash ou WSL bash
        if is_win:
            bash_paths = [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"]
            bash_exe = next((p for p in bash_paths if os.path.exists(p)), "bash")
        else:
            bash_exe = "bash"
        proc = subprocess.run([bash_exe, "-c", cmd], capture_output=True, text=True, timeout=30, cwd=cwd or None)
    elif shell_name == "powershell":
        pwsh = "pwsh" if subprocess.run(["command","-v","pwsh"],capture_output=True).returncode==0 else "powershell"
        if is_win or pwsh == "pwsh":
            proc = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=30, cwd=cwd or None)
        else:
            result["error"] = "PowerShell non disponible sur ce système"
            print(json.dumps(result, ensure_ascii=False)); sys.exit(0)
    elif shell_name == "cmd":
        if not is_win:
            result["error"] = "CMD est réservé à Windows"
            print(json.dumps(result, ensure_ascii=False)); sys.exit(0)
        proc = subprocess.run(["cmd", "/c", cmd], capture_output=True, text=True, timeout=30, cwd=cwd or None, shell=True)
    elif shell_name == "python":
        proc = subprocess.run(["python3" if not is_win else "python", "-c", cmd], capture_output=True, text=True, timeout=30, cwd=cwd or None)
    else:
        result["error"] = f"Shell inconnu: {shell_name}"
        print(json.dumps(result, ensure_ascii=False)); sys.exit(0)

    result["stdout"] = proc.stdout
    result["stderr"] = proc.stderr
    result["exitCode"] = proc.returncode
    result["durationMs"] = int((__import__("time").monotonic() - start) * 1000)
except subprocess.TimeoutExpired:
    result["error"] = "Timeout 30s dépassé"
    result["exitCode"] = 124
except FileNotFoundError as e:
    result["error"] = f"Shell introuvable: {e}"
except Exception as e:
    result["error"] = str(e)

print(json.dumps(result, ensure_ascii=False))
PY
