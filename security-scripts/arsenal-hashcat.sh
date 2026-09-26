#!/usr/bin/env bash
# arsenal-hashcat.sh — hashcat wrapper for Guyma Cyb (module "Arsenal").
#
# Usage:
#   ./arsenal-hashcat.sh <hash> [mode] [wordlist]
#     mode     : hashcat -m value (0 = MD5, 100 = SHA1, 1400 = SHA-256, ...).
#     wordlist : path to a wordlist; if absent, a short brute-force mask (?l?l?l?l)
#                is used as a fast demo (NOT exhaustive — caller can re-run with a
#                proper wordlist like /usr/share/wordlists/rockyou.txt).
#
# Behaviour:
#   - If `hashcat` is on PATH: runs hashcat --quiet -m <mode> <hashfile> [wordlist]
#     with --potfile-path pointing to a temp file, then reads the potfile to
#     extract the cracked plaintext (if any). Captures stdout/stderr as `output`.
#   - Else: returns an HONEST error "hashcat non installé (apt install hashcat)"
#     with `cracked:null, native:false`. NEVER fabricates a result.
#
# Notes:
#   - On systems without a GPU or OpenCL runtime, hashcat will fall back to
#     CPU mode (slow) or fail with an exit code; that error is surfaced honestly.
#   - The hash is written to a temp file (never passed as a CLI argument, which
#     would leak it into `ps`/process listings).
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

HASH="${1:-}"
MODE="${2:-0}"
WORDLIST="${3:-}"

if [[ -z "$HASH" ]]; then
    fail_json "usage: arsenal-hashcat.sh <hash> [mode] [wordlist]"
    exit 1
fi

log "hashcat" "hash=$HASH mode=$MODE wordlist=${WORDLIST:-<bruteforce-4l>}"

python3 - "$HASH" "$MODE" "$WORDLIST" <<'PY'
import json, os, subprocess, sys, tempfile, time
hash_val = sys.argv[1]
mode = sys.argv[2] or "0"
wordlist = sys.argv[3] or ""
START = time.time()

def has(cmd):
    try:
        proc = subprocess.run([cmd, "--version"], capture_output=True, timeout=4)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False

if not has("hashcat"):
    print(json.dumps({
        "tool": "hashcat",
        "hash": hash_val,
        "mode": mode,
        "native": False,
        "output": "",
        "cracked": None,
        "durationMs": int((time.time() - START) * 1000),
        "error": "hashcat non installé (apt install hashcat)",
    }, ensure_ascii=False))
    sys.exit(0)

# Write the hash to a temp file so it never appears on the command-line.
with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as fh:
    fh.write(hash_val + "\n")
    hashfile = fh.name

# Use a dedicated potfile (not the system default) so we can read it back safely.
potfile = tempfile.NamedTemporaryFile(mode="w", suffix=".potfile", delete=False)
potfile.close()

cmd = ["hashcat", "--quiet", "-m", str(mode), "--potfile-path", potfile.name]
if wordlist:
    cmd += [hashfile, wordlist]
else:
    # Short brute-force mask (?l?l?l?l = 26^4 = 456k attempts) as a fast demo.
    cmd += [hashfile, "-a", "3", "?l?l?l?l", "--increment"]

output = ""
err = ""
rc = -1
try:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=110)
    output = proc.stdout or ""
    err = proc.stderr or ""
    rc = proc.returncode
except subprocess.TimeoutExpired:
    try:
        os.unlink(hashfile); os.unlink(potfile.name)
    except OSError:
        pass
    print(json.dumps({
        "tool": "hashcat", "hash": hash_val, "mode": mode, "native": True,
        "output": "", "cracked": None,
        "durationMs": int((time.time() - START) * 1000),
        "error": "hashcat a dépassé le délai de 110s",
    }, ensure_ascii=False))
    sys.exit(0)
except OSError as e:
    try:
        os.unlink(hashfile); os.unlink(potfile.name)
    except OSError:
        pass
    print(json.dumps({
        "tool": "hashcat", "hash": hash_val, "mode": mode, "native": True,
        "output": "", "cracked": None,
        "durationMs": int((time.time() - START) * 1000),
        "error": f"exécution hashcat impossible: {e}",
    }, ensure_ascii=False))
    sys.exit(0)

# Read the cracked plaintext from the potfile (format: HASH:PLAINTEXT).
cracked = None
try:
    with open(potfile.name, "r") as fh:
        for line in fh:
            line = line.strip()
            if ":" in line:
                cracked = line.split(":", 1)[1].strip() or None
                if cracked:
                    break
except OSError:
    pass

try:
    os.unlink(hashfile); os.unlink(potfile.name)
except OSError:
    pass

# hashcat exit codes: 0 = cracked/success, 1 = exhausted/no match (normal),
# -1 = error, -2 = aborted, etc. 0 and 1 are NOT errors.
err_msg = None if rc in (0, 1) else f"hashcat exit code {rc}"
out_text = (output + ("\n" + err if err else ""))[:2000]

print(json.dumps({
    "tool": "hashcat",
    "hash": hash_val,
    "mode": mode,
    "native": True,
    "output": out_text.strip(),
    "cracked": cracked,
    "durationMs": int((time.time() - START) * 1000),
    "error": err_msg,
}, ensure_ascii=False))
PY
