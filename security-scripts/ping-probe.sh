#!/usr/bin/env bash
# ping-probe.sh — Test de connectivité ICMP (ping) pour Guyma Cyb.
#
# Usage:
#   ./ping-probe.sh <url|host> [--count N]
#
# - ping système > builtin TCP-connect
# - Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [[ $# -lt 1 ]]; then
    fail_json "usage: ping-probe.sh <url|host> [--count N]"
    exit 1
fi

HOST="$(extract_host "$1")"; shift
COUNT="4"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --count) COUNT="${2:-4}"; shift 2 ;;
        --count=*) COUNT="${1#--count=}"; shift ;;
        *) shift ;;
    esac
done

log "ping-probe" "Hôte: $HOST (count=$COUNT)"

python3 - "$HOST" "$COUNT" <<'PY'
import json, platform, re, socket, subprocess, sys, time
from datetime import datetime, timezone

host, count = sys.argv[1], int(sys.argv[2])
is_win = platform.system() == "Windows"
mode = "ping"
packets = []
stats = {"sent":0,"recv":0,"lossPct":100,"minMs":0,"avgMs":0,"maxMs":0,"mdevMs":0}
err = ""

def run_ping():
    flag_n = "-n" if is_win else "-c"
    if is_win:
        cmd = ["ping","-n",str(count),"-w","3000",host]
    else:
        cmd = ["ping", flag_n, str(count), "-W","3", host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=count*4+10)
        out = r.stdout
        if is_win:
            m = re.search(r"Packets:\s+Sent\s*=\s*(\d+).*Received\s*=\s*(\d+).*Lost\s*=\s*(\d+)", out, re.S)
            if m:
                stats["sent"]=int(m.group(1)); stats["recv"]=int(m.group(2))
                stats["lossPct"]=round(int(m.group(3))/max(int(m.group(1)),1)*100,1)
            tm = re.search(r"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms", out, re.S)
            if tm:
                stats["minMs"]=int(tm.group(1)); stats["maxMs"]=int(tm.group(2)); stats["avgMs"]=int(tm.group(3))
            for line in out.splitlines():
                mm = re.search(r"time[=<](\d+)ms", line)
                if mm: packets.append({"seq":len(packets)+1,"ms":float(mm.group(1))})
        else:
            m = re.search(r"(\d+)\s+packets transmitted.*?(\d+)\s+received.*?(\d+\.?\d*)%.*packet loss", out)
            if m:
                stats["sent"]=int(m.group(1)); stats["recv"]=int(m.group(2)); stats["lossPct"]=float(m.group(3))
            tm = re.search(r"rtt min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
            if tm:
                stats["minMs"]=float(tm.group(1)); stats["avgMs"]=float(tm.group(2))
                stats["maxMs"]=float(tm.group(3)); stats["mdevMs"]=float(tm.group(4))
            for line in out.splitlines():
                mm = re.search(r"time=([\d.]+)\s*ms", line)
                if mm: packets.append({"seq":len(packets)+1,"ms":float(mm.group(1))})
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False

ok = run_ping()
if not ok:
    mode = "builtin-tcp-connect"
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        print(json.dumps({"tool":"ping-probe","target":host,"mode":"none","error":f"DNS: {e}",
            "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}))
        sys.exit(0)
    stats["sent"]=count
    for i in range(count):
        try:
            t0=time.monotonic()
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip,80))
            ms=round((time.monotonic()-t0)*1000,2)
            s.close()
            packets.append({"seq":i+1,"ms":ms})
            stats["recv"]+=1
        except Exception:
            packets.append({"seq":i+1,"ms":0,"error":"timeout/refused"})
    stats["lossPct"]=round((stats["sent"]-stats["recv"])/stats["sent"]*100,1) if stats["sent"] else 100
    if packets and stats["recv"]>0:
        vals=[p["ms"] for p in packets if p.get("ms",0)>0]
        if vals:
            stats["minMs"]=min(vals); stats["maxMs"]=max(vals); stats["avgMs"]=round(sum(vals)/len(vals),2)

print(json.dumps({
    "tool":"ping-probe","target":host,"mode":mode,
    "stats":stats,"samples":packets,"error":err,
    "scannedAt":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
}, ensure_ascii=False))
PY
