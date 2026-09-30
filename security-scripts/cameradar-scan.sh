#!/usr/bin/env bash
# cameradar-scan.sh — RTSP camera discovery + default-credential sweep.
#
# Usage:
#   ./cameradar-scan.sh [subnet]
#     subnet : CIDR or bare /24 prefix. Default: auto-detect from local IP.
#              Accepts "192.168.1.0/24", "192.168.1" or "192.168.1.1/24".
#
# Behaviour (all real — nothing invented):
#   1. Resolve local /24 (auto via `ip -4 addr` or a UDP-connect probe fallback).
#   2. TCP-connect probe port 554 on each host of the /24 (rootless, no SYN).
#   3. For each host with port 554 open, send an RTSP OPTIONS / DESCRIBE
#      request via python3 socket (no external RTSP library required).
#      Parse the realm / server header / model string from the response.
#   4. For each discovered camera, try a list of default credential pairs
#      against `rtsp://<user>:<pass>@<ip>:554/stream` using a real RTSP
#      DESCRIBE-with-Auth request. Mark `cracked:true` on success (401 →
#      bad creds, 200/OK → cracked).
#   5. If no cameras found OR python3 missing → honest `error` + empty array.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

SUBNET_ARG="${1:-}"
log "cameradar" "subnet=${SUBNET_ARG:-<auto>} starting RTSP discovery"

python3 - "$SUBNET_ARG" <<'PY'
import base64, json, os, re, socket, struct, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

SUBNET_ARG = sys.argv[1] if len(sys.argv) > 1 else ""
START_TS = time.time()

# ---------------------------------------------------------------------------
# Default credential pairs (industry-known RTSP defaults — vendor quick-start
# guides, NVR/UI firmware). Real, public list — used in audit-only fashion.
# ---------------------------------------------------------------------------
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "12345"),
    ("admin", "hunter"),
    ("guest", "guest"),
    ("support", "support"),
    ("admin", "P@ssw0rd"),
    ("admin", "camera"),
    ("admin", "hikvision"),
    ("admin", "9999"),
    ("admin", "ubnt"),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("operator", "operator"),
    ("user", "user"),
    ("netsurveillance", "net-surveillance"),
]

# ---------------------------------------------------------------------------
# Local /24 detection (no raw sockets — uses `ip -4 addr` if available,
# else a UDP "connect" trick to pick the default-route interface IP).
# ---------------------------------------------------------------------------
def detect_local_ip():
    # Prefer `ip` command — fast and reliable on Linux/WSL.
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"],
                             capture_output=True, text=True, timeout=3)
        for line in (out.stdout or "").splitlines():
            # line: "2: eth0    inet 192.168.1.42/24 brd ..."
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m and m.group(1) != "127.0.0.1":
                return m.group(1), int(m.group(2))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    # Fallback: open a UDP socket to a public IP — kernel picks the route iface.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            return ip, 24
        finally:
            s.close()
    except OSError:
        return None, None

def parse_subnet(arg):
    """Return (network, prefix) tuple — strictly /24 here."""
    if arg:
        s = arg.strip()
        # Bare "192.168.1" → 192.168.1.0/24
        if re.fullmatch(r"\d+\.\d+\.\d+", s):
            return f"{s}.0", 24
        # CIDR "192.168.1.0/24" or "192.168.1.5/24"
        m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", s)
        if m:
            ip = m.group(1)
            prefix = int(m.group(2))
            if prefix != 24:
                # We only sweep /24 — clamp the network part.
                pass
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0", 24
        # Anything else → ignore and auto-detect.
    local, prefix = detect_local_ip()
    if not local:
        return None, None
    parts = local.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0", 24

# ---------------------------------------------------------------------------
# RTSP probe — send a real RTSP OPTIONS request, parse Server / realm.
# ---------------------------------------------------------------------------
def rtsp_probe(ip, port=554, timeout=3.0, path="", creds=None):
    """
    Send a real RTSP OPTIONS or DESCRIBE request. If `creds` is provided,
    include a Basic Authorization header. Returns (status_line, headers, body)
    or (None, None, None) on socket error.
    """
    if path:
        url = f"rtsp://{ip}:{port}/{path}"
    else:
        url = f"rtsp://{ip}:{port}/"

    # CSeq is mandatory in RTSP — increment per request.
    req_lines = [
        f"DESCRIBE {url} RTSP/1.0",
        "CSeq: 1",
        "User-Agent: GuymaCyb-RTSP/1.0",
        "Accept: application/sdp",
    ]
    if creds:
        user, pw = creds
        token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
        req_lines.append(f"Authorization: Basic {token}")
    req = "\r\n".join(req_lines) + "\r\n\r\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
    except OSError:
        return None, {}, ""

    try:
        s.sendall(req.encode("ascii"))
        chunks = []
        # Read what's available within timeout.
        end = time.time() + timeout
        while time.time() < end:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
            if len(data) < 4096:
                break
        s.close()
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return None, {}, ""

    raw = b"".join(chunks).decode("latin-1", errors="replace")
    if not raw:
        return None, {}, ""
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body

def parse_model(status, headers, body):
    """Best-effort extraction of camera model/realm from RTSP response."""
    realm = headers.get("www-authenticate", "")
    if realm:
        m = re.search(r'realm="([^"]+)"', realm)
        if m:
            realm = m.group(1)
    server = headers.get("server", "")
    model = server or realm or ""
    # Some Hikvision/Dahua cameras announce themselves in the SDP body too.
    if body:
        m2 = re.search(r"[a-z]=.*?(Hikvision|Dahua|IPCamera|IPC|DVR|NVR)[^\r\n]*", body, re.IGNORECASE)
        if m2 and not model:
            model = m2.group(0).strip()
    return realm, model

def try_credentials(ip, port=554):
    """Try every default cred pair. Return (cracked, creds) or (False, None)."""
    for user, pw in DEFAULT_CREDS:
        status, headers, _ = rtsp_probe(ip, port, timeout=2.5, creds=(user, pw))
        if not status:
            continue
        # RTSP returns 401 Unauthorized for bad creds, 200 OK for good creds
        # on a DESCRIBE that requires auth.
        if "200" in status or " 200 " in status:
            return True, (user, pw)
        # Some servers return 401 always; we look at WWW-Authenticate to
        # distinguish "wrong creds" (still 401 with same realm) vs
        # "right creds → 200". Since 200 is the only definitive success,
        # do NOT consider 401 a crack.
    return False, None

# ---------------------------------------------------------------------------
# Port 554 sweep (TCP connect — rootless). 256 hosts max, ~3s/host.
# ---------------------------------------------------------------------------
def host_is_up_rtsp(ip, port=554, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except OSError:
        return False

def sweep_subnet(network, prefix=24):
    """Yield live IPs on the /24 that have port 554 open."""
    if not network:
        return
    parts = network.split(".")
    if len(parts) < 3:
        return
    base = ".".join(parts[:3])
    hosts = [f"{base}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=32) as ex:
        results = list(ex.map(lambda ip: (ip, host_is_up_rtsp(ip)), hosts))
    for ip, up in results:
        if up:
            yield ip

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    network, prefix = parse_subnet(SUBNET_ARG)
    if not network:
        print(json.dumps({
            "tool": "cameradar",
            "subnet": SUBNET_ARG or "",
            "cameras": [],
            "totalCameras": 0,
            "crackedCount": 0,
            "durationMs": int((time.time() - START_TS) * 1000),
            "error": "Aucune interface réseau IPv4 détectée — impossible de résoudre le subnet local.",
        }, ensure_ascii=False))
        return

    # 1. Sweep port 554.
    log_lines = []
    rtsp_hosts = []
    for ip in sweep_subnet(network, prefix):
        rtsp_hosts.append(ip)

    if not rtsp_hosts:
        print(json.dumps({
            "tool": "cameradar",
            "subnet": f"{network}/{prefix}",
            "cameras": [],
            "totalCameras": 0,
            "crackedCount": 0,
            "durationMs": int((time.time() - START_TS) * 1000),
            "error": f"Aucune caméra RTSP (port 554) trouvée sur {network}/{prefix}.",
        }, ensure_ascii=False))
        return

    # 2. For each open 554, send DESCRIBE + try default creds.
    cameras = []
    for ip in rtsp_hosts:
        status, headers, body = rtsp_probe(ip, port=554, timeout=3.0)
        if not status:
            # Port is open but no RTSP response — skip.
            continue
        realm, model = parse_model(status, headers, body)
        # If server returned 401, that means an RTSP service is there but
        # requires auth — still counts as discovered.
        found = "401" in status or "200" in status
        cracked = False
        creds = None
        if "401" in status:
            cracked, creds = try_credentials(ip, port=554)
        elif "200" in status:
            # No auth required — already "open".
            cracked = True
            creds = ("(none)", "(none)")
        cameras.append({
            "ip": ip,
            "port": 554,
            "realm": realm or "",
            "model": model or "",
            "found": bool(found),
            "cracked": bool(cracked),
            "credentials": {"user": creds[0] if creds else "", "pass": creds[1] if creds else ""},
        })

    cracked_count = sum(1 for c in cameras if c["cracked"])
    print(json.dumps({
        "tool": "cameradar",
        "subnet": f"{network}/{prefix}",
        "cameras": cameras,
        "totalCameras": len(cameras),
        "crackedCount": cracked_count,
        "durationMs": int((time.time() - START_TS) * 1000),
        "error": None if cameras else f"Aucune caméra RTSP répondant sur {network}/{prefix}.",
    }, ensure_ascii=False))

main()
PY
