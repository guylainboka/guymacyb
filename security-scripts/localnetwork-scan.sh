#!/usr/bin/env bash
# localnetwork-scan.sh — Rootless local network discovery for Guyma Cyb.
#
# Usage:
#   ./localnetwork-scan.sh [interface]
#
# Strategy (all rootless — no raw sockets, no monitor mode, no sudo):
#   1. mDNS   — UDP multicast query to 224.0.0.251:5353 (avahi/Bonjour devices)
#   2. SSDP   — UDP M-SEARCH to 239.255.255.250:1900   (UPnP/IGD devices)
#   3. NetBIOS — UDP broadcast on 255.255.255.255:137  (Windows/Samba hosts)
#   4. rDNS   — reverse-DNS sweep of the local /24    (gethostbyaddr)
#   5. ARP cache read (/proc/net/arp) — MAC addresses for discovered IPs
#   6. TCP connect probe on a small set of common ports per discovered host
#
# NO invented data. If no interface / no hosts respond, an honest `error`
# field is returned with an empty `devices` array.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

IFACE="${1:-}"
log "localnetwork" "iface=${IFACE:-<auto>} starting rootless discovery"

python3 - "$IFACE" <<'PY'
import json, os, socket, struct, select, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

IFACE_ARG = sys.argv[1] if len(sys.argv) > 1 else ""
START_TS = time.time()

# On Linux, socket.ioctl doesn't exist — use fcntl.ioctl for SIOCGIFADDR.
import fcntl
SIOCGIFADDR = 0x8915

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# OUI vendor table (subset reused from wifi-scan.sh).
# ---------------------------------------------------------------------------
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

def lookup_vendor(mac):
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    return OUI_PREFIXES.get(prefix, "Unknown")

PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 515: "printer", 631: "ipp",
    1900: "ssdp", 5353: "mdns", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 8080: "http-proxy",
    8443: "https-alt", 9000: "sonarqube",
}

COMMON_PORTS = sorted(PORT_NAMES.keys())

# ---------------------------------------------------------------------------
# Local IP detection (no raw sockets — uses a UDP "connect" to pick the
# default-route interface's IP).
# ---------------------------------------------------------------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()

def detect_iface_name(local_ip):
    """Walk /sys/class/net and find the interface whose inet addr matches local_ip."""
    try:
        for dev in os.listdir("/sys/class/net"):
            if dev == "lo":
                continue
            # Read inet addr via SIOCGIFADDR through a socket (Linux: fcntl.ioctl).
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    info = fcntl.ioctl(s.fileno(), SIOCGIFADDR,
                                       struct.pack("256s", dev.encode()[:15]))
                    addr = socket.inet_ntoa(info[20:24])
                    if addr == local_ip:
                        return dev
                finally:
                    s.close()
            except OSError:
                continue
    except OSError:
        pass
    # Fallback: first non-lo interface.
    try:
        for dev in os.listdir("/sys/class/net"):
            if dev != "lo":
                return dev
    except OSError:
        pass
    return IFACE_ARG or ""

# ---------------------------------------------------------------------------
# mDNS discovery (UDP multicast 224.0.0.251:5353).
# ---------------------------------------------------------------------------
def probe_mdns(timeout=2.0):
    found = {}  # ip -> {hostname, discoveredVia}
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    # Standard DNS query for _services._dns-sd._udp.local (PTR).
    query = (
        b"\x00\x00"           # ID
        b"\x00\x00"           # flags (standard query)
        b"\x00\x01"           # QDCOUNT=1
        b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT/NSCOUNT/ARCOUNT=0
        + b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        + b"\x00\x0c"         # QTYPE = PTR
        + b"\x00\x01"         # QCLASS = IN
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    try:
        s.bind(("", MDNS_PORT))
    except OSError as e:
        # avahi-daemon may have port 5353 exclusively. Fall back to a random port.
        try:
            s.bind(("", 0))
        except OSError:
            s.close()
            return found
    # Join the multicast group so we receive multicast responses.
    try:
        mreq = struct.pack("4sl", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    except OSError:
        pass
    try:
        s.sendto(query, (MDNS_ADDR, MDNS_PORT))
    except OSError:
        s.close()
        return found
    s.setblocking(False)
    end = time.time() + timeout
    while time.time() < end:
        remaining = max(0.05, end - time.time())
        r, _, _ = select.select([s], [], [], remaining)
        if not r:
            continue
        try:
            data, addr = s.recvfrom(4096)
        except OSError:
            break
        ip = addr[0]
        if ip not in found:
            found[ip] = {"hostname": "", "discoveredVia": "mdns"}
    s.close()
    return found

# ---------------------------------------------------------------------------
# SSDP discovery (UDP M-SEARCH to 239.255.255.250:1900).
# ---------------------------------------------------------------------------
def probe_ssdp(timeout=2.0):
    found = {}
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    except OSError:
        pass
    try:
        s.bind(("", 0))
    except OSError:
        s.close()
        return found
    try:
        s.sendto(msg, (SSDP_ADDR, SSDP_PORT))
    except OSError:
        s.close()
        return found
    s.setblocking(False)
    end = time.time() + timeout
    while time.time() < end:
        remaining = max(0.05, end - time.time())
        r, _, _ = select.select([s], [], [], remaining)
        if not r:
            continue
        try:
            data, addr = s.recvfrom(4096)
        except OSError:
            break
        ip = addr[0]
        # Try to extract the friendly name / location URL.
        hostname = ""
        try:
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    hostname = line.split(":", 1)[1].strip()[:80]
                    break
        except Exception:
            pass
        if ip not in found:
            found[ip] = {"hostname": hostname, "discoveredVia": "ssdp"}
        elif not found[ip]["hostname"] and hostname:
            found[ip]["hostname"] = hostname
    s.close()
    return found

# ---------------------------------------------------------------------------
# NetBIOS Name Service broadcast (UDP 255.255.255.255:137).
# ---------------------------------------------------------------------------
def probe_netbios(timeout=2.0):
    found = {}
    NB_ADDR = "255.255.255.255"
    NB_PORT = 137
    # NBNS query for the wildcard name "*". The encoded form of '*' (0x2A) is
    # 'CK' (high nibble + 'A', low nibble + 'A'), padded with 30 'A's.
    query = (
        b"\x00\x00"           # txn id
        b"\x00\x10"           # flags: broadcast, recursion desired
        b"\x00\x01"           # QDCOUNT=1
        b"\x00\x00\x00\x00\x00\x00"
        + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        + b"\x00\x21"         # QTYPE = NBSTAT
        + b"\x00\x01"         # QCLASS = IN
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("", 0))
    except OSError:
        s.close()
        return found
    try:
        s.sendto(query, (NB_ADDR, NB_PORT))
    except OSError:
        s.close()
        return found
    s.setblocking(False)
    end = time.time() + timeout
    while time.time() < end:
        remaining = max(0.05, end - time.time())
        r, _, _ = select.select([s], [], [], remaining)
        if not r:
            continue
        try:
            data, addr = s.recvfrom(4096)
        except OSError:
            break
        ip = addr[0]
        hostname = ""
        mac = ""
        # The NBSTAT response has a header (12 bytes) + the echoed question (~34 bytes
        # fixed-length given our query), then 1 byte num_names, then name entries,
        # and at the very end a 6-byte MAC. The variable-length part makes parsing
        # brittle; we just attempt to read the trailing MAC and the first name.
        try:
            if len(data) >= 12:
                qdcount = (data[4] << 8) | data[5]
                offset = 12
                # Skip the question section (each question ends with a 0x00 type+class).
                for _ in range(qdcount):
                    # Skip labels until null terminator
                    while offset < len(data) and data[offset] != 0:
                        # compression pointer (high 2 bits = 0b11)
                        if (data[offset] & 0xC0) == 0xC0:
                            offset += 2
                            break
                        offset += data[offset] + 1
                    else:
                        # skip the 0x00 terminator
                        offset += 1
                    offset += 4  # QTYPE + QCLASS (2 + 2)
                # Now we should be at the answer section. If ANCOUNT > 0 we skip its
                # header (10 bytes) + name pointer (2 bytes), then 1 byte num_names.
                ancount = (data[6] << 8) | data[7]
                if ancount > 0 and offset + 12 <= len(data):
                    # Skip name (compression pointer = 2 bytes) + type/class/ttl/rdlength (10 bytes).
                    offset += 2 + 10
                    num_names = data[offset]
                    offset += 1
                    # Each name entry: 15 bytes name + 1 suffix byte + 2 bytes flags = 18 bytes.
                    if offset + 18 <= len(data):
                        name_field = data[offset:offset+15]
                        hostname = name_field.decode("ascii", errors="replace").strip()
                    # The MAC is at the end of the resource data, after all name entries.
                    mac_offset = offset + 18 * num_names
                    if mac_offset + 6 <= len(data):
                        mac_bytes = data[mac_offset:mac_offset+6]
                        mac = ":".join("%02X" % b for b in mac_bytes)
        except Exception:
            pass
        if ip not in found:
            found[ip] = {"hostname": hostname, "mac": mac, "discoveredVia": "netbios"}
        else:
            if not found[ip]["hostname"] and hostname:
                found[ip]["hostname"] = hostname
            if not found[ip].get("mac") and mac:
                found[ip]["mac"] = mac
    s.close()
    return found

# ---------------------------------------------------------------------------
# rDNS sweep of the local /24.
# ---------------------------------------------------------------------------
def rdns_one(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return (ip, host)
    except (socket.herror, socket.herror, OSError):
        return None

def rdns_sweep(subnet_base, count=254):
    results = {}
    ips = [f"{subnet_base}.{i}" for i in range(1, count + 1)]
    with ThreadPoolExecutor(max_workers=32) as ex:
        for r in ex.map(rdns_one, ips):
            if r:
                results[r[0]] = r[1]
    return results

# ---------------------------------------------------------------------------
# ARP cache read (/proc/net/arp).
# ---------------------------------------------------------------------------
def get_arp_table():
    arp = {}
    try:
        with open("/proc/net/arp", "r") as fh:
            lines = fh.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3].upper()
                    if mac != "00:00:00:00:00:00" and mac.count(":") == 5:
                        arp[ip] = mac
    except OSError:
        pass
    return arp

# ---------------------------------------------------------------------------
# TCP port probe (rootless connect()).
# ---------------------------------------------------------------------------
def tcp_probe(ip, port, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except OSError:
        return False

def scan_host_ports(ip, ports=COMMON_PORTS, timeout=0.5):
    results = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        out = list(ex.map(lambda p: (p, tcp_probe(ip, p, timeout)), ports))
    for port, is_open in out:
        if is_open:
            results.append({
                "port": port,
                "service": PORT_NAMES.get(port, "unknown"),
                "state": "open",
            })
    results.sort(key=lambda r: r["port"])
    return results

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
local_ip = get_local_ip()
if local_ip == "127.0.0.1":
    print(json.dumps({
        "tool": "localnetwork-scan",
        "interface": IFACE_ARG or "",
        "localIp": local_ip,
        "subnet": "",
        "devices": [],
        "totalCount": 0,
        "scannedAt": now_iso(),
        "durationMs": int((time.time() - START_TS) * 1000),
        "error": ("Aucune interface réseau non-loopback détectée. "
                  "Le scan réseau local nécessite une carte réseau connectée "
                  "(Wi-Fi ou Ethernet). GuymaCyb ne génère jamais de données inventées."),
    }, ensure_ascii=False))
    sys.exit(0)

subnet_base = ".".join(local_ip.split(".")[:3])

mdns_results = probe_mdns(timeout=2.0)
ssdp_results = probe_ssdp(timeout=2.0)
netbios_results = probe_netbios(timeout=2.0)
rdns_results = rdns_sweep(subnet_base)

# After all the probes, the ARP cache may now hold MACs for the discovered IPs.
arp = get_arp_table()

devices = {}  # ip -> dict

def add_device(ip, hostname="", mac="", discovered_via=""):
    if not ip or ip.startswith("127."):
        return
    if ip in devices:
        d = devices[ip]
        if hostname and not d.get("hostname"):
            d["hostname"] = hostname
        if mac and not d.get("mac"):
            d["mac"] = mac
            d["vendor"] = lookup_vendor(mac)
        if discovered_via and discovered_via not in d["discoveredVia"]:
            d["discoveredVia"].append(discovered_via)
        return
    devices[ip] = {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": lookup_vendor(mac) if mac else "Unknown",
        "discoveredVia": [discovered_via] if discovered_via else [],
        "openPorts": [],
        "services": [],
    }

for ip, info in mdns_results.items():
    add_device(ip, info.get("hostname", ""), arp.get(ip, ""), "mdns")
for ip, info in ssdp_results.items():
    add_device(ip, info.get("hostname", ""), arp.get(ip, ""), "ssdp")
for ip, info in netbios_results.items():
    add_device(ip, info.get("hostname", ""), info.get("mac") or arp.get(ip, ""), "netbios")
for ip, host in rdns_results.items():
    add_device(ip, host, arp.get(ip, ""), "rdns")
# Anything the kernel has cached in /proc/net/arp counts too (recent contact).
for ip, mac in arp.items():
    add_device(ip, "", mac, "arp")

# Quick TCP port scan on every discovered host.
for ip, d in devices.items():
    try:
        ports = scan_host_ports(ip, COMMON_PORTS, timeout=0.5)
        d["openPorts"] = [p["port"] for p in ports]
        d["services"] = ports
    except OSError:
        # Host may have become unreachable mid-scan — leave empty.
        pass

devices_list = list(devices.values())
devices_list.sort(key=lambda d: [int(x) for x in d["ip"].split(".") if x.isdigit()])

iface = IFACE_ARG or detect_iface_name(local_ip)
duration_ms = int((time.time() - START_TS) * 1000)

print(json.dumps({
    "tool": "localnetwork-scan",
    "interface": iface,
    "localIp": local_ip,
    "subnet": f"{subnet_base}.0/24",
    "devices": devices_list,
    "totalCount": len(devices_list),
    "scannedAt": now_iso(),
    "durationMs": duration_ms,
    "error": None if devices_list else (
        "Aucun hôte découvert via mDNS/SSDP/NetBIOS/rDNS. Le réseau local est "
        "probablement silencieux, isolé, ou les protocoles de découverte sont "
        "bloqués par le firewall du système hôte. GuymaCyb ne génère pas de données inventées."
    ),
}, ensure_ascii=False))
PY
