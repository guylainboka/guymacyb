#!/usr/bin/env python3
"""
builtin_portscan.py — Pure-Python TCP connect scanner.

Used as a fallback by nmap-scan.sh when the `nmap` binary is not installed.
Performs a simple TCP connect() probe against a fixed list of common ports,
with a per-port timeout and concurrent execution via threads.

CLI:
    builtin_portscan.py <host> [--ports 22,80,443] [--timeout 2] [--top N]

Stdout: exactly one JSON object (spec-compliant nmap-scan output).
Stderr: progress logs.
Exit:   0 on success, 1 on hard failure (still prints {"error":...} on stdout).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# Default port set required by the spec (Task C, §2).
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9090,
]

# Best-effort service labels for the default ports.
SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9090: "websm",
}


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit_error(msg: str) -> None:
    sys.stdout.write(json.dumps({"error": msg}) + "\n")
    sys.stdout.flush()


def log(tag: str, msg: str) -> None:
    sys.stderr.write(f"[{tag.upper()}] {msg}\n")
    sys.stderr.flush()


def probe_port(host: str, port: int, timeout: float) -> dict:
    """Attempt a TCP connect to (host, port). Returns a port result dict."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.monotonic()
        sock.connect((host, port))
        elapsed = (time.monotonic() - t0) * 1000.0
        result = {
            "port": port,
            "state": "open",
            "service": SERVICE_MAP.get(port, "unknown"),
            "reason": "syn-ack",
            "latencyMs": round(elapsed, 2),
        }
    except socket.timeout:
        result = {
            "port": port,
            "state": "filtered",
            "service": SERVICE_MAP.get(port, "unknown"),
            "reason": "no-response",
            "latencyMs": None,
        }
    except ConnectionRefusedError:
        result = {
            "port": port,
            "state": "closed",
            "service": SERVICE_MAP.get(port, "unknown"),
            "reason": "conn-refused",
            "latencyMs": None,
        }
    except OSError as exc:
        # Includes "no route to host", network unreachable, etc.
        result = {
            "port": port,
            "state": "filtered",
            "service": SERVICE_MAP.get(port, "unknown"),
            "reason": f"error:{exc.errno or 'unknown'}",
            "latencyMs": None,
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return result


def parse_ports(spec: str | None) -> list[int]:
    """Parse a port spec like '22,80,443' or '1-1000' into a sorted list."""
    if not spec:
        return list(DEFAULT_PORTS)
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                continue
            if lo_i > hi_i:
                lo_i, hi_i = hi_i, lo_i
            for p in range(max(1, lo_i), min(65535, hi_i) + 1):
                ports.add(p)
        else:
            try:
                p = int(chunk)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        return list(DEFAULT_PORTS)
    return sorted(ports)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Pure-Python TCP connect scanner (nmap fallback).")
    parser.add_argument("host", help="Target host (no scheme, no path).")
    parser.add_argument("--ports", default="", help="Port spec, e.g. '22,80,443' or '1-1000'.")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-port timeout (seconds).")
    parser.add_argument("--workers", type=int, default=32, help="Concurrent workers.")
    args = parser.parse_args(argv)

    if not args.host:
        emit_error("no host provided")
        return 1

    ports = parse_ports(args.ports)
    log("portscan", f"scanning {len(ports)} ports on {args.host} (timeout={args.timeout}s, workers={args.workers})")

    t_start = time.monotonic()
    results: list[dict] = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(probe_port, args.host, p, args.timeout): p for p in ports}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    p = futures[fut]
                    log("portscan", f"port {p} probe crashed: {exc}")
                    results.append({
                        "port": p,
                        "state": "filtered",
                        "service": SERVICE_MAP.get(p, "unknown"),
                        "reason": "probe-error",
                        "latencyMs": None,
                    })
    except KeyboardInterrupt:
        emit_error("interrupted")
        return 1

    duration_ms = int((time.monotonic() - t_start) * 1000)
    results.sort(key=lambda r: r["port"])

    # Mirror nmap's behavior: report only open ports in the compact JSON shape
    # required by the spec (still include closed/filtered in a `summary` field).
    open_ports = [r for r in results if r["state"] == "open"]

    payload = {
        "tool": "nmap",
        "target": args.host,
        "mode": "builtin-python",
        "ports": open_ports,
        "summary": {
            "open": len([r for r in results if r["state"] == "open"]),
            "closed": len([r for r in results if r["state"] == "closed"]),
            "filtered": len([r for r in results if r["state"] == "filtered"]),
            "totalScanned": len(results),
        },
        "scannedAt": iso_now(),
        "durationMs": duration_ms,
    }
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001
        emit_error(f"builtin_portscan crashed: {exc}")
        sys.exit(1)
