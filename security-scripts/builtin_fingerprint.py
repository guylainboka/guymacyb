#!/usr/bin/env python3
"""
builtin_fingerprint.py — Empreinte technologique web de secours (whatweb-like).
Utilisé par whatweb-scan.sh lorsque l'outil `whatweb` n'est pas installé.

Analyse les en-têtes HTTP et le HTML pour identifier les technologies :
 - Server, X-Powered-By, X-Generator, X-AspNet-Version
 - <meta name="generator">
 - Marqueurs HTML : wp-content (WordPress), __next (Next.js), vue, react, jquery,
   bootstrap, nginx, apache, cloudflare, fontawesome, etc.

Usage : builtin_fingerprint.py <url>
Sortie : un objet JSON unique sur stdout.
"""
import json
import re
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

UA = "GuymaCyb-Security-Auditor/1.0 (+security-research)"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        body = r.read(2_000_000).decode("utf-8", "replace")
        return r.status, dict(r.headers), body


def fingerprint_headers(headers):
    tech = []
    server = headers.get("Server") or headers.get("server") or ""
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    generator = headers.get("X-Generator") or headers.get("x-generator") or ""
    aspnet = headers.get("X-AspNet-Version") or headers.get("x-aspnet-version") or ""
    if server:
        tech.append(server)
    if powered:
        tech.append(powered)
    if generator:
        tech.append(generator)
    if aspnet:
        tech.append(f"ASP.NET {aspnet}")
    cf = headers.get("CF-Ray") or headers.get("cf-ray")
    if cf:
        tech.append("Cloudflare CDN")
    return tech, server


def fingerprint_html(body):
    tech = []
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    low = body.lower()
    checks = [
        ("wp-content", "WordPress"),
        ("wp-includes", "WordPress"),
        ("__next_data__", "Next.js"),
        ("__next", "Next.js/React"),
        ("data-reactroot", "React"),
        ("react", "React"),
        ("vue.", "Vue.js"),
        ("__nuxt", "Nuxt.js"),
        ("angular", "Angular"),
        ("jquery", "jQuery"),
        ("bootstrap", "Bootstrap"),
        ("font-awesome", "Font Awesome"),
        ("tailwind", "Tailwind CSS"),
        ("drupal", "Drupal"),
        ("joomla", "Joomla"),
        ("shopify", "Shopify"),
        ("magento", "Magento"),
        ("grafana", "Grafana"),
        ("jenkins", "Jenkins"),
        ("gitlab", "GitLab"),
        ("<meta name=\"generator\" content=\"", None),
    ]
    for marker, label in checks:
        if marker in low:
            if label:
                if label not in tech:
                    tech.append(label)
            elif marker.startswith("<meta"):
                mg = re.search(
                    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                    body,
                    re.I,
                )
                if mg:
                    g = mg.group(1).strip()
                    if g and g not in tech:
                        tech.append(f"Generator: {g}")

    if "nginx" in low and not any("nginx" in t.lower() for t in tech):
        tech.append("Nginx (HTML marker)")
    if "apache" in low and not any("apache" in t.lower() for t in tech):
        tech.append("Apache (HTML marker)")
    return tech, title


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: builtin_fingerprint.py <url>"}))
        sys.exit(1)
    raw = sys.argv[1].strip()
    url = raw if "://" in raw else f"https://{raw}"
    try:
        status, headers, body = fetch(url)
    except Exception as e:
        print(json.dumps({"error": f"echec fetch: {e}", "tool": "whatweb"}))
        sys.exit(1)

    tech_h, server = fingerprint_headers(headers)
    tech_html, title = fingerprint_html(body)
    seen = []
    for t in tech_h + tech_html:
        if t not in seen:
            seen.append(t)
    result = {
        "tool": "whatweb",
        "target": url,
        "mode": "builtin-python",
        "technologies": seen,
        "title": title,
        "statusCode": status,
        "server": server,
        "scannedAt": now_iso(),
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
