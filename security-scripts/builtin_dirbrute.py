#!/usr/bin/env python3
"""
builtin_dirbrute.py — Découverte de chemins/dossiers web de secours.
Utilisé par dirbrute.sh lorsque gobuster/dirb ne sont pas installés.

Scan multi-thread (16) d'une wordlist intégrée contre la cible.
Signale les chemins renvoyant 200/301/302/401/403.

Usage : builtin_dirbrute.py <url> [wordlist_path]
Sortie : un objet JSON unique sur stdout.
"""
import json
import ssl
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin

UA = "GuymaCyb-Security-Auditor/1.0 (+security-research)"

DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "api", "api/v1", "api/v2", "config", "backup", ".env", ".env.local",
    ".env.production", ".git", ".git/config", ".git/HEAD", ".gitignore",
    "robots.txt", "sitemap.xml", "sitemap.xml.gz", "server-status",
    "server-info", "phpinfo.php", "info.php", "test", "debug", "docs",
    "swagger", "swagger.json", "swagger-ui", "openapi.json", "openapi.yaml",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "metrics", "health", "status", "heartbeat", ".well-known/security.txt",
    "cgi-bin", "cgi-bin/printenv", "uploads", "files", "assets", "static",
    "js", "css", "images", "img", "vendor", "node_modules", "package.json",
    "composer.json", "composer.lock", ".DS_Store", "database.sql", "db.sql",
    "dump.sql", "backup.sql", "old", "new", "temp", "tmp", "private",
    "secret", "secrets", "keys", "token", "auth", "oauth", "dashboard",
    "panel", "control", "manage", "console", "config.php", "config.json",
    "config.yaml", "config.yml", "settings.py", "settings.json",
    "web.config", "htaccess", ".htaccess", "wp-config.php", "wp-config.bak",
    "xmlrpc.php", "install.php", "setup.php", "phpmyadmin", "pma",
    "mysql", "adminer", "adminer.php", "solr", "elastic", "elasticsearch",
    "kibana", "grafana", "prometheus", "jenkins", "gitlab", "jira",
    "confluence", ".svn", ".svn/entries", ".hg", ".bzr",
    "flag", "flag.txt", "id_rsa", "id_rsa.pub", "authorized_keys",
    "ssh", "ftp", "webalizer", "awstats", "logs", "log", "access.log",
    "error.log", "readme", "README", "README.md", "CHANGELOG",
    "LICENSE", "todo", "TODO", "notes", "draft",
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe(base_url, path, timeout=4):
    full = urljoin(base_url + "/", path.lstrip("/"))
    req = urllib.request.Request(
        full, headers={"User-Agent": UA}, method="GET"
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return path, r.status, len(r.read(65536))
    except urllib.error.HTTPError as e:
        return path, e.code, 0
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: builtin_dirbrute.py <url> [wordlist]"}))
        sys.exit(1)
    raw = sys.argv[1].strip()
    base = raw if "://" in raw else f"https://{raw}"
    wordlist = DEFAULT_WORDLIST
    if len(sys.argv) >= 3:
        try:
            with open(sys.argv[2], "r", encoding="utf-8", errors="replace") as f:
                wordlist = [w.strip() for w in f if w.strip() and not w.startswith("#")]
        except Exception as e:
            print(json.dumps({"error": f"wordlist illisible: {e}"}))
            sys.exit(1)

    found = []
    tested = 0
    start = time.monotonic()
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=16) as ex:
        futures = {ex.submit(probe, base, p): p for p in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            with lock:
                tested += 1
            if res and res[1] in (200, 301, 302, 303, 307, 308, 401, 403):
                path, status, size = res
                found.append({"path": path, "status": status, "size": size})

    duration_ms = int((time.monotonic() - start) * 1000)
    found.sort(key=lambda x: x["path"])
    print(json.dumps({
        "tool": "dirbrute",
        "target": base,
        "mode": "builtin-python",
        "discovered": found,
        "testedCount": tested,
        "foundCount": len(found),
        "scannedAt": now_iso(),
        "durationMs": duration_ms,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
