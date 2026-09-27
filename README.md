# Guyma Cyb

> Logiciel Windows de cybersécurité qui exécute de **vrais outils Linux** via le pont WSL
> (Windows Subsystem for Linux). Inspiré de **StrykerOSS** (application Android qui fait
> tourner un chroot Debian/QEMU pour lancer les outils Unix), adapté à Windows via WSL.
> **Aucune simulation** : outils réels, messages honnêtes si le matériel manque.

[![Build Windows .exe](https://github.com/guylainboka/guymacyb/actions/workflows/build-windows.yml/badge.svg)](https://github.com/guylainboka/guymacyb/actions/workflows/build-windows.yml)
[![License](https://img.shields.io/badge/license-proprietary-red.svg)](LICENSE)

## 🎯 Concept

Guyma Cyb est un logiciel desktop Windows **natif** (Electron) qui fait tourner de vrais
outils Linux de sécurité (nmap, aircrack-ng, nikto, hashcat, searchsploit, metasploit…)
grâce au **pont WSL**. Le logiciel se lance comme n'importe quelle application Windows —
double-clic sur l'icône — et les outils Linux tournent en arrière-plan via WSL.

| Plateforme | Comment les outils Linux tournent |
|---|---|
| **Windows** (déploiement final) | `wsl.exe -d Ubuntu -- bash <script>` — WSL est un sous-système Windows (démarrage < 1s, pas une VM traditionnelle) |
| **Linux** (dev/sandbox) | exécution directe (`bash <script>`) — équivalent natif |

### Stratégie d'exécution en 3 étapes (jamais de simulation)

1. **Outil natif** si installé (nmap, aircrack-ng, hashcat…) → exécution réelle
2. **Implémentation built-in Node** si l'outil manque → scan TCP par sockets, fetch HTTP
   réel, inspection TLS via `tls.connect`, DNS réel, découverte mDNS/SSDP/NetBIOS par
   multicast UDP
3. **État honnête** si le matériel manque (clé WiFi mode monitor) → message clair,
   données vides, **jamais de fausses données**

## 📥 Télécharger le .exe Windows

### Option 1 — Build automatique GitHub Actions (le plus simple)
1. Onglet **[Actions](https://github.com/guylainboka/guymacyb/actions)** du dépôt
2. Cliquez sur le workflow **"Build Windows .exe"** le plus récent (vert ✓)
3. En bas, section **Artifacts** → téléchargez `GuymaCyb-Setup-windows-x64`
4. Décompressez le zip → double-cliquez `GuymaCyb-Setup-v1.0.0.exe`

### Option 2 — Release GitHub (versions stables)
- Allez sur **[Releases](https://github.com/guylainboka/guymacyb/releases)**
- Téléchargez le `.exe` directement (disponible quand un tag `v*` est poussé)

## 🚀 Démarrage rapide (développement)

```bash
git clone https://github.com/guylainboka/guymacyb.git
cd guymacyb
bun install                 # ou: npm install

# (optionnel) Compiler le noyau Rust — un fallback Node réel est intégré,
# donc cette étape n'est plus obligatoire
cd shadowscan-core && cargo build --release && cd ..

# Lancer en dev
bun run dev                 # → http://localhost:3000
```

## 🏗️ Build du .exe (3 façons)

### Façon 1 — GitHub Actions (zéro setup local)
Push sur `main` ou tag `v*` → le workflow build automatiquement. Téléchargez l'artifact.
Voir https://github.com/guylainboka/guymacyb/actions

### Façon 2 — Build local Windows (le plus complet)
Pré-requis : Node 20+, Bun, Git, (Rust optionnel), Windows SDK (pour la signature).
```powershell
git clone https://github.com/guylainboka/guymacyb.git
cd guymacyb
bun install
desktop\build-windows-exe.bat
# → dist_electron\GuymaCyb-Setup-v1.0.0.exe (signé si .pfx présent)
```

### Façon 3 — Sans Rust (le plus rapide, grâce au fallback Node)
```powershell
bun install
bun run build
node desktop\build-server-bundle.js
npx electron-builder --win nsis --x64
```

## 🪟 Assistant de premier lancement (wizard)

Au premier lancement du `.exe`, un **assistant de configuration** démarre avant
l'application principale :

1. **Bienvenue** — présente le concept
2. **WSL** — détecte WSL (`wsl.exe -l -v`), propose l'installation en 1 clic
   (élévation UAC → `wsl --install`)
3. **Outils Linux** — grille des 15 outils (nmap, aircrack-ng…), bouton
   "Installer les manquants" → `apt-get install` dans WSL via `-u root` (pas de prompt sudo)
4. **Terminé** — récapitulatif + "Lancer Guyma Cyb"

Un fichier-marqueur `userData/.guymacyb-setup-done` empêche le wizard de reparaître.
Bouton "Configurer plus tard" à chaque étape.

## 🧱 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Electron (GUI shell, fenêtre desktop Windows)              │
│  ├─ Wizard de premier lancement (setup-wizard.html)         │
│  └─ Charge http://localhost:3000 dans BrowserWindow         │
└─────────────────────────────────────────────────────────────┘
                            │ spawn (ELECTRON_RUN_AS_NODE)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Express backend (dist-server/server.cjs, bundlé esbuild)   │
│  ├─ 30+ endpoints API REST                                   │
│  ├─ SQLite (sql.js WASM / shadow_core.db)                   │
│  └─ toolbridge.ts : pont WSL                                │
└─────────────────────────────────────────────────────────────┘
          │ spawn                        │ spawn
          ▼                              ▼
┌──────────────────────┐   ┌─────────────────────────────────┐
│  Noyau Rust          │   │  Scripts Linux de sécurité      │
│  shadowscan-core.exe │   │  security-scripts/*.sh          │
│  (scan, recon,       │   │  (nmap, nikto, whatweb,         │
│   headers, vuln)     │   │   dirbrute, dnsrecon, ssl-audit,│
│  OU fallback Node    │   │   ping, mtr, netcat, iperf3,    │
│  (fetch/net/tls/dns) │   │   wifi-scan, wpa-audit,         │
│                      │   │   deauth-detect, handshake,    │
│                      │   │   crack, wps, mac-changer,     │
│                      │   │   localnetwork, arsenal,        │
│                      │   │   geomac, cameradar, hid, usb)  │
└──────────────────────┘   └─────────────────────────────────┘
                                        │
                                        ▼ sur Windows
                          wsl.exe -d Ubuntu -- bash <script>
```

## 📦 Modules (18)

| Module | Description | Source |
|---|---|---|
| 📊 Tableau de bord | Vue d'ensemble, stats, statut WSL | StrykerOSS |
| 📡 Scanner & Recon | ping, DNS, ports (nmap ou TCP built-in), WhatWeb, MTR, SSL/TLS | original |
| 🌐 Analyse Web | en-têtes de sécurité, endpoints, findings | original |
| 🖧 Réseau Local | découverte rootless mDNS/SSDP/NetBIOS/rDNS + scan TCP | StrykerOSS |
| ⚡ Tests Actifs | suite active avec terminal live, Safe Mode | original |
| 🧪 Lab Attaques Web | 8 vecteurs OWASP (SQLi, XSS, SSRF, IDOR, JWT, CORS…) | original |
| 🛜 WiFi & Réseau | scan AP, audit WPA, détection deauth (aircrack-ng réel) | original |
| 🔑 Handshakes | capture + crack WPA (airodump-ng/aircrack-ng) | StrykerOSS |
| 📻 Lab Attaques WiFi | 8 vecteurs (deauth, evil-twin, KRACK, WPS…) | original |
| 📦 Arsenal | searchsploit + hashcat | StrykerOSS |
| 📍 GeoMac | géolocalisation MAC (OUI + WiGLE + carte OSM) | StrykerOSS |
| 🔒 MAC Changer | spoofing MAC (macchanger / ip link) | StrykerOSS |
| ⌨️ HID Attacks | payloads DuckyScript réels (5 types) | StrykerOSS |
| 🔌 USB Arsenal | gestion configfs (HID/storage/RNDIS/ECM/ACM) | StrykerOSS |
| 📹 Cameradar | scan RTSP + credentials par défaut | StrykerOSS |
| 🖥️ Terminal | bash/Termux, PowerShell, CMD, Python (exécution réelle) | original |
| 📚 Cours & Notions | 14 notions (WEP→WPA3, OSI, KRACK, AES-CCMP…) | original |
| ✅ Résultats & Preuves | findings, CVSS, preuves non destructives | original |
| 📝 Rapport & Remédiation | rapport consolidé, export SQLite/JSON | original |
| ⚙️ Core Manager | statut WSL, outils installés/manquants, installation | StrykerOSS |

## 🛠️ Stack technique

- **Frontend** : React 19, Vite 8, TypeScript 7, Tailwind CSS 4, Material Symbols
- **Backend** : Express 4, sql.js (SQLite WASM), esbuild (bundle production)
- **Noyau scan** : Rust (shadowscan-core, pure-Rust HTTP/TLS) **OU** fallback Node réel
- **Scripts sécurité** : Bash + Python (fallbacks natifs)
- **Desktop** : Electron 33 + electron-builder 25 (NSIS installer)
- **Signature** : Authenticode (signtool sur Windows, osslsigncode sur CI)
- **CI/CD** : GitHub Actions (windows-latest)

## 🔐 Signature Authenticode

Le `.exe` est signé automatiquement si :
- **En local** : `desktop/signing/guymacyb-code-signing.pfx` présent + `CSC_KEY_PASSWORD`
- **En CI** : secrets `WIN_CERT_PFX` (base64) + `WIN_CERT_PASSWORD` définis sur GitHub

Générer un cert self-signed (tests) :
```bash
node desktop/signing/generate-cert.cjs MonMotDePasse
```

⚠ Un cert self-signed prouve l'intégrité mais SmartScreen affiche "éditeur inconnu".
Pour la confiance SmartScreen, achetez un cert OV/EV (DigiCert/Sectigo) ou utilisez
Azure Trusted Signing / SignPath (gratuit OSS). Voir `desktop/signing/README.md`.

## 🔒 Principes défensifs & pas de simulation

- Tout test actif requiert une **autorisation explicite** (modale d'autorisation)
- **Safe Mode** bloque les sondes destructives
- **Aucune donnée simulée** : les 7 scripts WiFi ne génèrent plus de fausses SSID
  (FreeWifi_secure, Livebox…) — quand l'outil/hardware manque, un message honnête est retourné
- Les scans de base (HTTP, ports, DNS, TLS, réseau local) fonctionnent **sans WSL**
  via les implémentations Node natives

## 📁 Structure du projet

```
├── src/
│   ├── app/                      # React app (Vite)
│   ├── components/
│   │   ├── common/               # Header, Sidebar, Footer, modales
│   │   └── views/                # 18 vues de modules
│   ├── server/                   # toolbridge.ts (pont WSL), scanner, db, securityLab
│   └── data/                     # labAttackVectors, wifiLabVectors, courseNotions
├── security-scripts/            # 18 scripts bash (outils Linux)
│   └── lib/common.sh
├── shadowscan-core/             # Noyau Rust (optionnel)
├── desktop/
│   ├── electron-main.cjs        # Processus principal Electron + wizard
│   ├── setup-wizard.html        # Assistant premier lancement
│   ├── setup-preload.cjs        # Pont IPC sécurisé
│   ├── build-icon.cjs           # Génère l'icône .ico multi-résolution
│   ├── build-windows-exe.bat    # Pipeline build Windows
│   ├── assets/icon.ico          # Icône Windows (256→16)
│   └── signing/                 # Cert + scripts de signature
├── server.ts                    # Express (30+ endpoints)
├── electron-builder.yml         # Config packaging NSIS
└── .github/workflows/            # CI GitHub Actions
```

## 📋 Installation des outils Linux (pour les modules avancés)

Le wizard et le module **Core Manager** font ça en 1 clic. Pour le faire manuellement
dans WSL :
```bash
sudo apt-get update
sudo apt-get install -y nmap nikto whatweb aircrack-ng tshark iperf3 \
  dnsrecon sslscan sqlmap gobuster hashcat exploitdb reaver macchanger \
  wireless-tools iw
```

Pour le scan WiFi temps réel : branchez une **clé USB WiFi mode monitor**
(chipset AR9271 ou 88XXAU) + activez `airmon-ng start wlan0`.

## 📖 Documentation

- `desktop/signing/README.md` — signature Authenticode détaillée
- `desktop/README.md` — packaging Electron
- `security-scripts/install-tools.sh --check` — vérifier les outils installés
- Module **Cours & Notions** dans l'app — 14 notions de cybersécurité

## 📝 License

Propriétaire — usage défensif et éducatif uniquement. Toute utilisation offensive
sur des systèmes non autorisés est interdite.
