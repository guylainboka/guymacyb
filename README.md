# Guyma Cyb

> Logiciel desktop de cybersécurité défensive — audit web, scan réseau, tests WiFi, laboratoire d'attaques, remédiation. 100% local, sans IA ni cloud.

[![Build Windows .exe](https://github.com/guylainboka/guymacyb/actions/workflows/build-windows.yml/badge.svg)](https://github.com/guylainboka/guymacyb/actions/workflows/build-windows.yml)
[![License](https://img.shields.io/badge/license-proprietary-red.svg)](LICENSE)

## 📥 Télécharger le .exe Windows

Deux options :

### Option 1 — Build automatique GitHub Actions (le plus simple)
1. Va sur l'onglet **[Actions](https://github.com/guylainboka/guymacyb/actions)** du dépôt
2. Clique sur le workflow **"Build Windows .exe"** le plus récent
3. En bas, section **Artifacts** → télécharge `GuymaCyb-Setup-windows-x64`
4. Décompresse le zip → double-clique sur `GuymaCyb-Setup-v1.0.0.exe`

### Option 2 — Release GitHub (versions stables)
- Va sur **[Releases](https://github.com/guylainboka/guymacyb/releases)**
- Télécharge le `.exe` directement (disponible quand un tag `v*` est poussé)

## 🚀 Démarrage rapide (développement)

```bash
git clone https://github.com/guylainboka/guymacyb.git
cd guymacyb
bun install                 # ou: npm install

# Compiler le noyau Rust (1 fois)
cd shadowscan-core && cargo build --release && cd ..

# Lancer en dev
bun run dev                 # → http://localhost:3000
```

## 🏗️ Build manuel du .exe (sur Windows)

Prérequis : Node.js 20+, Bun, Rust (target `x86_64-pc-windows-gnu`), Git.

```powershell
desktop\build-windows-exe.bat
# → dist_electron\GuymaCyb-Setup-v1.0.0.exe
```

Voir [`desktop/README.md`](desktop/README.md) pour les détails et le cross-compile depuis Linux.

## 🧱 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Electron (GUI shell, fenêtre desktop)                      │
│  └─ Charge http://localhost:3000 dans BrowserWindow         │
└─────────────────────────────────────────────────────────────┘
                            │ spawn
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Express backend (dist-server/server.cjs, bundlé esbuild)   │
│  ├─ 25 endpoints API REST                                   │
│  ├─ SQLite (sql.js / shadow_core.db)                        │
│  └─ Spawne les moteurs externes à la demande                │
└─────────────────────────────────────────────────────────────┘
          │ spawn                        │ spawn
          ▼                              ▼
┌──────────────────────┐   ┌─────────────────────────────────┐
│  Noyau Rust          │   │  Scripts Linux de sécurité      │
│  shadowscan-core.exe │   │  security-scripts/*.sh          │
│  (scan, recon,       │   │  (nmap, nikto, whatweb,         │
│   headers, vuln)     │   │   dirbrute, dnsrecon, ssl-audit,│
│  CLI JSON pur-Rust   │   │   ping, mtr, netcat, iperf3,    │
│                      │   │   wifi-scan, wpa-audit,         │
│                      │   │   deauth-detect)                │
└──────────────────────┘   └─────────────────────────────────┘
```

## 📦 Modules (9)

| Module | Description | État Windows |
|---|---|---|
| 🔍 Scanner & Recon | Cartographie cible, connectivité, recon DNS/ports | ✅ |
| 🌐 Analyse Web | Scan HTTP, crawl, audit headers (Rust) | ✅ |
| ⚡ Tests Actifs | Suite active avec terminal live, Safe Mode | ✅ |
| 🧪 Lab Attaques Web | 10 vecteurs (SQLi, XSS, SSRF, IDOR, JWT, CORS…) | ✅ |
| 🛜 WiFi & Réseau | Scan AP, audit WPA/WPA2/WPA3, détection deauth | ⚠️ simulation |
| 🧫 Lab Attaques WiFi | 8 vecteurs (deauth, evil-twin, KRACK, WPS…) | ✅ |
| 📚 Cours & Notions | 14 notions (WEP→WPA3, OSI, KRACK, AES-CCMP…) | ✅ |
| ✅ Résultats & Preuves | Findings, CVSS, preuves HTTP | ✅ |
| 📊 Rapport & Remédiation | Rapport consolidé, export SQLite | ✅ |

⚠️ Le module WiFi temps réel nécessite Linux (aircrack-ng, mode monitor). Sur Windows, il bascule en mode simulation réaliste.

## 🛠️ Stack technique

- **Frontend** : React 19, Vite 8, TypeScript 7, Tailwind CSS 4
- **Backend** : Express 4, sql.js (SQLite), esbuild (bundle production)
- **Noyau scan** : Rust (reqwest + rustls, pure-Rust, cross-compilable)
- **Scripts sécurité** : Bash + fallbacks Python
- **Desktop** : Electron 33 + electron-builder 25 (NSIS installer)
- **CI/CD** : GitHub Actions (windows-latest)

## 🔒 Principes défensifs

- **100% local** : aucun cloud, aucune IA externe
- **Safe Mode** par défaut sur tous les tests actifs
- **Autorisation opérateur** obligatoire + horodatage SQLite
- **Preuves non-destructives** uniquement
- **Mapping OWASP Top 10 / CWE / MITRE ATT&CK**
- **Scoring CVSS** sur chaque vulnérabilité

## 📋 Installation des outils Linux (pour scan réel)

```bash
sudo ./security-scripts/install-tools.sh
# Installe : nmap, nikto, whatweb, sslscan, sqlmap, gobuster, dirb,
#            dnsrecon, masscan, hydra, wpscan, aircrack-ng, nftables,
#            tshark, suricata, snort, OpenVAS/Greenbone, nuclei,
#            iproute2, mtr, iperf3, netcat, socat, dig, ethtool...
```

## 📁 Structure du projet

```
guymacyb/
├── .github/workflows/      # CI GitHub Actions (build .exe)
├── shadowscan-core/        # Noyau Rust (Cargo.toml, src/main.rs)
├── security-scripts/       # 13 scripts Bash + 4 fallbacks Python
├── src/
│   ├── components/views/   # 9 vues React (frontend)
│   ├── data/               # Vecteurs lab + notions cours
│   ├── server/             # toolbridge, scanner, db, securityLab
│   └── types/              # Types TypeScript
├── desktop/                # Electron + NSIS + esbuild bundle
├── electron-builder.yml    # Config packaging Windows
├── server.ts               # Point d'entrée Express (25 endpoints)
└── package.json
```

## 📖 Documentation

- [`desktop/README.md`](desktop/README.md) — Packaging Windows (prérequis, build, cross-compile)
- [`shadowscan-core/README.md`](shadowscan-core/README.md) — Noyau Rust (CLI, sous-commandes)
- [`security-scripts/install-tools.sh`](security-scripts/install-tools.sh) — Installateur outils Linux
- [Onglet Actions GitHub](https://github.com/guylainboka/guymacyb/actions) — Builds CI et artifacts

## 📝 License

Propriétaire — © Guyma Cyb Security Systems. Voir [`desktop/assets/LICENSE.txt`](desktop/assets/LICENSE.txt) (à créer).
