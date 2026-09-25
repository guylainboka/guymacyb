# Guyma Cyb — Desktop Packaging (Electron + NSIS)

This folder contains everything needed to turn the Guyma Cyb web app (React +
Express + Rust + shell scripts) into a real installable Windows `.exe`.

## Architecture overview

```
┌────────────────────────────────────────────────────────────────────────┐
│  GuymaCyb.exe  (Electron shell — Chromium + Node.js bundled)           │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  desktop/electron-main.cjs  (main process)                       │  │
│  │   • single-instance lock                                         │  │
│  │   • spawns the bundled Express backend as a Node child process   │  │
│  │   • polls http://127.0.0.1:3000/api/health before loading the UI │  │
│  │   • augments PATH with bundled tools/ (nmap, openssl, git-bash)  │  │
│  │   • graceful shutdown (taskkill /T on Windows, SIGTERM elsewhere)│  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                          │                                             │
│                          ▼ spawn (ELECTRON_RUN_AS_NODE=1)              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  dist-server/server.cjs  (Express backend, bundled by esbuild)   │  │
│  │   • serves the pre-built frontend from dist/                     │  │
│  │   • /api/scan/analyze   → toolbridge.coreScan()  → Rust binary   │  │
│  │   • /api/tools/nmap     → toolbridge.toolNmap()  → bash script   │  │
│  │   • SQLite via sql.js (loads dist-server/sql-wasm.wasm)          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                          │ on each scan request                        │
│       ┌──────────────────┴──────────────────┐                          │
│       ▼                                     ▼                          │
│  shadowscan-core.exe                  security-scripts/*.sh            │
│  (Rust, pure-rustls)                  (nmap-scan.sh, nikto-scan.sh, …) │
│  CLI JSON: scan / recon / headers     Spawned via `bash` (Git Bash     │
│                                       on Windows, native bash on Linux)│
└────────────────────────────────────────────────────────────────────────┘
```

### Files in this folder

| File                       | Role                                                                                |
| -------------------------- | ----------------------------------------------------------------------------------- |
| `electron-main.cjs`        | Electron main process — spawns backend, manages window, single-instance lock.       |
| `build-server-bundle.js`   | esbuild script that bundles `server.ts` + `src/server/*.ts` → `dist-server/server.cjs` and copies `sql-wasm.wasm`. |
| `GuymaCyb-Setup.nsi`       | Raw NSIS installer script (fallback to electron-builder, which also uses NSIS internally). |
| `build-windows-exe.bat`    | Full Windows build pipeline (Rust → frontend → server bundle → electron-builder/NSIS). |
| `README.md`                | This file.                                                                          |
| `assets/`                  | (Create this folder) `icon.ico`, `LICENSE.txt`, optional wizard/header bitmaps.    |

### Files at the project root

| File                    | Role                                                                    |
| ----------------------- | ----------------------------------------------------------------------- |
| `electron-builder.yml`  | electron-builder config (appId, files, extraResources, nsis options).   |

---

## Prerequisites (Windows build machine)

Install on the Windows machine that will produce the `.exe`:

1. **Node.js 18+** with npm — <https://nodejs.org/>
2. **Bun** (optional, faster frontend build) — <https://bun.sh/>
3. **Rust** via rustup — <https://rustup.rs/>
   - Add the Windows GNU target: `rustup target add x86_64-pc-windows-gnu`
   - (Alternative: use the MSVC target `x86_64-pc-windows-msvc` with VS Build Tools 2022.)
4. **NSIS 3.x** — <https://nsis.sourceforge.io/> (only required for the raw-NSIS fallback)
5. **MinGW-w64** (only if cross-compiling the Rust core from Linux) — see below.
6. (Optional, for code signing) An Authenticode certificate + set env vars `CSC_LINK` and `CSC_KEY_PASSWORD`.

### Optional bundled tools (recommended for full security feature set)

The Linux security scripts (`security-scripts/*.sh`) need a bash interpreter
and the underlying CLI tools to run. On Windows you can bundle:

| Tool            | Where to place it             | Notes                                                                         |
| --------------- | ----------------------------- | ----------------------------------------------------------------------------- |
| Git for Windows | `tools/git-bash/`             | Provides `bash.exe`, `sh.exe`, `usr/bin/openssl`, etc. **Required** for the `*.sh` scripts to run on Windows. |
| Nmap            | `tools/nmap/`                 | Download the latest Windows self-extracting exe from <https://nmap.org/download.html>, extract with 7-Zip. |
| OpenSSL         | `tools/openssl-win64/bin/`    | From <https://slproweb.com/products/Win32OpenSSL.html>.                       |
| dig / nslookup  | (built into Windows)          | No bundling needed.                                                           |
| Python 3        | `tools/python/`               | Only needed for the `builtin_*.py` fallback scripts (rarely invoked if the .sh wrappers find their main tool). |

The Electron main process automatically adds these folders to `PATH` before
spawning the backend, so the security scripts find them at runtime.

---

## How to build (on Windows)

From the project root:

```bat
:: 1. Install JS dependencies (one-time)
npm install

:: 2a. Default build (electron-builder + NSIS):
desktop\build-windows-exe.bat

:: 2b. Raw NSIS fallback (skips electron-builder, runs makensis directly):
desktop\build-windows-exe.bat nsis
```

The installer appears at:

```
dist_electron\GuymaCyb-Setup-v1.0.0.exe
```

### What the build script does (5 steps)

1. **Prereq checks** — Node, cargo, NSIS/electron-builder availability; ensures the `x86_64-pc-windows-gnu` Rust target is installed.
2. **Rust core** — `cd shadowscan-core && cargo build --release --target x86_64-pc-windows-gnu` → `shadowscan-core.exe`.
3. **Frontend SPA** — `bun run build` (or `npm run build`) → `dist/index.html` + assets.
4. **Backend bundle** — `node desktop/build-server-bundle.js` → `dist-server/server.cjs` (+ `sql-wasm.wasm`).
5. **Package** — `npx electron-builder --win nsis --x64` (default) or `makensis desktop/GuymaCyb-Setup.nsi` (fallback).

### Dev mode (no packaging)

```bat
:: Terminal 1: start the Express+Vite dev server
bun run dev            :: or: npm run dev

:: Terminal 2: launch Electron in dev mode (attaches to the dev server on :3000)
set NODE_ENV=development
npx electron desktop/electron-main.cjs
```

In dev mode, `electron-main.cjs` does **not** spawn a backend — it just opens
the BrowserWindow at `http://localhost:3000` and assumes you ran `bun run dev`
in another terminal. This keeps HMR fast.

---

## How to build from Linux (cross-compile caveats)

The frontend, backend bundle, and NSIS installer can be prepared on Linux, but
**the Rust core and Electron's own native modules need a Windows toolchain**.
Two paths:

### Option A — Linux cross-compile for the Rust core only (recommended)

```bash
# 1. Install MinGW-w64 and the Rust target
sudo apt install mingw-w64     # or: dnf install mingw64-gcc
rustup target add x86_64-pc-windows-gnu

# 2. Cross-compile the Rust core
cd shadowscan-core
cargo build --release --target x86_64-pc-windows-gnu
# -> shadowscan-core/target/x86_64-pc-windows-gnu/release/shadowscan-core.exe

# 3. Build the frontend and backend bundle (no Windows needed)
cd ..
bun install
bun run build                       # -> dist/
node desktop/build-server-bundle.js # -> dist-server/server.cjs

# 4. Hand off the staged tree to a Windows machine (or Wine) to run
#    electron-builder with --win nsis --x64
```

### Option B — Full Windows build on CI

Use a Windows GitHub Actions runner (or any Windows VM). The supplied
`desktop/build-windows-exe.bat` runs end-to-end on a clean Windows machine
after `npm install`.

> **Note on `aws-lc-rs`**: if you switch the Rust core to use `aws-lc-rs` for
> TLS, you'll need a C compiler (clang or MSVC) plus `cmake` and `nasm` on the
> Windows build machine. The current Cargo.toml uses `rustls` with
> `ring`-backend (pure Rust + prebuilt asm), so it cross-compiles cleanly with
> only MinGW.

---

## What works on Windows vs Linux-only

| Feature                                | Windows (.exe)             | Linux (AppImage)        |
| -------------------------------------- | -------------------------- | ----------------------- |
| React UI + Electron shell              | ✅ Native                  | ✅ Native               |
| SQLite persistence (`shadow_core.db`)  | ✅ via sql.js wasm         | ✅ via sql.js wasm      |
| Rust scan engine (`scan/recon/headers`)| ✅ `shadowscan-core.exe`   | ✅ `shadowscan-core`    |
| `nmap-scan.sh`                         | ⚠️ needs Git Bash + nmap   | ✅ native               |
| `nikto-scan.sh`                        | ⚠️ needs Git Bash + Perl + nikto | ✅ native          |
| `whatweb-scan.sh`                      | ⚠️ needs Git Bash + whatweb | ✅ native              |
| `dirbrute.sh`                          | ⚠️ needs Git Bash (builtin Python fallback works) | ✅ native |
| `dnsrecon.sh`                          | ✅ uses `dig` (built into Windows 10/11) | ✅ native |
| `ssl-audit.sh`                         | ⚠️ needs Git Bash + openssl | ✅ native              |
| `ping-probe.sh`                        | ✅ uses Windows `ping` via bash | ✅ native           |
| `mtr-trace.sh`                         | ⚠️ needs Git Bash + mtr/winmtr | ✅ native            |
| `netcat-probe.sh`                      | ⚠️ needs Git Bash + ncat   | ✅ native               |
| `iperf3-client.sh`                     | ⚠️ needs Git Bash + iperf3 | ✅ native               |

**Summary**: the Rust engine + React UI + SQLite always work. The Linux shell
scripts work on Windows **only if** you bundle Git Bash (under `tools/git-bash/`)
and the underlying tool. Otherwise, calling those endpoints returns a clear
`{ error: "Script introuvable" }` or a tool-not-found error message — the rest
of the app keeps working.

---

## sql.js wasm bundling — how it works

`db.ts` calls `initSqlJs()` without a `locateFile` option. By default, sql.js
uses `__dirname + "/sql-wasm.wasm"` to find the wasm binary in Node.js.

When we bundle the server with esbuild (`desktop/build-server-bundle.js`):

- The bundle is CJS at `dist-server/server.cjs`.
- `__dirname` at runtime resolves to `dist-server/`.
- We copy `node_modules/sql.js/dist/sql-wasm.wasm` to `dist-server/sql-wasm.wasm`.

So sql.js finds the wasm next to the bundle with **no changes to `db.ts`**.

---

## Icon & license assets

Before running the build, place these (or the installer falls back to defaults):

```
desktop/
  assets/
    icon.ico           # multi-resolution Windows icon (256/128/64/48/32/16)
    LICENSE.txt        # plain-text license shown on the NSIS license page
    wizard.bmp         # optional 164x314 NSIS welcome/finish bitmap
    header.bmp         # optional 150x57 NSIS header bitmap
```

If `icon.ico` is missing, electron-builder uses its default Electron icon and
NSIS uses its default blue install icon.

---

## Verifying the build

After a successful build:

```bat
:: The installer should exist and be ~150-200 MB:
dir dist_electron\GuymaCyb-Setup-v1.0.0.exe

:: Verify the bundled Rust binary was built for Windows:
file shadowscan-core\target\x86_64-pc-windows-gnu\release\shadowscan-core.exe
:: -> should print "PE32+ executable (console) x86-64, for MS Windows"
```

---

## Known caveats

### `server.ts` binds to `0.0.0.0:3000`

The Express backend (line 442 of `server.ts`) hardcodes `app.listen(PORT, '0.0.0.0', …)`.
That means the bundled backend, once spawned by Electron, is reachable from the
local network (not just loopback). The Electron main process polls
`http://127.0.0.1:3000` for health, which works fine, but for defense-in-depth
on production machines you should add a Windows Firewall rule to block inbound
connections to port 3000. The NSIS installer does **not** add this rule
automatically (to avoid surprising users with firewall prompts).

### sql.js wasm path

`db.ts` calls `initSqlJs()` without a `locateFile` option. sql.js's default
Node.js loader uses `__dirname + "/sql-wasm.wasm"`. In the esbuild bundle,
`__dirname` resolves to `dist-server/` (where `server.cjs` lives), so we copy
the wasm next to the bundle. No change to `db.ts` is required.

### `import.meta.url` in `toolbridge.ts`

`toolbridge.ts` uses `import.meta.url` to compute `__dirname`. In CJS output
esbuild leaves `import.meta` empty. `desktop/build-server-bundle.js` adds a
banner that defines `__import_meta_url = require("url").pathToFileURL(__filename).href`
and uses `define: { 'import.meta.url': '__import_meta_url' }` to substitute it.
This makes `fileURLToPath(import.meta.url)` resolve to `__filename` at runtime —
matching the dev-mode behaviour.

### `PROJECT_ROOT` resolution in bundled backend

`toolbridge.ts` derives `PROJECT_ROOT = path.resolve(__dirname, '../..')`. In dev
mode `__dirname` is `src/server/`, so `PROJECT_ROOT` is the project root. In the
bundled backend, `__dirname` is `dist-server/`, so `PROJECT_ROOT` would be one
level above the install dir — wrong. To work around this without modifying
`toolbridge.ts`, the Electron main process sets `SHADOWSCAN_CORE_PATH` and
`SECURITY_SCRIPTS_DIR` env vars before spawning the backend; toolbridge checks
these first and skips its broken `PROJECT_ROOT`-relative defaults.

### `vite` is external

`server.ts` imports `vite` at the top of the file (for dev-mode HMR middleware).
In production `NODE_ENV=production` skips that branch, but the static import
remains, so esbuild would try to bundle ~10 MB of vite dev tooling. The bundle
script marks `vite` as `external`, which means the bundled `server.cjs` will
fail to `require('vite')` if someone runs it in dev mode — that's fine, the
bundle is production-only.

### Windows code signing

The installer and `GuymaCyb.exe` are not signed by default. SmartScreen will
show a warning the first time a user runs the installer. To sign, set env vars
`CSC_LINK` (path to .pfx) and `CSC_KEY_PASSWORD` before running
`desktop\build-windows-exe.bat`. electron-builder picks them up automatically.

