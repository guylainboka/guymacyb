// Guyma Cyb — Electron Main Process
// ----------------------------------
// Production desktop shell for the Guyma Cyb cybersecurity application.
//
// Architecture at runtime (production):
//
//   ┌─────────────────────────────────────────────────────────────┐
//   │ Electron (Chromium + Node.js)  ←  this file                 │
//   │   └─ BrowserWindow → http://localhost:3000  (frontend SPA)  │
//   │   └─ child process: node dist-server/server.cjs (Express)   │
//   │        └─ spawn on demand: shadowscan-core.exe (Rust)       │
//   │        └─ spawn on demand: security-scripts/*.sh (bash)     │
//   └─────────────────────────────────────────────────────────────┘
//
// In DEV mode (`NODE_ENV=development` or `GCYB_DEV=1`) we DON'T spawn a server:
// the developer is expected to run `bun run dev` (or `npm run dev`) in a terminal,
// which starts the Express+Vite dev server on port 3000. Electron just connects to
// it. This keeps hot-reload fast during development.
//
// In PROD mode (packaged .exe), we spawn the bundled `dist-server/server.cjs`
// using Electron's bundled Node (`process.execPath` with `ELECTRON_RUN_AS_NODE=1`
// so it behaves as plain Node, not Electron). The Rust binary and security scripts
// are NOT started separately — they are spawned on demand by the Express server
// via toolbridge.ts (one process per scan request).

const { app, BrowserWindow, shell, dialog, ipcMain } = require('electron');
const path = require('path');
const { spawn, execFile } = require('child_process');
const http = require('http');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const APP_NAME = 'Guyma Cyb';
const APP_VERSION = '1.0.0';
const SERVER_PORT = 3000;
const SERVER_HOST = '127.0.0.1';
const HEALTH_URL = `http://${SERVER_HOST}:${SERVER_PORT}/api/health`;
const HEALTH_TIMEOUT_MS = 30000; // max wait for server to come up
const HEALTH_POLL_INTERVAL_MS = 300;

// dev mode flag: dev = developer runs `bun run dev` separately, Electron just attaches.
const IS_DEV =
  process.env.NODE_ENV === 'development' || process.env.GCYB_DEV === '1';

// Resolve resource directories. In a packaged Electron app (electron-builder),
// files bundled under `extraResources` end up under `process.resourcesPath`.
// In dev (running `electron .`), they live at the project root.
const PROJECT_ROOT = IS_DEV
  ? path.resolve(__dirname, '..')
  : path.dirname(app.getPath('exe'));

const RESOURCES_DIR = IS_DEV
  ? PROJECT_ROOT
  : process.resourcesPath; // electron-builder extraResources root

// Bundled backend bundle (built by desktop/build-server-bundle.js).
const SERVER_BUNDLE = path.join(RESOURCES_DIR, 'dist-server', 'server.cjs');

// Bundled Rust scan engine — spawned on demand by the Express server via
// toolbridge.ts. We expose its path to the server via env var.
const RUST_CORE =
  process.platform === 'win32'
    ? path.join(RESOURCES_DIR, 'shadowscan-core', 'shadowscan-core.exe')
    : path.join(RESOURCES_DIR, 'shadowscan-core', 'shadowscan-core');

// Bundled Linux security scripts (run via bash on Windows — see desktop/README.md).
const SECURITY_SCRIPTS_DIR = path.join(RESOURCES_DIR, 'security-scripts');

// Bundled third-party tools (nmap, openssl, etc.) if shipped — added to PATH.
const TOOLS_DIR = path.join(RESOURCES_DIR, 'tools');

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

let mainWindow = null;
let serverProcess = null;
let serverReady = false;
let healthTimer = null;
let healthDeadline = null;
let isQuitting = false;

// ---------------------------------------------------------------------------
// Single-instance lock — only one Guyma Cyb may run at a time.
// ---------------------------------------------------------------------------

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  // Another instance is already running — bail out silently.
  app.quit();
} else {
  app.on('second-instance', () => {
    // Someone tried to launch a second instance — focus our window instead.
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

// ---------------------------------------------------------------------------
// Backend server lifecycle
// ---------------------------------------------------------------------------

/**
 * Build the environment for the bundled Express server.
 *
 * - `ELECTRON_RUN_AS_NODE=1` makes Electron's `process.execPath` behave as plain
 *   Node.js (so we can run a .cjs script with the Electron binary itself, without
 *   shipping a separate Node.js runtime).
 * - `NODE_ENV=production` tells server.ts to serve the pre-built dist/ folder via
 *   express.static instead of starting Vite middleware.
 * - `PORT` and `HOST` pin the server to loopback only (no remote exposure).
 * - `SHADOWSCAN_CORE_PATH` and `SECURITY_SCRIPTS_DIR` override toolbridge.ts's
 *   PROJECT_ROOT-relative defaults so the bundled Rust binary and scripts are
 *   found at their extraResources locations.
 * - `PATH` is augmented with bundled `tools/` so security scripts can find
 *   nmap/openssl/dig/etc. if shipped.
 */
function buildServerEnv() {
  const env = { ...process.env };

  env.ELECTRON_RUN_AS_NODE = '1';
  env.NODE_ENV = 'production';
  env.PORT = String(SERVER_PORT);
  env.HOST = SERVER_HOST;
  env.GCYB_DESKTOP = '1';
  env.GCYB_VERSION = APP_VERSION;

  env.SHADOWSCAN_CORE_PATH = RUST_CORE;
  env.SECURITY_SCRIPTS_DIR = SECURITY_SCRIPTS_DIR;

  // Augment PATH so the security scripts (which call nmap, openssl, dig, …)
  // can find bundled Windows builds of those tools if the user shipped them
  // under tools/ (the installer can optionally bundle nmap, OpenSSL-Win64, etc).
  if (fs.existsSync(TOOLS_DIR)) {
    const pathSep = process.platform === 'win32' ? ';' : ':';
    const extraPaths = [];
    if (process.platform === 'win32') {
      // Common Windows tool subfolders — harmless if absent.
      extraPaths.push(
        path.join(TOOLS_DIR, 'nmap'),
        path.join(TOOLS_DIR, 'openssl-win64', 'bin'),
        path.join(TOOLS_DIR, 'git-bash', 'bin'),
        path.join(TOOLS_DIR, 'git-bash', 'usr', 'bin')
      );
    } else {
      extraPaths.push(
        path.join(TOOLS_DIR, 'bin'),
        '/usr/local/bin',
        '/usr/bin',
        '/bin'
      );
    }
    env.PATH = extraPaths.join(pathSep) + pathSep + (env.PATH || '');
  }

  return env;
}

/**
 * Spawn the bundled Express server (production only).
 * Returns the spawned ChildProcess or null on failure.
 */
function startBackendServer() {
  if (IS_DEV) {
    console.log('[GuymaCyb] DEV mode — assuming `bun run dev` is already running on port 3000.');
    return null;
  }

  if (!fs.existsSync(SERVER_BUNDLE)) {
    dialog.showErrorBox(
      `${APP_NAME} — installation corrompue`,
      `Le bundle serveur est introuvable :\n\n${SERVER_BUNDLE}\n\n` +
        `Réinstallez ${APP_NAME} pour corriger le problème.`
    );
    app.quit();
    return null;
  }

  // Use Electron's bundled Node runtime to run the .cjs bundle. Setting
  // ELECTRON_RUN_AS_NODE=1 in env makes process.execPath behave as Node.
  const env = buildServerEnv();

  console.log(`[GuymaCyb] spawning backend: ${process.execPath} ${SERVER_BUNDLE}`);
  const child = spawn(process.execPath, [SERVER_BUNDLE], {
    cwd: RESOURCES_DIR,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  child.stdout.on('data', (d) => {
    process.stdout.write(`[server] ${d}`);
  });
  child.stderr.on('data', (d) => {
    process.stderr.write(`[server] ${d}`);
  });

  child.on('exit', (code, signal) => {
    console.log(`[GuymaCyb] backend exited (code=${code} signal=${signal})`);
    if (!isQuitting && code !== 0) {
      dialog.showErrorBox(
        `${APP_NAME} — backend crash`,
        `Le moteur Guyma Cyb s'est arrêté de façon inattendue (code ${code}).\n` +
          `L'application va se fermer. Redémarrez ${APP_NAME}.`
      );
      app.quit();
    }
  });

  child.on('error', (err) => {
    console.error('[GuymaCyb] failed to spawn backend:', err);
    dialog.showErrorBox(
      `${APP_NAME} — erreur de démarrage`,
      `Impossible de démarrer le moteur backend :\n\n${err.message}`
    );
    app.quit();
  });

  return child;
}

/**
 * Poll the /api/health endpoint until it responds 200 or the deadline passes.
 * Resolves with true on success, false on timeout.
 */
function waitForServer() {
  return new Promise((resolve) => {
    const start = Date.now();

    const checkOnce = () => {
      const req = http.get(
        { hostname: SERVER_HOST, port: SERVER_PORT, path: '/api/health', timeout: 2000 },
        (res) => {
          // Drain & discard — we only care about the status code.
          res.resume();
          if (res.statusCode === 200) {
            serverReady = true;
            resolve(true);
          } else {
            scheduleNext();
          }
        }
      );
      req.on('error', () => scheduleNext());
      req.on('timeout', () => {
        req.destroy();
        scheduleNext();
      });
    };

    const scheduleNext = () => {
      const elapsed = Date.now() - start;
      if (elapsed >= HEALTH_TIMEOUT_MS) {
        resolve(false);
        return;
      }
      healthTimer = setTimeout(checkOnce, HEALTH_POLL_INTERVAL_MS);
    };

    checkOnce();
  });
}

/**
 * Kill the backend server gracefully (production only).
 */
function stopBackendServer() {
  if (!serverProcess) return;
  isQuitting = true;
  try {
    if (process.platform === 'win32') {
      // On Windows, `kill()` doesn't propagate to grandchildren; use taskkill
      // against the whole process tree to ensure shadowscan-core.exe children
      // (spawned on demand by the Express server) are reaped too.
      spawn('taskkill', ['/pid', String(serverProcess.pid), '/f', '/t'], {
        stdio: 'ignore',
        windowsHide: true,
      });
    } else {
      serverProcess.kill('SIGTERM');
      // Hard kill after 3s if still alive.
      setTimeout(() => {
        try { serverProcess.kill('SIGKILL'); } catch {}
      }, 3000);
    }
  } catch (err) {
    console.warn('[GuymaCyb] error stopping backend:', err);
  }
}

// ---------------------------------------------------------------------------
// First-run setup wizard — détection WSL / outils / Rust + installation
// ---------------------------------------------------------------------------

// Fichier-marqueur : s'il existe, le wizard a déjà été complété (ou sauté).
const SETUP_DONE_FILE = path.join(app.getPath('userData'), '.guymacyb-setup-done');
const WSL_DISTRO = process.env.WSL_DISTRO || 'Ubuntu';
const IS_WIN = process.platform === 'win32';

// Liste des outils Linux que le wizard vérifie / installe.
// Doit rester en sync avec `TOOLS` dans `desktop/setup-wizard.html`.
const SETUP_TOOLS = [
  'nmap', 'nikto', 'whatweb', 'aircrack-ng', 'airodump-ng', 'tshark',
  'iperf3', 'dnsrecon', 'sslscan', 'sqlmap', 'gobuster', 'hashcat',
  'searchsploit', 'metasploit-framework', 'reaver', 'macchanger',
];
// Paquets apt correspondants (noms parfois différents du binaire).
const APT_PACKAGES = [
  'nmap', 'nikto', 'whatweb', 'aircrack-ng', 'tshark', 'iperf3',
  'dnsrecon', 'sslscan', 'sqlmap', 'gobuster', 'hashcat', 'exploitdb',
  'reaver', 'macchanger', 'wireless-tools', 'iw',
];

/** Exécute une commande et renvoie { stdout, stderr, exitCode }. */
function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd || process.cwd(),
      env: { ...process.env, LANG: 'C.UTF-8' },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      timeout: opts.timeoutMs || 30_000,
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => (stdout += d.toString()));
    child.stderr.on('data', (d) => (stderr += d.toString()));
    child.on('error', (e) => resolve({ stdout, stderr: stderr + e.message, exitCode: -1 }));
    child.on('close', (code) => resolve({ stdout, stderr, exitCode: code ?? -1 }));
  });
}

/** Détecte si WSL est installé + liste les distros (Windows uniquement). */
async function detectWsl() {
  if (!IS_WIN) {
    return { available: false, reason: 'Mode Linux natif — WSL non requis (outils exécutés directement)' };
  }
  // Vérifie la présence de wsl.exe
  const whichRes = await runCmd('where', ['wsl.exe'], { timeoutMs: 5000 });
  if (whichRes.exitCode !== 0) {
    return { available: false, reason: 'wsl.exe introuvable — WSL non installé' };
  }
  // Liste les distros installés
  const listRes = await runCmd('wsl.exe', ['-l', '-v'], { timeoutMs: 8000 });
  const out = (listRes.stdout + listRes.stderr).replace(/\x1b\[[0-9;]*m/g, '').replace(/\0/g, '');
  const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
  const distros = [];
  for (const line of lines.slice(1)) {
    const parts = line.split(/\s+/);
    if (parts.length >= 3) distros.push({ name: parts[0], state: parts[1], version: parts[2] });
  }
  // Teste si le distro par défaut démarre vraiment
  let defaultDistro = distros[0]?.name || WSL_DISTRO;
  if (distros.length > 0) {
    const testRes = await runCmd('wsl.exe', ['-d', defaultDistro, '--', 'echo', 'ok'], { timeoutMs: 10000 });
    if (testRes.exitCode !== 0 || !testRes.stdout.includes('ok')) {
      return { available: false, reason: 'WSL installé mais le distro ' + defaultDistro + ' ne démarre pas', distros };
    }
  } else {
    return { available: false, reason: 'WSL installé mais aucun distro — lancez `wsl --install -d Ubuntu`', distros: [] };
  }
  return { available: true, distros, defaultDistro };
}

/** Détecte les outils Linux installés (via WSL sur Windows, direct sur Linux). */
async function detectTools(wslInfo) {
  const available = [];
  const missing = [];
  // Construit une commande `which tool1 tool2 ...`
  const whichCmd = SETUP_TOOLS.join(' ');
  let res;
  if (IS_WIN && wslInfo.available) {
    res = await runCmd('wsl.exe', ['-d', wslInfo.defaultDistro, '--', 'bash', '-c', `which ${whichCmd} 2>/dev/null; echo "---EXIT:$?"`], { timeoutMs: 15000 });
  } else if (!IS_WIN) {
    res = await runCmd('bash', ['-c', `which ${whichCmd} 2>/dev/null; echo "---EXIT:$?"`], { timeoutMs: 10000 });
  } else {
    // Windows sans WSL — aucun outil Linux accessible
    SETUP_TOOLS.forEach((t) => missing.push(t));
    return { available, missing };
  }
  const out = res.stdout;
  // `which` imprime le ligne des chemins trouvés, puis on ajoute ---EXIT
  const lines = out.split('\n').filter((l) => l && !l.startsWith('---'));
  // `which` peut imprimer plusieurs chemins par ligne ou "which: no xxx in ..."
  for (const t of SETUP_TOOLS) {
    const found = lines.some((l) => l.includes('/' + t) || l.endsWith(t));
    if (found) available.push(t);
    else missing.push(t);
  }
  return { available, missing };
}

/** Détecte tout pour le wizard (WSL + outils + Rust + node). */
async function detectAll() {
  const wsl = await detectWsl();
  const tools = await detectTools(wsl);
  const rust = fs.existsSync(RUST_CORE);
  return {
    isWindows: IS_WIN,
    wsl,
    tools,
    rust,
    node: process.versions.node,
  };
}

/**
 * Installe WSL avec élévation UAC (Windows).
 * Utilise PowerShell Start-Process -Verb RunAs pour élever wsl --install.
 */
function installWslElevated(progress) {
  return new Promise((resolve) => {
    if (!IS_WIN) {
      return resolve({ exitCode: 0, output: 'Mode Linux natif — aucune installation WSL requise', rebootRequired: false });
    }
    // wsl --install --no-distribution pour éviter le téléchargement long du distro par défaut
    // (le wizard propose ensuite d'installer les outils). Mais l'activation du kernel WSL
    // requiert un redémarrage. On lance via PowerShell élevé.
    const psScript = `Start-Process wsl.exe -ArgumentList '--install','--no-distribution','-d','${WSL_DISTRO}' -Verb RunAs -Wait -PassThru | Select-Object -ExpandProperty ExitCode`;
    progress('$ wsl --install --no-distribution -d ' + WSL_DISTRO + '  (UAC)');
    const child = spawn('powershell.exe', ['-NoProfile', '-Command', psScript], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => { out += d.toString(); progress(d.toString().trim()); });
    child.on('close', (code) => {
      // Vérifie si un redémarrage est nécessaire (WSL2 kernel install requiert reboot)
      const rebootRequired = /restart|reboot|redémarr/i.test(out);
      progress(rebootRequired ? '⚠ Redémarrage requis pour activer le kernel WSL.' : '✓ Commande wsl --install terminée.');
      resolve({ exitCode: code ?? 0, output: out, rebootRequired });
    });
    child.on('error', (e) => {
      progress('✗ ' + e.message);
      resolve({ exitCode: -1, output: e.message, rebootRequired: false });
    });
  });
}

/**
 * Installe les outils Linux manquants dans WSL (apt-get).
 * Utilise `wsl -d <distro> -u root` pour éviter le prompt sudo.
 */
function installToolsInWsl(wslInfo, progress) {
  return new Promise((resolve) => {
    if (!IS_WIN || !wslInfo.available) {
      // Sur Linux natif : sudo apt-get (peut prompter)
      progress('$ sudo apt-get update && apt-get install -y ' + APT_PACKAGES.join(' '));
      const child = spawn('bash', ['-c', 'sudo apt-get update && sudo apt-get install -y ' + APT_PACKAGES.join(' ') + ' 2>&1'], {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = '';
      child.stdout.on('data', (d) => { const s = d.toString(); out += s; progress(s.trim()); });
      child.stderr.on('data', (d) => { const s = d.toString(); out += s; progress(s.trim()); });
      child.on('close', (code) => resolve({ exitCode: code ?? 0, output: out }));
      child.on('error', (e) => resolve({ exitCode: -1, output: e.message }));
      return;
    }
    const distro = wslInfo.defaultDistro;
    const cmd = `apt-get update -qq 2>&1 && apt-get install -y ${APT_PACKAGES.join(' ')} 2>&1`;
    progress('$ wsl -d ' + distro + ' -u root -- apt-get install -y ' + APT_PACKAGES.join(' '));
    const child = spawn('wsl.exe', ['-d', distro, '-u', 'root', '--', 'bash', '-c', cmd], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let out = '';
    child.stdout.on('data', (d) => { const s = d.toString(); out += s; progress(s.trim()); });
    child.stderr.on('data', (d) => { const s = d.toString(); out += s; progress(s.trim()); });
    child.on('close', (code) => {
      progress(code === 0 ? '✓ Installation terminée.' : '⚠ terminé (code ' + code + ')');
      resolve({ exitCode: code ?? 0, output: out });
    });
    child.on('error', (e) => resolve({ exitCode: -1, output: e.message }));
  });
}

// ---------------------------------------------------------------------------
// IPC handlers — le wizard (renderer) appelle ces canaux
// ---------------------------------------------------------------------------

ipcMain.handle('setup:detect-all', async () => {
  try { return await detectAll(); } catch (e) { return { error: e.message }; }
});

ipcMain.handle('setup:install-wsl', async (event) => {
  const progress = (line) => event.sender.send('setup:progress', line);
  return await installWslElevated(progress);
});

ipcMain.handle('setup:install-tools', async (event) => {
  const progress = (line) => event.sender.send('setup:progress', line);
  const wsl = await detectWsl();
  return await installToolsInWsl(wsl, progress);
});

ipcMain.handle('setup:launch-app', async (event) => {
  // Marquer le setup comme terminé + lancer l'app principale
  try {
    fs.writeFileSync(SETUP_DONE_FILE, JSON.stringify({ completedAt: new Date().toISOString(), skipped: false }));
  } catch (e) { console.warn('[setup] cannot write flag:', e); }
  // Fermer la fenêtre wizard
  const win = BrowserWindow.fromWebContents(event.sender);
  if (win) win.close();
  // Démarrer le serveur + ouvrir la fenêtre principale
  serverProcess = startBackendServer();
  createWindow();
  await loadApp();
  return { ok: true };
});

ipcMain.handle('setup:skip', async (event) => {
  try {
    fs.writeFileSync(SETUP_DONE_FILE, JSON.stringify({ completedAt: new Date().toISOString(), skipped: true }));
  } catch (e) { /* ignore */ }
  const win = BrowserWindow.fromWebContents(event.sender);
  if (win) win.close();
  serverProcess = startBackendServer();
  createWindow();
  await loadApp();
  return { ok: true };
});

// ---------------------------------------------------------------------------
// Wizard window
// ---------------------------------------------------------------------------

let wizardWindow = null;

function createWizardWindow() {
  wizardWindow = new BrowserWindow({
    width: 880,
    height: 680,
    minWidth: 720,
    minHeight: 600,
    title: `${APP_NAME} — Assistant de configuration`,
    backgroundColor: '#0a0e18',
    frame: true,
    autoHideMenuBar: true,
    show: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
      preload: path.join(__dirname, 'setup-preload.cjs'),
    },
  });
  wizardWindow.loadFile(path.join(__dirname, 'setup-wizard.html'));
  wizardWindow.on('closed', () => { wizardWindow = null; });
}

/** Détermine si le wizard doit s'afficher (premier lancement en production). */
function shouldShowWizard() {
  if (IS_DEV) return false; // en dev, on skip
  if (fs.existsSync(SETUP_DONE_FILE)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1024,
    minHeight: 700,
    title: `${APP_NAME} Desktop v${APP_VERSION}`,
    backgroundColor: '#0a0e18',
    frame: true,
    autoHideMenuBar: true,
    show: false, // show only when ready-to-show to avoid white flash
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      devTools: IS_DEV,
    },
  });

  // Open external links (http/https) in the user's default browser.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

async function loadApp() {
  const ok = await waitForServer();
  if (!ok) {
    dialog.showErrorBox(
      `${APP_NAME} — démarrage impossible`,
      `Le moteur backend n'a pas répondu à temps sur http://${SERVER_HOST}:${SERVER_PORT}.\n` +
        `Vérifiez votre antivirus ou vos règles de pare-feu local et relancez ${APP_NAME}.`
    );
    app.quit();
    return;
  }
  if (!mainWindow) return;
  mainWindow.loadURL(`http://${SERVER_HOST}:${SERVER_PORT}/`).catch((err) => {
    console.error('[GuymaCyb] failed to load URL:', err);
  });
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

app.whenReady().then(async () => {
  // Premier lancement (production) : afficher le wizard de configuration.
  if (shouldShowWizard()) {
    console.log('[GuymaCyb] Premier lancement — affichage du wizard de configuration.');
    createWizardWindow();
    // Le wizard appelle setup:launch-app (ou setup:skip) qui démarre ensuite
    // le serveur + la fenêtre principale. On ne fait rien d'autre ici.
    return;
  }

  // Lancement normal : spawn backend (production), puis fenêtre principale.
  serverProcess = startBackendServer();

  createWindow();

  // Start polling for server readiness; load URL when ready.
  await loadApp();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
      loadApp();
    }
  });
});

app.on('window-all-closed', () => {
  // On macOS keep the app alive (convention); everywhere else quit.
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  stopBackendServer();
});

// Defensive: if the Node process is killed (Ctrl-C in dev, taskkill in prod),
// make sure the backend child is reaped.
process.on('SIGINT', () => {
  stopBackendServer();
  process.exit(0);
});
process.on('SIGTERM', () => {
  stopBackendServer();
  process.exit(0);
});
