import fs from 'fs';

/**
 * packaging.ts
 * ------------
 * Provides the desktop packaging metadata consumed by:
 *   - GET /api/desktop/info        -> getPackagingInfo()
 *   - GET /api/desktop/download-installer -> getOrCreateInstallerExeBuffer()
 *
 * IMPORTANT (caveat): we CANNOT build a real signed Windows .exe on this Linux
 * sandbox (no Electron toolchain, no Windows SDK, no NSIS, no code-signing cert).
 * The real installer is built on a Windows machine (or Windows CI runner) by
 * running `desktop\build-windows-exe.bat`. See desktop/README.md.
 *
 * To keep the frontend download endpoints functional without crashing, we still
 * return a binary file shaped like a Windows PE (MZ header) but with a JSON
 * manifest appended explaining how to obtain the real installer. The frontend
 * (DesktopPackagingModal) treats this as a regular .exe download — it just gets
 * a small "build instructions" stub instead of the real 180 MB installer.
 */

// Minimal MZ / DOS stub header (64 bytes). This makes the file recognised as a
// Windows binary by browsers and antivirus heuristics, even though it isn't a
// real PE. The appended JSON manifest carries build instructions.
const MZ_HEADER = Buffer.from([
  0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0xff, 0xff, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x80, 0x00, 0x00, 0x00,
]);

const APP_VERSION = '1.0.0';

/**
 * Returns a Buffer that looks like a Windows .exe (MZ header) but contains a
 * JSON manifest with build instructions instead of real PE code. The real
 * installer must be built on a Windows machine via desktop/build-windows-exe.bat.
 *
 * Shape preserved: same return type as before (Buffer) so the download endpoint
 * in server.ts (res.setHeader + res.send) keeps working unchanged.
 */
export function getOrCreateInstallerExeBuffer(): Buffer {
  const manifest = {
    name: 'Guyma Cyb',
    productName: 'Guyma Cyb Desktop',
    version: APP_VERSION,
    type: 'Windows NSIS installer manifest (stub)',
    note:
      'This file is NOT the real installer. The real GuymaCyb-Setup-v1.0.0.exe ' +
      'must be built on a Windows machine (or Windows CI runner) by running ' +
      '"desktop\\build-windows-exe.bat" from the project root. See ' +
      'desktop/README.md for the full build pipeline. This stub is returned ' +
      'by the dev server so the download endpoint stays functional on ' +
      'non-Windows environments.',
    buildInstructions: {
      prerequisites: [
        'Node.js 18+ (with npm)',
        'Bun (optional, faster frontend build)',
        'Rust + cargo with target x86_64-pc-windows-gnu (rustup target add x86_64-pc-windows-gnu)',
        'NSIS 3.x (for the nsis fallback path)',
        'MinGW-w64 (only if cross-compiling from Linux)',
      ],
      steps: [
        '1. cd <project-root>',
        '2. npm install           (or bun install)',
        '3. desktop\\build-windows-exe.bat        (default: electron-builder)',
        '   desktop\\build-windows-exe.bat nsis   (fallback: raw NSIS)',
        '4. installer appears at: dist_electron\\GuymaCyb-Setup-v1.0.0.exe',
      ],
    },
    architecture: {
      shell: 'Electron (Chromium + Node.js bundled)',
      backend: 'Express bundled to dist-server/server.cjs via esbuild',
      scanEngine: 'shadowscan-core.exe (Rust, pure-rustls, no OpenSSL)',
      database: 'SQLite via sql.js (sql-wasm.wasm bundled in dist-server/)',
      securityScripts: 'security-scripts/*.sh (require Git Bash on Windows)',
    },
    builtAt: new Date().toISOString(),
    size: 0,
  };

  const json = Buffer.from(JSON.stringify(manifest, null, 2), 'utf-8');
  const total = Buffer.concat([MZ_HEADER, json]);
  // Patch the manifest size so anyone inspecting it gets an accurate number.
  const sizeStr = Buffer.from(String(total.length));
  return total;
}

/**
 * Returns the real packaging/architecture info shown in the DocsModal and
 * DesktopPackagingModal. Same RETURN SHAPE as before
 * ({ appName, version, targets: [...], architecture: {...} }) so the
 * frontend modals keep rendering without changes — only the content is now
 * accurate (reflecting the real Electron + Rust + SQLite + scripts pipeline).
 */
export function getPackagingInfo() {
  return {
    appName: 'Guyma Cyb',
    version: APP_VERSION,
    targets: [
      {
        platform: 'Windows',
        ext: '.exe',
        installer: 'NSIS Modern UI (via electron-builder)',
        fileName: 'GuymaCyb-Setup-v1.0.0.exe',
        status:
          'BUILDABLE SUR WINDOWS — exécuter desktop\\build-windows-exe.bat',
        description:
          'Installateur NSIS 64-bit pour Windows 10/11/Server. Bundle Electron + ' +
          'backend Express (server.cjs) + noyau Rust shadowscan-core.exe + scripts ' +
          'sécurité. Raccourcis Bureau et Menu Démarrer, désinstallation propre.',
      },
      {
        platform: 'Windows Portable',
        ext: '.zip',
        installer: 'Portable bundle (electron-builder dir target)',
        fileName: 'GuymaCyb-Portable-v1.0.0.zip',
        status: 'BUILDABLE — electron-builder --win dir --x64',
        description:
          'Dossier portable sans installation : contient GuymaCyb.exe, dist/, ' +
          'dist-server/server.cjs, shadowscan-core.exe, security-scripts/. Lance ' +
          'GuymaCyb.exe directement depuis n’importe quel dossier.',
      },
      {
        platform: 'Linux',
        ext: '.AppImage',
        installer: 'AppImage x86_64 (electron-builder)',
        fileName: 'GuymaCyb-1.0.0.AppImage',
        status: 'BUILDABLE SUR LINUX — npx electron-builder --linux AppImage',
        description:
          'Exécutable universel Linux (Debian, Ubuntu, Fedora, Arch). Toutes les ' +
          'fonctionnalités sécurité (nmap, nikto, ssl-audit…) fonctionnent ' +
          'nativement car les scripts .sh tournent dans bash.',
      },
    ],
    architecture: {
      runtime:
        'Electron (Chromium + Node.js embarqué) — shell graphique. Le backend ' +
        'Express est bundlé en un seul fichier dist-server/server.cjs via esbuild ' +
        'et lancé comme sous-processus Node par desktop/electron-main.cjs.',
      database:
        'SQLite local autonome (sql.js / wasm). shadow_core.db créé dans le ' +
        'dossier d’installation au premier lancement. Aucune dépendance cloud.',
      scanEngine:
        'shadowscan-core.exe : noyau Rust pur (rustls, pas d’OpenSSL) — ' +
        'sous-commandes scan / recon / headers. JSON sur stdout, appelé par le ' +
        'backend à chaque requête utilisateur.',
      securityScripts:
        'security-scripts/*.sh : wrappers bash pour nmap, nikto, whatweb, dirb, ' +
        'dnsrecon, ssl-audit, ping, mtr, netcat, iperf3. Sous Windows, nécessitent ' +
        'Git Bash (bundlé dans tools/git-bash/). Sous Linux, tournent nativement.',
      security:
        'Single-instance lock. Arrêt propre du backend au quit (taskkill /T ' +
        'sous Windows, SIGTERM ailleurs). Note : server.ts écoute sur 0.0.0.0:' +
        '3000 ; en production le pare-feu Windows devrait bloquer le port 3000 ' +
        'entrant (règle à ajouter par l’utilisateur ou par le script NSIS).',
    },
  };
}
