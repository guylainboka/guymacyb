// sign-exe.cjs — Signature Authenticode cross-platform via osslsigncode.
// À utiliser sur Linux / macOS / GitHub Actions CI pour signer les .exe
// (sur Windows natif, préférez sign-exe.bat qui utilise signtool du Windows SDK).
//
// Prérequis :
//   - osslsigncode installé (Linux : apt install osslsigncode, macOS : brew install osslsigncode)
//   - Le certificat .pfx (desktop/signing/guymacyb-code-signing.pfx)
//
// Usage :
//   CSC_KEY_PASSWORD=VotreMotDePasse node desktop/signing/sign-exe.cjs
//
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const PFX = path.join(__dirname, 'guymacyb-code-signing.pfx');
const PASS = process.env.CSC_KEY_PASSWORD || 'guymacyb';
const DIST_DIR = path.join(PROJECT_ROOT, 'dist_electron');

// Localiser osslsigncode
function findOsslSigncode() {
  const candidates = ['osslsigncode', '/usr/bin/osslsigncode', '/usr/local/bin/osslsigncode'];
  for (const c of candidates) {
    try { execFileSync('which', [c], { stdio: 'ignore' }); return c; } catch {}
  }
  return null;
}

function signFile(file) {
  const tool = findOsslSigncode();
  if (!tool) {
    console.error('[sign-exe] osslsigncode introuvable. Installez : apt install osslsigncode  (ou brew install osslsigncode)');
    process.exit(1);
  }
  if (!fs.existsSync(PFX)) {
    console.error(`[sign-exe] certificat introuvable : ${PFX}`);
    console.error('[sign-exe] générez-le avec : node desktop/signing/generate-cert.cjs');
    process.exit(1);
  }
  if (!fs.existsSync(file)) {
    console.error(`[sign-exe] cible introuvable : ${file}`);
    return;
  }
  console.log(`[sign-exe] signature : ${path.basename(file)}`);
  const args = [
    'sign',
    '-pkcs12', PFX,
    '-pass', PASS,
    '-t', 'http://timestamp.digicert.com',
    '-sha256',
    '-n', 'Guyma Cyb',
    '-i', 'https://github.com/guylainboka/guymacyb',
    file,
  ];
  try {
    execFileSync(tool, args, { stdio: 'inherit' });
    console.log(`[sign-exe] ✓ ${path.basename(file)} signé`);
  } catch (e) {
    console.error(`[sign-exe] ✗ échec signature ${path.basename(file)} : ${e.message}`);
  }
}

if (!fs.existsSync(DIST_DIR)) {
  console.error(`[sign-exe] dist_electron/ introuvable. Lancez d'abord : npx electron-builder --win nsis --x64`);
  process.exit(1);
}

// 1. Signer le runtime Electron (win-unpacked)
const runtime = path.join(DIST_DIR, 'win-unpacked', 'Guyma Cyb.exe');
signFile(runtime);

// 2. Signer tous les installeurs NSIS produits
const installers = fs.readdirSync(DIST_DIR)
  .filter((f) => /^GuymaCyb-Setup-v.*\.exe$/.test(f))
  .map((f) => path.join(DIST_DIR, f));

if (installers.length === 0) {
  console.warn('[sign-exe] aucun installeur NSIS trouvé dans dist_electron/');
} else {
  installers.forEach(signFile);
}

console.log('\n[sign-exe] Terminé. Vérifiez avec : osslsigncode verify "dist_electron/GuymaCyb-Setup-v1.0.0.exe"');
