// generate-cert.cjs — Génère un certificat self-signed de signature de code (Authenticode).
// Usage : node desktop/signing/generate-cert.cjs [password]
//
// Produit dans desktop/signing/ :
//   guymacyb-code-signing.key   (clé privée RSA 4096)
//   guymacyb-code-signing.crt   (certificat public, EKU=codeSigning, 3 ans)
//   guymacyb-code-signing.pfx   (bundle PKCS#12 — pour signtool/osslsigncode)
//
const { execFileSync } = require('child_process');
const path = require('path');

const OUT_DIR = __dirname;
const PASS = process.argv[2] || process.env.CSC_KEY_PASSWORD || 'guymacyb';
const KEY = path.join(OUT_DIR, 'guymacyb-code-signing.key');
const CRT = path.join(OUT_DIR, 'guymacyb-code-signing.crt');
const PFX = path.join(OUT_DIR, 'guymacyb-code-signing.pfx');

console.log('[generate-cert] Génération du certificat de signature de code...');
console.log(`[generate-cert] Mot de passe PFX : ${PASS}  (changez-le via CSC_KEY_PASSWORD)`);

// 1. Clé + cert self-signed avec EKU codeSigning
const subj = '/CN=Guyma Cyb Security/O=Guyma Cyb Security Systems/C=FR';
execFileSync('openssl', [
  'req', '-x509', '-newkey', 'rsa:4096', '-sha256', '-days', '1095', '-nodes',
  '-keyout', KEY, '-out', CRT, '-subj', subj,
  '-addext', 'extendedKeyUsage=codeSigning',
  '-addext', 'keyUsage=digitalSignature',
  '-addext', 'basicConstraints=critical,CA:FALSE',
], { stdio: 'inherit' });

// 2. Export PFX
execFileSync('openssl', [
  'pkcs12', '-export',
  '-inkey', KEY, '-in', CRT, '-out', PFX,
  '-passout', `pass:${PASS}`,
  '-name', 'Guyma Cyb Code Signing',
], { stdio: 'inherit' });

console.log('\n[generate-cert] ✓ Certificat généré :');
console.log(`  ${CRT}`);
console.log(`  ${KEY}`);
console.log(`  ${PFX}`);
console.log('\n[generate-cert] Pour signer le .exe :');
console.log('  CSC_LINK=desktop/signing/guymacyb-code-signing.pfx \\');
console.log('  CSC_KEY_PASSWORD=' + PASS + ' \\');
console.log('  npx electron-builder --win nsis --x64');
console.log('\n[generate-cert] ⚠ Self-signed = OK pour tests mais SmartScreen affichera');
console.log('[generate-cert]   "éditeur inconnu". Pour la confiance, achetez un cert OV/EV');
console.log('[generate-cert]   (DigiCert/Sectigo) ou utilisez Azure Trusted Signing / SignPath.');
