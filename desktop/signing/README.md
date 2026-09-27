# Signature Authenticode du .exe Guyma Cyb

Ce dossier contient les scripts et (après génération) le certificat de signature
de code pour signer l'installeur Windows `GuymaCyb-Setup-v*.exe`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `generate-cert.cjs` | Génère un certificat **self-signed** (.key/.crt/.pfx) — pour tests |
| `sign-exe.bat` | Signe les .exe sur **Windows** avec `signtool` (Windows SDK) |
| `sign-exe.cjs` | Signe les .exe sur **Linux/macOS/CI** avec `osslsigncode` |
| `guymacyb-code-signing.pfx` | Le certificat (généré — **NE JAMAIS committer**, déjà dans .gitignore) |

## 1. Générer le certificat

```bash
node desktop/signing/generate-cert.cjs            # password défaut : guymacyb
node desktop/signing/generate-cert.cjs MonPass456 # password personnalisé
```

Produit `.key`, `.crt`, `.pfx` dans ce dossier. Le `.pfx` est utilisé par les
outils de signature (signtool / osslsigncode).

## 2. Signer pendant le build (automatique)

`electron-builder` signe automatiquement les .exe si les variables d'environnement
sont définies :

**Windows (PowerShell) :**
```powershell
$env:CSC_LINK = "desktop\signing\guymacyb-code-signing.pfx"
$env:CSC_KEY_PASSWORD = "guymacyb"
npx electron-builder --win nsis --x64
```

**Linux / GitHub Actions :**
```bash
export CSC_LINK="desktop/signing/guymacyb-code-signing.pfx"
export CSC_KEY_PASSWORD="guymacyb"
npx electron-builder --win nsis --x64
```

electron-builder détecte la plateforme et utilise `signtool` (Windows) ou
`osslsigncode` (Linux/macOS) automatiquement.

## 3. Signer après le build (optionnel, post-build)

Si vous voulez signer un .exe déjà construit (sans relancer electron-builder) :

**Windows :**
```cmd
set CSC_KEY_PASSWORD=guymacyb
desktop\signing\sign-exe.bat
```

**Linux / CI :**
```bash
CSC_KEY_PASSWORD=guymacyb node desktop/signing/sign-exe.cjs
```

## 4. Vérifier la signature

```bash
# Windows
signtool verify /pa /all "dist_electron\GuymaCyb-Setup-v1.0.0.exe"

# Linux
osslsigncode verify "dist_electron/GuymaCyb-Setup-v1.0.0.exe"
```

## ⚠ Important : SmartScreen et certificats

Un certificat **self-signed** (généré ici) prouve que le .exe n'a pas été
modifié, mais **Windows SmartScreen affichera quand même "éditeur inconnu"**
car le cert n'est pas émis par une autorité reconnue.

Pour supprimer l'avertissement SmartScreen, vous avez besoin d'un certificat
**émis par une CA publique** :

| Option | Coût | SmartScreen |
|---|---|---|
| **OV Code Signing** (Sectigo/DigiCert) | ~200 $/an | Confiance après réputation |
| **EV Code Signing** (Sectigo/DigiCert) | ~350 $/an | Confiance **immédiate** |
| **Azure Trusted Signing** | ~10 $/mois | Confiance après réputation |
| **SignPath.io** (OSS gratuit) | 0 € (projets OSS) | Confiance après réputation |

Avec un vrai cert OV/EV, remplacez simplement le `.pfx` dans ce dossier et
rebuild avec `CSC_LINK`/`CSC_KEY_PASSWORD` définis.
