# Desktop Assets (optionnels mais recommandés)

Ce dossier contient les assets visuels et légaux pour le packaging Windows.

## Fichiers attendus

### `icon.ico` (recommandé)
- Icône Windows multi-résolution (256×256, 128×128, 64×64, 48×48, 32×32, 16×16)
- Utilisée pour : `GuymaCyb.exe`, l'installateur NSIS, les raccourcis bureau et menu Démarrer
- Format : `.ico` Windows (pas `.png` ni `.icns`)
- Outil en ligne pour convertir un PNG → ICO : https://icoconvert.com/
- Si absent : electron-builder utilise une icône Electron par défaut (ça compile mais ce n'est pas personnalisé)

### `LICENSE.txt` (optionnel)
- Texte de licence affiché dans la page "License" de l'assistant NSIS
- Format : texte brut (pas de markdown)
- Si absent : l'assistant NSIS saute la page licence (voir `electron-builder.yml` → `nsis.license`)

### `wizard.bmp` / `header.bmp` (très optionnel)
- Images NSIS pour personnaliser l'assistant d'installation
- `wizard.bmp` : 164×314 px (image de gauche de l'assistant)
- `header.bmp` : 150×57 px (image d'en-tête)
- Si absents : NSIS utilise son design Modern UI par défaut

## Comment générer une icône

1. Crée un logo carré (ex: 1024×1024 PNG)
2. Convertis en `.ico` multi-résolution avec https://icoconvert.com/ ou ImageMagick :
   ```bash
   convert logo.png -define icon:auto-resize=256,128,64,48,32,16 icon.ico
   ```
3. Place le fichier ici : `desktop/assets/icon.ico`
4. Re-build : `npx electron-builder --win nsis --x64`

## Note pour GitHub Actions CI

Le workflow `.github/workflows/build-windows.yml` build **même si ces assets sont absents** :
- `icon.ico` absent → icône Electron par défaut (compile OK)
- `LICENSE.txt` absent → page licence sautée (compile OK)

Pour un rendu professionnel, ajoute ces fichiers avant de taguer une release `v*`.
