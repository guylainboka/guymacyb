; ============================================================================
;  Guyma Cyb — NSIS Modern UI Installer Script
;  ----------------------------------------------------------------------------
;  Builds: GuymaCyb-Setup-v1.0.0.exe
;  Target: Windows 10 / 11 / Server 2019+  (x86_64 / x64)
;
;  HOW TO USE
;    1. Prerequisites (build machine):
;         - NSIS 3.x  (https://nsis.sourceforge.io/)  -> makensis on PATH
;         - Node.js 18+ and npm/bun (for frontend + server bundle)
;         - Rust + cargo with target x86_64-pc-windows-gnu or x86_64-pc-windows-msvc
;         - (optional) MinGW-w64 if cross-compiling the Rust core from Linux
;    2. From the project root, on Windows:
;         desktop\build-windows-exe.bat
;       (that script runs the full pipeline and invokes makensis on this file)
;    3. Output:
;         dist_electron\GuymaCyb-Setup-v1.0.0.exe
;
;  WHAT THIS INSTALLER BUNDLES
;    - Electron app (GuymaCyb.exe + Chromium runtime)        -> app\*
;    - Frontend SPA (pre-built by `vite build`)               -> app\dist\*
;    - Backend bundle (dist-server\server.cjs + sql-wasm.wasm) -> app\dist-server\*
;    - Rust scan engine (shadowscan-core.exe)                 -> app\shadowscan-core\
;    - Linux security scripts (run via bundled Git Bash)      -> app\security-scripts\*
;    - (optional) Windows tools (nmap, openssl, git-bash)     -> app\tools\*
;
;  NOTES / CAVEATS
;    - The Linux shell scripts (security-scripts\*.sh) require a bash interpreter
;      to run on Windows. Bundle Git for Windows (git-bash) under app\tools\git-bash
;      and the Electron main process will add it to PATH. Without Git Bash, the
;      Rust core (scan/recon/headers) still works fully — only the *.sh tool
;      integrations (nmap-scan, nikto-scan, …) are unavailable.
;    - The Rust binary MUST be built for Windows (x86_64-pc-windows-gnu or
;      x86_64-pc-windows-msvc). See desktop\README.md for cross-compile notes.
;    - Estimated install size: ~180 MB (Electron ~120 MB + Rust ~7 MB + scripts +
;      tools). The "EstimatedSize" registry value below is in KB.
; ============================================================================

; ----------------------------------------------------------------------------
;  Includes — Modern UI 2 + standard libraries
; ----------------------------------------------------------------------------
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "nsDialogs.nsh"

; ----------------------------------------------------------------------------
;  Product metadata
; ----------------------------------------------------------------------------
!define PRODUCT_NAME         "Guyma Cyb"
!define PRODUCT_NAME_NO_SPACE "GuymaCyb"
!define PRODUCT_VERSION      "1.0.0"
!define PRODUCT_PUBLISHER    "Guyma Cyb Security Systems"
!define PRODUCT_WEB_SITE     "https://github.com/guylainboka/guymacyb"
!define PRODUCT_EXE          "GuymaCyb.exe"
!define PRODUCT_REGKEY       "Software\Microsoft\Windows\CurrentVersion\App Paths\${PRODUCT_EXE}"
!define PRODUCT_UNINST_KEY   "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define ESTIMATED_SIZE_KB    "190000"  ; ~186 MB

; ----------------------------------------------------------------------------
;  Installer-wide settings
; ----------------------------------------------------------------------------
SetCompressor /SOLID lzma      ; best compression for bundled Chromium runtime
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin    ; per-machine install under Program Files

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "dist_electron\GuymaCyb-Setup-v${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${PRODUCT_REGKEY}" ""
BrandingText "${PRODUCT_NAME} ${PRODUCT_VERSION} — ${PRODUCT_PUBLISHER}"

; ----------------------------------------------------------------------------
;  Modern UI 2 — pages & visuals
; ----------------------------------------------------------------------------
!define MUI_ABORTWARNING
!define MUI_ICON                "desktop\assets\icon.ico"   ; (place a 256x256 .ico here)
!define MUI_UNICON              "desktop\assets\icon.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "desktop\assets\wizard.bmp" ; optional 164x314 bmp
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP  "desktop\assets\header.bmp"      ; optional 150x57 bmp

; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE    "desktop\assets\LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Custom page: outils externes recommandés (affichée après l'installation)
Page custom ShowToolsPage LeaveToolsPage

!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Language
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "French"

; ----------------------------------------------------------------------------
;  Section: Core application (required)
; ----------------------------------------------------------------------------
Section "${PRODUCT_NAME} (required)" SEC_CORE
  SectionIn RO   ; read-only — cannot be unchecked

  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
  File "desktop\${PRODUCT_EXE}"              ; the Electron main .exe (built by electron-builder)
  File "package.json"

  ; --- Frontend SPA (vite build output) -----------------------------------
  SetOutPath "$INSTDIR\dist"
  File /r "dist\*.*"

  ; --- Backend bundle (esbuild output) ------------------------------------
  SetOutPath "$INSTDIR\dist-server"
  File "dist-server\server.cjs"
  File "dist-server\sql-wasm.wasm"

  ; --- Electron main process (CJS) ----------------------------------------
  SetOutPath "$INSTDIR\desktop"
  File "desktop\electron-main.cjs"

  ; --- Rust scan engine ---------------------------------------------------
  SetOutPath "$INSTDIR\shadowscan-core"
  File "shadowscan-core\target\x86_64-pc-windows-gnu\release\shadowscan-core.exe"

  ; --- Linux security scripts (run via Git Bash on Windows) ---------------
  SetOutPath "$INSTDIR\security-scripts"
  File /r "security-scripts\*.sh"
  File /r "security-scripts\*.py"
  File /r "security-scripts\lib"

  ; --- (optional) bundled Windows tools — included only if present --------
  ${If} ${FileExists} "tools\nmap\*.*"
    SetOutPath "$INSTDIR\tools\nmap"
    File /r "tools\nmap\*.*"
  ${EndIf}
  ${If} ${FileExists} "tools\openssl-win64\*.*"
    SetOutPath "$INSTDIR\tools\openssl-win64"
    File /r "tools\openssl-win64\*.*"
  ${EndIf}
  ${If} ${FileExists} "tools\git-bash\*.*"
    SetOutPath "$INSTDIR\tools\git-bash"
    File /r "tools\git-bash\*.*"
  ${EndIf}

  ; --- SQLite database placeholder (created on first run) -----------------
  SetOutPath "$INSTDIR"
  ; (no-op — db.ts creates shadow_core.db in process.cwd() at first run)

  ; --- Shortcuts ----------------------------------------------------------
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" \
                 "$INSTDIR\${PRODUCT_EXE}" "" \
                 "$INSTDIR\${PRODUCT_EXE}" 0
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall ${PRODUCT_NAME}.lnk" \
                 "$INSTDIR\uninst.exe" "" \
                 "$INSTDIR\uninst.exe" 0
  CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" \
                 "$INSTDIR\${PRODUCT_EXE}" "" \
                 "$INSTDIR\${PRODUCT_EXE}" 0
SectionEnd

; ----------------------------------------------------------------------------
;  Section: Start Menu shortcut (optional, checked by default)
; ----------------------------------------------------------------------------
Section "Start Menu shortcut" SEC_STARTMENU
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" \
                 "$INSTDIR\${PRODUCT_EXE}" "" \
                 "$INSTDIR\${PRODUCT_EXE}" 0
SectionEnd

; ----------------------------------------------------------------------------
;  Section: Desktop shortcut (optional, checked by default)
; ----------------------------------------------------------------------------
Section "Desktop shortcut" SEC_DESKTOP
  CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" \
                 "$INSTDIR\${PRODUCT_EXE}" "" \
                 "$INSTDIR\${PRODUCT_EXE}" 0
SectionEnd

; ----------------------------------------------------------------------------
;  Section descriptions (hover text on the components page)
; ----------------------------------------------------------------------------
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_CORE} \
    "Installe ${PRODUCT_NAME}, le moteur de scan Rust, le backend Express et les scripts de sécurité."
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_STARTMENU} \
    "Crée un raccourci dans le menu Démarrer."
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} \
    "Crée un raccourci sur le Bureau."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ============================================================================
;  Custom page: Outils externes recommandés
;  ----------------------------------------------------------------------------
;  Affiche la liste des outils à installer pour profiter de toutes les
;  fonctionnalités (scan WiFi réel, nmap, aircrack-ng, etc.).
;  L'utilisateur peut cocher les outils, et un fichier tools-to-install.txt
;  est écrit dans le dossier d'installation pour que l'app affiche un prompt
;  "Installer les outils recommandés" au premier lancement.
; ============================================================================
Var Dialog
Var ChkNmap
Var ChkAircrack
Var ChkWireshark
Var ChkOpenSSL
Var ChkGitBash
Var ChkWSL

Function ShowToolsPage
  ; Skip si install silencieux
  IfSilent skip_tools_page

  nsDialogs::Create 1018
  Pop $Dialog
  ${If} $Dialog == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 24u "Pour utiliser toutes les fonctionnalités de Guyma Cyb (scan WiFi réel, nmap, aircrack-ng...), installez les outils recommandés ci-dessous. Le logiciel fonctionne en mode simulation sans ces outils.$\r$\nCochez les outils que vous souhaitez installer après la fin de l'installation."
  Pop $0

  ${NSD_CreateCheckbox} 0 30u 100% 12u "Nmap — scanner de ports & services (https://nmap.org/download.html)"
  Pop $ChkNmap

  ${NSD_CreateCheckbox} 0 44u 100% 12u "Aircrack-ng — suite WiFi (monitor mode, handshake, WPS) — Linux/WSL requis"
  Pop $ChkAircrack

  ${NSD_CreateCheckbox} 0 58u 100% 12u "Wireshark / tshark — capture de paquets (https://www.wireshark.org/)"
  Pop $ChkWireshark

  ${NSD_CreateCheckbox} 0 72u 100% 12u "OpenSSL-Win64 — certificats et TLS (https://slproweb.com/products/Win32OpenSSL.html)"
  Pop $ChkOpenSSL

  ${NSD_CreateCheckbox} 0 86u 100% 12u "Git for Windows — fournit Git Bash (requis pour les scripts .sh) (https://git-scm.com/)"
  Pop $ChkGitBash
  ${NSD_Check} $ChkGitBash  ; coché par défaut

  ${NSD_CreateCheckbox} 0 100u 100% 12u "WSL 2 — pour le scan WiFi réel via Linux (wsl --install)"
  Pop $ChkWSL

  nsDialogs::Show

  skip_tools_page:
FunctionEnd

Function LeaveToolsPage
  ; Écrire la liste des outils sélectionnés dans tools-to-install.txt
  FileOpen $0 "$INSTDIR\tools-to-install.txt" w
  ${NSD_GetState} $ChkNmap $1
  ${If} $1 == 1
    FileWrite $0 "nmap$\r$\n"
  ${EndIf}
  ${NSD_GetState} $ChkAircrack $1
  ${If} $1 == 1
    FileWrite $0 "aircrack-ng$\r$\n"
  ${EndIf}
  ${NSD_GetState} $ChkWireshark $1
  ${If} $1 == 1
    FileWrite $0 "wireshark$\r$\n"
  ${EndIf}
  ${NSD_GetState} $ChkOpenSSL $1
  ${If} $1 == 1
    FileWrite $0 "openssl$\r$\n"
  ${EndIf}
  ${NSD_GetState} $ChkGitBash $1
  ${If} $1 == 1
    FileWrite $0 "git-bash$\r$\n"
  ${EndIf}
  ${NSD_GetState} $ChkWSL $1
  ${If} $1 == 1
    FileWrite $0 "wsl$\r$\n"
  ${EndIf}
  FileClose $0
FunctionEnd

; ----------------------------------------------------------------------------
;  Post-install: write uninstaller + Add/Remove Programs registry
; ----------------------------------------------------------------------------
Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"

  ; App Paths so `GuymaCyb.exe` resolves from Run dialog
  WriteRegStr HKLM "${PRODUCT_REGKEY}" "" "$INSTDIR\${PRODUCT_EXE}"
  WriteRegStr HKLM "${PRODUCT_REGKEY}" "Path" "$INSTDIR"

  ; Add/Remove Programs entry
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "DisplayName"     "${PRODUCT_NAME}"
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion"  "${PRODUCT_VERSION}"
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "Publisher"       "${PRODUCT_PUBLISHER}"
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon"     "$INSTDIR\${PRODUCT_EXE}"
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout"    "${PRODUCT_WEB_SITE}"
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$\"$INSTDIR\uninst.exe$\""
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoModify"        1
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoRepair"        1
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "EstimatedSize"  ${ESTIMATED_SIZE_KB}
SectionEnd

; ----------------------------------------------------------------------------
;  Uninstaller
; ----------------------------------------------------------------------------
Section Uninstall
  SetOutPath "$INSTDIR"

  ; Kill running instances (best-effort — ignore errors)
  nsExec::ExecToLog 'taskkill /f /im ${PRODUCT_EXE}'
  nsExec::ExecToLog 'taskkill /f /im shadowscan-core.exe'
  nsExec::ExecToLog 'taskkill /f /im node.exe'

  ; Remove application files
  Delete "$INSTDIR\${PRODUCT_EXE}"
  Delete "$INSTDIR\package.json"
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\shadow_core.db"
  RMDir /r "$INSTDIR\dist"
  RMDir /r "$INSTDIR\dist-server"
  RMDir /r "$INSTDIR\desktop"
  RMDir /r "$INSTDIR\shadowscan-core"
  RMDir /r "$INSTDIR\security-scripts"
  RMDir /r "$INSTDIR\tools"
  RMDir /r "$INSTDIR\locales"   ; electron-builder locales
  RMDir /r "$INSTDIR\resources" ; electron-builder resources

  ; Remove shortcuts
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall ${PRODUCT_NAME}.lnk"
  RMDir  "$SMPROGRAMS\${PRODUCT_NAME}"

  ; Clean registry
  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_REGKEY}"

  ; If the install dir is now empty, remove it too
  RMDir "$INSTDIR"
SectionEnd

; ----------------------------------------------------------------------------
;  .onInit — abort on 32-bit Windows (we ship an x64 binary)
; ----------------------------------------------------------------------------
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP \
      "${PRODUCT_NAME} requires a 64-bit version of Windows (10, 11, or Server 2019+)."
    Abort
  ${EndIf}
FunctionEnd
