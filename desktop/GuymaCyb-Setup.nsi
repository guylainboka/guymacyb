; NSIS Modern User Interface
; Guyma Cyb v1.0.0 Windows Installer Script

!define PRODUCT_NAME "Guyma Cyb"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Guyma Cyb Security Systems"
!define PRODUCT_WEB_SITE "https://example.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\GuymaCyb.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

SetCompressor /SOLID lzma

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "dist_electron\GuymaCyb-Setup-v1.0.0.exe"
InstallDir "$PROGRAMFILES64\Guyma Cyb"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
  File /r "dist\*.*"
  File "server.js"
  File "package.json"

  ; Create Desktop Shortcut
  CreateShortCut "$DESKTOP\Guyma Cyb.lnk" "$INSTDIR\GuymaCyb.exe" "" "$INSTDIR\GuymaCyb.exe" 0
  CreateDirectory "$SMPROGRAMS\Guyma Cyb"
  CreateShortCut "$SMPROGRAMS\Guyma Cyb\Guyma Cyb.lnk" "$INSTDIR\GuymaCyb.exe" "" "$INSTDIR\GuymaCyb.exe" 0
  CreateShortCut "$SMPROGRAMS\Guyma Cyb\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "$INSTDIR\uninst.exe" 0
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\GuymaCyb.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd
