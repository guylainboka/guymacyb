@echo off
REM ==========================================================================
REM  GUYMA CYB — Signature Authenticode du .exe (Windows, signtool)
REM  --------------------------------------------------------------------------
REM  Signe l'installeur NSIS ET l'exécutable GuymaCyb.exe avec un certificat
REM  de signature de code (.pfx). À lancer APRÈS le build electron-builder.
REM
REM  Prérequis :
REM    - Windows SDK installé (signtool.exe — généralement dans
REM      C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe)
REM    - Le certificat .pfx (desktop/signing/guymacyb-code-signing.pfx)
REM    - Le mot de passe du .pfx (défaut : guymacyb — À CHANGER pour la prod)
REM
REM  Usage :
REM    set CSC_KEY_PASSWORD=VotreMotDePasse
REM    desktop\signing\sign-exe.bat
REM  Ou en laissant le défaut (développement/test) :
REM    desktop\signing\sign-exe.bat
REM ==========================================================================
setlocal enableextensions

set PROJECT_ROOT=%~dp0..\..
pushd "%PROJECT_ROOT%"

set PFX=desktop\signing\guymacyb-code-signing.pfx
set PASS=%CSC_KEY_PASSWORD%
if "%PASS%"=="" set PASS=guymacyb

REM Localiser signtool.exe (Windows SDK)
set SIGNTOOL=
for %%P in (
  "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
  "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
  "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
  "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
) do (
  if exist %%P set SIGNTOOL=%%~P
)

if "%SIGNTOOL%"=="" (
  echo [sign-exe] ERREUR : signtool.exe introuvable.
  echo [sign-exe] Installez le Windows SDK : https://developer.microsoft.com/windows/downloads/windows-sdk/
  exit /b 1
)

if not exist "%PFX%" (
  echo [sign-exe] ERREUR : certificat introuvable : %PFX%
  echo [sign-exe] Générez-le avec : desktop\signing\generate-cert.cjs
  exit /b 1
)

echo [sign-exe] signtool : %SIGNTOOL%
echo [sign-exe] certificat : %PFX%

REM Signer GuymaCyb.exe (le runtime Electron)
if exist "dist_electron\win-unpacked\Guyma Cyb.exe" (
  echo [sign-exe] signature : "Guyma Cyb.exe"
  "%SIGNTOOL%" sign /fd SHA256 /f "%PFX%" /p "%PASS%" /tr http://timestamp.digicert.com /td SHA256 "dist_electron\win-unpacked\Guyma Cyb.exe"
)

REM Signer l'installeur NSIS
for %%I in ("dist_electron\GuymaCyb-Setup-v*.exe") do (
  echo [sign-exe] signature : %%~nxI
  "%SIGNTOOL%" sign /fd SHA256 /f "%PFX%" /p "%PASS%" /tr http://timestamp.digicert.com /td SHA256 "%%I"
)

echo [sign-exe] Terminé. Vérifiez avec :
echo [sign-exe]   "%SIGNTOOL%" verify /pa /all "dist_electron\GuymaCyb-Setup-v1.0.0.exe"
popd
endlocal
