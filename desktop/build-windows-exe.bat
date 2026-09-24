@echo off
REM ========================================================
REM   GUYMA CYB - WINDOWS .EXE PACKAGING BUILD SCRIPT
REM   Compiles Guyma Cyb into GuymaCyb-Setup-v1.0.0.exe
REM ========================================================

echo [GUYMA CYB] Starting Desktop Packaging Pipeline...
echo.

echo 1. Building React SPA and Express Server...
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed!
    exit /b %ERRORLEVEL%
)

echo.
echo 2. Packaging with Electron-Builder for Windows (x64 NSIS Installer)...
npx --yes electron-builder --win nsis --x64 --config.extraMetadata.name="guyma-cyb" --config.productName="Guyma Cyb"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo  SUCCESS! 
    echo  Installer generated at: dist_electron\GuymaCyb-Setup-v1.0.0.exe
    echo ========================================================
) else (
    echo [ERROR] Packaging failed. Check build logs.
)
pause
