@echo off
REM ==========================================================================
REM  GUYMA CYB - WINDOWS .EXE PACKAGING BUILD SCRIPT (full pipeline)
REM  --------------------------------------------------------------------------
REM  Output: dist_electron\GuymaCyb-Setup-v1.0.0.exe
REM
REM  Pipeline:
REM    0. Prerequisite checks
REM    1. Build the Rust scan engine  (cargo build --release --target x86_64-pc-windows-gnu)
REM    2. Build the frontend SPA      (bun run build  ->  dist\)
REM    3. Bundle the Express backend  (node desktop\build-server-bundle.js  ->  dist-server\server.cjs)
REM    4. Stage bundled resources
REM    5. Package with electron-builder (default) OR makensis (fallback)
REM
REM  Usage:
REM    desktop\build-windows-exe.bat           -> default (electron-builder)
REM    desktop\build-windows-exe.bat nsis      -> use NSIS instead of electron-builder
REM
REM  Run from the project root on a Windows 10/11 machine with:
REM    - Node.js 18+ (with npm)        (https://nodejs.org/)
REM    - Bun (optional, faster)        (https://bun.sh/)
REM    - Rust + cargo with target x86_64-pc-windows-gnu
REM    - NSIS 3.x (if using the nsis fallback)
REM    - (optional) MinGW-w64 for cross-compiling Rust from Linux
REM ==========================================================================

setlocal enableextensions enabledelayedexpansion

set PROJECT_ROOT=%~dp0..
pushd "%PROJECT_ROOT%"

set PACKAGER=electron-builder
if /i "%~1"=="nsis" set PACKAGER=nsis

echo.
echo ==========================================================
echo   GUYMA CYB - Windows Desktop Packaging Pipeline
echo   Packager: %PACKAGER%
echo   Project : %CD%
echo ==========================================================
echo.

REM --------------------------------------------------------------------------
REM  0. Prerequisite checks
REM --------------------------------------------------------------------------
echo [0/5] Checking prerequisites...

where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js not found on PATH. Install Node.js 18+ from https://nodejs.org/
    goto :fail
)

REM Prefer bun for `bun run build` (faster), fall back to npm.
set RUNNER=npm
where bun >nul 2>nul
if %ERRORLEVEL% EQU 0 set RUNNER=bun
echo       Node runner: %RUNNER%

where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Rust cargo not found on PATH. Install Rust from https://rustup.rs/
    goto :fail
)

REM Verify the Rust windows target is installed (we add it if missing).
cargo rustc -v 2>nul | findstr /C:"x86_64-pc-windows-gnu" >nul
if %ERRORLEVEL% NEQ 0 (
    echo       Adding Rust target x86_64-pc-windows-gnu...
    rustup target add x86_64-pc-windows-gnu
)

if /i "%PACKAGER%"=="nsis" (
    where makensis >nul 2>nul
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] makensis not found on PATH. Install NSIS 3.x from https://nsis.sourceforge.io/
        goto :fail
    )
)

if /i "%PACKAGER%"=="electron-builder" (
    where npx >nul 2>nul
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] npx not found. Node.js install should provide it - check your PATH.
        goto :fail
    )
)

echo       Prerequisites OK.
echo.

REM --------------------------------------------------------------------------
REM  1. Build the Rust scan engine for Windows x64
REM --------------------------------------------------------------------------
echo [1/5] Building Rust scan engine (shadowscan-core) for x86_64-pc-windows-gnu...
pushd shadowscan-core
cargo build --release --target x86_64-pc-windows-gnu
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Rust build failed.
    popd
    goto :fail
)
popd
echo       Rust binary: shadowscan-core\target\x86_64-pc-windows-gnu\release\shadowscan-core.exe
echo.

REM --------------------------------------------------------------------------
REM  2. Build the frontend SPA (vite build -> dist\)
REM --------------------------------------------------------------------------
echo [2/5] Building frontend SPA (vite build)...
if /i "%RUNNER%"=="bun" (
    call bun run build
) else (
    call npm run build
)
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Frontend build failed.
    goto :fail
)
if not exist "dist\index.html" (
    echo [ERROR] dist\index.html not found - vite build produced no output.
    goto :fail
)
echo       Frontend: dist\index.html
echo.

REM --------------------------------------------------------------------------
REM  3. Bundle the Express backend (esbuild -> dist-server\server.cjs)
REM --------------------------------------------------------------------------
echo [3/5] Bundling Express backend (esbuild -> dist-server\server.cjs)...
call node desktop\build-server-bundle.js
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Server bundle failed.
    goto :fail
)
if not exist "dist-server\server.cjs" (
    echo [ERROR] dist-server\server.cjs not found.
    goto :fail
)
if not exist "dist-server\sql-wasm.wasm" (
    echo [ERROR] dist-server\sql-wasm.wasm not found.
    goto :fail
)
echo       Backend bundle: dist-server\server.cjs
echo.

REM --------------------------------------------------------------------------
REM  4. Stage bundled resources (electron-builder reads them from project root)
REM --------------------------------------------------------------------------
echo [4/5] Staging bundled resources...
REM (electron-builder.yml references these paths directly; nothing to copy here.)
REM Ensure dist_electron exists for output.
if not exist "dist_electron" mkdir "dist_electron"
echo       Staging complete.
echo.

REM --------------------------------------------------------------------------
REM  5. Package with electron-builder (default) OR makensis (fallback)
REM --------------------------------------------------------------------------
if /i "%PACKAGER%"=="nsis" (
    echo [5/5] Packaging with NSIS (makensis desktop\GuymaCyb-Setup.nsi)...
    call makensis "desktop\GuymaCyb-Setup.nsi"
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] NSIS packaging failed.
        goto :fail
    )
) else (
    echo [5/5] Packaging with electron-builder (win nsis x64)...
    REM electron-builder reads config from electron-builder.yml in the project root.
    call npx --yes electron-builder --win nsis --x64
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] electron-builder packaging failed.
        goto :fail
    )
)
echo.

REM --------------------------------------------------------------------------
REM  Success
REM --------------------------------------------------------------------------
if exist "dist_electron\GuymaCyb-Setup-v1.0.0.exe" (
    echo ==========================================================
    echo   SUCCESS
    echo   Installer: dist_electron\GuymaCyb-Setup-v1.0.0.exe
    echo ==========================================================
    popd
    endlocal
    exit /b 0
) else (
    echo [ERROR] Installer not found at dist_electron\GuymaCyb-Setup-v1.0.0.exe
    echo         (electron-builder may have produced a differently named file - check dist_electron\)
    goto :fail
)

:fail
echo.
echo ==========================================================
echo   BUILD FAILED
echo ==========================================================
popd
endlocal
exit /b 1
