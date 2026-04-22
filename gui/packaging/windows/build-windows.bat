@echo off
REM ══════════════════════════════════════════════════
REM  Zupt GUI — Windows Build Script
REM  Creates: ZuptGUI-2.1.6-Setup.exe
REM
REM  Prerequisites:
REM    1. Python 3.9+  (python.org)
REM    2. NSIS 3.x     (nsis.sourceforge.io)
REM    3. zupt.exe     (compiled zupt CLI binary for Windows)
REM
REM  Usage:
REM    cd packaging\windows
REM    build-windows.bat
REM ══════════════════════════════════════════════════
setlocal

echo.
echo  Zupt GUI — Windows Build
echo  ════════════════════════
echo.

REM ── Step 1: Install Python deps ──
echo [1/4] Installing dependencies...
pip install PySide6 pyinstaller --quiet --upgrade
if errorlevel 1 (
    echo ERROR: pip install failed. Is Python in PATH?
    pause
    exit /b 1
)

REM ── Step 2: Build .exe with PyInstaller ──
echo [2/4] Building ZuptGUI.exe...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

pyinstaller --onefile --windowed ^
    --name "ZuptGUI" ^
    --icon "..\..\assets\zupt.ico" ^
    --add-data "..\..\assets\zupt.ico;assets" ^
    --add-data "..\..\assets\zupt.png;assets" ^
    "..\..\src\zupt_gui.py"

if not exist "dist\ZuptGUI.exe" (
    echo ERROR: PyInstaller build failed.
    pause
    exit /b 1
)
echo    Built: dist\ZuptGUI.exe

REM ── Step 3: Check for zupt.exe ──
echo [3/4] Checking for zupt.exe...
if not exist "zupt.exe" (
    echo.
    echo  WARNING: zupt.exe not found in this directory.
    echo  The installer needs zupt.exe to bundle the CLI tool.
    echo  Options:
    echo    a) Copy zupt.exe here and re-run this script
    echo    b) Build zupt from source with MSYS2/MinGW:
    echo       pacman -S mingw-w64-x86_64-gcc make
    echo       cd zupt-2.1.6 ^&^& make
    echo       cp zupt.exe packaging/windows/
    echo.
)

REM ── Step 4: Build NSIS installer ──
echo [4/4] Building installer...
where makensis >nul 2>&1
if errorlevel 1 (
    echo.
    echo  NSIS not found. Install from: https://nsis.sourceforge.io
    echo  Then run: makensis zupt-installer.nsi
    echo.
    echo  Standalone exe ready at: dist\ZuptGUI.exe
    pause
    exit /b 0
)

makensis zupt-installer.nsi
if errorlevel 1 (
    echo ERROR: NSIS build failed.
    pause
    exit /b 1
)

echo.
echo  ════════════════════════════════════════════
echo  Build complete!
echo    Standalone:  dist\ZuptGUI.exe
echo    Installer:   ZuptGUI-2.1.6-Setup.exe
echo  ════════════════════════════════════════════
echo.
pause
