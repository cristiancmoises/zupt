@echo off
rem SPDX-License-Identifier: AGPL-3.0-or-later
rem Build the ZUPT GUI installer without downloading dependencies.
rem
rem Prerequisites must already be installed: Python 3.9+, PySide6, PyInstaller,
rem Inno Setup 6, and a source-built/tested zupt.exe. The CLI path can be
rem selected with ZUPT_CLI_EXE. Final output goes to ZUPT_DIST_DIR,
rem which defaults to a directory below %%TEMP%% (outside the Git checkout).
rem ZUPT_WINDOWS_RUNTIME_NOTICES_DIR is mandatory and must contain the
rem license/notices for the exact Python, PyInstaller, Qt and PySide/PyQt
rem runtime files embedded by this local build.

setlocal EnableExtensions
for %%I in ("%~dp0\..\..\..") do set "REPO_ROOT=%%~fI"
set "VERSION=%~1"
if not defined VERSION set "VERSION=5.2.3"
if not defined ZUPT_DIST_DIR set "ZUPT_DIST_DIR=%TEMP%\zupt-release"
if not defined ZUPT_CLI_EXE set "ZUPT_CLI_EXE=%REPO_ROOT%\zupt.exe"
set "WORK=%TEMP%\zupt-gui-build-%RANDOM%-%RANDOM%"
set "RC=1"

where pyinstaller >nul 2>nul || (
  echo ERROR: PyInstaller is required and is not downloaded by this script.>&2
  goto :cleanup
)
where ISCC.exe >nul 2>nul || (
  echo ERROR: Inno Setup 6 ISCC.exe is required.>&2
  goto :cleanup
)
if not exist "%ZUPT_CLI_EXE%" (
  echo ERROR: source-built CLI not found: %ZUPT_CLI_EXE%>&2
  goto :cleanup
)
if not defined ZUPT_WINDOWS_RUNTIME_NOTICES_DIR (
  echo ERROR: set ZUPT_WINDOWS_RUNTIME_NOTICES_DIR for the exact bundled runtime.>&2
  goto :cleanup
)
if not exist "%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%\MANIFEST.txt" (
  echo ERROR: runtime notice directory must contain MANIFEST.txt.>&2
  goto :cleanup
)
for %%I in ("%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%\MANIFEST.txt") do if %%~zI LEQ 0 (
  echo ERROR: runtime notice MANIFEST.txt must not be empty.>&2
  goto :cleanup
)
for %%N in (PYTHON-NOTICE.txt PYINSTALLER-NOTICE.txt QT-NOTICE.txt) do (
  if not exist "%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%\%%N" (
    echo ERROR: runtime notice directory is missing %%N.>&2
    goto :cleanup
  )
  for %%I in ("%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%\%%N") do if %%~zI LEQ 0 (
    echo ERROR: runtime notice %%N must not be empty.>&2
    goto :cleanup
  )
)
set "QT_BINDING_NOTICE_FOUND="
for %%N in (PYSIDE6-NOTICE.txt PYQT6-NOTICE.txt) do if exist "%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%\%%N" (
  for %%I in ("%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%\%%N") do if %%~zI GTR 0 set "QT_BINDING_NOTICE_FOUND=1"
)
if not defined QT_BINDING_NOTICE_FOUND (
  echo ERROR: runtime notices need non-empty PYSIDE6-NOTICE.txt or PYQT6-NOTICE.txt.>&2
  goto :cleanup
)

mkdir "%WORK%" || goto :cleanup
if not exist "%ZUPT_DIST_DIR%" mkdir "%ZUPT_DIST_DIR%" || goto :cleanup

"%ZUPT_CLI_EXE%" version >"%WORK%\cli-version.txt" 2>&1 || goto :cleanup
findstr /b /c:"zupt %VERSION%" "%WORK%\cli-version.txt" >nul || (
  echo ERROR: CLI version does not match %VERSION%.>&2
  goto :cleanup
)
"%ZUPT_CLI_EXE%" help >nul 2>&1 || goto :cleanup

pyinstaller --noconfirm --clean --onefile --windowed ^
  --name zupt-gui ^
  --icon "%REPO_ROOT%\gui\assets\zupt.ico" ^
  --add-data "%REPO_ROOT%\gui\assets\zupt.ico;assets" ^
  --add-data "%REPO_ROOT%\gui\assets\zupt-icon.png;assets" ^
  --distpath "%WORK%\dist" ^
  --workpath "%WORK%\build" ^
  --specpath "%WORK%" ^
  "%REPO_ROOT%\gui\src\zupt_gui.py" || goto :cleanup

set "GUI_EXE=%WORK%\dist\zupt-gui.exe"
if not exist "%GUI_EXE%" goto :cleanup
set "ZUPT_BIN=%ZUPT_CLI_EXE%"
"%GUI_EXE%" --version >"%WORK%\gui-version.txt" 2>&1 || goto :cleanup
findstr /b /c:"zupt-gui %VERSION%" "%WORK%\gui-version.txt" >nul || goto :cleanup

ISCC.exe "/DAppVersion=%VERSION%" "/DGuiExecutable=%GUI_EXE%" ^
  "/DCliExecutable=%ZUPT_CLI_EXE%" "/DBuildOutputDir=%ZUPT_DIST_DIR%" ^
  "/DRuntimeNoticesDir=%ZUPT_WINDOWS_RUNTIME_NOTICES_DIR%" ^
  "%REPO_ROOT%\packaging\windows\zupt-gui.iss" || goto :cleanup

if not exist "%ZUPT_DIST_DIR%\ZUPT-Setup-%VERSION%.exe" goto :cleanup
echo PASS: built %ZUPT_DIST_DIR%\ZUPT-Setup-%VERSION%.exe
set "RC=0"

:cleanup
if exist "%WORK%" rmdir /s /q "%WORK%"
endlocal & exit /b %RC%
