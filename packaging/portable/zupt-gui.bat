@echo off
rem SPDX-License-Identifier: AGPL-3.0-or-later
rem ZUPT GUI launcher for Windows (portable package).
rem
rem Requirements on the target machine:
rem   * Python 3.9+
rem   * PySide6 or PyQt6:   py -m pip install PySide6
rem   * The ZUPT CLI: zupt.exe next to this file, or on PATH.
rem
rem If zupt.exe sits beside this launcher we pin it via ZUPT_BIN so the
rem GUI drives the bundled CLI rather than any other copy on PATH.
setlocal
set "HERE=%~dp0"
if exist "%HERE%zupt.exe" set "ZUPT_BIN=%HERE%zupt.exe"

rem Prefer the py launcher, fall back to python on PATH.
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 "%HERE%zupt_gui.py" %*
) else (
  python "%HERE%zupt_gui.py" %*
)
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo zupt-gui exited with code %RC%.
  echo If you saw an import error, install the Qt binding:  py -m pip install PySide6
  echo If the CLI was not found, put zupt.exe next to this launcher or on PATH.
)
endlocal & exit /b %RC%
