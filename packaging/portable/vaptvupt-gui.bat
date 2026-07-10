@echo off
rem SPDX-License-Identifier: AGPL-3.0-or-later
rem VaptVupt GUI launcher for Windows (portable package).
rem
rem Requirements on the target machine:
rem   * Python 3.8+  (https://python.org — tick "Add python.exe to PATH")
rem   * PySide6 or PyQt6:   py -m pip install PySide6
rem   * The vaptvupt CLI: vaptvupt.exe next to this file, or on PATH.
rem
rem If vaptvupt.exe sits beside this launcher we pin it via VAPTVUPT_BIN so the
rem GUI drives the bundled CLI rather than any other copy on PATH.
setlocal
set "HERE=%~dp0"
if exist "%HERE%vaptvupt.exe" set "VAPTVUPT_BIN=%HERE%vaptvupt.exe"

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
  echo vaptvupt-gui exited with code %RC%.
  echo If you saw an import error, install the Qt binding:  py -m pip install PySide6
  echo If the CLI was not found, put vaptvupt.exe next to this launcher or on PATH.
  pause
)
endlocal
