VaptVupt GUI — portable cross-platform package
==============================================

The VaptVupt GUI is a single Python file (zupt_gui.py) built on Qt for Python
(PySide6, or PyQt6 as a fallback). It runs on Windows, macOS, Linux and the
BSDs — anywhere Python 3 and a Qt binding are installed. This portable package
contains the GUI plus a launcher for each platform; it drives the `vaptvupt`
command-line tool under the hood.

Contents
--------
  zupt_gui.py            The GUI (PySide6 / PyQt6).
  vaptvupt-gui.bat       Windows launcher.
  vaptvupt-gui.command   macOS launcher (double-clickable in Finder).
  vaptvupt-gui.sh        Linux / BSD launcher.
  assets/zupt-icon.png   Application icon.

Requirements
------------
  1. Python 3.8 or newer.
       Windows:  https://python.org  (tick "Add python.exe to PATH")
       macOS:    python.org, or `brew install python`
       Linux:    your distro's python3 package
       FreeBSD:  pkg install python311
       OpenBSD:  pkg_add python%3
  2. A Qt binding:
       pip (any OS):   python3 -m pip install PySide6
       Debian/Ubuntu:  sudo apt install python3-pyqt6
       Fedora/RHEL:    sudo dnf install python3-pyqt6
       FreeBSD:        pkg install py311-pyside6
       OpenBSD:        pkg_add py3-pyside6
  3. The vaptvupt CLI, either:
       * placed next to the launcher (vaptvupt.exe on Windows, vaptvupt
         elsewhere) — the launcher auto-detects it via VAPTVUPT_BIN, or
       * installed on PATH (deb/rpm/AppImage/Homebrew/pkg — see the project
         release page).

Running
-------
  Windows:  double-click vaptvupt-gui.bat
  macOS:    double-click vaptvupt-gui.command
            (first run: right-click > Open to bypass Gatekeeper for an
             unsigned script, or `xattr -dr com.apple.quarantine .`)
  Linux/BSD: ./vaptvupt-gui.sh

Troubleshooting
---------------
  * "requires PySide6 or PyQt6"  -> install a Qt binding (requirement 2).
  * "vaptvupt not found"         -> put the CLI next to the launcher or on PATH.
  * Set VAPTVUPT_DEBUG=1 to print the binary-discovery log to stderr.

Fully self-contained native installers (Windows .exe/.msi, macOS .dmg) that
bundle Python + Qt + the CLI are produced by the project's CI on real Windows
and macOS runners — see the release page. This portable package is the
dependency-light option that works identically on every platform.

License: AGPL-3.0-or-later. Project: https://git.securityops.co/cristiancmoises/vaptvupt
