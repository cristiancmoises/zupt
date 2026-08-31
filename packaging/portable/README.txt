ZUPT GUI — source-only portable launcher template
=====================================================

This tracked directory contains three launcher templates and this assembly
guide; it is not a complete bundle by itself. A downstream source-only bundle
may add the integrated Python GUI source and artwork listed below, together
with the required license/provenance files. It must not contain Python, Qt, a
precompiled ZUPT command, or a vendored library. Its presence in a release
would not be evidence that every target operating system was tested; consult
that release's validation matrix.

Contents
--------
  zupt_gui.py            GUI source module (the historical module filename is
                         retained internally for source compatibility).
  zupt-gui.bat           Windows launcher.
  zupt-gui.command       macOS Finder launcher.
  zupt-gui.sh            POSIX shell launcher.
  assets/zupt-icon.png   PNG application artwork.
  assets/zupt.ico        Windows application artwork.
  LICENSE-AGPL-3.0       Complete current GUI source license text.
  LICENSE-GUI            GUI licensing and historical-license note.
  ASSET-PROVENANCE.md    Artwork purpose, provenance, and license record.
  CHANGELOG.md           Release history and current compatibility notes.

Requirements
------------
  1. Python 3.9 or newer.
  2. PySide6 6.5 or newer, or a compatible PyQt6 package.
  3. ZUPT 5.2.5, installed as `zupt` on PATH or placed beside the launcher
     (`zupt.exe` on Windows). A local command must have been built
     and tested independently; this bundle never downloads one.

Running
-------
  Windows:  zupt-gui.bat
  macOS:    zupt-gui.command
  POSIX:    ./zupt-gui.sh

The launchers set ZUPT_BIN when a local command is present. The GUI then
checks `zupt version`, discovers native and optional capabilities, and
exposes SDK or PQ-box modes only when the command reports the corresponding
system-library integration enabled.

Troubleshooting
---------------
  * "requires PySide6 or PyQt6": install one Qt binding through your operating
    system package manager or another trusted, preconfigured Python source.
  * "zupt not found": install ZUPT 5.2.5 or place its command beside
    the launcher.
  * Set ZUPT_DEBUG=1 to print command-discovery diagnostics to stderr.

The old user-facing command name is not installed by this bundle. The `.zupt`
archive extension remains unchanged for format compatibility.

Current GUI source license: AGPL-3.0-or-later. Published historical revisions
include MIT grants for the exact material covered by their notices; see
LICENSE-GUI and the 5.2.2 erratum in CHANGELOG.md.
Project: https://github.com/cristiancmoises/zupt
