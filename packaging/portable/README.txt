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
  README.pt-BR.md        Brazilian Portuguese project overview.
  DOCUMENTACAO.pt-BR.md  Brazilian Portuguese operational guidance.
  docs/USER_GUIDE.md     English command, restoration and test reference.
  docs/GUIA_USUARIO.pt-BR.md  The same reference in Brazilian Portuguese.
  SECURITY.md            Security reporting and validation boundaries.
  DISTRIBUTION.md        Package, dependency and release policy.

Requirements
------------
  1. Python 3.9 or newer.
  2. PySide6 6.5 or newer, or a compatible PyQt6 package.
  3. ZUPT 5.2.10, installed as `zupt` on PATH or placed beside the launcher
     (`zupt.exe` on Windows). A local command must have been built
     and tested independently; this bundle never downloads one.

Running
-------
  Windows:  zupt-gui.bat
  macOS:    bash zupt-gui.command
  POSIX:    bash zupt-gui.sh

The .zupt format restores file contents but does not restore executable permissions.
Run these commands from the verified extracted bundle directory. For the macOS
Finder launcher, use `chmod u+x zupt-gui.command` on that verified file before
opening it in Finder. Do not change permissions recursively. The Windows batch
launcher does not need a Unix executable bit.

The launchers set ZUPT_BIN when a local command is present. The GUI then
checks `zupt version`, discovers native and optional capabilities, and
exposes SDK or PQ-box modes only when the command reports the corresponding
system-library integration enabled.

Troubleshooting
---------------
  * "requires PySide6 or PyQt6": install one Qt binding through your operating
    system package manager or another trusted, preconfigured Python source.
  * "zupt not found": install ZUPT 5.2.10 or place its command beside
    the launcher.
  * Set ZUPT_DEBUG=1 to print command-discovery diagnostics to stderr.

The old user-facing command name is not installed by this bundle. The `.zupt`
archive extension remains unchanged for format compatibility.

The guides remain under docs/ so the links in README.pt-BR.md also work offline.
Their SECURITY/DISTRIBUTION links resolve to policies in the bundle root;
source headers and test scripts still require a source checkout.
Consulte docs/GUIA_USUARIO.pt-BR.md para comandos, restauração e testes em pt-BR.
As políticas referenciadas acompanham os guias; links para headers e scripts
de teste ainda exigem o checkout das fontes.

Current GUI source license: AGPL-3.0-or-later. Published historical revisions
include MIT grants for the exact material covered by their notices; see
LICENSE-GUI and the 5.2.2 erratum in CHANGELOG.md.
Project: https://github.com/cristiancmoises/zupt
