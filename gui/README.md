# ZUPT GUI

The ZUPT GUI is a Python/Qt front end for the ZUPT 5.2.7 command-line
program. It starts the CLI as a subprocess; compression, archive parsing, and
cryptography remain in the C program.

The canonical project repository is
`https://github.com/cristiancmoises/zupt`.

## Requirements

- a working `zupt` CLI from the same release, available on `PATH` or through
  the `ZUPT_BIN` environment variable;
- Python 3.9 or newer;
- PySide6 or PyQt6;
- a graphical session for normal use.

Install and test the source-only CLI first:

```sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)" \
  WITH_SDK=0 WITH_PQBOX=0
make WITH_SDK=0 WITH_PQBOX=0 check
./zupt --version
```

The GUI detects the capabilities reported by that binary. Native `--pq` and
`--pq-only` are available in the default build. SDK and PQBOX controls are
usable only when the CLI was built explicitly against the corresponding system
development libraries; no precompiled optional library is shipped in Git.

## Run from the source tree

Using a virtual environment keeps Python packages outside the repository:

```sh
python3 -m venv ~/.local/share/zupt-gui-venv
~/.local/share/zupt-gui-venv/bin/pip install PySide6
ZUPT_BIN="$PWD/zupt" \
  ~/.local/share/zupt-gui-venv/bin/python gui/src/zupt_gui.py
```

Installing PySide6 can access the Python package index. Do that as an explicit
setup step; upstream CLI builds, package builds, and checks do not download
dependencies.

For noninteractive checks:

```sh
python3 gui/src/zupt_gui.py --version
python3 gui/src/zupt_gui.py --selftest
```

The first command does not prove that a full desktop session works. Test the
actual windows and archive operations on every platform for which a GUI package
is published.

## Functions

| Area | Function |
|---|---|
| Keys | Generate keys supported by the selected CLI build |
| Compress | Select input, compression settings, and an available encryption mode |
| Extract | Detect archive encryption, request the needed credential, and extract |
| Verify | Run archive integrity validation without extraction |
| Info | Display metadata reported by the CLI |
| Disk | Front end for the CLI disk backup and restore commands |

Disk operations can require additional operating-system privileges. Run only
the specific CLI operation that needs them; do not run the whole desktop session
as root.

## Desktop integration

`gui/install.sh --user` installs the integration supported by that script for
the current user. Review the script and its destination paths before running
it. File-manager menus and file associations differ across desktops and
operating systems and must be tested on the target system.

## Packaged GUI builds

Release pages provide only these GUI artifacts after their separate package and
installed off-screen GUI/CLI integration gates pass:

- `zupt-gui_5.2.7_all.deb`;
- `zupt-gui-5.2.7-1.noarch.rpm`;
- `zupt-gui-5.2.7-1.src.rpm`;
- `zupt-gui-5.2.7-portable.zip`.

The DEB/RPM packages install the Python/Qt source and depend on the matching
`zupt` CLI package. The portable ZIP contains source, launchers, icons, licenses,
and provenance only; it bundles no Python, Qt, CLI, or compiled runtime. Its
gate scans the assembled and extracted trees, enforces an exact safe-member
allowlist, and runs the extracted launcher off-screen against the tested CLI.
An absent artifact did not pass its gate and must not be inferred from another
format's result.

GUI AppImage, AppDir and Flatpak bundles, and Windows/macOS GUI installers are
not promoted by the upstream 5.2.7 release gates.
`packaging/build-gui-appimage.sh` is a downstream-only helper and fails unless
its operator supplies the exact verified runtime plus a complete
license/source-relink notice through `APPIMAGE_RUNTIME_COMPLIANCE_FILE`; that
material is included in the resulting AppDir.

The downstream Windows GUI helper similarly requires
`ZUPT_WINDOWS_RUNTIME_NOTICES_DIR` with a `MANIFEST.txt` that identifies
the exact Python, PyInstaller, Qt and PySide/PyQt runtime inputs and their
notices. It fails unless the directory also has non-empty
`PYTHON-NOTICE.txt`, `PYINSTALLER-NOTICE.txt`, `QT-NOTICE.txt`, and either
`PYSIDE6-NOTICE.txt` or `PYQT6-NOTICE.txt`. The installer includes that
directory together with every ZUPT license and notice. This requirement does
not make the untested GUI installer a 5.2.7 release asset. The promoted Windows
ZIP and macOS DMG are CLI-only.

Packaging recipes and scripts under `gui/packaging/` and `packaging/` are build
inputs, not evidence that a package has been accepted by a distribution. They
must build the CLI from the immutable source tag with
`WITH_SDK=0 WITH_PQBOX=0` unless source-built system dependencies are declared.
Generated packages, application bundles, and executables must remain outside
Git and outside upstream source archives.

The former standalone `gui/setup.py` sdist/wheel route is intentionally absent:
its outputs did not carry the complete project license payload. Use
`gui/install.sh` or the reviewed distribution helpers so the AGPL text and
artwork provenance are installed with the GUI.

## Troubleshooting

Verify the exact interpreter and CLI used by the GUI:

```sh
python3 -c 'import PySide6.QtWidgets'
zupt --version
ZUPT_BIN=/absolute/path/to/zupt \
  python3 gui/src/zupt_gui.py --selftest
```

If no window appears, run the GUI from a terminal and check the display/Wayland
or X11 error. When reporting a problem, include OS and desktop versions, Python
and Qt binding versions, `zupt --version`, and the non-sensitive error
message. Never attach passwords, private keys, tokens, or confidential archives.

## License

The current GUI source is AGPL-3.0-or-later. Published historical revisions
include MIT notices whose grants remain applicable to the exact material
distributed under them. See `gui/LICENSE-GUI`, the 5.2.2 licensing erratum in
`CHANGELOG.md`, and the repository-level license notices.
