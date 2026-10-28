# ZUPT GUI

[English installation guide](../INSTALL.md#gui) |
[Português do Brasil](../DOCUMENTACAO.pt-BR.md#interface-gráfica)

The ZUPT GUI is a Python/Qt front end for the command-line program.
Version 5.2.10 is in development; the official published version remains
[5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
The earlier 5.2.10 delivery was withdrawn. The instructions for its planned
packages below do not identify available official downloads.
The GUI starts the CLI as a subprocess; compression, archive parsing, and
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
make WITH_SDK=0 WITH_PQBOX=0 check-gui
```

`check-gui` requires an installed Qt binding and fails if it is missing or
broken. It exercises real VaptVupt archive creation, metadata, verification,
and byte-exact extraction, including missing/wrong/correct passwords, widget
reuse, GUI-thread callbacks, startup cancellation and closing a live operation.
It uses synthetic files and dummy passwords in a temporary directory. Normal
test completion is required; a forced GUI exit is not a passing result.
`make check` remains the separate CLI-only distribution gate.

The same suite tests unavailable module specs, missing loaders, and a missing
source-version macro by rerunning the real test bootstrap. These cases require
explicit errors; invalid specs must be rejected before module creation. They
do not replace the real GUI/CLI workflow checks above.

GUI operations have a monotonic 7200-second execution deadline measured before
the CLI child is spawned, including startup time and blocked output reads. The
standard-library watchdog thread starts before process creation and waits for
the launch attempt to return or raise before handling expiry. Backups lasting
longer than two hours are terminated and reported as failures. The wait after EOF
uses only the remaining budget. The launch wait is released before cancelling
and joining the watchdog, before child cleanup and completion. Cancellation,
deadline expiry and read errors attempt to stop the direct child, wait up to
five seconds and close its output
pipe. Each cleanup step is attempted even if an earlier one fails; cleanup
failure is reported as an operation failure. Diagnostics include only the
watchdog/cleanup stage and exception type, not arguments. Cleanup is best effort:
failed termination or waiting cannot guarantee reaping. The deadline cannot
forcibly interrupt blocked process creation and does not cover descendants
retaining the output pipe or uninterruptible OS operations. Tests cover real
silent/progress children, EOF without exit, remaining wait budget, watchdog
failures and exit/cancellation races.

The version and selftest commands do not prove that a full desktop session works. Test the
actual windows and archive operations on every platform for which a GUI package
is published.

The GUI replaces values following `-p` and `--password` with `[redacted]` in
its command log. The real subprocess arguments are unchanged: the password
still appears in the child process arguments. This change does not protect
against local process inspection; the CLI's `--pass-file`, `--pass-fd` and
`--password-prompt` interfaces avoid that exposure outside the GUI.

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

The installer also places the English and pt-BR user guides under
`PREFIX/share/doc/zupt-gui/docs/`, with `SECURITY.md` and `DISTRIBUTION.md`
in the parent documentation directory. A `DATADIR` override changes the
`share` location. Use `--destdir` to inspect a temporary installation without
modifying the host. `bash tests/test_packaging_syntax.sh` checks the actual
staged bytes and modes, custom paths and rejection of missing guides; it
does not build or approve a native package. Links to source headers and
test scripts still require the source checkout.

## Packaged GUI builds

The planned 5.2.10 GUI delivery is limited to the following formats.
None is approved for publication until its fresh package and installed
off-screen GUI/CLI integration gates pass:

- `zupt-gui_5.2.10_all.deb`;
- `zupt-gui-5.2.10-1.noarch.rpm`;
- `zupt-gui-5.2.10-1.src.rpm`;
- `zupt-gui-5.2.10-portable.zupt`.

The DEB/RPM packages install the Python/Qt source and depend on the matching
`zupt` CLI package. The portable `.zupt` contains source, launchers, icons,
licenses, provenance, bilingual guides and linked policies; it bundles no Python, Qt, CLI, or compiled
runtime. Its gate scans the assembled and extracted trees, enforces an exact safe-member
allowlist, and runs the extracted launcher off-screen against the tested CLI.
An absent artifact did not pass its gate and must not be inferred from another
format's result.

After verifying the signed inventory and checksums as described in
[INSTALL.md](../INSTALL.md#planned-5210-bundles-and-verification), use a trusted
desktop Zupt decoder and a new extraction directory:

```sh
zupt test zupt-gui-5.2.10-portable.zupt
zupt extract -o gui-check zupt-gui-5.2.10-portable.zupt
ZUPT_BIN=/absolute/path/to/verified/zupt \
  bash gui-check/zupt-gui-5.2.10-portable/zupt-gui.sh
```

Use an external Python/Qt environment and a CLI from the same release.
Extraction restores file contents, not executable permissions; invoke the
shell launcher through `bash` instead of changing permissions recursively.
Historical 5.2.9 packages retain their original formats and extraction tools.

GUI AppImage, AppDir and Flatpak bundles, and Windows/macOS GUI installers are
not promoted by the upstream 5.2.10 release gates.
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
not make the untested GUI installer a 5.2.10 release asset. Windows and macOS
binaries need independent native builds and tests.

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
