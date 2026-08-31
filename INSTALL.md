# Installing ZUPT 5.2.4

This guide covers the ZUPT command-line program and the optional Python GUI.
The canonical source repository is
`https://github.com/cristiancmoises/zupt`.

## Choosing an installation method

- Build from the immutable source tag when you want the upstream source-only
  path described below.
- Use a distribution package only when it matches your distribution release
  and architecture.
- Release-page DEB, RPM, Linux tar.xz, portable GUI ZIP, Windows ZIP, and macOS
  files are separate artifacts. Their presence does not make them part of the
  Git tree or upstream source archive. Use only artifacts whose release notes
  record a successful format-specific test for your target.

The immutable `v5.2.2` candidate was not promoted after CI integration
failures. The immutable `v5.2.3` candidate was not promoted because its
source-policy test assumed LF for a Windows `.bat` file checked out as the
required CRLF. Do not treat either candidate's artifacts as 5.2.4 packages.

The 5.2.4 package set eligible for promotion after each target gate succeeds is:

| Component | Gated artifacts |
|---|---|
| CLI | `zupt-5.2.4.tar.gz`, `zupt_5.2.4_amd64.deb`, openSUSE x86_64 binary/source RPMs, `zupt-5.2.4-linux-x86_64.tar.xz`, `zupt-5.2.4-windows-x86_64.zip`, and `ZUPT-5.2.4-macOS-*.dmg` |
| GUI | `zupt-gui_5.2.4_all.deb`, `zupt-gui-5.2.4-1.noarch.rpm`, `zupt-gui-5.2.4-1.src.rpm`, and `zupt-gui-5.2.4-portable.zip` |

The GUI packages require the matching `zupt` CLI package and must pass exact
payload/dependency checks plus an installed off-screen GUI/CLI integration
test. The source-only portable GUI ZIP bundles launchers, notices, and GUI
source, but not Python, Qt, or the CLI. The Linux tar.xz carries the tested CLI
beside the complete public license/notice payload. AppImage, AppDir, Flatpak
bundles, GUI platform installers, and bare Linux/Windows executables are not
promoted for 5.2.4. The Windows ZIP and macOS DMG contain the CLI only. Exact
target boundaries are listed in `README.md`.
The release's `SHA256SUMS` and validation notes, not the mere presence of a
download link, identify an artifact that completed its gate.

Do not install a package for a different distribution or CPU architecture.

## Build requirements

The default CLI build requires:

- a C11 compiler;
- GNU make;
- the platform C library, math library, and threading support;
- standard build utilities including `gzip` for installation and source export.

It does not need a vendored binary, OpenSSL, libargon2, `libvuptsdk`, or
`libpqvaptvupt`. Dependencies must be installed before the build; `make` does
not download anything.

Typical package-manager commands are:

```sh
# Debian / Ubuntu
sudo apt install build-essential gzip

# Fedora / RHEL family
sudo dnf install gcc make gzip

# openSUSE
sudo zypper install gcc make gzip

# Arch Linux
sudo pacman -S base-devel gzip
```

Package names can differ by distribution release. These commands are examples,
not a statement that 5.2.4 has been accepted into each distribution repository.

## Build and test from source

Verify the checkout or extracted archive, then use the source-only feature set:

```sh
scripts/check-source-only.sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)" \
  WITH_SDK=0 WITH_PQBOX=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 check
./zupt --version
./zupt --help
```

From a release archive, run the scanner as follows before extraction or from a
trusted checkout after download:

```sh
scripts/check-source-only.sh --archive /path/to/zupt-5.2.4.tar.gz
```

The default build provides the native password, ML-KEM-768 + X25519 hybrid
`--pq`, and ML-KEM-768 `--pq-only` paths. See `SECURITY.md` and
`THREAT_MODEL.md` before selecting an encryption mode.

For password encryption, prefer one of the explicit non-argv inputs:

```sh
# Interactive, without terminal echo; compress confirms the password.
zupt compress --password-prompt backup.zupt files/

# Read the first line of a mode-0600 file.
zupt test --pass-file /secure/path/password.txt backup.zupt

# Read the first line from an inherited descriptor.
zupt extract --pass-fd 3 -o restored backup.zupt 3</secure/path/password.txt
```

`-p/--password PASSWORD` remains available for compatibility, but the password
can be visible in shell history and process listings. `--pass-file` and
`--pass-fd` reject empty, NUL-containing, or overlong input and remove the
line-ending delimiter.

`make check` is the downstream-safe test gate. `make test-all` runs the broader
upstream suite. Optional tests remain conditional on their corresponding
system-built dependencies and must be reported as skipped when unavailable.

## Install

The upstream default prefix is `/usr/local`:

```sh
sudo make WITH_SDK=0 WITH_PQBOX=0 install
zupt --version
```

For a distribution-style `/usr` installation, or when building a package:

```sh
make DESTDIR="$pkgroot" PREFIX=/usr \
  WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 install
```

`DESTDIR` stages the files below a package root; it is not embedded in installed
paths. `PREFIX`, `BINDIR`, `LIBDIR`, `INCLUDEDIR`, and `MANDIR` can be overridden
without replacing packager-supplied compiler or linker flags.

The default installation provides `zupt`. To install the `vaptvupt` command
and manual-page compatibility aliases for versions 3.0.0 through 5.2.1, use:

```sh
sudo make INSTALL_LEGACY_ALIAS=1 install
```

The openSUSE main package installs `/usr/bin/zupt` as the primary command and
does not need the optional compatibility alias.

To remove an installation made with the same prefix:

```sh
sudo make PREFIX=/usr/local uninstall
```

## Optional system integrations

The SDK and PQBOX integrations are independent and disabled by default:

```sh
# Requires a system libvuptsdk development package or explicit SDK_* flags
make WITH_SDK=1 WITH_PQBOX=0

# Requires a system libpqvaptvupt development package or explicit PQBOX_* flags
make WITH_SDK=0 WITH_PQBOX=1

# Enable both only when both system dependencies are installed
make WITH_SDK=1 WITH_PQBOX=1
```

The Makefile normally obtains flags from `pkg-config`. A packager may provide
`SDK_CPPFLAGS`/`SDK_LDLIBS` or `PQBOX_CPPFLAGS`/`PQBOX_LDLIBS` explicitly. A
missing dependency is an error: there is no download and no fallback to a local
precompiled library.

Textual assembly under `jasmin/` can be selected separately with
`WITH_JASMIN=1` on a supported x86_64 compiler target. The directory contains
Jasmin-generated outputs and a separately identified hand-written production
unit; it is off by default and the portable C implementations are the baseline
build. Do not infer that an architecture is supported until that target has
actually built and passed its tests.

## GUI

The GUI invokes the `zupt` CLI; it does not replace the CLI or implement
archive cryptography in Python. Install and verify the CLI first:

```sh
zupt --version
python3 -m venv ~/.local/share/zupt-gui-venv
~/.local/share/zupt-gui-venv/bin/pip install PySide6
~/.local/share/zupt-gui-venv/bin/python gui/src/zupt_gui.py
```

The GUI can use PySide6 or PyQt6. Prefer a distribution-managed Qt binding when
available. A package-specific installer may provide launchers and desktop
integration; consult its release notes instead of assuming a particular GUI
package version or filename.

For a headless sanity check:

```sh
python3 gui/src/zupt_gui.py --version
python3 gui/src/zupt_gui.py --selftest
```

## Troubleshooting

If the CLI is not found, inspect the selected prefix:

```sh
command -v zupt
printf '%s\n' "$PATH"
```

If the GUI cannot find it, install the CLI in a directory on `PATH` or set
`ZUPT_BIN` to its absolute path. `VAPTVUPT_BIN` remains a compatibility
fallback. For Qt import failures, verify the same
Python interpreter that starts the GUI:

```sh
python3 -c 'import PySide6.QtWidgets'
```

For build failures, rerun with `V=1` and include the compiler target, full build
command, and first error in the issue report. Do not attach credentials,
private keys, passwords, or sensitive archives.

Report issues at:
`https://github.com/cristiancmoises/zupt/issues`.
