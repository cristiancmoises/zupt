# Installing ZUPT 5.2.8

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
required CRLF. The immutable `v5.2.4` candidate was not promoted after exact-tag
GitHub Actions run `33431386002`: 12 jobs succeeded, the sole openSUSE
service-harness job failed because its executor did not enter the service
directory, and dependent Windows/macOS jobs were skipped. A local Tumbleweed
reproduction confirmed both the explicit tag ref and the corrected
working-directory contract. This is release/test integration only; the product,
archive format, cryptography, codec, and SDK ABI are unchanged. The immutable
`v5.2.5` candidate was likewise not promoted: exact-tag GitHub Actions run
`33434986357` recorded 13 successful jobs and failed native Windows/macOS jobs.
The immutable `v5.2.6` candidate was not promoted after run `33442264243`
recorded 13 successful jobs and two native failures: unused x86 SHA-NI helper
declarations on macOS arm64 under `-Werror`, and early Windows abortion while
argv-transcoding a safe UTF-8 fixture. Version 5.2.7 corrected those boundaries
but was not promoted after exact-tag run `33445470664`: 13 jobs succeeded,
macOS failed because its filesystem rejected the raw-C1 filename fixture with
`EILSEQ`, and Windows was cancelled after the hosted job stalled in `make
check`; a MinGW/Wine reproduction isolated the cause to the non-console
password-prompt test entering `_getch`. Version 5.2.8 makes both
fixtures portable, hardens the three CodeQL High path-race boundaries described
in the security documents, and adds `sdk-test` to release and hosted Linux
gates. It still requires fresh exact-version validation. Do not treat any prior
candidate's artifacts or evidence as 5.2.8 packages or validation.

The 5.2.8 package set eligible for promotion after each target gate succeeds is
exactly these 13 assets:

| Component | Gated artifacts |
|---|---|
| Source and checksums | `zupt-5.2.8.tar.gz`, `zupt-5.2.8.tar.gz.sha256`, and `SHA256SUMS` |
| CLI | `zupt_5.2.8_amd64.deb`, `zupt-5.2.8-0.x86_64.rpm`, `zupt-5.2.8-0.src.rpm`, `zupt-5.2.8-linux-x86_64.tar.xz`, `zupt-5.2.8-windows-x86_64.zip`, and exactly one `ZUPT-5.2.8-macOS-{x86_64\|arm64}.dmg` |
| GUI | `zupt-gui_5.2.8_all.deb`, `zupt-gui-5.2.8-1.noarch.rpm`, `zupt-gui-5.2.8-1.src.rpm`, and `zupt-gui-5.2.8-portable.zip` |

The GUI packages require the matching `zupt` CLI package and must pass exact
payload/dependency checks plus an installed off-screen GUI/CLI integration
test. The source-only portable GUI ZIP bundles launchers, notices, and GUI
source, but not Python, Qt, or the CLI. The Linux tar.xz carries the tested CLI
beside the complete public license/notice payload. AppImage, AppDir, Flatpak
bundles, GUI platform installers, and bare Linux/Windows executables are not
promoted for 5.2.8. The Windows ZIP and macOS DMG contain the CLI only. Exact
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
not a statement that 5.2.8 has been accepted into each distribution repository.

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
scripts/check-source-only.sh --archive /path/to/zupt-5.2.8.tar.gz
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
