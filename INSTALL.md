# Installing ZUPT

This guide covers the ZUPT 5.2.10 CLI and optional Python GUI, using desktop
archive format 1.6. The canonical source is [GitHub](https://github.com/cristiancmoises/zupt).
Obtain signed tags, official packages and `SHA256SUMS` from the
[release page](https://github.com/cristiancmoises/zupt/releases), and select the
asset matching your operating system and architecture. Historical assets keep
their original tar/ZIP/DMG or native formats.

## Choosing an installation method

- Build from the immutable source tag when you want the upstream source-only
  path described below.
- Use a distribution package only when it matches your distribution release
  and architecture.
- Release-page DEB/RPM/SRPM and the five `.zupt` bundles are separate artifacts.
  Their presence does not make them part of the
  Git tree or upstream source archive. Use only artifacts whose release notes
  record a successful format-specific test for your target.

## 5.2.10 bundle formats and verification

The 5.2.10 bundle contract uses five genuine, unencrypted VaptVupt level-9
`.zupt` containers. Obtain the matching assets from the selected release page:

| Bundle | Contents and prerequisites |
|---|---|
| `zupt-5.2.10-source.zupt` | Exact final signed source tree; a trusted desktop Zupt decoder is needed to unpack it. |
| `zupt-5.2.10-linux-x86_64.zupt` | Static-musl Linux x86_64 CLI and complete runtime notices. |
| `zupt-5.2.10-windows-x86_64.zupt` | Native x86_64 CLI and five mandatory MinGW/GCC runtime notices; no Qt GUI. |
| `zupt-5.2.10-macos-arm64.zupt` | CLI-only `ZUPT-5.2.10-macOS-arm64.dmg`; not a universal binary or Qt GUI. |
| `zupt-gui-5.2.10-portable.zupt` | Frontend source/scripts/notices; Python, PySide6 or PyQt6, and a matching `zupt` CLI remain external. |

Native packages are `zupt_5.2.10_amd64.deb`, CLI binary/source RPMs
`zupt-5.2.10-0.{x86_64,src}.rpm`, `zupt-gui_5.2.10_all.deb`, and GUI
`zupt-gui-5.2.10-1.{noarch,src}.rpm`. Do not install an SRPM as a binary package.
AppImage, AppDir, Flatpak and platform GUI installers are not in this delivery.

Verify the registered signing fingerprint through an independently trusted
channel: `0CFA43B9AA9642EAAF2BE983C4C661C9ECFB46E8`. Import the
confirmed `release-key.asc`, then verify the inventory before unpacking:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
zupt test zupt-5.2.10-source.zupt
zupt extract -o source-check zupt-5.2.10-source.zupt
```

Use a new extraction directory and inspect the restored files. A trusted 5.2.9
desktop CLI is one bootstrap option for plain format-1.6 bundles. Validate
compatibility with the selected release; this does not imply encrypted/PQ
interoperability. Do not rename a tarball to `.zupt`.
Extraction restores regular file contents, not executable modes. For the
verified Linux CLI bundle, restore only its executable permission:

```sh
zupt test zupt-5.2.10-linux-x86_64.zupt
zupt extract -o linux-check zupt-5.2.10-linux-x86_64.zupt
chmod u+x linux-check/zupt-5.2.10-linux-x86_64/zupt
linux-check/zupt-5.2.10-linux-x86_64/zupt --version
```

Forge-generated source archives and standard SRPM build inputs are separate
internal/downstream inputs, not manually uploaded `.tar.gz` release downloads.

The manifest and signature must match the exact files being installed. A local
extracted DEB/RPM smoke test is not a native installation test; see
[DISTRIBUTION.md](DISTRIBUTION.md) for the required package gates. Earlier
artifacts signed with the legacy key
`CF8BA569591B6E7F4D24B0736C95BFAE0646DCCA` retain their own verification scope.

## Historical releases (not current validation)

Historical assets retain their release-specific formats and signatures. Use the
matching extraction tool and verification instructions, and keep earlier tags
and checksums immutable. The [audit history](AUDIT.md#recorded-validation-and-historical-results)
summarizes prior outcomes; they do not qualify a different release or package.

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
not a statement that 5.2.10 has been accepted into each distribution repository.

## Build and test from source

After verifying and extracting the source bundle above, enter and audit its
tree. Restore execute permission on the source checker and the three test
wrappers that execute themselves through temporary symlinks:

```sh
cd source-check/zupt-5.2.10-source
chmod u+x scripts/check-source-only.sh \
  tests/test_frama_aes_nist_wrapper.sh \
  tests/test_frama_ans_decode_bounds_wrapper.sh \
  tests/test_jasmin_source_wrapper.sh
bash scripts/check-source-only.sh --tree .
```

A Git checkout retains tracked execute modes. For a release-pinned build,
select and verify a published signed tag as described in the
[source-build guide](docs/USER_GUIDE.md#build-from-source). Build the source-only feature set with:

```sh
scripts/check-source-only.sh --tree .
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)" \
  WITH_SDK=0 WITH_PQBOX=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 check
./zupt --version
./zupt --help
```

Pin downstream recipes to the selected signed tag and verify the source digest.
Never bypass checksum verification to make a mismatched recipe work.

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

### Downstream recipe validation

For an installation, select an official published release and its matching
recipe. Verify the recipe source URL,
checksum and exact signed source commit, then build and test it with the
target package manager.

`packaging/guix/zupt.scm` selects the GUI package, whose launcher pins the
matching store CLI. A `guix build -f packaging/guix/zupt.scm` check builds a
store result; it does not install it in the profile. Inspect the result before
any `guix package -f` transaction. Guix smoke tests do not establish
AUR/Homebrew/Nix installation support. Never disable checksum verification.

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

For the verified portable `.zupt` frontend, extract into a new directory and
invoke its launcher through `bash`, since execute modes are not preserved:

```sh
zupt test zupt-gui-5.2.10-portable.zupt
zupt extract -o gui-check zupt-gui-5.2.10-portable.zupt
ZUPT_BIN=/absolute/path/to/verified/zupt \
  bash gui-check/zupt-gui-5.2.10-portable/zupt-gui.sh
```

Use your external Python/Qt environment; the portable bundle does not ship
Python, Qt or the CLI.

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
