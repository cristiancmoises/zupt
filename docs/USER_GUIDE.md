# ZUPT user guide

This guide covers the supported command-line and graphical workflows for ZUPT.
Every example uses a disposable path, makes verification explicit, and keeps
passwords out of process arguments.

Contact the project only at [sac@securityops.co](mailto:sac@securityops.co).
For vulnerability reports, follow the [security policy](../SECURITY.md).

Read this guide in [Brazilian Portuguese](GUIA_USUARIO.pt-BR.md).

## Contents

- [Release status](#release-status)
- [Install or update on openSUSE Tumbleweed](#install-from-opensuse-tumbleweed)
- [Build, install or uninstall from source](#build-from-source)
- [Create, verify and restore archives](#command-line-workflow)
- [Recover trusted legacy archives](#trusted-legacy-archives-without-ait)
- [Extract software bundles](#working-with-zupt-bundles)
- [Use the graphical interface](#gui-workflow)
- [Run validation and report results](#validation-and-reporting)
- [Reproduce audit checks](#reproduce-the-audit-checks)
- [Troubleshoot common problems](#troubleshooting)

For package layouts and release requirements, see the
[distribution guide](../DISTRIBUTION.md). The [audit guide](../AUDIT.md)
records findings, analysis assumptions and remaining coverage.

## Release status

This guide covers ZUPT 5.2.10 and desktop archive format 1.6. The
[release page](https://github.com/cristiancmoises/zupt/releases) provides signed
tags, packages, release notes and checksums. Select the release and asset for
your platform and follow the [verification instructions](../INSTALL.md#5210-bundle-formats-and-verification).

ZUPT Web is available at <https://zupt-web.securityops.co> for disposable,
non-sensitive examples. It is a separate deployment with its own version,
limits and trust boundary.

## Install from openSUSE Tumbleweed

ZUPT is available through the community OBS project
[`home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators).
Use the [openSUSE package page](https://software.opensuse.org/package/zupt) to
select the exact distribution and architecture. For Tumbleweed, review the
repository and signing key before enabling it:

```sh
sudo zypper refresh
sudo zypper install zupt
zupt --version
```

For an installed package update:

```sh
sudo zypper refresh
sudo zypper update zupt
zupt --version
```

Review the transaction and keep repository signature checks enabled. These
commands update ZUPT; they do not perform a Tumbleweed distribution upgrade.
The package is maintained downstream by the openSUSE community; thanks to
[Cabelo](https://build.opensuse.org/users/cabelo) for maintaining that package.

## Build from source

The distribution profile requires a C11 compiler, GNU Make, the system C and
math libraries, and POSIX threads. The build does not download dependencies.
Choose a signed tag from the [release page](https://github.com/cristiancmoises/zupt/releases).
Replace `PUBLISHED_TAG` below with that exact tag and verify its signature with
the independently trusted key described in [INSTALL.md](../INSTALL.md):

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git fetch origin tag PUBLISHED_TAG
git verify-tag PUBLISHED_TAG
git switch --detach PUBLISHED_TAG
git rev-parse HEAD
```

Build the selected revision:

```sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
```

The default build is source-only and uses the portable C implementation. The
optional SDK and PQBOX integrations must be supplied by the operating system;
the Makefile never downloads or loads a library from the repository.

For an installation staging directory:

```sh
stage=$(mktemp -d)
make install DESTDIR="$stage" PREFIX=/usr INSTALL_LEGACY_ALIAS=0
find "$stage" -type f -o -type l | sort
```

The default installation prefix is `/usr/local`. For a local installation,
use `sudo make install PREFIX=/usr/local INSTALL_LEGACY_ALIAS=0`. Uninstall
with the same path variables:

```sh
sudo make uninstall PREFIX=/usr/local INSTALL_LEGACY_ALIAS=0
```

Packagers can override `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS`, `AR`,
`RANLIB`, `STRIP`, `DESTDIR`, `PREFIX`, `BINDIR`, `LIBDIR`, `INCLUDEDIR` and
`MANDIR`. `INSTALL_LEGACY_ALIAS=1` adds the renamed-era `vaptvupt` compatibility
command and manual page; the default is 0. Packages should retain 0 unless
ownership and conflicts for that name have been checked.

## Command-line workflow

Create, inspect, verify and restore an archive in a new directory:

```sh
mkdir -p demo/input demo/restored
printf '%s\n' 'example data' > demo/input/readme.txt
zupt compress demo/backup.zupt demo/input
zupt list demo/backup.zupt
zupt test demo/backup.zupt
zupt extract -o demo/restored demo/backup.zupt
cmp demo/input/readme.txt demo/restored/readme.txt
```

Use `zupt --help` and `man zupt` for the complete option set. Keep passwords
out of shell history and process listings:

```sh
zupt compress --password-prompt demo/encrypted.zupt demo/input
umask 077
printf '%s\n' 'example-password' > demo/password.txt
zupt compress --pass-file demo/password.txt demo/encrypted.zupt demo/input
rm -f demo/password.txt
```

Prefer an interactive terminal or a mode-0600 password file for real backups.
Do not place production secrets in examples, CI logs or web uploads.

Encrypted archives authenticate metadata and blocks with HMAC-SHA256. The
`--pq` mode combines ML-KEM-768 and X25519; `--pq-only` uses ML-KEM-768 alone.
Unencrypted archives provide corruption detection, not confidentiality or
authentication.

## Trusted legacy archives without AIT

`extract`, `list`, `test` and `disk restore` require a valid archive-integrity
trailer by default, without trusting header flags to decide whether
authentication is required. This prevents removing a trailer and clearing an
unauthenticated encryption flag from silently downgrading metadata checks.
`--allow-legacy-no-ait` is accepted only by those four commands, solely for
recovery of a known, trusted archive created before AIT was introduced. Do not
use it for untrusted or attacker-writable input. Verify recovered data and
migrate it to an archive created with an official current release. Compression
and disk backup never create a no-AIT archive.

`info` reports unauthenticated framing metadata without validating AIT or
contents. Its successful exit is not an integrity result.

This exception is separate from v5.2.1 disk-index compatibility. Published
v5.2.1 disk archives normally have AIT. The tested narrow scope includes the
718-byte password-encrypted, deduplicated DATA/DATA/REF/DATA disk fixture,
stored as auditable hexadecimal text with provenance and SHA-256. It uses the
fixed-width legacy index and linear AAD sequence; the reader lists, tests,
extracts and restores it byte-exact. The historical full Linux gate passed on
`ff99770`. This does not cover every historical combination or establish that
an old reader supports new flag-gated encodings.

## Working with `.zupt` bundles

Release bundles use ZUPT's own `.zupt` container. They are not tarballs and
must be checked before extraction:

```sh
zupt test zupt-5.2.10-linux-x86_64.zupt
mkdir -p linux-check
zupt extract -o linux-check zupt-5.2.10-linux-x86_64.zupt
chmod u+x linux-check/zupt-5.2.10-linux-x86_64/zupt
linux-check/zupt-5.2.10-linux-x86_64/zupt --version
```

`.zupt` extraction restores file contents, not executable modes. Apply execute
permission only to verified executables. For a source bundle, inspect
the extracted tree before building:

```sh
zupt test zupt-5.2.10-source.zupt
zupt extract -o source-check zupt-5.2.10-source.zupt
find source-check -maxdepth 2 -type f -print | sort
```

Before building and running the audit tests from this extracted source, follow
the [source permission setup](../INSTALL.md#build-and-test-from-source). It
restores execute permission only on the source checker and three test wrappers;
do not make the entire extracted tree executable.

Do not rename an arbitrary tar archive to `.zupt`, and do not treat a local
prototype as an official release. Release checksums and signatures belong to
the exact published asset.

To check a local source bundle, first prepare a reviewed `staged-source`
directory containing only the intended regular source files. Keep Git metadata,
credentials, build outputs and the output archive outside that directory. Use
a new extraction destination:

```sh
zupt compress --vv -l 9 -t 1 source-validation.zupt staged-source
zupt info source-validation.zupt
zupt test source-validation.zupt
zupt extract -t 1 -o source-restored source-validation.zupt
diff -r staged-source source-restored/staged-source
```

Confirm that `info` reports `Encrypted: no`; `test` does not accept `-t`.
The comparison checks contents, not executable permissions. Restore only known,
verified source modes before running build helpers.
## GUI workflow

The GUI is a Python/Qt frontend around the local `zupt` executable. Install the
CLI first, then install PyQt6 or PySide6 from the operating system. From a
source checkout:

```sh
export ZUPT_BIN="$(command -v zupt)"
python3 gui/src/zupt_gui.py
```

The GUI does not bypass CLI verification. Use a new destination directory for
each restore, review the selected archive and output path, and confirm the
result with `zupt test` or a byte comparison.

Operation logs display CLI output and archive names as plain text. Tags such
as `<b>` and entities such as `&amp;` remain literal; they must not change the
appearance or meaning of a diagnostic. Selecting older output and scrolling
up must not be disrupted by new log entries.

UTF-8 characters may span multiple reads from the CLI pipe. The worker keeps
decoding state within each operation and flushes it at normal EOF. Invalid or
unfinished sequences use replacement characters instead of failing the job;
this affects display only, not archived filenames or payload bytes.

To test the current checkout rather than an older installed CLI, build it and
run the actual GUI workflow suite with the selected interpreter:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
env ZUPT_BIN="$PWD/zupt" QT_QPA_PLATFORM=offscreen make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check-gui
```

For the source GUI installer, prepare a temporary staging directory instead
of changing the host. In Bash, use `stage=$(mktemp -d)`; in fish, use
`set -l stage (mktemp -d)`. Then run:

```sh
bash gui/install.sh --destdir "$stage" --prefix /usr
cmp docs/USER_GUIDE.md "$stage/usr/share/doc/zupt-gui/docs/USER_GUIDE.md"
cmp docs/GUIA_USUARIO.pt-BR.md "$stage/usr/share/doc/zupt-gui/docs/GUIA_USUARIO.pt-BR.md"
bash tests/test_packaging_syntax.sh
```

The installer includes both guides and the linked SECURITY, DISTRIBUTION, AUDIT,
INSTALL and THREAT_MODEL pages. The regression requires real staged bytes, mode
0644, a custom data directory and missing-guide rejection before any
installation output. Native GUI DEB builds use this installer, but these staging
checks do not build or validate the DEB. Other native packaging helpers have
separate payload and runtime gates. Source-header and test-script references
need the checkout.

Windows bundles and both macOS DMG documentation locations include both user
guides and SECURITY, DISTRIBUTION, AUDIT, INSTALL and THREAT_MODEL. After
extracting the Windows bundle or mounting the DMG read-only, compare that
private, quiescent tree against its exact source checkout:

```sh
make -j1 test-installed-docs
python3 -B scripts/check-installed-docs.py . /path/to/windows-extraction windows
python3 -B scripts/check-installed-docs.py . /path/to/read-only-dmg macos
```

The checker only reads files; it does not extract or mount packages. It checks
the Windows directory version and both macOS `Info.plist` versions against the
source header. POSIX documents must have mode 0644. Native Windows NT files
normally report 0666; that profile does not establish ACL correctness. The
earlier 30-case Linux suite for `7fe4eb5` passes 29 cases and skips the native
NT-junction case. The expanded working-tree suite defines 32 cases, including
two GUI-installer staging regressions. Before this documentation update, its
local Linux run passes 31 cases and skips the native NT-junction case. The
earlier six Windows/macOS recipe-staging controls pass without executing the
placeholder CLI. Run native Windows/macOS package CI for each changed revision;
earlier `b25a486` packages do not cover these changes.

Native Windows CI on `3e50a65` reports 12 permission-fixture subtest failures:
the checker accepts files after the fixture requests mode 0600, although the
profile requires 0644. This suggests a permission-change capability mismatch;
the raw log does not print the observed mode. The read-only 0444 controls are
rejected as intended. The failed run does not qualify packages or establish a
codec/cryptographic fault. The local correction tests read-only rejection
separately and skips the owner-only capability case explicitly if 0600 cannot
be materialized. The checker criteria remain unchanged; repeat native checks.

The portable frontend has a separate packaging regression target; it uses
real `.zupt` containers and does not require Qt:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-portable-gui
```

To rehearse a local frontend package, use a fresh output directory. In Bash,
set `release_dir=$(mktemp -d)`; in fish, use `set -l release_dir (mktemp -d)`.
Then run this single-line command in either shell:

```sh
env ZUPT_BIN="$PWD/zupt" DIST_DIR="$release_dir" bash packaging/build-portable-gui.sh
```

The helper checks the matching CLI, requests unencrypted VaptVupt level 9, tests
the container and verifies the exact 20-file inventory. Both user guides remain
under `docs/`; SECURITY, DISTRIBUTION, AUDIT, INSTALL and THREAT_MODEL remain in
the bundle root. It scans both source trees and compares all extracted bytes. It
writes the `.zupt`, its SHA-256 sidecar and a retained `.extracted` directory.
Existing output targets are refused. A publication error can leave verified
partial outputs for inspection; the helper does not delete final paths that
another process may have replaced. This local rehearsal is not a signed release
or native package approval. Python, Qt and the independently tested CLI remain
external dependencies. Source-header and test-script links still require the
checkout; this is not a complete offline copy of the repository documentation.
Run an extracted shell launcher through `bash`, not by assuming executable
permissions survived extraction.

The portable-package checks verify archive contents, checksums, extracted bytes
and failure handling. They use real CLI operations but do not execute Qt:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-portable-gui
make audit-licenses
```

Run `check-gui` separately with a supported Qt binding and qualify installed
packages on their target platform.

<!-- Stable fragment links from earlier editions. -->
<a id="test-fixture-file-handling"></a>
<a id="portable-check-supervision-and-tool-coverage"></a>
<a id="reproducing-the-static-analyzer-checks"></a>
<a id="current-formal-evidence-reviewed-2026-11-12"></a>
<a id="local-precommit-checks-2026-10-28"></a>
<a id="ans-exact-output-bounds"></a>
<a id="earlier-gcc-and-gui-validation-2026-10-23"></a>
<a id="bounded-ans-logarithm-proof"></a>
<a id="ans-frequency-validation"></a>
<a id="ans-decode-table-entry-bounds"></a>
<a id="earlier-maintained-formal-repeat-2026-10-21"></a>
<a id="ci-credential-gate-regression"></a>
<a id="native-package-documentation-checks"></a>
<a id="rpm-spec-metadata"></a>
<a id="package-tool-failure-regressions"></a>
<a id="linux-disk-capacity-abi-checks"></a>
<a id="archive-output-capability-checks"></a>
<a id="legacy-disk-fixture-checks"></a>
<a id="decode-slack-test-supervision"></a>
<a id="sdk-symbol-check-supervision"></a>
<a id="exact-size-and-bcj-test-supervision"></a>
<a id="worker-allocation-failures-and-archive-preservation"></a>
<a id="static-analysis-gate-controls"></a>
<a id="sdk-callback-tests"></a>
<a id="native-key-file-read-tests"></a>
<a id="threaded-suite-password-and-integrity-controls"></a>
<a id="installed-executable-checks"></a>
<a id="guix-gui-build-time-checks"></a>
<a id="pyqt6-fallback-and-native-object-lifetime"></a>
<a id="gui-query-failures"></a>
<a id="fuzz-harness-build-and-seed-validation"></a>
<a id="codec-and-cryptographic-checks"></a>
<a id="direct-refill-boundaries"></a>
<a id="ans-reader-consumption-and-conditional-wp-check"></a>
<a id="reproduce-the-focused-ans-sanitizer-tests"></a>
<a id="ans-logarithm-ranges"></a>
<a id="portable-aes-known-answer-and-eva-checks"></a>
<a id="reproduce-the-cli-sanitizer-smoke-checks"></a>
<a id="optional-integration-and-assembly-profiles"></a>
<a id="jasmin-enabled-runtime-and-current-source-suite"></a>
<a id="scoped-aes-key-schedule-wp-analysis"></a>
<a id="portable-aes-block-loop-wp-checks"></a>
<a id="earlier-continuous-fuzz-resource-failure"></a>


## Validation and reporting

Use [AUDIT.md](../AUDIT.md) for the maintained check matrix, prerequisites,
recorded evidence and assurance limits. Run checks on the exact revision being
assessed and keep the commands, tool versions, exit statuses and diagnostics.
An optional or platform-specific `SKIP` describes untested coverage.

### Reproduce the audit checks

Run source and license checks before compilation, then the normal test suite:

```sh
bash scripts/check-source-only.sh --tree .
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-asan-run
```

In a Git checkout, also run `make source-audit` to check the index and committed
archive. Extracted source uses the standalone `--tree .` check above.

`test-asan-run` executes the sanitizer smoke test; `test-asan` alone builds it.
Use a fresh source copy for each compiler or sanitizer configuration. The source
scanner rejects generated binaries, so repeat a source-only scan on a clean
source copy rather than treating build output as source.

The release gate also requires six maintained Frama-C analyses and the
five-source Jasmin gate. Their [models and prerequisites](../AUDIT.md#formal-verification)
are narrower than a whole-program proof. Distribution-friendly `check` and
`test-all` do not replace those formal checks or native package acceptance.

### Optional Rust varint checks

The experimental `rust/varint` crate is a separate `no_std` implementation of
canonical unsigned base-128 integers. It is not linked into the production C11
CLI and does not verify complete archives. With Rust/Cargo 1.93 or newer,
rustfmt, Clippy and the required C toolchain installed, run:

```sh
make test-rust-varint
make audit-rust-varint
```

The test target prepares the real C oracle and runs offline, locked debug and
release comparisons. See the [Rust scope and commands](../AUDIT.md#experimental-rust-varint)
for prerequisites and checks outside that profile.

## Troubleshooting

- `zupt: command not found`: verify `PATH` or use the staged path printed by
  `make install DESTDIR=...`.
- A password error: retry with an interactive terminal or a mode-0600 file;
  never add the password to the command line.
- A failed `zupt test`: preserve the original archive and log, then restore
  from a known-good copy. Do not disable integrity checks for a new backup.
- A GUI startup error: verify `python3`, one supported Qt binding and
  `ZUPT_BIN`; run the CLI directly to separate frontend issues from archive
  issues.
- An openSUSE dependency or signature error: refresh repository metadata and
  inspect the enabled vendor. Do not disable signature verification or force
  a vendor change.

For security reports, follow [SECURITY.md](../SECURITY.md) and avoid including
backup contents, keys, passwords or private workload data.
