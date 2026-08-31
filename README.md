# ZUPT 5.2.4

ZUPT is a command-line backup archiver written in C11. It combines the
bundled VaptVupt compression codec with authenticated AES-256-CTR +
HMAC-SHA256 encryption, native ML-KEM-768/X25519 hybrid encryption, archive
integrity checks, multithreaded operation, and a Python/Qt graphical frontend.

Version 5.2.4 corrects release/source-policy integration. The immutable
`v5.2.3` candidate was not promoted because its source-policy test assumed LF
for a Windows `.bat` file that Git correctly checks out as CRLF. This correction
does not change the archive format, cryptography, codec, or SDK ABI.

Version 5.2.2 restored the original ZUPT product name and the `zupt` command.
The `.zupt` archive extension, format v1.6, magic bytes, codec identifiers, and
SDK ABI remain unchanged. An optional `vaptvupt` command alias may be provided
for scripts written against versions 3.0.0 through 5.2.1.

## Corrective changes in 5.2.4

The release gate now validates the required CRLF checkout form without treating
it as source drift. All current release paths move to 5.2.4 and require fresh
exact-tag CI, package, native-platform, source-only, and checksum evidence before
promotion. The `v5.2.3` tag remains immutable and unpromoted.

## Corrective changes introduced in 5.2.3

The corrective release carries the 5.2.2 security and format work forward
without a new archive format, codec, or SDK ABI. It realigns every current
version-bearing package and release path to 5.2.3, stabilizes the GUI version
contract used by package gates, and repairs native RPM container setup for
Tumbleweed and Fedora. A fresh exact-tag CI, package, native-platform,
source-only, and checksum record is required before any asset is promoted. See
[CHANGELOG.md](CHANGELOG.md) for the release record.

## Security and source baseline introduced in 5.2.2

This patch release makes the upstream and distribution path auditable from
source and tightens archive integrity handling:

- removed incomplete vendored SDK/PQBOX header snapshots and every fallback to
  local precompiled libraries;
- made WITH_SDK and WITH_PQBOX opt-in system integrations with explicit failure
  when their development dependencies are unavailable;
- removed build-tree RPATH/RUNPATH injection and architecture-wide AVX2 flags;
- made compiler target detection, packager flags, staged installation and
  cleanup portable;
- hardened extraction against traversal components, symlinks, hardlinks,
  Windows reparse points, and pre-existing output files; verified data is
  published from a private temporary file only after size and checksum checks;
- made normal, solid, and disk-image compression publish archives atomically
  without opening a symlink or hardlink target at the requested leaf; POSIX
  canonicalizes a user-selected parent once and then pins its physical
  directory, while Windows rejects reparse-point parents; compression also
  rejects an output that resolves to the input itself, including alternate
  path spellings, hardlinks, and symlinks, even when `--force` is used;
- made disk restore validate and consume one private snapshot of the input
  archive before opening its destructive destination; raw-device capacity is
  queried before the first write and an unknown or undersized target fails
  closed;
- require both XXH64 and an independent SHA-256/128 digest match in the writer
  before a block is replaced with a deduplication reference;
- bind every encrypted data or dedup-reference frame to its logical position;
  an authenticated reference also carries the position needed to authenticate
  the original data frame, so neither a data frame nor an otherwise equivalent
  reference can be moved silently;
- require an archive-integrity trailer (AIT) for every validating content-read
  path by default, without trusting unauthenticated header flags; the explicit
  legacy override is only for a known, trusted archive created before AIT
  existed;
- authenticate reference offsets in new encrypted+dedup archives, and bind the
  encrypted disk index to its archive metadata;
- store and verify a chained whole-image content hash in new disk archives;
  this XXH64 value detects corruption but is not a cryptographic authenticator
  in an unencrypted archive;
- serialize fixed-width format values explicitly as little-endian and reject
  non-canonical or overflowing uint64 varints;
- reject unexpected frame types wherever decoded DATA is required, including
  multithreaded, serial, solid, test, and disk-image readers;
- retain narrow reader paths for the fixed-width disk index and encrypted
  deduplication AAD sequence published by 5.2.1; an actual password-encrypted
  DATA/DATA/REF/DATA disk fixture is tested byte-exact without claiming that older
  readers accept the new 5.2.2 records;
- use a randomly created private directory for benchmark scratch files and
  remove it without following links, instead of deriving a writable path only
  from the process ID;
- added a reusable source-only scanner, adversarial scanner tests and CI gates;
- added current openSUSE/OBS packaging under packaging/opensuse;
- restored ZUPT/`zupt` as the product, command, package, GUI, documentation,
  and release-artifact identity without changing the archive or SDK formats;
- added explicit `--password-prompt`, `--pass-file`, and `--pass-fd` inputs so a
  password need not be placed in process arguments;
- create native private-key files without replacement using POSIX mode `0600`
  or a Windows current-user-only DACL, and strictly validate ZKEY/ZPQK checksum,
  version, flags, reserved bytes, exact size, and public/private role before use;
- restore POSIX terminal state after handled password-prompt interruptions and
  render archive comments without emitting raw terminal-control sequences;
- make the regression interpreter explicitly Bash and add bounded nested-
  archive resource handling to the source-only scanner;
- documented the bundled codec, GUI data assets and all applicable license scopes;
- added gated, source-built release-package workflows without committing
  package artifacts or compiled code to Git.

See [CHANGELOG.md](CHANGELOG.md) for the release record.

## Canonical source

- Canonical: https://github.com/cristiancmoises/zupt

Release tags and source archives are published from this repository.

## Source-only policy

Tracked Git state and source archives contain source/build/packaging files,
documentation, tests, and necessary non-executable data only. They do not
contain object files, shared or static libraries, compiled executables,
RPM/DEB/AppImage packages, unresolved Git LFS pointers, or release binaries.

Release pages may provide separately generated packages requested for end
users. Those assets must be built from the tagged source, tested on their target
environment, and kept outside Git and the source archive. A format that was not
built and tested is not presented as supported.

## 5.2.4 release artifacts

The 5.2.4 release workflow is defined to produce the following files only after
the corresponding target gate succeeds. `SHA256SUMS` records the exact promoted
filenames and digests. The release notes identify the tested commit and the
manually dispatched CI run; that run's job definitions and logs are the runtime
evidence for runner image, architecture, toolchain, results, and explicit
skips. This table is not a substitute for that evidence.

| Format | Intended target and validation boundary |
| --- | --- |
| `zupt-5.2.4.tar.gz` | Reproducible, source-only archive; scanned twice-built input plus SHA-256. |
| `zupt_5.2.4_amd64.deb` | Ubuntu 24.04 amd64 package; install, functional round trip, and uninstall gate. |
| `zupt-5.2.4-*.x86_64.rpm` and `.src.rpm` | openSUSE Tumbleweed x86_64 source/binary RPM gate; package inspection, install, round trip, and uninstall. |
| `zupt-5.2.4-linux-x86_64.tar.xz` | Linux x86_64 CLI plus the complete public license/notice payload; dependency allowlist and extracted-package functional gate. |
| `zupt-gui_5.2.4_all.deb` | Architecture-independent Python/Qt GUI package; exact dependency/payload checks plus installed off-screen GUI/CLI integration gate. |
| `zupt-gui-5.2.4-1.noarch.rpm` | Architecture-independent Python/Qt GUI RPM; package inspection plus installed off-screen GUI/CLI integration gate. |
| `zupt-gui-5.2.4-1.src.rpm` | Source RPM corresponding exactly to the gated noarch GUI RPM. |
| `zupt-gui-5.2.4-portable.zip` | Source-only GUI and launchers with licenses/provenance; source scan, exact member allowlist, and extracted off-screen GUI/CLI gate. |
| `zupt-5.2.4-windows-x86_64.zip` | Native Windows x86_64 executable with notices; extracted-ZIP round-trip gate. |
| `ZUPT-5.2.4-macOS-*.dmg` | Native macOS image; mounted packaged executable round-trip gate, with the actual architecture in the filename. |

An asset absent from the release was not promoted through its mandatory gate.
Do not infer support for another distribution release, OS version, CPU
architecture, raw UNC/SMB destination, or package manager from a similarly
named file. Binary assets are release outputs, never source-build inputs.

No AppImage is promised for 5.2.4. The inspected upstream type-2 runtime lacked
a complete notice/source-relink handoff for every statically linked component,
so redistributing it would not meet this release's provenance gate. AppDir and
Flatpak bundles and GUI platform installers are likewise outside the promoted
set because their runtime, license, or target gates are incomplete. A bare
Linux executable or Windows `.exe` is not promoted: each CLI executable is
carried only inside its notice-bearing archive. The Windows ZIP and macOS DMG
remain CLI-only.

The promoted GUI artifacts are the gated architecture-independent DEB,
noarch/source RPM, and source-only portable ZIP listed above. The portable ZIP
does not bundle Python, Qt, or the ZUPT CLI; its launchers select compatible
software already installed on the target. Other historical GUI packages and
platform installers are not carried forward implicitly.

The canonical source repository is
<https://github.com/cristiancmoises/zupt>. Release assets referenced by the AUR,
Homebrew, Guix, or generic RPM recipes must exist in the canonical GitHub
release at their recorded URL before those recipes are published.

Audit the current checkout and its Git archive with:

~~~sh
bash scripts/check-source-only.sh
bash tests/test_source_only.sh
~~~

For a tag or an existing source archive:

~~~sh
bash scripts/check-source-only.sh --tag v5.2.4
bash scripts/check-source-only.sh --archive /path/to/zupt-5.2.4.tar.gz
~~~

Unknown `.bin` files fail the scan. A necessary binary data fixture may be
allowed only with `--data-manifest FILE`; each tab-separated record must name
its path, purpose, provenance, and SPDX license. This exception never permits
compiled or executable magic, packages, AppImages, bytecode, or Git LFS
pointers. Nested scans cap recursion, member count, individual expansion, and
total expanded bytes and fail closed at a limit. On committed Linux candidate
`ff99770`, all 39 source-only scanner cases passed, including GNU thin archives,
scanner-bomb limits, and safe diagnostic cases.

## Build from source

Required for the default build:

- a C11 compiler;
- GNU make;
- the system C, math and threading libraries.

Git, tar and gzip are needed for source-archive generation. Bash and Python 3
are used by the complete test suite. No build target downloads dependencies.

Build the distribution configuration:

~~~sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" \
    WITH_SDK=0 WITH_PQBOX=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 check
~~~

The Makefile honors CC, CPPFLAGS, CFLAGS, LDFLAGS, LDLIBS, AR, RANLIB,
STRIP, DESTDIR, PREFIX, BINDIR, LIBDIR, INCLUDEDIR and MANDIR. Project include
paths are added separately and do not replace distribution optimization or
hardening flags.

The default x86 build targets the architecture ABI baseline. SHA-NI is compiled
in its own translation unit and runtime-gated. AVX2 is not enabled across whole
codec translation units. Textual assembly under `jasmin/` can be requested with
WITH_JASMIN=1 on a compatible x86_64 compiler target; it includes generated
Jasmin output and separately identified hand-written assembly. The portable C
fallback is the default.

## Optional SDK and PQBOX integrations

Both optional integrations are off by default and never load a library from the
repository:

| Option | Enables | Dependency behavior |
| --- | --- | --- |
| WITH_SDK=1 | --pq-sdk and the SDK-backed Argon2id path | Uses the system libvuptsdk development package through pkg-config. |
| WITH_PQBOX=1 | --pq-box | Uses the system libpqvaptvupt development package through pkg-config. |

If a system package has no pkg-config file, an administrator may supply
SDK_CPPFLAGS and SDK_LDLIBS, or PQBOX_CPPFLAGS and PQBOX_LDLIBS, explicitly.
Enabling an option without usable system link flags stops at Makefile parsing
with an actionable error. There is no download, vendored binary fallback or
automatic RPATH.

The default source-only build retains password encryption through
PBKDF2-SHA256, native hybrid encryption through --pq, and ML-KEM-only encryption
through --pq-only. It reports SDK/PQBOX-only operations as unavailable rather
than silently changing modes.

## Install and uninstall

For a normal local installation:

~~~sh
sudo make install
~~~

The upstream default prefix is `/usr/local`. Use a staged `PREFIX=/usr`
installation for packaging rather than writing directly into `/usr` as an
unprivileged user.

For packaging or inspection:

~~~sh
stage=$(mktemp -d)
make install DESTDIR="$stage" PREFIX=/usr INSTALL_LEGACY_ALIAS=0
find "$stage" -print
~~~

`INSTALL_LEGACY_ALIAS=1` explicitly adds the renamed-era compatibility command
and manual page named `vaptvupt`. The default is 0. Distribution packages
should keep it at 0 unless they have verified ownership and conflicts for that
compatibility name.
The openSUSE package installs `zupt` as the primary command.

Uninstall uses the same path variables:

~~~sh
sudo make uninstall PREFIX=/usr/local INSTALL_LEGACY_ALIAS=0
~~~

## Tests

The principal source-only gates are:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 check
make WITH_SDK=0 WITH_PQBOX=0 test-all
make test-asan
make test-asan-run
make audit-licenses
bash tests/test_source_only.sh
bash scripts/test-installed-zupt.sh ./zupt
~~~

The installed/functional test covers text, random and empty files, nested
directories, spaces and UTF-8 names, archive verification, extraction and
SHA-256 comparison, wrong-password rejection, corrupt-archive rejection,
destination-symlink escape protection, atomic archive-output replacement,
--help, --version and invalid options.

`disk restore` first copies the measured archive into a private, auto-deleted
scratch file, validates that snapshot, and restores from the same open stream.
Set `ZUPT_TMPDIR` to an existing private scratch directory when the default
temporary filesystem lacks space; it must hold at least the compacted archive
size. An invalid override fails without falling back elsewhere or opening the
destination. Regular-file destinations retain atomic publication; raw block
devices are accepted only when their capacity can be determined and is large
enough. The privileged undersized-loop-device regression is reported `SKIP`,
not `PASS`, when the environment cannot create a loop device.

The immutable, non-promoted 5.2.2 candidate at commit `ff99770` passed the local
`make release-check`. Recorded results include packaging
`PASS=49 FAIL=0 SKIP=0`, the 39/39 source-only scanner suite, strict GCC and
Clang, GCC `-fanalyzer`, a 9/9 full tool-enabled static-analysis run,
ASan/UBSan/LSan, and 1,000 mutation-fuzz iterations without a
sanitizer-detected crash. An earlier off-screen GUI smoke run remains supporting
evidence rather than an exact-candidate package result.

Those results are historical upstream self-audit evidence, not independent
certification and not 5.2.4 results. Post-tag CI integration failures prevented
5.2.2 promotion. The immutable 5.2.3 candidate was also not promoted because its
source-policy test assumed LF for a `.bat` checkout that correctly used CRLF.
The exact 5.2.4 candidate must repeat all required gates;
native Windows and macOS, hosted GitHub CI/release promotion, authenticated OBS,
and resolution of the openSUSE automatic `debugsource` rpmlint `no-binary`
finding remain pending until recorded otherwise. Unexecuted gates are `SKIP`,
never `PASS`.

On Windows, 5.2.4 scopes output handling to normal local Win32 paths. A MinGW
cross-build or Wine run is not native-Windows evidence; the `windows-latest`
package job, including its Unicode round trip, remains a mandatory publication
gate. Win32 extended-length and device-namespace paths, raw UNC output roots
such as `\\server\share`, and mapped/network-drive output are not supported in
this version. Restore to a normal local path first.

Tests for WITH_SDK=1 or WITH_PQBOX=1 are optional-dependency tests. A missing
system library is reported as SKIP and is never counted as a PASS for that
feature.

## Trusted legacy archives without AIT

`extract`, `list`, `test`, and `disk restore` require a valid
archive-integrity trailer by default, without trusting header flags to decide
whether authentication is required. This prevents an attacker from silently
removing the trailer, clearing an unauthenticated encryption flag, and
downgrading authentication of header and footer metadata.
`--allow-legacy-no-ait` is accepted only by `extract`, `list`, `test`, and
`disk restore`, and exists only to recover a known, trusted archive created
before AIT was introduced. Do not use that override for an archive from
untrusted or attacker-writable storage; verify and migrate the recovered data to
a newly created 5.2.4 archive. Compression and disk backup never create a
no-AIT archive.

`info` is deliberately different: it reports unauthenticated framing metadata,
including whether a trailer appears to be present, without validating the AIT
or archive contents. Its success is not an integrity result and must not be used
to decide that an untrusted archive is safe.

This no-AIT exception is distinct from the v5.2.1 disk-index compatibility
path. Published v5.2.1 disk archives normally have an AIT; the narrow
compatibility scope includes an actual v5.2.1 password-encrypted, deduplicated
disk archive with a DATA/DATA/REF/DATA sequence using the fixed-width legacy index
and the legacy linear AAD sequence. The repository stores that 718-byte archive
as auditable hexadecimal text with its provenance and SHA-256; the candidate
lists, tests, extracts, and restores it byte-exact. The full local Linux gate
passed on commit `ff99770`. This is not a claim that a 5.2.1 reader understands every new
flag-gated 5.2.2 encoding or that every historical combination was tested.

The candidate commands and outcome fields for 5.2.4 are maintained in the
release handoff and
[packaging/opensuse/README.md](packaging/opensuse/README.md). They must be
updated from the final release candidate before tagging. No architecture or
distribution is claimed merely because the code has a fallback path.

## Source archive

Generate the reproducible source archive outside the repository:

~~~sh
make dist
sha256sum /tmp/zupt-5.2.4.tar.gz
bash scripts/check-source-only.sh \
    --archive /tmp/zupt-5.2.4.tar.gz
~~~

Archive ordering, ownership and timestamps are normalized. The default epoch is
recorded in `.source-date-epoch`; a packager may override SOURCE_DATE_EPOCH.
Running the export twice from identical committed input and epoch must produce
the same SHA-256. The AUR, Homebrew and Guix recipes are `export-ignore` so
their checksum fields do not make the archive self-referential. `make dist`
archives the verified `HEAD` tree object rather than embedding the commit ID,
so a commit changing only those ignored recipes leaves the fixed-epoch archive
byte-identical. The recipes remain versioned in Git and must be filled with the
final digest before the tag is published.

## openSUSE and OBS

The maintained upstream recipe is in packaging/opensuse. It is prepared for an
immutable v5.2.4 tag, disables submodules and Git LFS, builds with
WITH_SDK=0 WITH_PQBOX=0, runs real checks, and installs without the renamed-era
`vaptvupt` alias.

This repository does not claim that the package has been submitted to or
accepted by openSUSE Factory. The packaging README distinguishes local parsing,
container/RPM builds, OBS operations and architectures that were not executed.

## Bundled codec provenance

The bundled compression codec is source from recorded upstream tag v2.65.3.
The immutable integration commit is
59f9ebc59ea13c6edf1d199ca795cdbf00e62226. The repository also records local
integration adjustments; details are in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

The package declares bundled(vaptvupt-codec) = 2.65.3. It does not claim that
the codec is unbundled or provided by a system library.

## Security notes

- Keep passwords and private keys out of command histories where possible. Use
  `--password-prompt`, `--pass-file` with restrictive permissions, or an
  inherited descriptor through `--pass-fd`; `-p/--password` exposes its next
  argument to process inspection.
- Native private-key generation refuses an existing destination and uses POSIX
  mode `0600` or a Windows current-user-only DACL. A failed write/flush/close
  leaves its incomplete or durability-uncertain exclusive file for manual
  review and removal instead of unlinking a possibly replaced pathname.
  ZKEY/ZPQK inputs with a bad
  checksum, version, flags, reserved bytes, length, or role are rejected.
- Compression does not protect a compromised endpoint or weak credentials.
- Archive metadata and total size can still reveal information.
- Treat unexpected authentication, format or integrity errors as failures; do
  not discard the original input until a restored copy has been verified.
- Report vulnerabilities according to [SECURITY.md](SECURITY.md).

## GUI

The optional GUI is under `gui/`. It invokes the `zupt` CLI and needs Python 3
plus PySide6 or PyQt6. GUI image assets are data files whose purpose,
provenance and license are recorded in [gui/assets/README.md](gui/assets/README.md).
The integrated source and lightweight consistency checks do not constitute a
target-native audit of every historical GUI format. The 5.2.4 artifact promise
is limited to the gated GUI DEB, noarch/source RPM, and source-only portable ZIP
listed above; AppImage, AppDir, Flatpak bundles, and platform GUI installers
remain excluded.

## Maintainers and openSUSE credit

Cristian Cezar Moisés is the creator and current upstream maintainer of ZUPT and
the author of the current upstream source, build, test, documentation, and
packaging changes, including the 5.2.2 baseline and corrective 5.2.3/5.2.4 work.

Alessandro de Oliveira Faria (Cabelo) is credited as the openSUSE collaborator
and downstream package maintainer. He reviews the handoff, commits it in the
OBS project he maintains, and may make the additional openSUSE-side adjustments
he considers necessary. That downstream role is not attribution of ZUPT source
authorship or of the upstream 5.2.2, 5.2.3, or 5.2.4 changes.

## License

The application and tool code are AGPL-3.0-or-later. The separately identified
bundled compression codec files are GPL-3.0-or-later. The adapted XXH64
routines additionally retain Yann Collet's BSD-2-Clause terms. Portions of the
native ML-KEM implementation adapted from pq-crystals/kyber use its CC0-1.0
option. Portions of native X25519 adapted from curve25519-donna retain its
BSD-3-Clause terms; the x86 BCJ state machine is adapted from Igor Pavlov's
public-domain LZMA SDK source. Preserve all five license texts, NOTICE,
THIRD-PARTY-NOTICES.md, copyright notices and per-file SPDX headers.

Published historical revisions include MIT grants for exact first-party
material distributed with those notices. Those permissions are not revoked by
the current SPDX notices; see `LICENSE`, `gui/LICENSE-GUI`, and the 5.2.2
licensing erratum in `CHANGELOG.md` for the recorded scope and evidence.

A separately executed commercial agreement may be available for controlled
first-party rights. [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) is an inquiry
notice, not a commercial grant and not a replacement for the public licenses.
