# ZUPT

[English](README.md) | [Português do Brasil](README.pt-BR.md)

The published official version is
[ZUPT 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
Version **5.2.10 is undergoing validation**, not an official
download. Its earlier tag and delivery were withdrawn; publication remains
blocked until the reviewed source, packages, signatures, and platform gates are
accepted together. Source version strings and local tags do not establish
release status.

ZUPT is a command-line backup archiver written in C11. It combines the
bundled VaptVupt compression codec with authenticated AES-256-CTR +
HMAC-SHA256 encryption, native ML-KEM-768/X25519 hybrid encryption, archive
integrity checks, multithreaded operation, and a Python/Qt graphical frontend.

Available for openSUSE: [download and update instructions](#opensuse-and-obs).

Try [ZUPT Web online](https://zupt-web.securityops.co) with non-sensitive sample
files and disposable passwords or keys. Uploaded data is processed on the
server. Available features, versions, and limits may differ from the local
CLI/GUI.

## Documentation

- [Installation](INSTALL.md): verified downloads, source builds, and GUI setup.
- [User guide](docs/USER_GUIDE.md): command-line, `.zupt`, openSUSE and GUI
  workflows in English.
- [GUI usage](gui/README.md): requirements, operation limits, and troubleshooting.
- [Distribution](DISTRIBUTION.md): package contents and release validation gates.
- [Release history](CHANGELOG.md): released versions and unreleased changes.
- [Security](SECURITY.md) and [threat model](THREAT_MODEL.md): supported boundaries
  and limitations.
- [Português do Brasil](DOCUMENTACAO.pt-BR.md): installation, operation, and
  verification.
- [Guia de usuário em pt-BR](docs/GUIA_USUARIO.pt-BR.md): comandos, bundles,
  openSUSE Tumbleweed, GUI and troubleshooting.

## Official version 5.2.9

The official 5.2.9 release bundles VaptVupt 2.65.11 and retains archive format
1.6 and codec identifier `0x0010`. Download its packages from the
[5.2.9 release page](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9)
and verify the accompanying checksums. Existing 5.2.9 packages are unchanged.

## Version 5.2.10 validation snapshot

Version 5.2.10 updates the bundled VaptVupt codec from 2.65.11 to 2.65.13.
It prepares only reachable matcher buckets for small BALANCED/EXTREME inputs
and their first-block prepass, sizes hash3 history to the actual chain, and
initializes the Huffman tree root explicitly. Zupt retains its parser guards,
secure-wipe fallback, wrapper policy, licensing notices, and read-back check.
Archive format 1.6, codec identifier `0x0010`, CLI behavior, and SDK ABI remain
unchanged. Release assets require fresh checks against the exact tagged source.

The POSIX password prompt now disables echo before displaying the prompt and
waits for input with an atomic signal transition. Nonblocking reads handle
terminal input flushing without hanging, and cleanup restores the original
terminal settings and descriptor flags. Regression tests cover all four handled
signals, prompt ordering, flushed input, confirmation and password-size limits.
The Windows prompt and archive grammar are unchanged.

### Version comparison

| Area | 5.2.9 official | 5.2.10 development snapshot |
| --- | --- | --- |
| Bundled VaptVupt codec | 2.65.11 | 2.65.13, with the compatibility and bounds fixes described above |
| Archive format | 1.6 | 1.6 (unchanged) |
| Codec identifier | `0x0010` | `0x0010` (unchanged) |
| Rust migration | C11 application | Optional canonical-varint Rust core and C/Rust compatibility tests; production CLI and packages still use C11 |
| Public CLI and SDK ABI | Published contract | Preserved; working-source checks passed with documented skips; the final committed archive still needs validation |
| Guix CLI acceptance | Published package baseline | Run the functional script on the installed CLI after stripping and RUNPATH validation; current native derivation and dependency-closure acceptance remain pending |
| Native key-file reads | Published ZKEY/ZPQK grammar | Same formats and rejection codes; stop probes after EOF/read errors, with 66 injected-I/O cases on supported GNU/Linux targets |
| SDK temporary-file handling | Published behavior | Reject truncated temporary paths; stop reads at error/EOF, preserve read diagnostics across callbacks, check seek/tell/read/close and wipe failed buffers; remove only owned temporary keys after write failures; fortified formatting retains bounds and has 28 glibc regression cases, passing local GCC/Clang ordinary and fortification 2/3 SDK profiles; hosted rerun pending |
| In-tree SDK assembly selection | Published build rules | `WITH_JASMIN` reaches C callers as well as assembly linkage; 25 recipe assertions cover selection and external-provider isolation, with 11 further symbol-check supervision controls. Portable defaults and ABI stay unchanged; these controls do not establish SDK hardware AES dispatch |
| ANS decoder bounds | Existing APIs and frame grammar | Three malformed metadata fixtures and five exact-output sequence cases pass the production-scalar Frama-C profile: zero alarms, 63 valid preconditions and 558/983 reached statements. This is a fixed-fixture result, not a general decoder proof |
| Recorded runtime validation | Published release checks are not restated here | On 2026-10-27, strict GCC 14.3.0 and Clang 22.1.8 pass actual `test-all` and in-tree SDK/license/symbol targets on the corrected source; a separate GCC `WITH_JASMIN=1` profile also passes with AES-NI dispatch. Each records 15 explicit skips; final runtime and package acceptance remain separate |
| Formal and distribution gates | Published artifact baseline | The six maintained Frama-C gates and five-source Jasmin checks (repeated 2026-10-30) pass against the same frozen source. Results are conditional and limited; source analyses and runtime checks remain distinct from full `release-check` and final-package acceptance |
| Publication status | Official release | Unpublished; no candidate download |

The table separates the published baseline from the current source. Publication
requires validation of one recorded source snapshot through compilation,
packaging and extraction, followed by review of the exact commit, signatures
and remaining skipped platforms.

## Gradual Rust migration

The first Rust component is `rust/varint`: an optional, allocation-free
`no_std` encoder/decoder for the canonical unsigned integers used by the
archive parser. It forbids `unsafe` and has no external crate dependencies.
It is not linked into the CLI or installed packages; existing C11 build and
distribution requirements are unchanged. This is a tested migration foothold,
not a claim that the current archive parser has become memory-safe Rust.

Run `make test-rust-varint audit-rust-varint` with Rust/Cargo 1.93 or newer,
rustfmt, Clippy and a C toolchain supporting section garbage collection.
The recorded Linux/GCC run passes nine focused tests, two C-oracle tests
and 114,721 differential cases in both debug and release, plus formatting
and Clippy. See the [audit instructions](docs/USER_GUIDE.md#optional-rust-varint-checks)
for scope, reproduction and missing formal/fuzz coverage. The 5.2.10 release
gates remain mandatory; starting Rust does not authorize publication.

The accompanying strict GCC 14.3.0 distro `check` and real CLI functional
suite also pass with Cargo disabled, with 11 explicit platform/provider/tool
skips. This is a local Linux profile, not native openSUSE/Guix package acceptance
or a fresh formal-analysis run.

## Historical 5.2.8 validation (not 5.2.10 evidence)

Version 5.2.8 closes three CodeQL High path-race findings: SDK key copies now
publish atomically through an already-open private object, POSIX disk restore
classifies and retains the descriptor it actually opened, and benchmark cleanup
traverses only pinned descriptors or handles without following links or Windows
reparse points. It also makes the raw-C1 scanner fixture explicitly skip a
filesystem that rejects creation with `EILSEQ`, normalizes Bash 3.2 signed-byte
diagnostics, and brings `sdk-test` into the
release and hosted Linux gates. Windows password prompts now reject redirected
input before entering `_getch` and treat console EOF as an error; its key-file
regression validates the protected current-user-only DACL rather than an MSYS
POSIX-mode projection. The C/C++ default-branch scan run `33452563116` of
commit `7a8e5c5` completed successfully after the follow-up changed the new SDK
regression to no-follow descriptors plus `fstat` and descriptor reads. Alerts
#5 through #10 are fixed, and the authenticated code-scanning API reported zero
open alerts. Final release-commit CodeQL run `33456049125` also completed
successfully, with the API still reporting zero open alerts. These corrections
do not change archive format v1.6,
cryptography, the bundled codec release, or the SDK ABI.

The predecessor `v5.2.7` tag is immutable and was not promoted. Exact-tag run
`33445470664` concluded `cancelled` at `2026-08-31T23:11:19Z`, with 13
successful jobs, a macOS raw-C1/EILSEQ fixture failure, and a cancelled Windows
job. The hosted Windows job stalled in `make check`; a MinGW/Wine reproduction
attributed the stall to a non-console password prompt entering `_getch`. No
v5.2.7 evidence transfers automatically to v5.2.8.

Manual pre-tag run `33452602634` then completed 14 of 15 jobs successfully at
`7a8e5c5`, including the native macOS DMG gate and the Windows build and full
distribution checks. Its Windows smoke test failed only when the old MSYS
`grep` matched a literal non-BMP filename after the product had already
compressed and verified all five files. MinGW/Wine reproduction confirmed the
exact `F0 9F 98 80` UTF-8 bytes in ZUPT's redirected listing. The corrected
gate creates that name from byte escapes, validates Latin-1, BMP, and non-BMP
listing bytes with Python, and requires extraction plus a full tree diff. The
failed run is diagnostic evidence, not release-candidate approval.

The immutable `v5.2.8` candidate at commit
`ebb9ab3aa1d42c50030ca02883f6162dc4771fe1` subsequently passed all 15 jobs in
manually dispatched exact-tag run `33456209269`. That run includes the pinned
local OBS source-service chain, reproducible source checks, GCC/Clang, analyzers,
sanitizers, DEB/RPM/SRPM and portable-package gates, the native Windows ZIP
round trip, and the mounted macOS arm64 DMG test. Corrected promotion run
`33457868306` validated and published exactly 13 assets. The canonical source
archive is 798296 bytes with SHA-256
`378b9506211545b9594cf0d38ac8955d9b1cac34eb6b379ae0ec26b84edb65f7`.

Version 5.2.2 restored the original ZUPT product name and the `zupt` command.
The `.zupt` archive extension, format v1.6, magic bytes, codec identifiers, and
SDK ABI remain unchanged. An optional `vaptvupt` command alias may be provided
for scripts written against versions 3.0.0 through 5.2.1.

## Codec compatibility refresh in 5.2.10

The in-tree codec integrates VaptVupt tag `v2.65.13` at commit
`e30dc9329be7cf9f233b1ac0b1fc9ed31f530391`. It is a consumer adaptation rather than a
byte-identical canonical copy: Zupt retains its GPL-3.0-or-later codec notices,
Darwin/NetBSD volatile secure-wipe fallback, and optimal-parser signed bounds.
Zupt keeps its established
level-to-mode mapping, codec-checksum-off policy, automatic window and BCJ
selection, and decode-plus-compare acceptance check. Zupt records its own
per-block XXH64; encrypted modes additionally authenticate ciphertext and
metadata with HMAC-SHA256. It continues
to use independent one-shot frames and does not require a kernel module or the
new caller-owned FAST context. Focused cross-version fixtures are supporting
local evidence, not a substitute for the complete 5.2.10 release matrix.

Brazilian Portuguese introductions and operational guidance are provided in
[README.pt-BR.md](README.pt-BR.md) and
[DOCUMENTACAO.pt-BR.md](DOCUMENTACAO.pt-BR.md).

## Corrective changes introduced in 5.2.8

SDK key saves use atomic descriptor/handle-backed publication and preserve the
requested private/public modes without reopening the destination. Disk restore
opens a POSIX target once before its type, identity, and device-capacity
decisions, and benchmark cleanup is descriptor-relative on POSIX and
handle/reparse-point aware on Windows. The live-workspace symlink regression,
SDK link-target/mode regression, static path-race guards, portable raw-C1
fixture with Bash 3.2 unsigned-byte normalization, native redirected-prompt
and protected-DACL regressions, byte-exact BMP/non-BMP Windows list and extract
checks, and `sdk-test` CI step cover these boundaries. All current release
paths moved to 5.2.8 and received fresh exact-tag hosted CI, package,
native-platform, source-only, checksum, OBS, and promotion evidence in runs
`33456209269` and `33457868306`.

## Corrective changes introduced in 5.2.7

The SHA-NI regression keeps x86-only helper declarations out of unsupported
arm64 builds, and the safe UTF-8 Windows fixture crosses the argv boundary in a
byte-stable representation. Those test-harness changes did not alter the
archive format, cryptography, codec, or SDK ABI. Exact-tag run `33445470664`
subsequently exposed the separate macOS raw-C1/EILSEQ fixture failure; Windows
was cancelled after the hosted job stalled in `make check`; MinGW/Wine then
isolated the stall to a non-console password prompt entering `_getch`. The run recorded 13 successful jobs, one
failure, and one cancellation; v5.2.7 remained unpromoted.

## Corrective changes introduced in 5.2.6

Darwin and NetBSD select the portable compiler-resistant secure-wipe fallback;
scanner option/path arrays are guarded for Bash 3.2; and hostile Windows path
fixtures use explicit bytes and reject dangerous raw diagnostic fragments.
Those corrections changed release/test integration only. The resulting v5.2.6
candidate was not promoted because its next exact-tag run exposed the distinct
arm64 SHA-NI helper and safe UTF-8 Windows argv failures described above.

## Corrective changes introduced in 5.2.5

The exact-tag openSUSE gate executes its standalone service chain from the
directory containing `_service`. A local Tumbleweed reproduction confirmed
that `refs/tags/v5.2.4` resolves correctly and that entering the service
directory completes `obs_scm`, `tar`, and `recompress`. The immutable v5.2.4
candidate recorded 12 successful jobs in run `33431386002`; its openSUSE job
failed before the correction and dependent Windows/macOS jobs were skipped.

## Corrective changes introduced in 5.2.4

The release gate now validates the required CRLF checkout form without treating
it as source drift. That candidate required fresh exact-tag CI, package,
native-platform, source-only, and checksum evidence before promotion. The
`v5.2.3` tag remains immutable and unpromoted.

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
- Codeberg mirror: https://codeberg.org/berkeley/zupt
- SecurityOps Brazil mirror: https://git.securityops.com.br/cristiancmoises/zupt
- SecurityOps global mirror: https://git.securityops.co/cristiancmoises/zupt

GitHub remains canonical. Published assets must be mirrored byte-for-byte on
the three hosts above after the exact-source gates and publication checks pass.

## Source-only policy

Tracked Git state and source archives contain source/build/packaging files,
documentation, tests, and necessary non-executable data only. They do not
contain object files, shared or static libraries, compiled executables,
RPM/DEB/AppImage packages, unresolved Git LFS pointers, or release binaries.

Release pages may provide separately generated packages requested for end
users. Record the runtime tag and any packaging-only build commit separately,
test each artifact on its stated target, and keep binaries outside Git and the
source archive. An untested format is not presented as supported.

## Planned 5.2.10 release artifacts (not published)

The following names and checks describe the planned release, not available
downloads. The five release bundles must be genuine, unencrypted `.zupt`
archives compressed with VaptVupt at level 9, tested with `zupt test` and complete
extraction comparison. Native DEB/RPM/SRPM packages retain their formats.
Release notes identify the runtime source, actual build commit, tests and limits.

| Artifact | Validation required before publication |
| --- | --- |
| `zupt-5.2.10-source.zupt` | Source-only tree; complete Git-blob comparison to the validated official tag. |
| `zupt-5.2.10-linux-x86_64.zupt` | Linux x86_64 CLI and complete public notices; extracted CLI round trip. |
| `zupt-5.2.10-windows-x86_64.zupt` | Native Windows x86_64 CLI, five runtime notices and packaged Unicode/restricted-PATH round trips. |
| `zupt-5.2.10-macos-arm64.zupt` | Native arm64 CLI DMG inside the bundle; DMG verification and mounted-binary round trips on macOS. Not universal. |
| `zupt-gui-5.2.10-portable.zupt` | GUI frontend source, scripts and notices; external Python, Qt and matching CLI required. |
| `zupt_5.2.10_amd64.deb` | Real DEB build, dependency/payload inspection and extracted or installed CLI test. |
| `zupt-5.2.10-0.x86_64.rpm` and `zupt-5.2.10-0.src.rpm` | Real RPM/SRPM build, source provenance, payload inspection and extracted or installed CLI test. |
| `zupt-gui_5.2.10_all.deb`, `zupt-gui-5.2.10-1.noarch.rpm`, `zupt-gui-5.2.10-1.src.rpm` | GUI package metadata, dependencies, notices and off-screen GUI/CLI integration. |
| `SHA256SUMS`, `SHA256SUMS.asc`, `release-key.asc` | Exact asset hashes, verified detached signature and public signing key. |

Historical checks of the withdrawn delivery distinguish these results. They
do not validate a future corrected 5.2.10 release:

- Native Windows/macOS run [36858438699](https://github.com/cristiancmoises/zupt/actions/runs/36858438699)
  passed on packaging/test commit P `4a66b0cab55900bc64699428fb41c48c07de126a`.
  Its `src`, `include`, `jasmin`, `sdk/src` and `Makefile` match runtime tag C
  `24995eb7652a31eedc46386bab14c63cbb31e050`; this is not exact-tag C CI.
- The C-tag GUI DEB job in [36849573076](https://github.com/cristiancmoises/zupt/actions/runs/36849573076)
  passed. C-source GUI RPM/SRPM and portable frontend checks also passed; a
  successful job does not turn the overall failed C workflow into a PASS.
- Guix C CLI and the grafted GUI are installed in local profile generation 85;
  version, CLI functional/PTY and six-tab GUI off-screen checks passed.
  Generation 84 is retained and all 39 unrelated profile entries are unchanged.
- Local static-musl CLI and extracted DEB/RPM tests passed; these are not native
  Ubuntu/openSUSE installations. The strict GCC failure belonged to that
  withdrawn delivery.

Earlier corrected-source snapshots passed strict GCC and Clang suites. A host
GCC 16 attempt stopped when ASan could not map its shadow memory under
`ulimit -v`; that incomplete run is retained. The subsequent GCC 14 run in an
isolated VM passed `test-all` for an earlier C-core snapshot, including its ANS4 bounds
and unsigned MAC reduction changes. Later documentation, formal wrappers and
regenerated assembly have separate focused checks; this VM result does not
approve the final release artifacts or untested native platforms. Focused ANS
and instrumented-CLI repetitions after the reader/refill changes now pass in
their recorded 255-file VM snapshots. They do not replace a current full-suite
VM run, fuzz coverage, final-package acceptance or the unresolved formal gates.

Only assets actually listed with matching signed inventory are published.
For new 5.2.10 artifacts, verify the current public key fingerprint independently:
`0CFA43B9AA9642EAAF2BE983C4C661C9ECFB46E8`, then run
`gpg --verify SHA256SUMS.asc SHA256SUMS` and `sha256sum --check SHA256SUMS`.
Earlier artifacts may use the registered legacy key
`CF8BA569591B6E7F4D24B0736C95BFAE0646DCCA`; use the fingerprint recorded for
that release. Both public keys are registered to the maintainer's GitHub
account. A valid local signature does not by itself establish forge verification.
See [INSTALL.md](INSTALL.md) for extraction and installation. AppImage, AppDir,
Flatpak bundles, platform GUI installers and other architectures are excluded.
Prior releases keep their original artifacts.

`.zupt` extraction restores regular file contents, not executable modes.
After verifying a Linux bundle, apply `chmod u+x` only to its `zupt` file;
invoke the portable shell launcher with `bash zupt-gui.sh`. Source build helpers
also need selected execute permissions as documented in [INSTALL.md](INSTALL.md).

The old 13-asset promotion workflow is disabled for v5.2.10 and later.
Its source tarballs and portable tar.xz outputs are internal CI/build inputs,
not new public release uploads. The release procedure publishes only the
verified current asset set; a missing signature must never be described as a
signed artifact.

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
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
~~~

The Makefile honors CC, CPPFLAGS, CFLAGS, LDFLAGS, LDLIBS, AR, RANLIB,
STRIP, DESTDIR, PREFIX, BINDIR, LIBDIR, INCLUDEDIR and MANDIR. Project include
paths are added separately and do not replace distribution optimization or
hardening flags.

The default x86 build targets the architecture ABI baseline. SHA-NI is compiled
in its own translation unit and runtime-gated. AVX2 is not enabled across whole
codec translation units. Textual assembly under `jasmin/` can be requested with
WITH_JASMIN=1 on a compatible x86_64 compiler target. All five current units,
including four-block AES, are generated with Jasmin 2026.09.0 and carry source
hashes in their headers. The portable C fallback is the default.

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

Run the source checks in a fresh source-only checkout before compiling:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 source-audit
bash tests/test_source_only.sh
~~~

Then build and execute the runtime checks:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 sdk-test
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-asan-run
bash scripts/test-installed-zupt.sh ./zupt
~~~

`test-all` includes `tests/test_audit.sh`; authenticated system-SDK checks
report an explicit skip when `WITH_SDK=0`. Use another fresh source-only
checkout to repeat the source scan after building. The scanner rejects
generated binaries even when Git ignores them. Run `make clean` before
changing the compiler or feature flags; Make does not track those values as
object-file dependencies. See the [audit instructions](docs/USER_GUIDE.md#reproduce-the-audit-checks)
for optional SDK and assembly profiles.

The focused ANS4 metadata regression is part of `check`. Run it separately,
then run its Frama-C gate with Frama-C 29.0 on `PATH` (or set `FRAMA_C` to
the executable):

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-decode-bounds
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds-wrapper
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds
~~~

The reader regression is also in `check`. Its separate conditional WP gate
requires Python 3, Frama-C 29.0, Why3 and recognized Z3 4.12.2:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-reader-wrapper
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-reader
~~~

See the [audit guide](docs/USER_GUIDE.md#reproduce-the-audit-checks) for the
initialization/width assumptions, solver configuration and exact proof scope.

The ANS logarithm check analyzes the unchanged C helper, not a replacement.
Its native boundary checks and 60 synthetic result controls are in `check`;
the separate range analysis requires Frama-C 29.0 and GCC 14.3.0 on `PATH`:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-log-bounds-wrapper
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-log-bounds
~~~

This proves selected helper ranges, not callers, table equivalence or the
complete decoder. Reproduction details are in the audit guide.

The portable AES fixture and its supervisor controls are also part of `check`:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-aes-nist test-frama-aes-nist-wrapper
FRAMA_C=frama-c FRAMA_CPP_CC=gcc FRAMA_TIMEOUT=timeout \
  make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-aes-nist
~~~

The separate Eva gate requires Frama-C 29.0, GCC **14.3.0**, `awk` (GNU awk
in the recorded environment) and a GNU-compatible deadline tool; use
`FRAMA_TIMEOUT=gtimeout` when that is its installed name. The native fixture
links the portable C implementation even in assembly-enabled builds and
checks four fixed [NIST SP 800-38A F.1.5](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
blocks with 64 active byte assertions. The wrapper's mock supervisor does not analyze
AES or enforce a deadline. See the
[AES audit instructions](docs/USER_GUIDE.md#portable-aes-known-answer-and-eva-checks)
for UBSan commands, tool overrides and the precise proof limits.

The Jasmin supervisor's warning-scan controls also run in `check`:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-source-wrapper
~~~

Four synthetic cases distinguish a warning, no warning, scanner error and
scanner-unavailable status. Errors `2` and `127` stop the gate before
downstream work instead of being accepted as no warning. These controls use
mock tools and do not run or prove Jasmin analysis.

On x86_64 Linux with Jasmin 2026.09.0 and the documented development tools:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-source
~~~

This analyzes and regenerates five sources, checks exported symbols and
relocation-free instruction correspondence, and exercises the generated AES
block and four-block functions. See the
[audit guide](docs/USER_GUIDE.md#reproduce-the-audit-checks) for dependencies,
tool-path overrides, the C/assembly UBSan profile and coverage limits.

The emitted AES stack-wipe checker is also independently exercised without
Jasmin tools. It requires Bash, `awk` and `sed` in addition to Make; the
recorded run used GNU sed 4.9:

~~~sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-wipe-checker
~~~

Seventeen controls accept both pinned 15/16-slot tails and reject fifteen
malformed variants, including comment/string markers, extra operands or
instructions, early returns and emitted bytes after return. This checks the
alignment, frame, zero-store, restore and return pattern; it does not prove
processor register erasure, prologue/control-flow correctness or all callers.

The ANS Eva gate requires zero alarms, 63 valid preconditions and six exact
fixture witnesses. It covers three malformed ANS4 metadata cases, one
literal-only tail and four v1/v2 match tails with exact-sized destinations in
the production scalar implementation. Missing tools, scanner errors, warnings,
pruned paths or incomplete/conflicting summaries fail instead of skipping.
The profile uses Frama-C libc models; native and sanitizer runs remain separate
checks. It does not establish general decoder, Huffman or SIMD safety.
Frama-C and Jasmin validation remain mandatory before release;
see the [audit guide](docs/USER_GUIDE.md#reproduce-the-audit-checks) for the
machine model, the scoped AES key-schedule WP command and analysis limits.
`release-check` depends on `test-jasmin-source` and
`test-jasmin-wipe-checker`,
`test-frama-ans-decode-bounds`, `test-frama-ans-reader`,
`test-frama-ans-frequencies`, `test-frama-ans-logarithm`,
`test-frama-ans-log-bounds` and `test-frama-aes-nist`; it requires the
documented tools and an
AES-NI/AVX-capable x86_64 Linux maintainer host. These formal-tool dependencies
are not imposed on the distribution-friendly `check` or `test-all` targets.

The installed/functional test covers text, random and empty files, nested
directories, spaces and UTF-8 names, archive verification, extraction and
SHA-256 comparison, wrong-password rejection, corrupt-archive rejection,
destination-symlink escape protection, atomic archive-output replacement,
--help, --version and invalid options.

### Recorded validation of the development source

The earlier continuous decoder campaign failed its resource gate. In the
257-file disposable-VM snapshot, the exact Clang 22.1.8 executable
27ffda8eecf2108b5481f47f8efd5bff23d3084564f925ed37ad4e143dae19a3 reached
2,360,279 executions and 2,040 new units before libFuzzer exited 71 at 598 MiB
against the unchanged 512-MiB RSS limit. The target cgroup peaked at
660,992,000 bytes without an OOM or PID event. The saved 127-byte input has
SHA-256 d378fd4c77b7c57cc96bc62e04a69ad8fc3f95b849c76791c256e1ab38eba534.
Symbolization of the displayed live-heap context returned
`___interceptor_malloc`, `operator new` and `main`. That context covers
24,383,368 of 24,791,125 live bytes; another 244,292,744 bytes were quarantined.
These frames do not explain the full 598-MiB RSS or rule out contributions
from codec allocations. The run stopped after about 8.04 seconds of its
30-second budget. That failed result remains recorded. After the malformed-input
allocation guards, a new continuous 30-second VM campaign completed with
6,837,592 executions, 2,535 new corpus units, 486 MiB peak RSS and no artifacts.
The successful result applies to that recorded source snapshot and harness.

The following results are from the isolated, bounded validation runs recorded
outside the repository. A `PASS` is limited to the stated scope; `BLOCKED` and
`NOT RUN` are not release approvals. Earlier snapshots are identified where
relevant; their results do not validate subsequent source changes.

Earlier full suites are labelled with their own source snapshots. The
annotation-only AES helper and block-loop changes have separate WP/Eva checks;
that comparison found identical preprocessed C and unchanged public
preconditions. Subsequent decoder changes have their own results below.

Rows describe individual snapshots, not cumulative approval. The latest focused
result is listed first; earlier limitations remain recorded.
The private scalar-load results below use a pinned little-endian target.

| Check | Result | Scope and limitation |
| --- | --- | --- |
| Full GCC suite and current GUI, 2026-10-23 UTC | PASS WITH SKIPS | The frozen 294-file source passes the actual strict GCC 14.3.0 `test-all` in a disposable 2-CPU/2-GiB VM, with 15 explicit skips. The run includes 81 ASan exact-size cases, 1,024 BCJ bijections, byte-exact L5/L9 BCJ round trips, timing regression and three ML-KEM/OpenSSL comparisons. A separate bounded VM passes 64 current GUI tests, 33 historical reference tests and six bootstrap controls with PySide6/Qt 6.9.2 and the byte-identical CLI. Real sanitizer negatives, ordered completion, diagnostics and source checks pass in both runs. Missing old Qt inputs and an image-size failure remain recorded; no limits were raised. Final docs, fresh Clang repetition, broader formal review, full `release-check` and final packages remain separate. |
| Bounded ANS logarithm and WP supervision, 2026-10-23 UTC | PASS, CONDITIONAL | The original shift-based C helper passes 50 exact WP JSON goals (52/52 console) for inputs 0–4095, including both OR-bound invariant obligations through native bit-range tactics. The new `test-frama-ans-logarithm` release gate retains raw scripts/report and rejects incomplete subgoal totals. All 132 synthetic controls pass; a matched two-line guard removal produces nine failures. GCC 14.3.0/Clang 22.1.8 scalar ANS tests, preprocessing and whole-object comparisons pass. The integrated source also passes strict `check` and CLI functional smoke with 11/10 explicit skips. Executable C, API and format remain unchanged. No general table/caller proof, fresh ASan campaign, full `test-all`, final-package or production approval; final documentation follows the runtime snapshot. |
| Jasmin and unchanged ANS-core repeat, 2026-10-23 UTC | PASS, FOCUSED; LOGARITHM PROOF OPEN | The bounded ordinary Jasmin 2026.09.0 gate passes all five source analyses and generated/runtime instruction comparisons, 1,026 AES blocks and 1,539 AES4 cases. Seven executable/library files match their hash-pinned package members; environment, warning-screen and wipe controls pass. Strict scalar GCC 14.3.0/Clang 22.1.8 ANS tests pass again, including 16,785,408 table entries. The original C remains unchanged: a private unsigned-division alternative was not adopted after failing whole-object byte comparison. Its passing bounded WP result is not a proof of the maintained shift implementation. No new sanitizer, whole-program, final-package, performance or production-readiness claim; final documentation is outside the runtime snapshot. |
| ANS decode-table entry characterization, 2026-10-22 UTC | PASS TESTS; FORMAL PROBE INCOMPLETE | Strict scalar GCC 14.3.0 and Clang 22.1.8 pass all 4,097 frequency splits between labels 0/255 and a uniform 256-symbol table: 16,785,408 entries checked for width, reachable-state range and symbol multiplicity. A targeted private width mutation passes the old test and fails the expanded test. The same cases pass ASan/LSan/UBSan in the bounded VM, with source hashes and all 25 completion records verified. A separate private WP experiment has 109 valid JSON goals, 17 timeouts and three model warnings; it is not adopted or a completed table/caller proof. The earlier 14-unknown count is historical, not a reconciled current inventory. No codec/API/format change, new performance result or production approval; final documentation is outside the runtime snapshot. |
| ANS frequency validation and direct sanitizer repeat, 2026-10-22 UTC | PASS, FOCUSED | The new `test-frama-ans-frequencies` release gate proves 23 exact WP goals with Frama-C 29.0 and recognized Z3 4.12.2, including unsigned-overflow checks, under explicit initialized/separated-input assumptions. Reader and metadata gates remain unchanged and pass. Strict scalar GCC 14.3.0/Clang 22.1.8 tests pass; a private 16-bit-accumulator mutation passes old tests and fails the new eight-case check. The current 294-file snapshot also passes the direct 79,560-state ANS test and eight frequency cases with ASan/LSan/UBSan in the bounded VM, plus CLI sanitizer smoke and separate ordinary SDK/interoperability checks. Source digests and all 25 completion records are verified. Final documentation is outside that runtime snapshot. Caller proofs, full-suite/package qualification and production approval remain separate. |
| Fresh GCC guest sanitizer/SDK profile, 2026-10-22 UTC | PASS, FOCUSED | On a frozen 294-file snapshot, GCC 14.3.0 passes real ASan heap-overflow, LSan leak and UBSan overflow negative controls before building the CLI. `test-asan-run` and the instrumented CLI functional smoke pass without sanitizer findings. Separate ordinary in-tree SDK/license/export checks and three ML-KEM/OpenSSL 3.5.7 comparisons pass. All 25 ordered completion records, process/collector exits and source/tool integrity checks pass under the unchanged two-CPU/2-GiB VM envelope. This is not a fresh full `test-all`, direct ANS-refill ASan campaign, Qt test, whole-program proof or final-package approval; final documentation edits are outside the runtime snapshot. |
| Replacement VM isolation controls, 2026-10-22 UTC | PASS, ENVIRONMENT ONLY | A separately pinned installed kernel passes seven generic and nine native isolation/resource/supervision controls, with the exact 17-record completion protocol. Thirteen synthetic parser cases also pass. The guest remains limited to two CPUs/2 GiB with no network, host disks or home; target-envelope controls retain 768 MiB, 16 tasks and 512-MiB scratch. No Zupt payload, guest compiler or sanitizer runs in this profile. A namespace-startup failure and linker-wrapper warning are preserved; the corrected run retains all caps and produces the same controller bytes. This qualifies only the measured isolation slice, not ASan/LSan, final packages or production. |
| Direct ANS refill boundaries, 2026-10-22 UTC | PASS, FOCUSED | The existing allocation test checks 79,560 initial states against an independent byte-loop oracle, with exact-sized nonempty source spans and two fills per state. GCC 14.3.0 and Clang 22.1.8 ordinary/non-recovering UBSan profiles pass. Two private mutations pass the old test and fail the new checks at counts 56/57. Strict `check` and CLI smoke also pass with 11/10 skips. A private finite Frama-C 29.0 extension has 33 valid preconditions and zero unknowns/invalids/alarms; the maintained reader WP gate retains 30 exact valid goals. These do not close the 14 broader caller obligations. The missing historical kernel blocked ASan/LSan at that checkpoint. The first replacement-kernel CLI profile did not exercise this direct test under ASan; the later direct sanitizer result is recorded in the current row above. Final documentation is outside the runtime snapshot. No codec, format, performance or production-readiness claim. |
| AES formal-gate diagnostic capitalization, 2026-10-22 UTC | PASS, FOCUSED | A new regression exposed an uppercase warning incorrectly accepted by the old result gate. Case-insensitive diagnostic matching now passes all 32 supervisor controls; the real fixed-vector Eva profile remains clean (162/162 statements, 21 assertions, seven preconditions). Strict GCC 14.3.0/Clang 22.1.8 `check` and CLI smoke pass with 11/10 explicit skips. No cryptographic implementation change, whole-program proof, fresh full `test-all` or final-package approval; final documentation edits are outside the runtime snapshot. |
| Current Jasmin-enabled application and portable GUI helper, 2026-10-21 UTC | PASS WITH 11 SKIPS | On the fixed 294-file source, actual `WITH_JASMIN=1` strict GCC 14.3.0 `check`, cryptographic vectors (16/0), CLI functional smoke and threaded tests (14/0) pass. F-06 reports Jasmin AES-NI, 2,000 honest round trips and zero encryption failures, mismatches or accepted HMAC tampers. The same CLI passes all 12 portable-helper test methods with subcases, including genuine unencrypted level-9 `.zupt`, exact 17-file payload/checksum/extraction and failure/race controls. Runtime, collector and source/input integrity checks pass under the unchanged bounded native profile. No Qt execution, new full optional-profile `test-all`, assembly sanitizer coverage, final native-package or production approval; final documentation edits are outside this snapshot. |
| Maintained Frama-C and Jasmin repeat, 2026-10-21 UTC | PASS, LIMITED FORMAL SCOPE | The fixed 294-file source passes all four unchanged Frama-C 29.0 gates with GCC 14.3.0, Why3 1.7.2 and recognized Z3 4.12.2: three malformed metadata fixtures, reader init/take (30 exact valid JSON goals; console 34/34), logarithm ranges and four fixed AES vectors. Separate ordinary/qualified-UBSan Jasmin 2026.09.0 runs pass five-source safety/CT/regeneration/instruction/wipe checks, 1,026 AES blocks and 1,539 AES4 cases each. Real solver and failure controls precede the checks; source and independent process/collector statuses pass. UBSan covers C fixtures, not assembly. Final documentation edits are outside these snapshots; broader alarm/unknown disposition, caller contracts, actual optional-profile runtime and final-package qualification remain separate. No complete-program proof or production approval. |
| SDK symbol-check supervision and current-source Clang suite, 2026-10-21 UTC | PASS WITH 14 VM SKIPS | Six false approvals were reproduced when a tool failed after emitting valid output. The symbol recipe now checks each producer and distinguishes grep's no-match status from errors. All 25 existing recipe controls and 11 actual-target supervision cases pass. On the corrected 294-file snapshot, strict Clang 22.1.8 `test-all`, licenses, actual internal SDK and symbol checks pass in the bounded VM: 24 ordered records, 81 ASan exact-size cases, 1,024 BCJ bijections, two CLI BCJ round trips, timing regression and three ML-KEM/OpenSSL comparisons. Ordinary strict GCC `check` and CLI tests pass with 11 skips. No SDK implementation/API/format change, new speed comparison, complete-program proof or final-package/production approval; final documentation edits are outside that VM snapshot. Commands and limits are in the user guides. |
| BCJ supervision and current-source GCC suite, 2026-10-21 UTC | PASS WITH 15 VM SKIPS | Five false approvals were reproduced before checking CLI and enumeration status. All ten compiler controls and nine BCJ supervisor cases now pass. On the corrected 294-file snapshot, strict GCC 14.3.0 `test-all`, license, internal SDK and symbol checks pass in the bounded 2-CPU/2-GiB VM: 24 ordered records, timing regression, 81 ASan exact-size cases, 1,024 BCJ bijections, two real CLI BCJ round trips and three ML-KEM/OpenSSL comparisons. Ordinary `check` and the CLI suite also pass with 11 skips. No runtime/API/format change, new speed comparison, final-package or production approval; final documentation edits are excluded from that VM snapshot. Reproduction and limitations are in the user guides. |
| Worker allocation failures, 2026-10-21 UTC | PASS, FOCUSED GCC AND UBSAN | Five real-CLI STORE cases use a 64-KiB input and two workers: normal operation, then initial-buffer and final-payload allocation failures with absent/existing destinations. Worker-scoped link wrappers verify allocation order, one deliberate fault, successful thread starts and completed worker functions. Failures return exactly 1, preserve prior destination bytes and leave no partial archive; the clean archive verifies and extracts byte-exactly. Strict GCC 14.3.0 ordinary and non-recovering UBSan runs pass. The expanded ordinary `check` and CLI suite pass with 11 skips. Reproduction is in both user guides. Clang was unavailable; this does not explain the earlier automatic-24-thread OOM, prove leak freedom, or approve native packages or production. |
| Decode-slack cleanup and serial routing, 2026-10-21 UTC | PASS, FOCUSED; EARLIER OOM RETAINED | Three cleanup controls expose a failed `find` incorrectly accepted as empty; checked nonrecursive `rmdir` now preserves errors and rejects hidden files without changing them. A subsequent full check failed L5 automatic compression with 24 threads under the unchanged 1-GiB address-space limit. The supposed serial cases omitted `-t 1`; six supervisor cases reject that omission before the routing fix. Explicit serial L1/5/9 and four-thread L1/9 now pass the real 10-MiB round trips, strict GCC 14.3.0 `check` and CLI functional suite, with 11 explicit skips. All ten supervisor cases, three cleanup controls and 54 source-audit cases pass. This does not diagnose the failed allocation, fix automatic-thread memory use, or qualify native packages or production. |
| Extracted-byte accounting failures, 2026-10-20 | PASS, FOCUSED | Two false approvals were reproduced when a failed `wc` emitted zero or the complete count. The auditor now rejects byte-count pipeline errors explicitly. All 54 scanner cases pass without skips, including empty-error and successful forwarding controls; a fresh scan covers 292 files. Strict GCC 14.3.0 `check` and the real CLI functional suite pass with the same 11 explicit skips. Existing budgets and codec/API/format remain unchanged. This does not qualify every archive/tool failure, native packages or production. |
| Decode-slack test supervision, 2026-10-20 | PASS, FOCUSED | Six false approvals were reproduced before checking CLI exit status. All ten new synthetic controls pass, covering complete output followed by compression/extraction failure, stale archives, corrupt/missing output and an executable path with spaces. Strict GCC 14.3.0 `check` also runs the retained real 10-MiB round trips at L1/5/9 and multithreaded L1/9; these and the CLI functional suite pass with the same 11 explicit skips. A fresh source scan covers 292 files. Synthetic supervision is not codec, sanitizer, native-package or production approval. |
| Source-only enumeration failures, 2026-10-20 | PASS, FOCUSED | Six false approvals were reproduced before the fix. Tree, extracted-file and Git-index enumeration now reject failed producers, including plausible partial output. All 50 scanner cases pass without skips; a fresh 291-file scan finds zero archives. Strict GCC 14.3.0 `check` and the real CLI functional suite also pass, retaining 11 explicit skips. No codec/API/format change, concurrent-mutation guarantee, native-package or production approval. |
| Private scalar-load investigation, 2026-10-19 | PRIVATE, NOT ADOPTED | The exhausted-reader profile passes 63 exact WP roots. A separate live-bulk contract passes all 64 roots with an initialized, readable, separated eight-byte span; its matched negative leaves only the false postcondition unproved. All three explicit range cases close. This covers field bounds/advances, not accumulator functional equality or the general reader. Eight strict GCC/Clang ordinary/UBSan ANS runs pass. A private in-process comparison on seven accepted synthetic datasets finds no consistent timing benefit. Original codec bytes and their two Typed warnings remain unchanged; no other-endian or production approval. |
| Mixed ANS4 lane exhaustion, 2026-10-19 | PASS, FOCUSED | The maintained `test-ans-allocation` adds 288 calls against a synthetic accepted input with lane lengths 0/1/8/9 and an independently derived literal oracle. Exact allocation ends, four alignments, output lengths 1..36, consumed length, allocation counts and 144 reused-workspace calls are checked. Strict GCC 14.3.0/Clang 22.1.8 pass ordinarily and with non-recovering UBSan; fresh GCC ASan/LSan/UBSan scalar and AVX2 VM builds pass. Two private lane corruptions pass the old target but fail the new checks. Not an encoder-produced archive or proof of all refill patterns; codec/API/format unchanged. |
| Full suites with mixed-lane regression, 2026-10-19 | PASS WITH SKIPS | The fixed 291-file source passes actual strict GCC 14.3.0 and Clang 22.1.8 `test-all`, plus separate license, in-tree SDK and exported-symbol targets in the bounded VM; all 24 ordered records and independent statuses pass for each. SDK/PQBOX/Jasmin are disabled; GCC retains 15 explicit skips and Clang 14, including external providers and unsupported platforms/tools. The old Clang profile is blocked by missing artifacts; a separately pinned installed provider passes, not a byte-equivalent replacement. Ordinary suites with focused sanitizer tests, not globally instrumented builds. Later documentation edits are excluded. Formal warnings and final-package gates remain open. |
| Explicit `memcpy` model clauses, 2026-10-19 | BLOCKED, DIAGNOSED | A private Frama-C 29 header overlay adds only explicit termination and exit clauses to the existing libc contract, without changing codec C. The missing-spec warning disappears; the same 62 positive goal identities pass, while two Typed pointer-cast warnings still reject strict admission. A matched false postcondition remains unproved (62/63). These are external libc assumptions, not a libc proof or a general refill proof. The stock-header baseline retains its three warnings. |
| Expanded ANS target with ASan/LSan/UBSan, 2026-10-19 | PASS, FOCUSED VM | Frozen 291-file source, strict GCC 14.3.0 at `-O2`: separate fresh project-SIMD-disabled and AVX2 builds of the actual `test-ans-allocation` target each pass the 9,360 new states and retained tests. Three real sanitizer fault controls are rejected; all 23 ordered records and process/collector/integrity/protocol statuses pass. Product peaks are 236,113,920/235,483,136 bytes, without OOM/PID-limit events or surviving descendants, within the unchanged 2-CPU/2-GiB VM and 768-MiB target limit. No new Clang ASan, full-suite, generic refill proof or final-package approval. |
| Exhausted ANS state preservation, 2026-10-19 | PASS, FOCUSED | The maintained `test-ans-allocation` adds 9,360 synthetic states: eight positions including `SIZE_MAX`, counts 0..64, six accumulator patterns and NULL/local-byte/reader-alias sources. Strict GCC 14.3.0 and Clang 22.1.8 pass at `-O2`, also with non-recovering UBSan and real overflow controls. Two private corruption mutations pass the old test and fail the new check. This checks field preservation, not every possible source access; the later GCC memory-sanitizer VM result is recorded above. No codec, API or format change. |
| Exhausted ANS refill WP diagnostic, 2026-10-19 | BLOCKED | Private annotations on the unchanged executable C, Frama-C 29.0/GCC 14.3.0/recognized Z3 4.12.2: loop invariants improve a new 40/54 result to 62/62 goals, but three `memcpy`/Typed warnings still fail strict admission. A matched false postcondition leaves precisely its extra goal unproved (62/63). These are new goal sets, not reconciliation of the historical 78-goal result. General refill, callers and release qualification remain open. |
| Current-source Clang suite and in-tree SDK, 2026-10-19 UTC | PASS WITH 14 SKIPS | Frozen 291-file snapshot: strict Clang 22.1.8 `test-all`, license checks, 15 SDK cases and symbol checks pass in the same bounded VM envelope. All 24 ordered records and process/collector/integrity/protocol statuses pass; timing regression, 81 ASan exact-size cases, BCJ round trips and three actual ML-KEM/OpenSSL comparisons pass. An earlier run's 15 skips included missing guest OpenSSL; adding its two already-pinned selection entries closes that gap without changing product code or tests. The initial pre-boot image-cap failure is retained; BCJ/XZ transport fits without raising limits. Broader formal, platform and final-package gates remain open. |
| Current-source GCC suite and in-tree SDK, 2026-10-19 UTC | PASS WITH 15 SKIPS | Frozen 291-file snapshot: actual strict GCC 14.3.0 `test-all`, then license, SDK and symbol checks pass in the 2-CPU/2-GiB VM. This includes the timing regression gate, 81 ASan exact-size cases and three ML-KEM/OpenSSL cases. All 24 required control/completion records and process, collector, integrity and protocol statuses pass. External providers and unavailable platform/tools remain skipped; not final-package or production approval. |
| Jasmin-enabled CLI integration, 2026-10-19 UTC | PASS WITH 11 SKIPS | Actual `WITH_JASMIN=1` strict GCC `check`, CLI functional smoke and 14/14 threaded checks pass. F-06 confirms the Jasmin AES-NI path: 2,000 honest round trips and zero silent accepted one-bit HMAC tampers. This is runtime integration, not assembly sanitizer coverage, a constant-time proof or full-suite qualification of that optional profile. |
| Historical AVX2 byte-identity profile, 2026-10-19 UTC | FAIL BEFORE SUITE | Decoder `.text` differs from the historical cast-only reference after four intentional literal-count allocation guards. The original failure remains recorded; its `test-all` and SDK never ran. The separate current-source profile above executes the unchanged suite without relabeling historical byte identity as passed. |
| C checks after the recognized-solver repeat, 2026-10-19 UTC | PASS WITH 11 SKIPS | A fresh strict GCC 14.3.0 `check` and the real CLI functional smoke suite pass with SDK/PQBOX/Jasmin and Cargo disabled. Platform, external-SDK, privileged loop-device, optional-shell and man-renderer gaps remain explicit. This repeats the existing bounded C profile; it is not full `test-all`, native-package, GUI, sanitizer-VM or release qualification. |
| Selected formal gates with recognized Z3, 2026-10-19 UTC | LIMITED PASS | A subsequent repeat uses the retained, hash-checked Z3 4.12.2 binary and pinned runtime without downloads, rebuilding or product dependencies. Why3 1.7.2 recognizes its actual version; real SMT contradiction/satisfiable controls pass before Frama-C. All four unchanged Frama-C 29.0/GCC 14.3.0 gates pass: ANS metadata bounds, logarithm ranges, reader initialization/extraction WP and fixed-vector AES. The reader report has 30 exact valid JSON goals (16 Qed, 14 Z3 4.12.2; console 34/34). A fresh Jasmin 2026.09.0 qualified UBSan fixture run also passes five selected sources, 1,026 AES blocks and 1,539 AES4 cases. UBSan covers C fixtures, not assembly. The earlier unrecognized-version result remains separate. Retained-byte hashes are not upstream signature verification; these conditional checks do not close broader proof obligations, validate final packages or establish production readiness. |
| Selected formal gates after tool restoration, 2026-10-19 UTC | LIMITED PASS; SOLVER-DETECTION WARNING | The four unchanged Frama-C 29.0/GCC 14.3.0 gates pass: malformed ANS metadata (138/358 statements, zero alarms, 20 valid preconditions), logarithm ranges (15/15 statements, two valid assertions), fixed-vector AES (162/162 statements, 21 valid assertions, seven valid preconditions, 64 byte checks), and reader WP (30 exact JSON goals, console 34/34). Why3 1.7.2 reports Z3 4.13.0 as unrecognized during detection; the existing reader gate accepts that identity, without establishing recognized-solver qualification. A fresh Jasmin 2026.09.0 qualified UBSan fixture repeat passes five-source checks, 1,026 AES blocks and 1,539 AES4 cases after a real overflow control fails. UBSan instruments C fixtures, not assembly. Initial restoration/configuration failures remain recorded. These conditional slices do not prove the complete decoder, C callers or cryptographic implementation, validate final packages or establish production readiness. |
| Complete T6 small-file comparison, 2026-10-19 UTC | PASS, LIMITED SHELL CONTRACT | T6 requires successful compression and extraction, 1,000 regular output files and a recursive comparison of every relative path and byte, rather than five sampled files. All 79 controls pass, retaining the earlier 71. Five new faults reproduce false approvals; missing/extra-file cases already rejected by count now retain diagnostics. The fake T6 extraction layout matches a real archive probe. A separate real-CLI run passes 14/14 threaded checks. These checks do not establish metadata preservation, performance, formal proof or production readiness. |
| T14 compression acceptance, 2026-10-19 UTC | PASS, LIMITED SHELL CONTRACT | Both timed compressors must exit zero and leave regular, nonempty outputs before T14 reports timing success. Per-compressor merged stdout/stderr logs are replayed on failure. Eleven new controls retain the earlier 60, bringing `make test-threaded-harness` to 71. All ten fault controls expose false approvals in the old script: each phase fails before/after writing, or returns zero with missing, empty or directory output. Corrected failures require status 1, one T14 failure, 13/1 totals, diagnostics, ordered 1/4-thread calls and cleanup, without timing-success output. The real CLI separately passes 14/14 threaded checks. These synthetic controls and informational elapsed times do not establish compression performance, archive integrity, sanitizer-runtime or production readiness. |
| Independent Jasmin repeat, 2026-10-19 UTC | LIMITED PASS | The existing Jasmin 2026.09.0 tools run without the missing Frama-C profile. Ordinary GCC 14.3.0 and non-recovering UBSan fixture builds each pass all five sources' compilation, conditional safety, CT/DOIT, lowering and generated/runtime instruction checks, plus 1,026 AES blocks and 1,539 AES4 cases. A real overflow control confirms UBSan rejection before the qualified repeat. Recovered executable hashes match the preserved record; the three executables and four APRON libraries match their hash-pinned package members. This does not instrument assembly with UBSan, discharge C caller preconditions, validate final packages or replace Frama-C/Why3; the reader attempt at that snapshot stopped before analysis because its pinned executable was absent. See the later restoration result above. |
| Threaded-suite binary fixtures, 2026-10-18 | PASS, LIMITED FIXTURE ACCEPTANCE | Require both `dd` producers to succeed and independently check the 512,000-byte random and 204,800-byte zero fixtures before T1. Ten new controls retain the earlier 50, bringing `make test-threaded-harness` to 60. Eight producer faults (complete output followed by failure, or successful empty/short/oversized output for either file) expose false approvals in the old script. A ninth negative covers the newly added size validator failing after printing success. All nine now exit 1 with diagnostics and cleanup before compression/extraction/integrity calls. The normal control independently checks sizes and zero content. The CLI is synthetic; this is not codec, concurrency, performance, sanitizer-runtime or production qualification. |
| C and downstream checks after the binary-fixture guard, 2026-10-18 | PASS WITH 11 SKIPS | Fresh GCC 14.3.0 warning-error `check` and the actual CLI functional suite pass with SDK/PQBOX/Jasmin and Cargo disabled. A separate real-CLI threaded run passes all 14 checks, including 1/2/4/8-thread round trips, encryption, wrong-password rejection and integrity. Existing Guix phase/launcher controls pass with installed Guile 3.0.11 and its matching module union; the patched harness also runs all 60 controls. These phase tests use process doubles, not a native derivation or Qt runtime. Threaded elapsed times are not benchmark evidence; formal, package and final release gates remain pending. |
| Formal-tool availability recheck, 2026-10-18 | BLOCKED BEFORE ANALYSIS | A later repeat cannot start because the pinned validation profile, Frama-C 29.0 and Why3 1.7.2 paths are unavailable. The first selected ANS check stops during environment setup; no analyzer or subsequent Jasmin gate runs. Earlier selected formal results remain historical evidence for unchanged inputs, not a new pass. Restore or requalify the pinned environment before final formal/release acceptance; no tools, criteria or limits were silently substituted. |
| Current CLI sanitizer VM slice, 2026-10-18 | PASS, BOUNDED RUNTIME | The frozen 284-file source passes in a disposable 2-CPU/2-GiB VM with a 768-MiB/16-task target cgroup and 512-MiB scratch. Guest isolation/resource/cleanup controls and actual ASan/LSan/UBSan negative controls pass before the product. The instrumented CLI passes `test-asan-run` and installed functional smoke with leak detection enabled. Separate uninstrumented in-tree SDK/license/export tests and three ML-KEM/OpenSSL interoperability cases pass. VM/collector/integrity/protocol statuses are zero; exactly 25 ordered completion records are required. Later changes are result-only documentation. This does not qualify full `test-all`, fuzzing, exact-size, external SDK, GUI, native packages or production. |
| Threaded-suite JSON fixture, 2026-10-18 | PASS, LIMITED FIXTURE ACCEPTANCE | Preserve the seeded generator; require status 0 and independently validate 5,000 records, sequential integer IDs, matching names and finite scores before compression. Nine controls cover normal output and eight producer/data/validator failures, including full output followed by nonzero exit and an invalid interior record. Failures require status 1, diagnostics, cleanup and no compression/extraction/integrity calls. All eight negatives reject the old unguarded producer. The normal fixture retains its observed SHA-256 with the pinned Python; no cross-version determinism claim. Together with the original 41 controls, this snapshot ran 50, before the ten binary-fixture controls above. The CLI is synthetic; this is not codec, concurrency, performance or production qualification. |
| Threaded-suite workspace lifecycle, 2026-10-18 | PASS, LIMITED SHELL LIFECYCLE | Exclusive `mktemp -d` workspaces respect `TMPDIR`, use mode 0700 and stop before the CLI if creation fails. Seven executable controls cover a legacy-name symlink/private sentinel, spaces in `TMPDIR`, caller `umask 000`, actual fixture mode 0600, normal cleanup, HUP/INT/TERM exits and three creation failures. All seven reject the old setup; its INT control exits zero and a generated file has mode 0666. This group brings the subtotal to 41 controls including the 34 password/integrity controls, before the nine JSON-fixture controls above. CLI behavior is synthetic; these filesystem/process checks do not establish codec, concurrency, sanitizer-runtime or production readiness. |
| Threaded-suite password and integrity controls, 2026-10-18 | PASS, SYNTHETIC PROCESS BOUNDARY | T9 requires status 1, the authentication diagnostic and a full log without sanitizer markers. T10 requires status 0, a clean full-log scan and exactly one complete nine-file success summary; scan errors, wrong counts and contradictory summaries, including a NUL prefix, fail. This group retains 34 whole-script controls: one positive, 13 T9 negatives and 20 T10 negatives. The original T10 falsely approves 18 of the first 33 controls; a further regression exposes the NUL-prefixed conflicting summary in the first fix. The CLI fixture uses private hardlinks and does not compress or encrypt; its timing output is not performance evidence. Other command-status and fixture-generation gaps remain; this is not full native threaded or production qualification. |
| Guix installed-CLI acceptance hook, 2026-10-18 | PASS, PRIVATE STAGED PROFILE | The actual recipe invokes the existing functional script with `$out/bin/zupt` after stripping and RUNPATH validation. Scheme regressions cover ordering, exact paths with spaces, default/enabled/disabled tests, cross-build defaults and child failure propagation. A fresh strict GCC CLI passes the real installed check after private Make installation and Guix postprocessing, with the build-tree executable removed; a missing installed binary is rejected. This is not a native Guix derivation, accepted dependency closure, GUI build, profile installation or release approval. |
| ANS reader exact-state regression, 2026-10-18 | PASS, HOST PROFILE | The existing `test-ans-allocation` target adds seven literal-state steps for zero-width reads, masked refill, short tails and EOF. A private eager-refill mutation passes the old suite but the extended suite compiles and rejects it at the first zero-width read. The real core passes non-recovering UBSan with `NDEBUG` under GCC 14.3.0 and Clang 22.1.8; strict `check` and CLI tests pass with 11/10 respective skips. Existing 2,312 bit-reference and 520 exhausted-counter cases remain unchanged. This adds regression coverage, not a codec change, newly established decoder vulnerability, general proof, current VM ASan/LSan or release approval. |
| Current-source Clang checks, 2026-10-18 | PASS WITH 10 SKIPS | Strict Clang 22.1.8 `check` and the real CLI functional suite pass with SDK/PQBOX/Jasmin disabled. The first isolated attempt fails because a UBSan helper cannot load `libgcc_s.so.1`; a fresh run supplies only the installed compiler's configured support-library directory, without changing source, flags, criteria or limits. Windows, five external-SDK cases, privileged loop-device coverage, zsh, fish and man-page renderers remain skipped. This is not full `test-all`, current VM ASan/LSan, native-package or production qualification. |
| Portable GUI bundle and RPM metadata, 2026-10-18 | LIMITED PASS | A fresh strict GCC 14.3.0 CLI passes its functional script and all 12 portable-package tests: genuine unencrypted level-9 `.zupt`, 17 exact frontend files, checksums, extraction, rejection controls and preservation of existing outputs. The covered-source SPDX-marker check passes. Real RPM 4.20.1 parses the openSUSE spec and lists 14 declared build requirements; the recorded Guix macros use a store prefix, not `/usr`. These checks do not establish native RPM/DEB/Guix builds, installed dependencies, complete legal clearance, Qt execution in this profile or release approval. |
| GUI query failure handling, 2026-10-18 | PASS, HOST OFFSCREEN; FULL LINT STILL FAILS | Three synchronous queries retain fallbacks for OS, subprocess and text-decoding failures, but no longer hide unexpected programming errors as missing metadata. Two regression methods cover 18 expected failures and nine unexpected errors; the latter first fail against the old code. All 64 GUI methods pass separately with genuine PySide6 6.9.2 and PyQt6 6.9.1/Qt 6.9.2, alongside fresh strict GCC `check` and CLI tests with 11 ordinary skips. Formatting and both preferred-provider typing profiles pass; full Ruff improves from 16 to 11 diagnostics without suppressions or mode changes. This is not native-package, desktop, current VM sanitizer or production qualification. |
| Extended native CLI and ML-KEM interoperability, 2026-10-18 | PASS, LIMITED HOST PROFILE | A fresh strict GCC 14.3.0 CLI passes the functional script, regression 22/0, built-in PQ 10/0 and dedup properties 14/0. The unchanged ML-KEM script separately passes all three real comparisons against OpenSSL 3.5.7, without skips. SDK/PQBOX/Jasmin are disabled in this CLI build; the separate Jasmin result is below. No fresh Clang, full threaded suite, constant-time timing gate, current VM sanitizer campaign or native-package acceptance is implied. Legacy comparison output is informational, not a compression-performance qualification or FIPS certification. |
| Encrypted private-key policy, 2026-10-17 | PASS, LOCAL REGRESSION ONLY | The new synthetic PKCS#8 encrypted-private-key header was incorrectly accepted before the regex correction. All six regression methods now pass with nine credential patterns; public-key, RSA public-key and certificate headers remain accepted. The actual gate also passes on a private index of the selected 283 files. Fresh strict GCC `check` and CLI functional tests also pass, retaining 11 explicit skips. This checks header policy, not PEM validity, encryption strength or comprehensive secret detection. |
| Full credential-detector startup, 2026-10-17 | BLOCKED | The pinned Gitleaks 8.30.1 detector fails on nonempty clean input under the unchanged 1-GiB address-space cap while reserving 4 GiB of virtual address space. Version/input-rejection controls pass but do not start the detector. The recorded pre-fix inventory contains 279 UTF-8 text files and four binary images; zero project files were scanned. No limit was raised or scanner substituted. Filename-dependent, decoded and binary coverage is also unqualified. |
| ANS4 cumulative lane bounds, 2026-10-17 | PASS, LIMITED FIXTURES | The new 33-byte fixture rejects a fourth lane after the first consumes the only payload byte, preserving output and consumed length. Genuine Frama-C 29 reaches 138/358 statements with zero alarms and 20 valid preconditions; all 57 supervisor controls pass. GCC/Clang scalar UBSan and allocation-mutation controls pass through existing Makefile policies. Fresh strict GCC `check` and CLI tests pass with 11 skips. Direct strict Clang still reports 16 existing cast-alignment diagnostics; the supported recipe retains its object-local exception. No production-code change or release approval. |
| CI credential gate, 2026-10-17 | PASS, LOCAL REGRESSION ONLY | The original gate falsely accepted three Git failure/inconsistent-result controls. Six regression methods now pass, including eight synthetic credential patterns, five invalid Git outcomes and isolation from ambient Git overrides. Fresh strict GCC `check` and CLI functional tests pass on the recorded 283-file snapshot, retaining 11 explicit skips. New-test Ruff/format and both Pyright profiles pass. This narrow pattern check is not a qualified full credential scan, hosted CI result, native-package or release approval. |
| Qt fallback and native object-lifetime regression, 2026-10-17 | PASS, HOST OFFSCREEN ONLY | All 62 methods pass with genuine PySide6 6.9.2 and PyQt6 6.9.1/Qt 6.9.2. Retained QObject receivers observe all three native deletions on the GUI thread; a retained worker wrapper prevents garbage collection from masking missing cleanup. Both providers reject the private cleanup-removal mutation and five probe mutations, with positive controls passing. Final profiles rebuild strict GCC `all` and run CLI functional tests: 18 PySide stages and 19 PyQt stages pass. Full strict GCC `check` also passed immediately before the one-line fixture capture clarification, with identical C/GUI inputs and 11 ordinary CLI skips. Both final PySide typing profiles report zero errors. Production GUI/C code is unchanged; full Ruff still fails with 16 findings. Native packages, VMs, whole-suite sanitizers and release readiness remain unqualified. |
| GUI probe contracts, before unused-binding cleanup, 2026-10-17 | PASS, HOST ONLY | Six POSIX real-process tests extend the existing 56-test suite to 62 methods. They cover executable checks, version status, help fallback/cache, archive-info streams and command status/arguments. Fresh strict GCC checks, CLI functional tests and all 18 host stages pass, retaining 11 ordinary skips. All six probe tests also pass separately; five private mutations fail in their expected methods. Preferred-provider Pyright basic/default both report zero errors after correcting a test-helper argument ambiguity. Production GUI bytes are unchanged; full Ruff still reports 23 diagnostics and both files fail formatting. These synthetic probe fixtures do not qualify native packages, whole-suite sanitizers or the release. |
| Guix installed policies, 2026-10-17 | PASS, HOST PHASES ONLY | Regression tests first detect missing CLI `DISTRIBUTION.md`, then missing GUI `SECURITY.md`. The recipe now installs security and distribution policies with both user guides for CLI and GUI; actual phases compare four CLI and ten GUI files byte-for-byte. Fresh strict GCC checks, CLI functional tests, all 56 GUI tests and 17 stages pass on the corrected 282-file snapshot before this documentation update, with 11 ordinary skips. The withdrawn origin is unchanged; this is not a native Guix derivation, dependency closure, package installation or release approval. |
| Fresh instrumented VM admission, 2026-10-17 | BLOCKED, NOT RUN | The corrected 282-file source, 243-file historical baseline, tool pins and explicit runtime slice were verified. Preflight exits 78 at 4,754,292 KiB available against the unchanged 5-GiB floor, before image preparation, guest controls or product execution. A separate private wrapper regression reproduces six false approvals of incomplete guest transcripts; all 11 wrapper tests pass after requiring the ordered control/stage/termination protocol. Synthetic wrapper success is not ASan/LSan/UBSan coverage. VM limits remain 2 CPUs/2 GiB. |
| Qt provider and thread affinity, 2026-10-17 | PASS, HOST / PYSIDE6 TYPES ONLY | A real Qt regression reproduces a `TypeError` because the controller's `thread` attribute hides `QObject.thread()`. Private `_thread` storage restores the inherited method without changing worker ownership or join order. All 56 GUI tests, fresh strict GCC checks, CLI functional tests and 17 stages pass on the recorded 282-file snapshot before this documentation update, with 11 ordinary skips. Actual Pyright basic/default analyses of the GUI and test file report zero errors using genuine PySide6 declarations; no rules are suppressed. Missing Qt retains the tested diagnostic and exit 1. PyQt6 runtime, native packages, real desktops and release readiness remain unqualified. |
| UTF-8 across GUI pipe reads, 2026-10-17 | PASS, HOST ONLY | Five new test methods exercise 31 stream/cleanup scenarios; 22 assertions fail before the fix. A per-run incremental decoder preserves split 2/3/4-byte characters and finalizes incomplete UTF-8 at EOF with replacement. All 55 actual Qt tests, fresh strict GCC 14.3.0 checks, real CLI functional tests and 17 stages pass on the recorded 282-file snapshot before this documentation update, with 11 ordinary skips. Progress, cancellation, child cleanup and archive bytes remain unchanged. This does not qualify PyQt6, native packages, whole-suite sanitizers or the release. |
| Literal GUI logs, 2026-10-17 | PASS, HOST ONLY | Three rendering regressions fail before the fix. After switching logs to Qt plain text, all 50 GUI tests pass, including nine new checks for markup, Unicode, line boundaries, selection, scrolling, styling and a real archive path. Strict GCC 14.3.0 `check`, CLI functional tests and all 17 recorded stages pass on the selected 282-file snapshot before this documentation update; 11 ordinary checks remain explicit skips. Python 3.12.12/PySide6/Qt 6.9.2 run offscreen, without network. PyQt6, native packages, real desktop sessions and the release are not qualified by this run. |
| Python quality checks, 2026-10-17 | IMPORTS / FORMAT PASS; FULL LINT NOT CLEAN | After the unused-binding cleanup, organize imports and format the GUI and workflow tests with Ruff 0.16.10. Import and formatting checks now pass; full lint falls from 20 to 16 diagnostics with the other findings and effective settings unchanged. F401/RUF059 and PLW1510 remain clean. A constrained syntax comparison preserves non-import AST fields, import records within each consecutive group, comment text/order, license headers and the 62 ordered test methods; it does not prove import initialization effects. Fresh strict GCC/CLI checks and all 18 host stages pass, including all 62 methods, with 11 ordinary CLI skips. Both genuine PySide6 typing profiles report zero errors. No rules, exception policies or resource limits changed. Full lint, PyQt6 runtime, native packages, whole-suite sanitizers and production remain unqualified. |
| Static-analysis gate and source inventory, 2026-10-17 | PASS LIMITED | All 53 supervisor scenarios pass. The expanded controls reproduced 19 additional false approvals, plus a later omission when SHA-NI source disappeared during analysis. The gate now checks source producers, `grep` status/count consistency and required SHA-NI compilation; genuine no-match results remain accepted, while warnings and forbidden patterns remain rejected. Private source fixtures and compiler/analyzer doubles test the supervisor, not C correctness. The real GCC static run passes 9/9; cppcheck is unavailable. Both user guides provide reproduction commands and coverage limits. |
| Instrumented VM admission, earlier 282-file snapshot, 2026-10-17 | BLOCKED, NOT RUN | The disposable GCC ASan/LSan/UBSan profile was prepared with pinned tools before the subsequent static-gate changes. Admission observed 4,894,876 KiB available RAM, below the unchanged 5-GiB floor, and exited 78 before image preparation or product execution. No current-source VM validation occurred in that attempt, and no sanitizer pass or production approval is inferred from it. The later 284-file VM slice is recorded separately above. |
| Assembly-enabled CLI and in-tree SDK, 2026-10-17 | PASS WITH SKIPS, HOST ONLY | Fresh strict GCC 14.3.0 and Clang 22.1.8 builds pass `check`, the real CLI functional suite, SDK runtime tests and export checks on the same recorded 282-file snapshot, before this results-table update. All 18 GCC and 15 Clang stages pass; each verifies ten real C-object assembly references. The 25-assertion recipe regression and 53 static-analysis supervisor scenarios run in both suites. GCC exercises a custom SDK directory and Clang the default. Native Windows, external libvuptsdk, privileged devices and unavailable tools remain explicit skips (11 in GCC `check`, 10 in Clang `check`). GCC static controls pass nine checks; cppcheck is unavailable. This is not whole-suite sanitizer, native-package, SDK hardware AES dispatch or release approval. |
| Guix generated package-test interpreters, 2026-10-17 | PASS LIMITED | The real interpreter-phase regression passes nine shell-control groups without `/bin/sh` or `/usr/bin/env`, including 20 DEB and 55 RPM helper cases. The added cases fail before the two-path recipe correction. Earlier executor setup failures and the initial full-run packaging failure remain recorded. Package tools are controlled replacements; real phase execution does not qualify native Guix, DEB or RPM builds. |
| Guix source phases and strict GCC host checks, 2026-10-16 | PASS WITH SKIPS, HOST ONLY | Fresh strict GCC 14.3.0 `make check` and the real CLI functional suite pass after the actual source/fixture phases and ML-KEM supervisor fix on the recorded 281-file snapshot, before subsequent documentation edits. The networkless namespace has no `/bin/sh` or `/usr/bin/env`. Seven fixture groups and 29,413 codec boundary checks execute; SDK/PQBOX/Jasmin are disabled and 11 platform/provider/tool skips remain explicit. Frama-C wrappers use synthetic controls here, not real analyzers. This is not a Guix derivation or native package qualification. |
| ML-KEM/OpenSSL process-error regressions and real interoperability, 2026-10-16 | LIMITED PASS | All 27 crypto-wrapper controls pass, including 15 ML-KEM cases: two valid flows, three supported skip paths and ten producer failures. The original nine false approvals were reproduced before the fix. With real OpenSSL 3.5.7, GCC 14.3.0 and Clang 22.1.8 each pass deterministic public-key comparison and both shared-secret directions, with no skips. Cryptographic code and comparison criteria are unchanged; these finite checks are not certification, native Bash 3.2 execution or a constant-time proof. Reproduction commands are in both user guides. |
| Current Guix GUI recipe phases with real Qt, 2026-10-16 | LIMITED PASS, HOST OFFSCREEN | A matching freshly built CLI and the recorded installed GUI module pass launcher version, six-tab selftest and all 41 workflows with Python 3.12.12 and PySide6/Qt 6.9.2. All 17 recorded stages pass, and 13 installed files match source bytes. The GUI-only file cap is 32 MiB for the unchanged cancellation fixture; ordinary stages retain 16 MiB within the same 128-MiB RAM filesystem. Earlier private-driver and fixture-capacity failures remain recorded. Manual dependency-path mapping is not a native Guix derivation, closure validation, desktop-session test or release approval; later test-supervisor/documentation edits are excluded. |
| Complete local source `.zupt` round trip, 2026-10-16 | PASS WITH SKIPS, LOCAL ONLY | All 281 regular files in the recorded snapshot, before this documentation update, pass unencrypted VaptVupt level 9 compression, archive integrity, exact extracted inventory and byte comparison. Original permissions are restored only after verification. Strict Clang 22.1.8 `make check` and the extracted CLI functional suite pass; the Clang reader also accepts the GCC-generated archive. SDK/PQBOX/Jasmin are disabled for this build, and native-platform/tool skips remain explicit. This unsigned local artifact is not the final signed-tag export or native package approval. |
| Source-export producer failures, 2026-10-16 | LIMITED PASS | All 17 source-state/producer controls pass locally. Failed Git/gzip producers, including complete output followed by an error, must stop before the scanner or delivery; existing outputs preserve bytes and inode identity. Successful repeated fixture exports remain byte-identical. The test forwards real producer output with controlled exit faults and uses a phase-order scanner fixture, not the actual content policy. No final source commit, native package, signature or release approval is established. |
| Installed-executable checksum failure handling, 2026-10-16 | LIMITED PASS | The real CLI and expanded 65-case POSIX validator harness pass locally. Six pre-fix false approvals with failed hash producers were reproduced; input/extracted-tree guards now reject them, and find/sort failures receive stage diagnostics. Original byte comparisons and 53 CLI status/crash/sanitizer controls are unchanged. Both checksum interfaces use controlled adapters to an available real hash engine; this is not native Perl, cross-platform package or release qualification. Reproduction commands are in both user guides. |
| Native package no-clobber publication | LIMITED PASS | 21 publisher tests, 20 DEB cases and 55 RPM cases pass locally, including late collisions, complete helper publication, staging replacement, cleanup-error precedence, checksum filename escaping and search-only ancestors. The four helpers share descriptor-relative publication in an owned, non-shared-writable output directory. External build/package tools remain controlled replacements. Per-file no-clobber is not whole-batch atomicity, arbitrary namespace-race protection, crash durability or native package/release approval; both guides document the trust boundary and retained partial outputs. |
| DEB/RPM tool-failure boundaries, 2026-10-15 | LIMITED PASS | The earlier `make test-packaging-failures` run passed 12 DEB and 47 RPM cases under both `umask 022` and `077`. Actual helpers rejected failed metadata/inventory/ELF commands even with plausible output; DEB refused preexisting dangling output symlinks. External build/package tools were controlled replacements, not native package qualification. The initial mode-sensitive RPM fixture failure remains recorded and was corrected without weakening the checker. Publication races were still open at that stage; the expanded checks above cover per-file no-clobber, not batch atomicity. Reproduction commands are in both user guides. |
| Private SDK staging, 2026-10-15 | PASS, LINUX SCOPE | Ordinary GCC 14.3.0 and separate Clang 22.1.8 UBSan and ASan/UBSan builds: 40 staging cases, 13 callback cases, 15 existing SDK checks and symbol verification pass. All five public staging paths use exclusive, restricted creation; collisions preserve contents and device/inode identity. Permission, stdio-conversion, write and close faults check cleanup. Windows COFF builds and six bridge-model cases do not establish native Windows/DACL validation. Cleanup assumes trusted temporary ancestors. |
| SDK callback bounds and I/O, 2026-10-15 | PASS, FOCUSED | Fresh ordinary GCC 14.3.0 build and separate Clang 22.1.8 UBSan and ASan/UBSan SDK builds: 15 existing checks, 13 stream cases and exported-symbol checks pass. Both stream entry points reject oversized callback counts before a write; partial reads, close failures, cleanup and first-error precedence are covered. The exploratory whole-core `-Wconversion -Werror` build fails on existing LZ index conversions. Reproduction: the user guides' SDK callback section. Host SDK coverage; native packages and release approval remain pending. |
| Selected Frama-C/Jasmin gates, 2026-10-18 | LIMITED PASS | Five actual current-source gates pass with Frama-C 29.0, Why3 1.7.2, Z3 4.12.2, Jasmin 2026.09.0 and GCC 14.3.0. Logarithm Eva reaches 15/15 statements; fixed-vector AES reaches 162/162 with 64 byte checks; reader WP validates 30 exact JSON goals (16 Qed, 14 Z3; console 34/34); three malformed-metadata fixtures reach 138/358 statements with zero alarms and 20 valid preconditions. All five Jasmin safety/CT/DOIT/lowering/instruction checks, 1,026 AES blocks and 1,539 CTR4 cases pass. Earlier missing-cmp and libcrypto-loader failures remain recorded; only the private test environment was corrected. These conditional slices do not prove the complete decoder, SDK or application, or qualify final packages. |
| Portable GUI policy delivery, 2026-10-15 | LIMITED PASS | Twelve packaging groups pass with actual `.zupt` operations and an exact 17-file payload, including both guides and their linked SECURITY/DISTRIBUTION policies. Missing archive policies and missing/symlinked policy sources are rejected. The pre-fix archive regression reproduced both absent files. This is host packaging coverage, not Qt runtime, native packages or release approval; older 13/15-file results below retain their historical scope. |
| Extracted DEB/RPM documentation checks, 2026-10-15 | LIMITED PASS | Sixteen regression tests exercise the real checker, including native directory layouts, exact bytes/modes, missing files, duplicate roots, symlinks and FIFO rejection. The actual GUI staging installer also passes it. All four native package helpers now call it before delivering artifacts, and the recipes include both guides and linked policies. Native Debian/RPM builds remain blocked on a qualified environment; fixture/staging checks do not approve their outputs. |
| Documentation delivery regressions, 2026-10-14 | LIMITED PASS | Portable GUI packaging passes all 11 groups with 15 exact files, including both user guides. Real Guix recipe phases verify two CLI guides, eight GUI files and four fixture-wrapper groups. The GUI installer stages both guides plus SECURITY/DISTRIBUTION byte-for-byte at mode 0644 and rejects missing guides before installation; the metadata suite reports 56 passes, zero failures and three explicit skips. The earlier Guile memory failure remains recorded; adding its compiled-module path passes the separate phase at the same 1-GiB limit. These host checks do not qualify native DEB/RPM/Guix packages or a release. |
| Selected formal checks on tree `678d86278f8fc1060b899ad8ced2eebb974442cc`, 2026-10-14 | LIMITED PASS | Frama-C 29.0/Z3 4.12.2 and Jasmin 2026.09.0 gates pass for ANS metadata, reader, logarithm ranges and fixed-vector AES, plus the five assembly sources and wipe checker. No whole-program proof, final-package approval or coverage of subsequent installer/documentation edits. |
| Selected current-source Frama-C checks, 2026-10-13 | LIMITED PASS | Metadata Eva: zero alarms and 14/14 preconditions; reader initialization/extraction: 30 exact JSON goals; fixed-vector AES: 21 assertions, seven preconditions and 64 byte checks. Twenty selected source hashes stayed unchanged. The separate exhausted-reader diagnostic progressed from Qed 44/78 to Z3 78/78 goals, but three warnings keep strict admission at exit 1. No complete decoder proof or final-package validation |
| Selected current-source Jasmin checks, GCC/Clang, 2026-10-13 | LIMITED PASS | Five selected sources pass safety, CT, DOIT, lowering and matching instruction bytes; 1,026 AES blocks, 1,539 CTR cases, four warning controls and 17 wipe-checker controls pass. Seventeen selected source hashes stayed unchanged. Caller obligations, register erasure and final-package validation remain outside scope |
| GCC 14 release preflight and Qt/PyQt GUI workflows, earlier snapshot | PASS | Full suite `20/0/3`, release preflight `50/0/6`, 39 GUI cases in the Linux VM |
| Portable GUI `.zupt` and Qt workflows, frozen 248-file snapshot, 2026-10-07 | PASS | Fresh GCC 14.3.0 CLI, Python 3.12.12, PyQt6 6.9.1/Qt 6.9.2; 39/39 offscreen tests, 13 exact frontend files tested and extracted byte-for-byte. In-tree SDK 15/0, static checks 9/0 and metadata 50/0/6 pass; seven unavailable checks remain explicit. Not a native DEB/RPM/Guix install or a signed release artifact; later documentation changes are excluded |
| `test-all` integration suite, earlier guard snapshot | PASS | Core 22/0, multithread 14/0, PQ 10/0, dedup 14/0, exact-size 81/0, ML-KEM/OpenSSL 3/0 and constant-time gate; SDK/PQBOX integrations explicitly skipped |
| Host GCC 16 full-suite attempt | BLOCKED | ASan shadow-memory mapping failed under `ulimit -v`; suite incomplete, not a product PASS |
| GCC 14 full suite in an isolated VM, earlier C-core snapshot | PASS | `test-all`, ASan and the ANS4 regression passed; summary `20/0/3`; SDK/PQBOX and other unavailable checks retain explicit skips. Later formal wrappers, documentation and regenerated assembly were outside this snapshot |
| GCC 14.3.0 full suite after AES initialization changes, 2026-10-07 | PASS | Frozen 248-file source, isolated 2-CPU/2-GiB VM: strict `test-all` with `WITH_JASMIN=0 WITH_SDK=0 WITH_PQBOX=0`, timing gate and ASan runtime controls passed; 14 explicit skips remain untested. Ordinary suite, not globally ASan/UBSan-instrumented. Formal wrapper controls do not replace actual analyzer runs; not a native package installation; later documentation edits are excluded |
| Clang 22.1.8 full suite and in-tree SDK after AES initialization changes, 2026-10-07 | PASS | Same frozen source and VM limits: strict `test-all` with `WITH_JASMIN=0 WITH_SDK=0 WITH_PQBOX=0`, then in-tree SDK and license checks passed; 15 explicit skips remain untested, including OpenSSL interoperability. Ordinary suite plus ASan runtime controls, not globally ASan/UBSan-instrumented; later documentation edits are excluded |
| GCC 14.3.0 instrumented CLI after AES initialization changes, 2026-10-07 | PASS | Same frozen source: `test-asan-run` and installed-smoke checks passed with ASan/UBSan and leak detection enabled. Archive round trips, encrypted/deduplicated synthetic disk images, wrong passwords, corruption and extraction-path checks executed. Separate ordinary SDK 15/0 and ML-KEM/OpenSSL 3/0 checks passed. No native package or active swap/device test; later documentation edits are excluded |
| Clang 22.1.8 full suite with assembly after AES initialization changes, 2026-10-07 | PASS | Same frozen source, isolated 2-CPU/2-GiB VM: strict `test-all` with `WITH_JASMIN=1 WITH_SDK=0 WITH_PQBOX=0` and timing gate passed. Actual vector dispatch required Jasmin AES-NI and OS-enabled AVX; 15 explicit skips remain untested. Ordinary suite, not globally ASan/UBSan-instrumented. Compiler regeneration is a separate check; not a native Guix package build or installation; later documentation edits are excluded |
| GCC 14 full suite with assembly, 247-file snapshot | PASS | Isolated VM `test-all` with `WITH_JASMIN=1 WITH_SDK=0 WITH_PQBOX=0`; 14 explicit skips remain untested. Later warning-scan wrapper, Makefile and documentation edits were not included; this is not a full GCC 248-file result |
| Clang 22 full suite with assembly, earlier 248-file snapshot | PASS | Isolated VM `test-all` with `WITH_JASMIN=1 WITH_SDK=0 WITH_PQBOX=0`; 15 explicit skips remain untested, including OpenSSL interoperability. Ordinary suite, not a globally ASan/UBSan-instrumented build |
| ML-KEM/OpenSSL interoperability, GCC247/Clang248 | PASS / NOT RUN | Three checks passed in GCC247. Clang248 had no `openssl` executable and skipped this check; native ML-KEM vectors do not replace interoperability coverage |
| Clang 22 ASan/UBSan/LSan decoder fuzzing, earlier snapshot | PASS | 2,719,486 bounded executions, zero artifacts; not exhaustive coverage |
| Source-only scanner and adversarial suite, 2026-10-07 snapshot after ANS4 gate/documentation changes | PASS | 248 files including 17 existing Markdown documents, zero archives, 40/40 cases without skips; scanner ran without building. Markdown magic/LFS/archive checks included, removed-library text checks limited to code/scripts. Files, modes and source inventory remain identical before/after the checks; final Git index/tag audit awaits an immutable reviewed commit |
| License inventory, frozen 248-file snapshot | PASS | `make audit-licenses` passed; inventory checks are not legal clearance |
| Native GNU Guix CLI derivation, frozen 248-file snapshot, 2026-10-09 | LIMITED PASS | GCC 14.3.0; real build, enabled `check` and installation phases completed in the isolated 2-CPU/2-GiB VM. The earlier complete volatile run of this same source and derivation retains ten explicit skips and validates the registered output's size/hash. No native GUI build or host profile installation; later documentation changes are excluded |
| Historical compressed export of the native Guix CLI output, 2026-10-09 | FAIL | The export exceeded its compressed-file limit after build/check/install. Transfer status and final receipts remain mandatory; a representative alternative also exceeded the capture limit. No retained package or release promotion is claimed |
| Native Guix CLI candidate restoration and functional smoke, 2026-10-09 | LIMITED PASS | A separate bounded binary transfer preserved the exact 927,760-byte output and SHA-256. Private restoration and reserialization matched byte-for-byte; all eight installed-smoke checks passed on the actual CLI. Complete VM acceptance still failed: final console receipts were truncated at poweroff, and the quiet client omitted phase/test logs. No accepted package, GUI validation, host installation or release promotion; later documentation edits are excluded |
| Native Guix CLI rerun with complete console evidence, 2026-10-09 | LIMITED PASS | The same frozen source and derivation completed build, enabled `check`, installation and teardown with full phase logs and ten explicit skips. The bounded console-drain correction passed in the 2-CPU/2-GiB VM, and the generated output matched the earlier candidate's exact size/hash. This separate run transferred no package and does not override the failed binary-transfer run; no GUI build, accepted retained package, host installation or release promotion. Later documentation changes are excluded |
| Checked-in assembly integration (`WITH_JASMIN=1`), earlier snapshot | PASS | 16 ML-KEM vectors and timing gate; compiler regeneration was not run in that snapshot |
| Native Guix CLI with complete console and UART comparison, 2026-10-10 | LIMITED PASS | The same frozen 248-file source and derivation completed build, enabled `check`, installation and teardown in the isolated 2-CPU/2-GiB VM. Full classifiers passed; the fresh 927,760-byte UART stream matched the preserved candidate byte-for-byte through EOF, with all four statuses zero. Ten explicit skips remain. No new durable artifact was created; retained-package acceptance, native GUI and final release gates remain open. Earlier failed runs remain failed; later documentation changes are excluded |
| Private retained Guix CLI copy and restoration, 2026-10-10 | LIMITED PASS | A 277,792-byte XZ copy of that exact output passed single-stream CRC32 validation, full decoding/comparison through EOF, checked file/directory synchronization and complete readback. Restoration from the compressed copy and NAR reserialization matched the preserved reference; all eight actual installed-smoke checks passed. Thirteen synthetic retention controls passed separately. Only the private retained-copy gate is closed, not power-loss durability, native GUI or production approval. XZ is private evidence; public packages still require `.zupt`. The frozen build excludes later documentation changes |
| Guix GUI copy-install regression and packaging metadata, 2026-10-10 | LIMITED PASS | Actual recipe copy phase: five installed manpage/license/provenance files match source bytes. Metadata suite: 55 passes, zero failures, two explicit skips (Make and dpkg-parsechangelog); Nix parsing uses a dummy store. No dependency build, launcher/Qt runtime, pinned archive or native GUI package validation |
| Guix GUI relative icon and staged PySide6 workflows, 2026-10-10 | LIMITED PASS | Missing module-relative icon reproduced before the fix; six installed files now match source bytes. Python 3.12.12, PySide6 6.9.2/Qt 6.9.2: exact restored CLI 5.2.10 selected, icon found, six-tab offscreen selftest and 38 selected workflow tests passed in an unprivileged, networkless sandbox. The 32-MiB close/cancel fixture was not run under its 1-MiB file limit. Direct Python execution, not the generated launcher or a native GUI package build; no production approval |
| Guix GUI generated launcher and desktop phases, 2026-10-10 | LIMITED PASS | Actual recipe phases with controlled default-output references: argument boundaries, unset/empty/inherited paths, pinned CLI, complete 48-leaf library prefix, child exit status, executable mode and required desktop fields passed. Eight private mutations were rejected for the expected reasons. Separately, the generated launcher ran the real six-tab PySide6 selftest with the restored CLI 5.2.10 and existing dependencies. Some leaf versions lag the recipe snapshot; no dependency lowering/build, complete native GUI derivation, real desktop activation or production approval |
| Complete staged PySide6 GUI workflows, 2026-10-10 | LIMITED PASS | All 39 unchanged tests passed with zero failures/skips, including closing the window with a live CLI, child cancellation and worker cleanup. Separate RAM-only sandbox: 128-MiB temporary storage, 32-MiB file limit, 135-second outer deadline, CPUs 0/1 and 1-GiB per-process address space. Current GUI with the restored frozen-source CLI and existing PySide6/Qt 6.9.2; direct Python workflows, not a complete native Guix GUI build or production approval |
| GUI completed-job object disposal, 2026-10-10 | LIMITED PASS | Retained Qt objects reproduced with three successful real CLI jobs; the new regression failed before the two-line fix, then passed with exactly one job/thread/worker destruction notification per operation while the window stayed open. All 40 GUI tests passed after updating observations of disposed threads. Same separate RAM-only profile and staged inputs; not an RSS-leak proof, PyQt6 validation, native GUI derivation or production approval |
| GUI close-confirmation lifetime regression, 2026-10-10 | LIMITED PASS | A real CLI job completed during the modal confirmation, reproducing access to a deleted QThread before the fix. Re-enumerating active jobs after confirmation fixes that case; all 41 GUI tests passed twice without failures or skips, including the final test-source revision. Same staged PySide6/Qt 6.9.2 inputs and separate RAM-only profile; not native Guix GUI, PyQt6, real-display or production validation |
| Guix GUI build-time check phase, 2026-10-10 | LIMITED PASS | Added the actual post-install phase: installed launcher version, six-tab selftest and unrestricted 41-test workflows passed twice with staged PySide6/Qt 6.9.2 inputs, including the final recipe revision. Focused Scheme regressions cover default/enabled/disabled checks, exact calls, inherited-path isolation and failures at each child position with environment restoration. The source origin still selects the earlier tag archive; current-source pinning, native dependency-closure/build acceptance and production gates remain pending |
| ANS/ANS4 decoder argument and allocation regressions | PASS | GCC and Clang checks reject NULL/undersized arguments, cover five allocation-failure paths with no leaked storage, and reject an S/T payload that declares literals with an empty literal section before allocating decoder scratch |
| Current strict source-only `check`, 2026-10-13 | PASS WITH SKIPS | GCC 14.3.0 with warning errors, the declared `file` scanner utility, and SDK/PQBOX/Jasmin disabled: all executed checks passed, including rebuilt fuzz harnesses, injected-I/O cases, installed-smoke controls, source audit and known-answer vectors. This is not a final VM, full formal-tool, native-package or release approval. |
| Current bounded VM direct-decoder campaign, 2026-10-13 | PASS, BOUNDED SCOPE | Current scalar decoder in a networkless 2-CPU/2-GiB Guix VM, 30-second continuous run: 6,837,592 executions, 2,535 new corpus units, 486 MiB peak RSS and zero artifacts, with supervisor status 0. This covers the recorded harness and limits only; it is not exhaustive fuzzing, an absence-of-defects claim, or cross-platform package approval. |
| Earlier local release-check, 2026-10-13 | PASS WITH SKIPS; MIXED SOURCE | `make WITH_SDK=0 WITH_PQBOX=0 release-check` returned zero. Functional/formal checks used the working source; reproducible archive, extracted-source build and smoke checks used commit `a2a9080f4118dddda1b37d478025d8eba1e743f3`, excluding later corrections and new tests. This run does not validate the current package source. SDK/PQBOX and platform skips remain recorded. |
| Source-bound release-check before later sequence allocation changes, 2026-10-14 | PASS WITH SKIPS | Private 260-file Git tree `f35b40c9aa3aea97b29971072f5b5e38fff60553`: strict GCC 14.3.0, selected Frama-C/Jasmin gates, new distribution/quick-suite controls and extracted-source checks passed. Repeated internal source archives have SHA-256 `1ec1d900f19da97519384e27ab811bd01c70ace3e136bd75747d48686407d6eb`. Later sequence allocation changes require their own run; native platform/package and signature gates remain pending. |
| Source-bound release-check after sequence allocation changes, 2026-10-14 | PASS WITH SKIPS | Tree `16292cf6802ce02b87d8329e9f7e7b034f6871cc`: full strict GCC 14.3.0 run, selected Frama-C/Jasmin gates, golden encoder-byte parity, runtime regressions and extracted-source build/smoke passed. Repeated internal archive SHA-256 `378998f7f06f3087551d4aac5c4fffe8f78be3422cd64321ad2d671d1ba256c7`. SDK/PQBOX, native target packages and signatures remain outside this result; later documentation edits are excluded. |
| VM campaign before later sequence allocation changes, 2026-10-14 | FAIL: RSS LIMIT | Same 260-file snapshot, Clang 22.1.8, scalar ASan/UBSan/LSan and unchanged VM limits: 1,274,617 executions, 2,131 new units, status 71 at 535 MiB against 512 MiB; target cgroup peak 586,133,504 bytes, no OOM/PID event. The 159-byte artifact SHA-256 is `62376516a0d205dc987e4d1a38c5cc5b639685600c346ccc68ef3895a1adbe20`. The VM's outer exit zero does not override the failed campaign. |
| VM campaign after sequence allocation changes, 2026-10-14 | PASS, BOUNDED SCOPE | Tree `16292cf6802ce02b87d8329e9f7e7b034f6871cc`, Clang 22.1.8 scalar ASan/UBSan/LSan, same seven seeds, seed 1337, 30 seconds, input ≤4 KiB/output ≤64 KiB and unchanged 512-MiB RSS cap: 4,812,958 executions, 2,560 new units, 453 MiB peak RSS, status zero and no artifacts. Target cgroup peak 519,835,648 bytes, no OOM/PID event or surviving descendant. Both campaign and supervisor verdicts passed. Earlier failures remain recorded; this is one bounded campaign, excluding later documentation edits and native package validation. |
| Decoder allocation regressions, 2026-10-14 | PASS, FOCUSED | GCC 14.3.0 and Clang 22.1.8 with nonrecovering UBSan: 2,216 context truncation/alignment cases, malformed single-stream initial states, six invalid-window cases and ten table/empty-stream cases pass. Invalid windows, invalid tables and valid empty sequences need no scratch allocation. These tests do not establish that the cumulative VM RSS failure is resolved. |
| Private level-9 source `.zupt` validation, 2026-10-14 | PASS, LOCAL PACKAGE | Tree `16292cf6802ce02b87d8329e9f7e7b034f6871cc`, 260 files: a genuine unencrypted `.zupt` passed `zupt test`, full extracted-byte comparison, fresh GCC build and CLI functional smoke. Executable modes were restored from the recorded source inventory. SHA-256 `2e7e691f182cd87144e8d82dc2090c98d3c0c4c7e834bd4f3a5e23527633c9c6`; local evidence only, unsigned and unpublished, excluding later documentation edits. |
| Explicit VaptVupt source bundle, 2026-10-14 | PASS, LOCAL PACKAGE | Same 260-file tree, `compress --vv -l 9 -t 2`: archive identifies VaptVupt level 9; test, all extracted bytes, build and functional smoke pass. SHA-256 `4d9d02c128daaea6d0337201a91a79ec9a15b2d52b9c03ba028f704c647ee943`. The earlier default-codec artifact is retained separately. Neither artifact is a signed official release. |
| Current GUI with the extracted CLI and installed PySide6, 2026-10-14 | PASS, HOST SANDBOX | All 41 existing tests pass with Python 3.12.12, PySide6 6.9.2 and Qt 6.9.2, selected current CLI and matching GUI source. Networkless sandbox with read-only source/tools, private temporary storage, no host home, two-CPU affinity, 1-GiB address-space and 64-MiB file limits; normal completion marker required. This is an offscreen workflow check, excluding native GUI package construction and real desktop/display integration. |
| Current PyQt6 VM portable-GUI profile, 2026-10-14 | BLOCKED: DEPENDENCIES | Fourteen pinned Qt/PyQt6-related store roots are unavailable; preflight exits before guest execution. The separately completed PySide6 workflows do not count as a pass for this VM profile or its portable-package checks. |
| Portable GUI `.zupt` helper, 2026-10-14 | PASS, HOST SANDBOX ONLY | Genuine unencrypted VaptVupt level 9, exactly 13 frontend files, source-only scans, byte comparison, extracted launcher version/help/six-tab selftest and 41 offscreen workflows with Python 3.12.12/PySide6 6.9.2/Qt 6.9.2. Two-CPU networkless sandbox, no host home, 1-GiB address-space and 64-MiB file caps. Package-boundary regressions separately reject CLI errors, altered inventories, output collisions and demonstrated publication races. Local test assets are not signed releases; native GUI/package and desktop gates remain open. |
| Linux disk-capacity ioctl regression, 2026-10-14 | PASS, FOCUSED | GCC 14.3.0, Clang 22.1.8 and musl 1.2.6: both libc request ABIs and 16 wrapper controls pass; strict compilation of the actual disk source also passes. Selected Clang checks two modeled bionic-header configurations. No real device is accessed; modeled headers do not validate an Android NDK package, the full suite or a release. Reproduction commands are in the user guides. |
| Core checks after the legacy fixture compiler fix, 2026-10-14 | PASS WITH SKIPS | Source tree `9ec6288ec183a2cab8188c0ffe3ffcdc0812ba43` (267 files): strict GCC 14.3.0 and Clang 22.1.8 `make check` pass, including four new compiler-boundary controls. Clang also passes all 11 portable GUI packaging groups. Optional SDK, native Windows, privileged device and unavailable documentation-tool checks remain explicit skips. |
| Static Linux CLI artifact regressions, 2026-10-14 | PASS WITH SKIPS | The same source produces a musl 1.2.6 static x86_64 CLI: compiled C fixtures, 22 CLI script groups, 22 regression checks, 14 threaded checks and 14 deduplication checks pass. The legacy encrypted/deduplicated 5.2.1 fixture lists, tests, extracts and restores byte-exactly. This profile does not test dynamic `LD_PRELOAD` prompt controls, optional SDK modes or privileged loop devices. |
| Paired local CLI/source `.zupt` bundles, 2026-10-14 | PASS, LOCAL ONLY | Genuine unencrypted VaptVupt level 9: 15 binary-bundle files, including full runtime notices and EN/PT-BR guides, and all 267 source files restore byte-exactly. The verified extracted CLI passes the functional smoke suite. These unsigned local artifacts precede this README update; they are not official downloads or native package approval. |
| Earlier host ASan release gate and VM admission | FAILED / BLOCKED, HISTORICAL | The earlier host `release-check` fails when ASan cannot reserve its shadow under the unchanged 1 GiB address-space limit. Earlier VM admission attempts stop below the unchanged 5 GiB host-memory floor. These failures remain recorded; the later bounded 284-file VM slice above passes without disabling sanitizers or changing limits. Full release acceptance remains incomplete. |
| Installed PySide6/Qt VM image preparation, 2026-10-14 | BLOCKED: IMAGE LIMIT | The selected installed runtime links Mesa/LLVM. XZ-6, XZ-9 and a reduced runtime selection reached the unchanged 128-MiB compressed-image limit, returning status 153 before guest execution. Failed logs are retained. This is an infrastructure failure, not an executed GUI test or release approval. |
| ANS bounds regression and Frama-C 29.0 Eva gate | LIMITED PASS | Eight fixed fixtures; GCC 14.3.0, `gcc_x86_64`: zero alarms, 63/63 valid preconditions, 558/983 statements in 16/95 functions and six exact fixture witnesses. C `assert` checks use Frama-C libc preconditions; native and SIMD runtime checks are separate |
| ANS4 formal-gate diagnostic controls, 2026-10-16 | PASS, LIMITED SCOPE | All 56 controls pass, retaining the previous 47. Eight new complete-profile diagnostics reproduce false passes before the scanner fix; case-insensitive warning/error/failure/timeout detection now rejects them. A positive unsupported-ACSL note remains admissible. Scanner errors 2/127, pruned/conflicting profiles and PASS-marker checks remain enforced. The real metadata gate also passes again: 14/14 preconditions, zero alarms, 121/343 statements. Synthetic controls do not analyze the codec; the real gate covers only its two rejection fixtures. |
| ANS reader reset and zero-extension regressions | PASS | Strict scalar GCC 14.3.0 and Clang 22.1.8, also with UBSan at `-O1 -fno-sanitize-recover=undefined`: 2,312 fixed/mixed-width and alignment configurations covering widths 0..32, poisoned-context reset and 160 reads each, two single-stream consumption fixtures, ANS4 output lengths 1..4096 and untouched output suffixes. Another 520 synthetic exhausted-counter states (`p == l`, NULL source, counts 0..64) pass; these are not giant-buffer tests. Current-source Clang scalar/AVX2 ASan/UBSan/leak follow-up also passes as scoped below. Existing zero extension, API and encoding grammar remain unchanged |
| Current ANS and exact-size codec sanitizer VM, 2026-10-10 | FOCUSED PASS | Frozen 255-file source, Clang 22.1.8, two executions in a diskless/networkless 2-CPU/2-GiB VM. Actual ANS/Huffman source instrumented with ASan/UBSan and leak detection: scalar and AVX2 allocation, reset, exhausted-counter and logarithm regressions pass. Exact-size C tests pass 81/0 plus 1,024 BCJ bijection cases; three labelled sanitizer negative controls are rejected. L5/L9 archive roundtrips separately use the ordinary CLI. Final target peak 235,048,960 bytes within the unchanged 768-MiB/16-task cgroup; no OOM, PID-limit event or surviving descendant in product stages. Not complete CLI/fuzz, formal, native-package or production approval; subsequent documentation edits are outside this VM snapshot |
| Current scalar direct-decoder coverage campaign, 2026-10-12 | FAIL: RSS LIMIT | Frozen 255-file source, Clang 22.1.8, seven validated same-core seeds and three rejected sanitizer controls. After 2,108,708 units, libFuzzer exited 71 at 536 MiB against its unchanged 512-MiB RSS limit; target cgroup peak 582,819,840 bytes, no cgroup OOM event. It emitted one 1,549-byte replay input (SHA-256 `ba965d744bb9479ba620b9bf74e0644ee915c61bd07f97ee471ff2deedfcb8aa`). This does not establish a codec defect; the 30-second campaign is failed and coverage gate remains open. Do not infer a pass from the outer supervisor exit. No release approval |
| Current direct-decoder host diagnostic, 2026-10-13 | LIMITED PASS | Current source, Clang 22.1.8 scalar ASan/UBSan/LSan, seven validated seeds, `max_len=4096`, 65,536-byte output, 30 seconds and the libFuzzer 512-MiB RSS limit: 4,878,375 executions, 2,269 new units, peak RSS 344 MiB and zero artifacts. This host-only run has no VM cgroup/isolation evidence and is not comparable enough to override the earlier isolated-VM RSS-limit failures. It does not clear the fuzz or release gate. |
| Saved-input replay from that campaign, 2026-10-12 | PASS, ONE INPUT ONLY | Rebuilt fuzzer matched the failed campaign's binary SHA-256 and replayed the exact 1,549-byte artifact once under the same ASan/UBSan/LSan and 512-MiB RSS limits. It exited cleanly at 43 MiB with no sanitizer finding. This rules out only an immediate failure on that one input; it does not resolve cumulative campaign memory growth or convert the failed 30-second campaign into a pass. Fuzz gate remains open |
| Repeated campaign with callback scratch reuse, 2026-10-12 | FAIL: RSS LIMIT | Same frozen 255-file codec source, Clang 22.1.8, flags, seed corpus, 30-second duration, sanitizer settings and 512-MiB RSS limit. A private harness variant reused fixed input/output buffers instead of allocating them per callback, but libFuzzer still exited 71 after 1,849,145 inputs at 514 MiB. Its report showed 241,285,420 quarantined bytes; target cgroup peaked at 566,075,392 bytes without an OOM event. A 61-byte OOM artifact was retained (SHA-256 `64f87f69076908aa56d2ff61522957d97f906434d278991a880ff822d956eb87`). The test-harness allocation change did not resolve the resource failure; its cause remains under investigation. Coverage gate remains open |
| Allocator-release diagnostic, 2026-10-12 | FAIL: RSS LIMIT | Same binary and codec inputs, with `allocator_release_to_os_interval_ms=500`; quarantine capacity and sanitizer checks were unchanged. The run reached 544 MiB and exited 71 after 1,303,122 inputs; 267,264,876 bytes remained quarantined. Target cgroup peak was 594,120,704 bytes with no OOM event. The 114-byte artifact (SHA-256 `80ca07be03c5082830ee9d81a2399268a465adf33f6ed145dc71e8059c258673`) and raw log are retained. Returning reusable pages more frequently did not clear the gate; memory growth remains unresolved |
| Segmented direct-decoder coverage profile, 2026-10-12 | PASS, SCOPED | A private libFuzzer adapter called the real `vv_decompress` from the frozen 255-file source using Clang 22.1.8, scalar mode, ASan/UBSan/LSan, `max_len=4096`, seven validated seeds plus a cumulative corpus, the default ASan quarantine and the unchanged 512-MiB per-process RSS cap. Thirty independent 1-second runs (seeds 1338–1367) completed: 15,382,624 executions, 3,058 new corpus units, maximum process RSS 440 MiB, target cgroup peak 472,612,864 bytes, zero artifacts/events/descendants. Each process exit resets ASan quarantine, so this segmented profile is not equivalent to a continuous 30-second run and is not exhaustive coverage. Earlier continuous-run RSS failures remain unresolved; the fuzz and release gates stay open. This private adapter is not the in-tree AFL stdin harness |
| Current instrumented CLI smoke, SDK and ML-KEM VM, 2026-10-10 | FOCUSED PASS | Frozen 255-file source, Clang 22.1.8, diskless/networkless 2-CPU/2-GiB VM. Fresh CLI C objects use ASan/UBSan at `-O1`, leak detection and fatal diagnostics: archive and encrypted/deduplicated synthetic-disk roundtrips, help/version and all eight installed-functional checks pass. Separate ordinary in-tree SDK tests pass 15/0; ordinary ML-KEM/OpenSSL 3.5.7 interoperability passes 3/0. Instrumented-CLI target peak 146,800,640 bytes; all five product stages exit zero with no resource events or surviving descendants. The initial missing-OpenSSL execution remains blocked; a private profile-only dependency fix passes within the unchanged 128-MiB image cap. Not full `test-all`, fuzz, formal proof, package installation or production approval; subsequent documentation edits are excluded |
| ANS reader initialization/extraction WP gate | CONDITIONAL PASS | Frama-C 29.0/recognized Z3 4.12.2, `gcc_x86_64`: 30/30 exact non-smoke JSON obligations (12 initialization, 18 extraction), console 34/34 including termination/unreachable results; 40 synthetic result controls. Proves reset, extraction, count saturation, frame and selected runtime-error conditions under explicit context/width/count assumptions; not refill, caller or complete decoder correctness |
| Frama-C ANS range/metadata gates, 2026-10-16 | LIMITED PASS | Real Eva analyses with pinned Frama-C 29.0 and GCC 14.3.0 x86_64: logarithm 2/2 assertions, 2/2 preconditions, 15/15 statements; malformed-metadata fixtures 14/14 preconditions, 121/343 statements. Both report zero warnings/alarms and pass their existing exact-result gates; the metadata log retains an unsupported ACSL `memset` note. The 60 logarithm supervisor controls also pass. This is not a valid-stream decoder, caller/refill or whole-program proof. |
| ANS logarithm supervisor diagnostics, 2026-10-16 | PASS, SUPERVISOR ONLY | All 60 synthetic result controls pass, including uppercase/mixed-case diagnostics that previously escaped rejection. Clean reports, incomplete profiles and tool/scanner/parser failures retain their criteria. This does not rerun Frama-C or establish C correctness. |
| ANS logarithm range gate and native boundaries, 2026-10-10 | LIMITED PASS | Actual unchanged scalar helper, Frama-C 29.0/GCC 14.3.0, `gcc_x86_64`: every admitted uint32 input and separately every frequency 0..4096; 2/2 range assertions, 2/2 interval preconditions, zero warnings/alarms, 15/15 reached statements in 2/75 functions. Strict GCC/Clang UBSan passes 4,195 native boundary checks; a private zero-result mutation fails them. All 57 synthetic gate controls pass. Not exact-log functional proof, caller bounds, table equivalence or complete decoder proof |
| Full native `make check` with logarithm controls, before CLI seed reuse, 2026-10-10 | MIXED | Strict Clang 22.1.8 passes with explicit skips; two GCC 14.3.0 executions reach the unchanged 125-second deadline during source-scanner tests (124), not full-suite passes. The scanner's 40 adversarial checks pass separately, and that selected 254-file source tree has zero archives. SDK/PQBOX/Jasmin disabled. No final-package or production approval |
| Full native `make check` with CLI seed reuse, 2026-10-10 | PASS WITH SKIPS | Strict GCC 14.3.0 passes twice (124.44/123.31 seconds); Clang 22.1.8 passes in 86.52 seconds. Original 125-second deadline, two-CPU affinity and 1-GiB per-process address space retained. GCC has little margin; these samples do not establish reliable deadline headroom. Ten new shell-only controls pass after reproducing the old override failure; actual UBSan and non-LTO I/O/archive regressions remain intact. SDK/PQBOX/Jasmin disabled; earlier deadline failures and skips remain recorded. No VM ASan/leak, final-package or production approval |
| Expanded ANS4 valid-stream Eva experiment, private fixture | BLOCKED | A synthetic 4096-byte round trip passed native ASan/UBSan/leak checks. Eva reached the table and four-lane decoder but reported 15 alarms and five unknown preconditions; the higher-precision run timed out at 120 seconds. Unresolved analysis results, not confirmed runtime bugs or production approval |
| Fresh ANS4 valid-stream Eva diagnostic, 2026-10-10 | BLOCKED | Fresh pinned Frama-C 29.0 and unchanged private synthetic fixture: the original 16/512 profile again reports 15 alarms and five unknown preconditions. Varying only plevel to 4096 without global loop unrolling fails at the smaller diagnostic profile's 1-MiB log limit (status 153), before a final summary. Captured log bytes/hashes verified; no code, oracle or malloc-model change, alarm suppression, completed high-precision analysis or production approval |
| ANS4 valid-stream Eva precision profile before the refill guard, 2026-10-10 | BLOCKED | Same private 4096-byte fixture, slevel 16/plevel 512, local 256-symbol unrolling and gauges scoped to the four-lane decoder: 349/496 statements, zero memory alarms, 38 valid and 13 unknown preconditions. Earlier three-alarm and table-timeout results remain recorded. Executable C was unchanged in this annotation-only comparison; oracle and nullable malloc model are unchanged; unresolved extraction callers and fixture assertions prevent a complete proof or production approval |
| ANS refill diagnostics after the bounds correction, 2026-10-10 | BLOCKED | Same valid-stream Eva profile: zero memory alarms, 37 valid/14 unknown of 51 preconditions, 349/496 statements. Separate synthetic exhausted-counter entry: one sure memory alarm, nine valid/one invalid precondition after merging locations; scoped entry-slevel 20000 trial times out at 25 seconds (124). Manual invariant reasoning does not discharge these results. No generic refill proof or production approval |
| Full native `make check` after the reader refactor, before the refill guard, 2026-10-10 | PASS WITH SKIPS | Strict GCC 14.3.0 and Clang 22.1.8, SDK/PQBOX/Jasmin disabled, two-CPU affinity and isolated RAM-only builds. Missing `libgcc_s.so.1` initially failed Clang; a scoped runtime path fixed the environment. Two GCC deadline failures remain recorded before the successful isolated repeat. This is not VM ASan/leak coverage, SDK/assembly validation, final-package acceptance or release approval |
| Full native `make check` after the refill guard, 2026-10-10 | PASS WITH SKIPS | Current refill source and 520-counter regression, strict GCC 14.3.0/Clang 22.1.8, SDK/PQBOX/Jasmin disabled. Both parallel attempts timed out at 125 seconds (124); sequential repeats pass under the unchanged two-CPU, RAM-only and per-process limits. Raw logs retain failures and platform/provider/tool skips. No current-source VM ASan/leak, SDK/assembly, final-package or production approval |
| Portable AES known-answer regression | PASS | Frozen 248-file source, GCC 14 and Clang 22 with non-recovering UBSan: four fixed NIST F.1.5 blocks, 64 byte assertions, active despite caller `-DNDEBUG`; direct assertion-disabled builds are rejected |
| Historical portable AES, Frama-C 29.0 Eva gate | LIMITED PASS | Earlier frozen 248-file source, GCC 14.3.0, `gcc_x86_64`: 0 alarms, 4/4 loop properties and 7/7 preconditions valid, 64 reached `__FC_assert` calls, main returns 0; 160/160 statements in 5 analyzed functions out of 27. Fixed key/vectors only, not arbitrary-input AES equivalence |
| Portable AES with internal initialization assertions, earlier Eva snapshot, 2026-10-07 | LIMITED PASS | Same fixed NIST fixture, before helper annotations: 0 warnings/alarms, 6/6 properties and 7/7 preconditions valid, 64 reached byte-oracle calls and returning main; 162/162 statements in 5/27 functions. Missing-plugin runs were rejected and retained before completing the tool closure; not arbitrary-input AES equivalence |
| Portable AES with helper contracts, earlier Eva snapshot, 2026-10-07 | LIMITED PASS | Before block-loop annotations, same fixed NIST fixture: 0 warnings/alarms, 7/7 properties and 7/7 preconditions valid, 64 reached byte-oracle calls, returning main and 162/162 statements in 5/27 functions. The old six-property gate rejected the new result before its reviewed schema update; not arbitrary-input AES equivalence |
| Portable AES with block-loop contracts, Eva, 2026-10-07 | LIMITED PASS | Current source, Frama-C 29.0/GCC 14.3.0: 0 warnings/alarms, 21/21 properties and 7/7 preconditions valid, 64 reached byte-oracle calls, main returns 0 and 162/162 statements in 5/27 functions. Missing-tool/plugin runs were rejected and retained before completing the isolated runtime. Fixed key/vectors only, not arbitrary-input AES equivalence |
| AES formal-gate diagnostic controls | PASS | 28 synthetic cases retain all previous 27 and reject the old seven-property summary, alongside four/six-property and 160-statement rejection. Diagnostics, tools, status, bodies, byte counts and pruned main remain checked. Historical 24/26/27-case runs are separate; mocked supervisor checks arguments but enforces no deadline and does not analyze AES |
| Jasmin warning-scan diagnostic controls | PASS | Four synthetic cases preserve warning/no-warning behavior and reject scanner errors 2/127 before downstream work; no actual Jasmin analysis |
| Frama-C bounded Eva harness, earlier snapshot | PASS | Concrete malformed frame produced 0 alarms, with 6/6 preconditions proven over 5 functions; bounded slice only |
| Broader Frama-C Eva run with a bounded 64-byte input | BLOCKED | 33 alarms, no sure alarms after guards; unresolved analysis results do not establish confirmed runtime faults |
| Earlier default-entry Frama-C Eva run | INCONCLUSIVE | 10 alarms from an underconstrained pointer context; not confirmed runtime bugs |
| Historical Frama-C WP/Qed cryptographic subset | PARTIAL | 285/653 goals discharged (251 Qed, 12 termination, 22 unreachable); 368 unknown; warning-rich diagnostic run, not a complete proof |
| Historical Frama-C WP cryptographic subset with Z3 4.13.0 | PARTIAL | 346/653 discharged (251 Qed, 61 Z3, 12 termination, 22 unreachable); 305 timeouts and 2 unknown; cached Why3 did not recognize this Z3 version, so this is diagnostic evidence, not an accepted proof gate |
| Historical AES key-schedule initialization, Frama-C 29.0 WP/Qed | PARTIAL | Annotation-only loop contracts improve 16/39 to 39/58 discharged (37 Qed, 1 termination, 1 unreachable); 19 unknown and Typed-model separation hypotheses remain; strict proof gate fails |
| AES key-schedule initialization, WP/Qed/Z3, 2026-10-07 | LIMITED PASS | Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 and supported Z3 4.12.2: 60/60 console obligations and 58/58 exact JSON goals valid, retaining all 56 baseline IDs plus two proved internal assertions. No unknowns, timeouts or failures; public preconditions unchanged. Selected bounds, frame, initialization and termination contracts only, not functional AES/FIPS equivalence or whole-program security |
| AES arithmetic helpers `xtime`/`gmul`, WP/Qed/Z3, 2026-10-07 | LIMITED PASS | Same pinned tools and budgets: 19/19 console and 17/17 exact JSON obligations valid, including function/loop frames, invariant establishment/preservation and both variant checks. Six added ACSL lines change no executable C or public precondition; the original termination timeout remains recorded. Initialization WP was rechecked separately on the same AES source. Not functional GF multiplication or AES equivalence |
| Portable AES block loops, WP/Qed/Z3, 2026-10-07 | LIMITED PASS | 35 added ACSL lines: all 214 exact JSON goals valid, including 28 invariant and 14 variant obligations, output initialization and termination. Baseline 113/144 with 31 timeouts remains recorded. Freshly pinned installed Frama-C 29.0/Why3 1.7.2 with recognized Z3 4.12.2, unchanged model/budgets; init 58/58 and helpers 17/17 rechecked separately. Preprocessed C is identical; no public-contract change. Selected bounds/frame/initialization/termination, not functional AES, constant-time behavior or whole-program proof |
| Original Jasmin source baseline, before correction | FAIL | Four exported contracts were missing; regenerated AES read the wrong key offset and stored only eight output bytes |
| Historical unparameterized AES4 safety analysis | BLOCKED | 120-second analysis limit reached; the later pointer/count-parameterized result is separate, not a reclassification of this run |
| Corrected Jasmin 2026.09.0 compilation and safety analysis | LIMITED PASS | Five sources compile without warnings; AES4 declares pointer/count roles and loop termination; safety reports no violation under caller allocation and alias conditions |
| Corrected Jasmin CT/DOIT and instruction-lowering checks | LIMITED PASS | Explicit contracts pass on all five sources, including AES4; not verification of every C caller or of complete FIPS equivalence |
| Jasmin tool-runtime availability before restoration, 2026-10-07 | BLOCKED | The exact recorded PPL 1.2 library dependency was absent; the original failure and earlier tool profiles remain recorded |
| Fresh five-source Jasmin gate after runtime restoration, 2026-10-07 | LIMITED PASS | Authenticated official Guix PPL 1.2 subset, restored privately without store/profile changes. GCC 14.3.0 and Clang 22.1.8 each pass the actual Make target: five safety/CT/DOIT/lowering checks, matching generated/runtime instructions, 1,026 AES blocks and 1,539 CTR cases, plus four supervisor controls. Networkless read-only source/tool mounts, 1 GiB address space, CPUs 0/1 and unchanged 120-second limits. Caller preconditions apply; final packaged binaries are not checked |
| Generated Jasmin AES block regression | PASS | Frozen 248-file source, GCC 14 and Clang 22 host gates: two NIST vectors and 1,024 synthetic OpenSSL differential blocks, in-place/misaligned; fifteen emitted stack-wipe stores checked |
| Generated Jasmin AES4 regression | PASS | Frozen 248-file source, GCC 14 and Clang 22 host gates: 1,539 NIST/OpenSSL, separate/in-place, misaligned, split-call, counter-wrap and zero-count cases per compiler; sixteen emitted stack-wipe stores checked; no throughput claim |
| Current C/assembly cryptographic callers with non-recovering UBSan | PASS | GCC 14 and Clang 22, each with `WITH_JASMIN=0` and `1`: 16 vectors and 2,000 F-06 round trips per profile, zero accepted altered MACs; format unchanged |
| Cryptographic-test AES dispatch coverage | PASS | Tests initialize real CPU detection; GCC 14/Clang 22 UBSan runs and private call instrumentation confirm C, AES block, AES4 and disabled-feature fallback paths. Instrumentation is coverage only; caller correctness is not proved |
| Jasmin source/runtime assembly consistency | PASS | Frozen 248-file source, GCC 14 and Clang 22: all five generated/runtime objects export the exact global function at `.text` start, contain no relocations and have matching `.text`; historical mismatch retained as a failing control |
| Native Windows/macOS/musl, final packages, signatures and release promotion | NOT RUN/BLOCKED | These gates must pass against the exact reviewed commit before publication |

The focused Eva and five-source Jasmin gates pass in their recorded environments.
The missing Jasmin runtime dependency was authenticated and restored privately;
both compiler profiles now have fresh five-source results. Historical failures
remain separate, and this focused result does not approve final packages.
Broader Frama-C/WP and final distribution gates remain incomplete. These
results do not establish full cryptographic functional equivalence, an
independent audit or production readiness.

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
certification and not 5.2.8 results. Post-tag CI integration failures prevented
5.2.2 promotion. The immutable 5.2.3 candidate was also not promoted because its
source-policy test assumed LF for a `.bat` checkout that correctly used CRLF.
The immutable v5.2.4 candidate then recorded 12 successful jobs in exact-tag CI
run `33431386002`; the sole openSUSE service-harness job failed because the
standalone executor did not enter its service directory, so dependent Windows
and macOS jobs were skipped. A local Tumbleweed reproduction proved the explicit
tag ref and corrected working-directory contract, but neither that reproduction
nor the successful v5.2.4 jobs are v5.2.8 evidence. The immutable v5.2.5
candidate was not promoted after exact-tag GitHub Actions run `33434986357`:
13 jobs succeeded, but the native Windows hostile-path fixture and macOS
build/check gate failed. Their 5.2.6 corrections were followed by exact-tag run
`33442264243`, which also completed 13 jobs successfully but failed native
macOS on arm64-unused SHA-NI helper declarations under `-Werror` and native
Windows during safe UTF-8 fixture argv transcoding. The immutable v5.2.6 tag was
not promoted. The immutable v5.2.7 tag was also not promoted: exact-tag run
`33445470664` reached the macOS raw-C1 filename-creation failure with `EILSEQ`,
recorded 13 successful jobs, and cancelled Windows after the hosted job stalled
in `make check`; a MinGW/Wine reproduction isolated the stall to
`test --password-prompt ... </dev/null` entering `_getch`. The
exact 5.2.8 candidate then repeated all required gates: exact-tag run
`33456209269` completed 15/15 jobs successfully, including native Windows and
macOS, the pinned local OBS service chain, source/package gates, and the
openSUSE RPM checks. Promotion run `33457868306` published the exact tested
asset allowlist. Unexecuted environments remain `SKIP`, never `PASS`; these
project-run results are not independent certification.

On Windows, 5.2.10 scopes output handling to normal local Win32 paths. A MinGW
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
a newly created 5.2.10 archive. Compression and disk backup never create a
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

The build/audit commands and recorded 5.2.8 outcomes are maintained in the
release evidence and
[packaging/opensuse/README.md](packaging/opensuse/README.md). No architecture or
distribution is claimed merely because the code has a fallback path.

## Source archive

The earlier `v5.2.10` tag and release were withdrawn. Do not use stale
AUR, Homebrew or Guix recipe pins as an official installation source. Those
recipes and hashes must be finalized against the validated official source
before publication. Historical package or profile checks do not validate that
future release. The commands below describe its planned archive verification.

Publish new source releases as unencrypted `.zupt` archives. The release
procedure exports the exact tagged tree into a private staging directory,
audits that tree, and uses the built Zupt CLI to compress it. Test and extract
each archive and compare the complete extracted tree before publishing it:

~~~sh
zupt test zupt-5.2.10-source.zupt
zupt extract -o source-check zupt-5.2.10-source.zupt
sha256sum zupt-5.2.10-source.zupt
cd source-check/zupt-5.2.10-source
chmod u+x scripts/check-source-only.sh
bash scripts/check-source-only.sh --tree .
~~~

Zupt assigns archive identifiers and creation times, so verification compares
payload content rather than promising byte-identical `.zupt` output.
`SHA256SUMS` identifies the actual published files and its detached signature
authenticates that manifest. `make dist` retains its reproducible tarball for
internal RPM/OBS and distribution build inputs; that tarball is not a public
release asset. AUR, Homebrew and Guix recipe hashes refer to their declared
source input and require independent validation when that input changes.

## openSUSE and OBS

ZUPT is available for openSUSE through the community OBS project
[`home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators).
Use the [openSUSE package page](https://software.opensuse.org/package/zupt)
to choose your distribution, or browse the verified download repositories for
[Leap 16.0](https://download.opensuse.org/repositories/home:/cabelo:/innovators/16.0/)
and [Tumbleweed](https://download.opensuse.org/repositories/home:/cabelo:/innovators/openSUSE_Tumbleweed/).
Select the matching OS release and architecture; inspect the repository and its
signing key before enabling it. These are community packages, not a claim of
Factory acceptance or inclusion in the default distribution repositories.

As checked on 2026-09-30, both x86_64 repositories offer ZUPT **5.2.9**.
That downstream version is separate from the **5.2.10 development source**;
do not assume that it includes the development codec update.

After enabling the matching repository on a non-transactional openSUSE system:

~~~sh
sudo zypper refresh
sudo zypper install zupt
~~~

To update an already installed package from your configured repositories:

~~~sh
sudo zypper refresh
sudo zypper update zupt
zupt --version
~~~

Review the proposed transaction; do not disable signature checks or force a
vendor change. These commands do not perform a Tumbleweed distribution upgrade.
See the [openSUSE Zypper guide](https://doc.opensuse.org/documentation/tumbleweed/zypper/)
for repository management and system-update guidance.

The upstream recipe is in packaging/opensuse. It currently names v5.2.10,
whose public tag was withdrawn; it is not an official installation recipe until
its source pin and checks are finalized. Its intended profile disables
submodules and Git LFS, builds with WITH_SDK=0 WITH_PQBOX=0, runs real checks,
and installs without the renamed-era `vaptvupt` alias.

This repository does not claim that the package has been submitted to or
accepted by openSUSE Factory. The packaging README distinguishes local parsing,
container/RPM builds, OBS operations and architectures that were not executed.

## Bundled codec provenance

The bundled compression codec is source from VaptVupt tag `v2.65.13` at commit
`e30dc9329be7cf9f233b1ac0b1fc9ed31f530391`. The repository preserves local
wrapper, safety, platform, and provenance adjustments; details are in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

The package declares `bundled(vaptvupt-codec) = 2.65.13`. It does not claim that
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
target-native audit of every historical GUI format. The 5.2.10 artifact promise
is limited to the gated GUI DEB, noarch/source RPM, and portable `.zupt` frontend
listed above; AppImage, AppDir, Flatpak bundles, and platform GUI installers
remain excluded.

## Maintainers and openSUSE credit

Cristian Cezar Moisés is the creator and current upstream maintainer of ZUPT and
the author of the current upstream source, build, test, documentation, and
packaging changes, including the 5.2.2 baseline and corrective
5.2.3/5.2.4/5.2.5/5.2.6/5.2.7/5.2.8/5.2.10 work.

Thank you to Alessandro de Oliveira Faria
([Cabelo](https://build.opensuse.org/users/cabelo)) for helping maintain the
community openSUSE package. He is credited as the openSUSE collaborator
and downstream package maintainer. He reviews the handoff, commits it in the
OBS project he maintains, and may make the additional openSUSE-side adjustments
he considers necessary. That downstream role is not attribution of ZUPT source
authorship or of the upstream 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, or
5.2.8 or 5.2.10 changes.

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
