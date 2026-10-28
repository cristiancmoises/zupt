# Distributing ZUPT

This document describes the packaging material maintained in the ZUPT
source repository. A recipe in `packaging/` is not evidence that a package has
been accepted by a distribution or that every target platform has been tested.
Record each build and test result separately; an unexecuted target is a skip.

The published official version is
[5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
Its existing artifacts and formats remain unchanged. Version 5.2.10 is being
validated; the withdrawn delivery and its old source/package pins must not
be treated as the final version. New bundles must use genuine level-9 `.zupt`
containers; native DEB/RPM/SRPM keep their package formats. Record the final
signed runtime tag and actual build commit separately for every artifact.

The canonical repository is:

```text
https://github.com/cristiancmoises/zupt
```

GitHub is the canonical source and release host. Packaging must never fetch
`zupt-web` or substitute an asset from another project.

## Historical validation (not 5.2.10 evidence)

The `v5.2.2`, `v5.2.3`, `v5.2.4`, `v5.2.5`, `v5.2.6`, and `v5.2.7` tags are
immutable non-promoted candidates.
The v5.2.3 source-policy test assumed LF for a Windows `.bat` file that Git
correctly checks out as CRLF. Exact-tag GitHub Actions run `33431386002` then
recorded 12 successful v5.2.4 jobs, one openSUSE service-harness failure caused
by its working directory, and skipped dependent Windows/macOS jobs. A local
Tumbleweed reproduction confirmed that `refs/tags/v5.2.4` is valid and that
entering the service directory completes the source-service chain. Corrective
working-directory integration was carried by v5.2.5, whose exact-tag GitHub
Actions run `33434986357` completed 13 jobs successfully but failed the native
Windows and macOS jobs. Its v5.2.6 corrections reached exact-tag run
`33442264243`, where 13 jobs succeeded but macOS arm64 failed on unused x86
SHA-NI test-helper declarations under `-Werror`, and Windows aborted during safe
UTF-8 fixture argv transcoding. Version 5.2.7 corrected those failures, but
exact-tag run `33445470664` ended with 13 successful jobs, a macOS raw-C1
fixture failure with `EILSEQ`, and a cancelled Windows job after the hosted job
stalled in `make check`; a MinGW/Wine reproduction isolated a non-console
password-prompt hang in `_getch`. Manual 5.2.8 pre-tag run `33452602634`
subsequently passed 14 of 15 jobs, including native macOS and the complete
Windows distribution checks, before an old MSYS `grep` non-BMP pattern failed
in the later smoke. ZUPT's redirected listing was byte-correct; the corrected
gate uses byte-exact, locale-independent checks and requires extraction plus a
full tree diff. The failed run is diagnostic evidence only.
Exact-tag run `33456209269` subsequently passed all 15 jobs at
`ebb9ab3aa1d42c50030ca02883f6162dc4771fe1`, including the pinned local OBS
source-service chain, native
Windows/macOS, and every package gate. Promotion run `33457868306` published
the exact tested 13-file set; the source archive SHA-256 is
`378b9506211545b9594cf0d38ac8955d9b1cac34eb6b379ae0ec26b84edb65f7`.
Corrective packages and release assets use `v5.2.8`; never move or
overwrite an earlier tag or checksum, and never transfer prior evidence
automatically. Version 5.2.8 corrects those native test boundaries, hardens
three path-race boundaries, and adds the SDK regression to release/hosted Linux
gates. The archive format, cryptography, codec, and SDK ABI remain unchanged.

Version 5.2.9 updates the bundled codec to 2.65.11 and adds Brazilian
Portuguese documentation. Distribute it only when its annotated tag, complete
hosted/native matrix, reproducible source digest, and artifact promotion record
exist. No 5.2.8 result transfers automatically.

## Source-only boundary

Git, the public source `.zupt` bundle, and internal/forge source archives contain source code,
textual assembly, documentation, packaging metadata, and necessary data files.
They do not contain compiled objects or executables, shared or static libraries,
or DEB/RPM/AppImage packages.

The default build is deliberately independent of the optional SDK and PQBOX
libraries:

```sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)" \
  WITH_SDK=0 WITH_PQBOX=0
make WITH_SDK=0 WITH_PQBOX=0 check
```

`WITH_SDK=1` and `WITH_PQBOX=1` use separately installed system development
libraries. They never load a library committed under `vendor/`, never download
a dependency during build or test, and fail explicitly when their development
metadata is unavailable. Distribution builds should keep both options at `0`
unless the corresponding source-built system packages are declared as build
requirements.

Audit the current tree or a generated archive with:

```sh
scripts/check-source-only.sh
# Internal RPM/OBS or forge-generated source input, not a public upload:
scripts/check-source-only.sh --archive /path/to/zupt-5.2.10.tar.gz
```

The scanner reports paths, not file contents, and exits nonzero on a violation.

## Source bundle and reproducible build inputs

The final `zupt-5.2.10-source.zupt` must export every regular Git blob of the
final signed runtime tag, including recipes omitted by `git archive` through
`export-ignore`.
It uses unencrypted VaptVupt level 9, passes `zupt test`, and is compared after
extraction against all tagged source bytes. Archive IDs/times can differ, so
content comparison, not byte-identical `.zupt` output, is the contract.
The archive format does not preserve executable modes: restore execute
permission only for selected verified scripts before running source helpers.

`make dist` verifies committed `HEAD` and exports its tree object, normalizes
member order, timestamps, owner/group metadata, and gzip metadata, and audits
the result before moving it to its destination. Exporting the tree rather than
the commit omits Git's commit-ID PAX header:

```sh
make DIST_TARBALL=/tmp/zupt-5.2.10.tar.gz dist
sha256sum /tmp/zupt-5.2.10.tar.gz
```

The canonical release uses the tracked `.source-date-epoch`; an explicit
`SOURCE_DATE_EPOCH` override intentionally creates a different archive. With
identical committed input and epoch, repeated exports must have the same
SHA-256 digest. `make dist` requires a clean committed tree, including new
source and test files; staged, unstaged, deleted or untracked files make it fail
before replacing an existing output. Ignored build outputs are excluded from
the archive and remain subject to the source-content audit. This prevents a
successful build of current files from being paired with an older `HEAD`
archive. Run `make test-dist-source-state` for the eight source-state controls.

This reproducible tarball remains an internal RPM/OBS build input, not a new
public `.tar.gz` upload. AUR, Homebrew and Guix instead pin their declared
forge-generated archive for C; do not substitute the make-dist digest.
The three recipes are marked `export-ignore`, avoiding checksum cycles in
those archive inputs, but remain present in Git and the full public source
`.zupt`. Do not commit generated archives or checksum files. Platform-generated
tag archives and tarballs inside standard SRPMs are not manual release uploads.

## Staged installation

Packagers should preserve distribution flags and install into a package root:

```sh
make -j"${JOBS:-1}" WITH_SDK=0 WITH_PQBOX=0 \
  CPPFLAGS="$CPPFLAGS" CFLAGS="$CFLAGS" \
  LDFLAGS="$LDFLAGS" LDLIBS="$LDLIBS"
make WITH_SDK=0 WITH_PQBOX=0 check
make DESTDIR="$pkgroot" PREFIX=/usr \
  WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 install
```

`INSTALL_LEGACY_ALIAS=0` installs only `zupt`. The `vaptvupt`
command can be requested explicitly with `INSTALL_LEGACY_ALIAS=1`, but it is
not installed by default and is not part of the openSUSE main package. This
keeps the canonical package surface limited to ZUPT and `zupt`.

The Makefile accepts the usual `BINDIR`, `LIBDIR`, `INCLUDEDIR`, `MANDIR`, and
completion-directory overrides. It does not strip package builds or add a
private-library RPATH.

## Packaging material

| Target | Maintained path | Intended output |
|---|---|---|
| openSUSE / OBS | `packaging/opensuse/` | source and binary RPM through OBS |
| Debian / Ubuntu | `packaging/debian/`, `packaging/build-deb.sh` | Debian metadata and binary DEB after the target gate |
| RPM release artifact | `packaging/opensuse/zupt.spec`, `packaging/build-rpm.sh` | source and binary RPM after the target gate |
| GUI DEB | `packaging/build-gui-deb.sh` | `zupt-gui_5.2.10_all.deb` after payload/dependency and installed integration gates |
| GUI RPM | `packaging/build-gui-rpm.sh` | `zupt-gui-5.2.10-1.noarch.rpm` and matching `.src.rpm` after package and installed integration gates |
| Linux CLI archive | validated CLI and complete runtime notices | `zupt-5.2.10-linux-x86_64.zupt`; tar.xz CI intermediates are not public uploads |
| Portable GUI source | `packaging/portable/`, `.github/workflows/ci.yml` | `zupt-gui-5.2.10-portable.zupt`; ZIP is an internal CI artifact |
| Fedora / RPM-based systems | `packaging/rpm/zupt.spec` | downstream RPM starting point |
| AppImage helper | `packaging/build-appimage.sh` | downstream-only helper; no 5.2.10 AppImage is promoted |
| Windows | `.github/workflows/cross-platform.yml` | tested ZIP payload rewrapped as `zupt-5.2.10-windows-x86_64.zupt` |
| macOS | `packaging/build-dmg.sh` | native arm64 DMG inside `zupt-5.2.10-macos-arm64.zupt`, not universal |
| Arch Linux | `packaging/aur/PKGBUILD` | AUR package recipe |
| Homebrew | `packaging/homebrew/zupt.rb` | formula-built package |
| Guix | `packaging/guix/zupt.scm` | Guix package definition |
| Nix | `packaging/nix/flake.nix` | flake-built package |

These files are upstream starting points. Use each distribution's isolated
builder and current policy checks; do not claim support based only on parsing a
recipe.

### openSUSE / OBS

The authoritative instructions, tested matrix, and outstanding gates are in
`packaging/opensuse/README.md`. The normal local flow is:

```sh
cd packaging/opensuse
xmllint --noout _service
osc service manualrun
rpmspec -P zupt.spec >/dev/null
osc build openSUSE_Tumbleweed x86_64 zupt.spec
```

Run `rpmlint` on all produced RPMs and install the binary RPM in a disposable
environment for `--version`, `--help`, and archive round-trip tests. Presence of
the OBS files upstream does not mean the package has been submitted or accepted
by openSUSE Factory.

### Debian and RPM release artifacts

The release helper scripts build from this source tree, stage into temporary
directories, run their format and installed-binary checks, and place only their
final outputs in an explicitly selected directory. Run them from an exact
checkout of the immutable tag inside a clean target container, chroot, or VM:

```sh
release_dir=$(mktemp -d)

# Native Debian/Ubuntu binary package
DIST_DIR="$release_dir" RUN_CHECKS=1 packaging/build-deb.sh

# Source and binary RPM using the openSUSE spec
DIST_DIR="$release_dir" packaging/build-rpm.sh

# Architecture-independent GUI DEB and noarch/source GUI RPM
DIST_DIR="$release_dir" packaging/build-gui-deb.sh
DIST_DIR="$release_dir" packaging/build-gui-rpm.sh
```

`packaging/build-deb.sh` creates a native binary DEB; it does not claim to
create a Debian source package. The files in `packaging/debian/` are Debian
source-package metadata and must be staged as the source package's top-level
`debian/` directory before using `dpkg-buildpackage`. Running
`dpkg-buildpackage` directly at the ZUPT repository root is not the
documented release-artifact path.

`packaging/build-rpm.sh` creates its audited Source0 archive, builds both the
binary RPM and source RPM, inspects the installed payload, and copies both
outputs to `DIST_DIR`. The separate `packaging/rpm/zupt.spec` is a
Fedora-family downstream starting point; build and lint it only after staging
Source0 in a normal RPM build tree.

Run the target's metadata and lint tools in addition to the script gates. A
package built for one distribution release or architecture is not evidence for
another.

The GUI helpers package Python/Qt source rather than compiled application code.
They check package contents and metadata, extract the payload, and compile the
Python source for syntax. They do not install the package or run Qt. The separate
native CI jobs install the GUI and matching `zupt` CLI, run the off-screen
workflow tests, and remove both packages. Both stages must pass on the target
distribution; a successful GUI DEB gate does not imply an RPM gate, or vice versa.

### Portable and native release artifacts

The planned public Linux x86_64 `.zupt` must bundle a tested static-musl `zupt`
CLI with complete application/codec/runtime licenses and notices. This is an
acceptance requirement, not an artifact already approved for publication.
The current Linux CI job builds a dynamically linked glibc CLI; that result
does not satisfy the static-musl requirement. A pinned local Guix musl 1.2.6
toolchain is now available with GCC 14.3.0. Final-source binary validation,
runtime-license inventory and native package acceptance remain release gates.
Inspect the link map and ELF dependencies: a compiler name or static ELF alone
does not establish which libc and startup objects were used. Bundled runtime
notices must retain the complete musl copyright file, applicable source-specific
notices and the GCC runtime license/exception for incorporated startup objects.
The extracted CLI must pass
version, help and round-trip checks. `.zupt` stores file contents,
not execute modes: after verifying the inventory and extracting, apply
`chmod u+x` only to the selected `zupt` executable before running it.

The `zupt-gui-5.2.10-portable.zupt` bundle is frontend source: it contains the GUI
Python source, shell/macOS/Windows launchers, icons, provenance, changelog, and
licenses, but no Python, Qt, CLI, or compiled runtime. The gate scans both the
assembled and extracted trees, verifies an exact safe member allowlist, and
runs the extracted launcher off-screen against the tested CLI.
Invoke a verified shell launcher through `bash zupt-gui.sh`; do not assume
extraction preserved its executable bit. This is not a self-contained binary.

The portable gate is implemented by `packaging/build-portable-gui.sh`, with
`make test-portable-gui` regression controls and the `gui-portable` CI job.
Select a tested matching CLI through `ZUPT_BIN` and a fresh `DIST_DIR` when
running the helper. It emits the verified `.zupt`, a SHA-256 sidecar and an
extracted tree for the real Qt workflow suite. It neither signs nor publishes
a release. See the English and PT-BR user guides for reproduction commands.

AppImage creation is deliberately offline and is not a 5.2.10 release gate.
Supply a locally verified `appimagetool`, type-2 runtime, and the complete
license/source-relink compliance notice for those exact runtime bytes; the
helper never downloads any input:

```sh
DIST_DIR="$release_dir" RUN_CHECKS=1 \
APPIMAGETOOL=/verified/path/appimagetool \
APPIMAGE_RUNTIME_FILE=/verified/path/runtime-x86_64 \
APPIMAGE_RUNTIME_COMPLIANCE_FILE=/verified/path/runtime-compliance.txt \
  packaging/build-appimage.sh
```

The runtime inspected while preparing 5.2.2 omitted a linked component from
its notice and did not provide the complete LGPL source/relink handoff required
by this release policy. No AppImage produced by this helper is promoted by the
upstream 5.2.10 delivery. AppDir and Flatpak bundles and GUI platform installers
are also excluded. Bare Linux and Windows executables are not promoted; their
CLI programs appear only inside notice-bearing archives. The Windows ZIP and
macOS DMG remain CLI-only.

Run `packaging/build-dmg.sh` only on a native macOS host. It records the host
architecture in the filename and tests the binary before and after packaging:

```sh
DIST_DIR="$release_dir" RUN_CHECKS=1 packaging/build-dmg.sh
```

The Windows ZIP (including its executable and notices) must be built and tested
by the Windows job in `.github/workflows/cross-platform.yml`; it is not a
cross-compiled release claim from a Linux build. No Wine result is retained as
5.2.10 native evidence. Extended-length/device namespace paths, raw UNC output
roots, and mapped/network-drive output are not supported in 5.2.10. Publish the
exact architecture recorded by the native job.
These helpers create binary distribution artifacts for the release page, not
content to be committed to Git or included in the source archive.

### AUR, Homebrew, Guix, and Nix

The official release is 5.2.9. The withdrawn 5.2.10 source and packaging pins
must not be presented as final installation instructions. Before distributing
5.2.10, regenerate each recipe's source URL and checksum from the final signed
runtime tag and record the actual recipe commit.

Before the tag exists, run branch or pull-request CI with the default
`verify_recipe_pins=false`; it must not fetch an unpublished tag. After the
final signed tag and the recipe-only pin commit exist, manually dispatch
`.github/workflows/ci.yml` for that exact commit with
`verify_recipe_pins=true`. Treat any download, URL or digest failure as a
release blocker.

Validate each recipe's declared input, then build and test with its package
manager. Previous Guix package checks do not approve the corrected source or
establish AUR/Homebrew/Nix installation support. See [INSTALL.md](INSTALL.md).
The check phase must not fetch source or dependencies dynamically.

The Guix CLI recipe runs `make WITH_SDK=0 WITH_PQBOX=0 check` with the build
compiler. Python and Git are native test inputs, not CLI runtime dependencies.
The recipe also resolves the build-side shell for scripts generated by four
test harnesses; standard source-shebang patching only fixes their entry lines.
Checking that phase's routing and prerequisites does not replace executing
the suite in the Guix builder or testing the installed CLI and GUI.

## Release-page artifacts

The source-only policy applies to Git and the source bundle. The five planned
5.2.10 level-9 `.zupt` bundles are source, Linux x86_64 CLI, Windows x86_64 CLI,
macOS arm64 CLI DMG, and portable GUI frontend. CLI/GUI DEB/RPM/SRPM packages
retain their standard formats. No new tar.gz, tar.xz or ZIP is manually uploaded
as a public bundle. Historical 5.2.9 formats remain historical.

Tests of the withdrawn 5.2.10 packages remain historical evidence. Native
Windows/macOS, GUI and distribution-package checks must be rerun against the
final source and assets. Local extracted DEB/RPM checks are not native
Ubuntu/openSUSE installations. Platform and optional skips remain skips;
neither old CI results nor skipped checks approve the new release.

For every published artifact:

1. identify the final signed runtime tag and the actual build commit;
2. keep `WITH_SDK=0 WITH_PQBOX=0` unless system dependencies are declared;
3. record the exact OS, distribution release, architecture, and toolchain;
4. run format validation plus installed `--version`, `--help`, and archive
   round-trip tests;
5. publish a SHA-256 checksum;
6. scan the source inputs and ensure no credential or build path is embedded;
7. label an unbuilt or untested target `SKIP`, never `PASS`.

The mandatory formal gates are separate release conditions: run Frama-C Eva/WP
over the reviewed source and resolve or justify every alarm with the required
provers, then regenerate and validate the Jasmin sources as well as exercising
the checked-in `WITH_JASMIN=1` path. A bounded harness or a passing assembly
integration alone is not formal verification. Missing toolchains, unknown
proof obligations, or unresolved alarms keep the release unpublished.

Do not infer multi-architecture compatibility from portable source. Do not add
precompiled optional libraries to make a package build.

Publish 5.2.10 only as an official release after all required validation gates
are satisfied. Do not publish a candidate or known-issues prerelease. Missing
critical tests or unresolved failures block publication.
Use `SHA256SUMS`, `SHA256SUMS.asc` and `release-key.asc`; verify the current
5.2.10 fingerprint independently: `0CFA43B9AA9642EAAF2BE983C4C661C9ECFB46E8`.
The registered legacy key `CF8BA569591B6E7F4D24B0736C95BFAE0646DCCA` remains
applicable to earlier artifacts signed with it. Preserve their signatures and
release-specific verification instructions. The current configured key was
checked against the maintainer's registered GitHub public keys; confirm the
forge's signature status separately before publication.
An absent asset or mismatched checksum is unpublished/unverified, not a reason
to redirect to an older file. Never describe a missing signature as verified.

## Downstream checklist

- [ ] The source URL resolves to the final signed runtime tag; the actual build commit is recorded.
- [ ] The source tree passes `scripts/check-source-only.sh`; internal tar inputs also pass `--archive`.
- [ ] The recipe checksum matches the downloaded source exactly.
- [ ] `WITH_SDK=0 WITH_PQBOX=0` is explicit, or system dependencies are complete.
- [ ] Distribution compiler and linker flags are preserved.
- [ ] The real upstream `check` target runs without network access.
- [ ] Installation uses `DESTDIR` and does not write under `/usr/local`.
- [ ] The main package installs `zupt`; any `vaptvupt` alias is explicitly documented as compatibility-only.
- [ ] Licenses include AGPL-3.0-or-later for the application,
  GPL-3.0-or-later for the bundled source codec, and BSD-2-Clause for the
  xxHash-derived XXH64 routines, plus CC0-1.0 for the
  pq-crystals/kyber-derived ML-KEM portions and BSD-3-Clause for the
  curve25519-donna-derived X25519 portions.
- [ ] Package contents, dependencies, hardening, RPATH/RUNPATH, and debug info
  have been inspected with target-native tools.
- [ ] Installed-package smoke and round-trip tests pass.
- [ ] Only tested target artifacts are attached to the release.
