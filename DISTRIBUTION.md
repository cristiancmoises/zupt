# Distributing ZUPT 5.2.7

This document describes the packaging material maintained in the ZUPT
source repository. A recipe in `packaging/` is not evidence that a package has
been accepted by a distribution or that every target platform has been tested.
Record each build and test result separately; an unexecuted target is a skip.

The canonical repository is:

```text
https://github.com/cristiancmoises/zupt
```

GitHub is the canonical source and release host. Packaging must never fetch
`zupt-web` or substitute an asset from another project.

The `v5.2.2`, `v5.2.3`, `v5.2.4`, `v5.2.5`, and `v5.2.6` tags are immutable
non-promoted candidates.
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
UTF-8 fixture argv transcoding. Corrective packages and release assets must use
`v5.2.7`; never move or overwrite an earlier tag or checksum, and never
transfer prior evidence automatically.
This corrective version changes release/test integration only; the product,
archive format, cryptography, codec, and SDK ABI remain unchanged.

## Source-only boundary

Git, `git archive`, and the upstream source tarball contain source code,
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
scripts/check-source-only.sh --archive /path/to/zupt-5.2.7.tar.gz
```

The scanner reports paths, not file contents, and exits nonzero on a violation.

## Reproducible source archive

`make dist` verifies committed `HEAD` and exports its tree object, normalizes
member order, timestamps, owner/group metadata, and gzip metadata, and audits
the result before moving it to its destination. Exporting the tree rather than
the commit omits Git's commit-ID PAX header:

```sh
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  make DIST_TARBALL=/tmp/zupt-5.2.7.tar.gz dist
sha256sum /tmp/zupt-5.2.7.tar.gz
```

With identical committed input and `SOURCE_DATE_EPOCH`, repeated exports must
have the same SHA-256 digest. Do not generate a release tarball from uncommitted
working-tree files.

The AUR, Homebrew, and Guix recipes pin the checksum of this tarball. They are
marked `export-ignore` in `.gitattributes` so their own checksum fields do not
make the archive self-referential. A commit changing only those ignored recipes
therefore leaves the fixed-epoch archive byte-identical. The recipes remain
versioned in Git and must be updated after the final source archive checksum is
known.

Do not commit the generated tarball or checksum file. Host them as immutable
release assets after the release tag is published.

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
| GUI DEB | `packaging/build-gui-deb.sh` | `zupt-gui_5.2.7_all.deb` after payload/dependency and installed integration gates |
| GUI RPM | `packaging/build-gui-rpm.sh` | `zupt-gui-5.2.7-1.noarch.rpm` and matching `.src.rpm` after package and installed integration gates |
| Linux CLI archive | `.github/workflows/ci.yml` | `zupt-5.2.7-linux-x86_64.tar.xz` with notices after dependency, member, and extracted functional gates |
| Portable GUI source | `packaging/portable/`, `.github/workflows/ci.yml` | `zupt-gui-5.2.7-portable.zip` after source scan, member allowlist, and extracted off-screen integration gate |
| Fedora / RPM-based systems | `packaging/rpm/zupt.spec` | downstream RPM starting point |
| AppImage helper | `packaging/build-appimage.sh` | downstream-only helper; no 5.2.7 AppImage is promoted |
| Windows | `.github/workflows/cross-platform.yml` | native ZIP (executable plus notices) after the required native gate |
| macOS | `packaging/build-dmg.sh` | native-architecture DMG after the native gate |
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
They validate exact version, payload, dependency, ownership and legacy-alias
expectations, then test the installed launcher off-screen against the matching
`zupt` CLI. A successful GUI DEB gate does not imply an RPM gate, or vice versa.

### Portable and native release artifacts

The Linux x86_64 gate packages the tested `zupt` executable as
`zupt-5.2.7-linux-x86_64.tar.xz` beside README, changelog, security guidance,
and every applicable public license and notice. Its dynamic-library allowlist,
archive member allowlist, and extracted CLI functional suite must pass.

The `zupt-gui-5.2.7-portable.zip` artifact is source-only: it contains the GUI
Python source, shell/macOS/Windows launchers, icons, provenance, changelog, and
licenses, but no Python, Qt, CLI, or compiled runtime. The gate scans both the
assembled and extracted trees, verifies an exact safe member allowlist, and
runs the extracted launcher off-screen against the tested CLI.

AppImage creation is deliberately offline and is not a 5.2.7 release gate.
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
upstream 5.2.7 workflow. AppDir and Flatpak bundles and GUI platform installers
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
5.2.7 release evidence. Extended-length/device namespace paths, raw UNC output
roots, and mapped/network-drive output are not supported in 5.2.7. Publish the
exact architecture recorded by the native job.
These helpers create binary distribution artifacts for the release page, not
content to be committed to Git or included in the source archive.

### AUR, Homebrew, Guix, and Nix

After calculating the final reproducible source archive, but before creating or
publishing the immutable tag, update each recipe to version 5.2.7 and to the
exact digest or content hash expected by its package manager. These recipe
directories are excluded from the source archive, so this does not create a
checksum cycle. Commit the pinned recipes in the tagged tree, then build and
test with each package manager before publishing its recipe. Keep build inputs
offline-capable: the check phase must not fetch source or dependencies
dynamically.

## Release-page artifacts

The source-only policy applies to Git and upstream source archives. A release
page may also carry CLI/GUI DEB and RPM artifacts, the notice-bearing Linux CLI
tar.xz, source-only portable GUI ZIP, CLI Windows ZIP, or CLI macOS DMG when
each is built from the tagged source in its target environment and passes its
format-specific tests. These are separate outputs, never inputs to a source
build.

For every published artifact:

1. start from the immutable `v5.2.7` tag;
2. keep `WITH_SDK=0 WITH_PQBOX=0` unless system dependencies are declared;
3. record the exact OS, distribution release, architecture, and toolchain;
4. run format validation plus installed `--version`, `--help`, and archive
   round-trip tests;
5. publish a SHA-256 checksum;
6. scan the source inputs and ensure no credential or build path is embedded;
7. label an unbuilt or untested target `SKIP`, never `PASS`.

Do not infer multi-architecture compatibility from portable source. Do not add
precompiled optional libraries to make a package build.

Publish release assets at the canonical GitHub release. If an expected asset is
absent or has a different checksum, report that target as unpublished rather
than redirecting consumers to an unverified file.

## Downstream checklist

- [ ] The source URL resolves to the immutable `v5.2.7` tag.
- [ ] The source archive passes `scripts/check-source-only.sh --archive`.
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
