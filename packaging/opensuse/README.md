# ZUPT 5.2.8 for openSUSE Build Service

This directory is the upstream, source-only OBS recipe for ZUPT. It is a
handoff for the downstream maintainer; its presence does not mean that the
package has been submitted to or accepted by openSUSE Factory.

Cristian Cezar Moisés, ZUPT's creator and current upstream maintainer,
prepared the current source, build, test, documentation, and upstream packaging
changes in this handoff. Alessandro de Oliveira Faria (Cabelo) is credited only
as the openSUSE collaborator and downstream OBS package maintainer: he reviews
the handoff, commits it through the portal/project he maintains, and may make
the openSUSE-side adjustments he considers necessary. This role does not
attribute upstream code or the
5.2.2/5.2.3/5.2.4/5.2.5/5.2.6/5.2.7/5.2.8 upstream changes to Cabelo.

## Files and source policy

| File | Purpose |
|---|---|
| `_service` | Fetch the immutable `v5.2.8` tag and create `Source0` at build time. |
| `zupt.spec` | Build and test the CLI with optional external system integrations disabled. |
| `zupt.changes` | openSUSE-format package history. |
| `source-audit.sh` | Handoff wrapper for the repository scanner; run it from the complete handoff tree. |

The source service uses `obs_scm`, with Git submodules and Git LFS explicitly
disabled. Its primary URL is the canonical upstream:

```text
https://github.com/cristiancmoises/zupt.git
```

`obs_scm` stores an `.obscpio` plus `.obsinfo`. The `tar` and `recompress`
services reconstruct `zupt-5.2.8.tar.gz` inside the build environment, which
matches `Source0` in the spec.

This source policy does not prohibit separately built release-page packages.
The upstream 5.2.8 gates may publish the CLI source tarball, DEB, binary RPM,
SRPM, notice-bearing Linux tar.xz, Windows ZIP, and macOS DMG, together with a
GUI DEB, noarch RPM, GUI SRPM, and source-only portable GUI ZIP after each
format-specific test succeeds. None of those files is an OBS `Source0` input
or belongs in Git. AppImage and bare executables remain excluded: the former
lacks an audited runtime source/relink handoff, while the latter does not carry
the required license and notice payload beside the program.

## License and bundled codec

The resulting executable combines the AGPL-3.0-or-later application with the
GPL-3.0-or-later VaptVupt codec, adapted BSD-2-Clause XXH64 routines, and
CC0-1.0 pq-crystals/kyber-derived ML-KEM portions, plus BSD-3-Clause
curve25519-donna-derived X25519 portions, so the RPM uses:

```text
AGPL-3.0-or-later AND GPL-3.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND CC0-1.0
```

The bundled codec is VaptVupt codec tag `v2.65.3`. It was integrated into this
repository by commit `59f9ebc59ea13c6edf1d199ca795cdbf00e62226` and is declared
as `bundled(vaptvupt-codec) = 2.65.3`. That integration commit records the local
ANS safe-zone reserve patch applied on top of the upstream tag. The package
retains all license and notice files, including Yann Collet's xxHash notice;
it does not claim that the codec is unbundled.

## Optional SDK and PQBOX integrations

The OBS package always builds with:

```text
WITH_SDK=0 WITH_PQBOX=0
```

The resulting CLI retains the in-tree password, ML-KEM-768, X25519 and hybrid
features. It does not enable the optional libvuptsdk-backed Argon2id/`--pq-sdk`
integration or the separate libpqvaptvupt-backed `--pq-box` integration. Those
options may only be enabled in a future package after their complete source or
system development packages, licenses, ABI and dependencies have been audited.
The build does not download dependencies and never loads a repository-local
`.so`, `.a` or `.o` fallback.

## Archive integrity and compatibility in 5.2.2

New encrypted archives bind every DATA and DEDUP_REF frame to its logical
position. An authenticated reference also carries the authenticated position of
the source DATA frame, and new disk archives use flag-gated index/content-hash
metadata. The on-disk version byte remains 1.6, but an older reader is not
claimed to accept every new 5.2.2 encoding.

The packaged `extract`, `list`, `test`, and `disk restore` paths require an
archive-integrity trailer by default, without trusting unauthenticated header
flags. `--allow-legacy-no-ait` is accepted only by those commands for recovery
of a known, trusted pre-AIT archive and emits a downgrade warning. `info` merely
reports unauthenticated framing and apparent AIT presence; it does not validate
the trailer or contents. Package documentation must not recommend the override
for untrusted input or present `info` success as an integrity result.

The separate v5.2.1 compatibility claim is narrow: an actual
password-encrypted, deduplicated DATA/DATA/REF/DATA disk archive created from the
immutable v5.2.1 tag is stored as hexadecimal text with its source and SHA-256
provenance. The 5.2.2 reader reconstructs the legacy linear block-AAD sequence,
lists, tests, extracts, and restores its input byte-exact through the
fixed-width legacy disk-index parser. This does not cover every historical mode
and passed in the full local Linux gate for commit `ff99770`; the target RPM
`%check` must still exercise it before that package is promoted.

Disk restore also snapshots the measured archive into a private scratch file
before opening the destination, then validates and restores from that same
stream. An invalid `ZUPT_TMPDIR` override (or the compatibility fallback
`VAPTVUPT_TMPDIR`) and an unknown or insufficient raw-device capacity fail
before the first target write. The package check covers
the unprivileged unknown-capacity path; its loop-device size regression is
reported `SKIP`, not `PASS`, when the builder cannot create a loop device.

## Migration from the former package name

The main package is named `zupt` and installs only `/usr/bin/zupt`, its man
page, and its completions. The spec has a versioned `Provides: vaptvupt` and
`Obsoletes: vaptvupt` so an installed package under the former public name can
upgrade cleanly. It intentionally does not claim or install a second
`/usr/bin/vaptvupt` executable. The bundled codec and optional library keep
their established VaptVupt identifiers because those are compatibility-facing
API names, not the application package name.

## Local validation workflow

Run these commands in an OBS package checkout, not in the upstream Git tree:

```sh
xmllint --noout _service
osc service manualrun
rpmspec -P zupt.spec >/dev/null
spec-cleaner --diff zupt.spec
osc build --clean --keep-pkgs="$PWD/.osc-build-results" \
  openSUSE_Tumbleweed x86_64
rpmlint .osc-build-results/*.rpm
```

`osc service manualrun` materializes the service marked `manual` (the pinned
SCM input). The tarball itself is
reconstructed by the build-time services. Neither `%build` nor `%check` may
access the network.

For a source RPM check outside OBS, place the service-produced
`zupt-5.2.8.tar.gz` next to the spec and use a disposable RPM build tree:

```sh
rpm_top=$(mktemp -d)
trap 'rm -rf -- "$rpm_top"' EXIT
mkdir -p "$rpm_top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
rpmbuild --define "_topdir $rpm_top" --define "_sourcedir $PWD" \
  -bs zupt.spec
```

After building, inspect the RPM contents and dependencies, run `rpmlint`, then
install it in a disposable openSUSE environment and execute
`scripts/test-installed-zupt.sh`. Do not claim a repository or architecture
as supported until its build and installed smoke test have actually passed.

## Prior 5.2.2 committed-candidate local Linux validation

The immutable 5.2.2 candidate at `ff99770` passed the full local
`make release-check`. Packaging policy
and syntax reported `PASS=49 FAIL=0 SKIP=0`; source-only scanner testing passed
39/39, including GNU thin archives and safe diagnostic cases; strict GCC,
strict Clang, GCC `-fanalyzer`, the 9/9 full tool-enabled static-analysis run,
ASan/UBSan/LSan, and 1,000 mutation-fuzz iterations passed. A reduced
environment completed six available static checks and reported `cppcheck`
unavailable rather than passing it. Earlier off-screen GUI smoke evidence is
supporting evidence, not an exact-commit package result.

Post-tag CI integration failures prevented 5.2.2 promotion. These historical
local results do not establish 5.2.8, native Windows or macOS success, hosted
GitHub CI/release promotion, authenticated OBS acceptance, or resolution of the
automatic openSUSE `debugsource` rpmlint `no-binary` finding. The immutable
5.2.3 candidate was not promoted because its source-policy test assumed LF for
a Windows `.bat` file checked out as CRLF.

## Prior 5.2.4 exact-tag source-service evidence

The immutable v5.2.4 candidate was not promoted. Exact-tag GitHub Actions run
`33431386002` recorded 12 successful jobs and one failed openSUSE job. That job's
standalone `Serviceinfo` harness passed the service directory to the executor
but did not make it the process working directory; dependent native Windows and
macOS jobs were skipped.

A disposable local openSUSE Tumbleweed reproduction independently resolved
`refs/tags/v5.2.4` to the tagged commit. With `osc` 1.27.3,
`obs-service-obs_scm` 0.12.4, `obs-service-tar` 0.12.4, and
`obs-service-recompress` 0.5.2 installed, the same executor completed
`obs_scm`, `tar`, and `recompress` after `os.chdir(service_dir)`. It produced
exactly one `zupt-5.2.4.tar.gz`; its SHA-256 was
`aa68a58fc2e88ee92296542de1f189e2b8a803154d832fb04d5296b25acaef8f`, and the
source scanner reported `PASS source-only: 204 files, 1 archives`.

This result establishes that the explicit tag revision works and isolates a
release/test harness defect. It does not change the product, archive format,
cryptography, codec, or SDK ABI; it does not make skipped native jobs pass or
establish authenticated OBS/Factory acceptance. No v5.2.4 evidence transferred
automatically to v5.2.8; the exact candidate later repeated every applicable
upstream gate in run `33456209269`, as recorded below. The automatic openSUSE
`debugsource` rpmlint `no-binary` finding remains unresolved and unsuppressed.

## Prior 5.2.5 exact-tag native-gate evidence

The immutable v5.2.5 candidate was not promoted. Exact-tag GitHub Actions run
`33434986357` completed 13 jobs successfully and failed the native Windows and
macOS jobs. Windows exposed a hostile-path fixture that did not preserve its
requested bytes across the command-line boundary; macOS exposed the unsupported
`explicit_bzero` assumption and Bash 3.2 empty-array handling. The 5.2.6
corrections address those release/test integration defects without an archive,
cryptographic, codec, or SDK ABI change.

## Prior 5.2.6 exact-tag native-gate evidence

The immutable v5.2.6 candidate was not promoted. Exact-tag GitHub Actions run
`33442264243` completed 13 jobs successfully and failed two native jobs. The
macOS arm64 SHA-NI test build treated unused x86-only helper declarations as
errors under `-Werror`; Windows argv transcoding aborted the safe printable
UTF-8 fixture before its intended path assertions. The 5.2.7 changes correct
those test-harness boundaries without an archive-format, cryptographic, codec,
or SDK ABI change. They do not establish 5.2.8 hosted, native, OBS, or promotion
evidence.

## Prior 5.2.7 exact-tag native-gate evidence

The immutable v5.2.7 candidate was not promoted. Exact-tag GitHub Actions run
`33445470664` concluded `cancelled` at `2026-08-31T23:11:19Z`, with 13
successful jobs, one failed macOS job, and one cancelled Windows job. macOS
rejected creation of the raw-C1 scanner fixture
with `EILSEQ`; the hosted Windows job stalled in `make check`, and a MinGW/Wine
reproduction isolated the cause to a redirected password prompt entering
`_getch`. Version 5.2.8 makes those test
boundaries fail or skip without hanging, addresses CodeQL High #5/#6/#7 in SDK
key publication, disk restore, and benchmark cleanup, and adds `sdk-test` to
release and hosted Linux gates. None of those changes establishes an exact
5.2.8 OBS, native, hosted-CI, or promotion result.

## 5.2.8 exact-tag upstream package evidence

Manually dispatched exact-tag GitHub Actions run `33456209269` passed all 15
jobs at `ebb9ab3aa1d42c50030ca02883f6162dc4771fe1`. Its openSUSE Tumbleweed
x86_64 job parsed and normalized the spec, executed the pinned standalone OBS
source-service chain, source-scanned the resulting archive, built the binary
RPM and genuine SRPM, ran `rpmlint` without suppressions, and completed the
install/round-trip/uninstall test. The canonical source archive is 798296 bytes
with SHA-256
`378b9506211545b9594cf0d38ac8955d9b1cac34eb6b379ae0ec26b84edb65f7`.

Promotion run `33457868306` published the exact tested binary RPM and SRPM with
the other gated assets. The source package is identified by
`%{SOURCEPACKAGE}=1` and an absent `%{SOURCERPM}`; its `%{ARCH}` legitimately
reflects the spec's build architecture and is not the SRPM discriminator.
Repository, Git archive, and upstream source tarball scans remain binary-free.

This is upstream local-service and package evidence, not a claim that the
package was submitted to or accepted by openSUSE Factory, nor a result for the
full set of automatically generated OBS debug packages or any untested
architecture.

## Prior openSUSE packaging validation

The local results below were produced on 2026-08-24 from the 5.2.2 candidate
snapshot captured for the packaging run, in a disposable openSUSE Tumbleweed
20260822 x86_64 container. This matrix was documented afterward, so the results
validate that captured snapshot, not the later documentation edit, a future
commit or a tag. Commit- and tag-dependent checks must be repeated after the
final commit; the validation tarball checksum below is not a release checksum.
`SKIP` is not success.

| Gate | Result | Evidence |
|---|---|---|
| `_service` XML syntax | PASS | `xmllint --noout`; installed service definitions and parameters also exercised locally. |
| ShellCheck for packaging, export, source-policy, and security regression scripts | PASS | ShellCheck 0.10.0 returned zero for the scripts listed in the CI source-policy job, including the scanner and new archive/disk regressions; repeat after the final commit/tag. |
| Upstream source-only scanner and adversarial scanner tests | PASS | Clean snapshot: 191 files; OBS tar: 191 files/1 archive; SRPM tree: 193 files/1 archive; 29 positive/negative scanner regressions passed. |
| Reproducible source archive (two builds, same SHA-256) | PASS | Two local `obs_scm`/`tar`/`recompress` runs were byte-identical (`39e59f5e...`, validation only; regenerate after the real tag). |
| Upstream build, `make check`, and `make test-all` | SKIP | The real RPM `%check`/`make check` passed; an exact-candidate `make test-all` result was not produced by this packaging run. |
| Positional DATA/DEDUP_REF AAD and mandatory-AIT regressions | PASS | `%check` passed AIT removal, F-09 preface, DATA/REF reorder/replay, little-endian, varint and atomic-output regressions. |
| v5.2.1 encrypted+dedup disk compatibility | PASS | Working-tree candidate decoded the textual 718-byte v5.2.1 DATA/DATA/REF/DATA fixture, then `list`, `test`, generic extraction, and byte-exact disk restore passed; repeat after the final commit/tag. |
| `rpmspec` parse | PASS | Both `rpmspec -P` and `rpmspec --parse` returned zero; Source0 resolved to `zupt-5.2.2.tar.gz`. |
| `spec-cleaner` | PASS | Version 1.2.4+2 returned zero and proposed no diff. |
| `rpmbuild` source and binary RPM | PASS | `rpmbuild -bs` and `-ba` passed from the service-generated Source0 with the openSUSE `.changes` conversion. |
| `rpmlint` main RPM + SRPM | PASS | 0 errors and one `invalid-url Source0` warning for the service-generated local Source0; no `rpmlintrc` or suppression was added. |
| `rpmlint` including automatic debug packages | FAIL | `debugsource: no-binary` error and expected `debuginfo: unstripped-binary-or-object` warning from the complete generated package set; debug packages were not disabled or suppressed. |
| `osc service` | PASS | Installed `obs_scm` 0.12.4, `tar` 0.12.4 and `recompress` 0.5.2 produced the correctly named source tar locally; canonical tag fetch remains tag-dependent. |
| Tumbleweed x86_64 local build/install/round trip/uninstall | PASS | Tumbleweed 20260822 container: RPM `%check`, root and `nobody` installed tests, content/hardening audit and clean uninstall passed. This is not an OBS/Factory result. |
| Official OBS `osc build` invocation | FAIL | The command reached `https://api.opensuse.org` but returned HTTP 401 because no OBS credentials are configured. |
| Factory/Tumbleweed x86_64 OBS validation | SKIP | The failed authenticated `osc build` invocation produced no Factory build result; local Tumbleweed evidence is not promoted to Factory evidence. |
| aarch64, ppc64le, s390x, riscv64 | SKIP | No build evidence yet. |
| Leap and SLE | SKIP | No build evidence yet. |

`SKIP` is not success. Factory/Tumbleweed x86_64 remains the primary downstream
gate.

## Handoff procedure for Alessandro/Cabelo

1. Upstream completes every applicable pre-tag source and local audit gate,
   then creates and verifies the annotated `v5.2.8` tag. Exact-tag hosted,
   native-platform, package, and promotion gates must pass before release or
   downstream handoff; the tag itself is never moved to repair a failure.
2. With Git, `file`, bsdtar, tar, zip, unzip and SHA-256 tools installed, run
   `scripts/export-opensuse-package.sh v5.2.8`. Verify the reported ZIP and
   SHA-256 outside the Git index. The handoff includes both
   `packaging/opensuse/source-audit.sh` and its required
   `scripts/check-source-only.sh`; keep that relative layout while auditing.
3. Check out the OBS package:

   ```sh
   osc checkout home:cabelo:innovators zupt
   cd home:cabelo:innovators/zupt
   ```

4. From the extracted handoff root, run
   `packaging/opensuse/source-audit.sh --archive /path/to/zupt-5.2.8.tar.gz`.
   Then copy `_service`, `zupt.spec`, `zupt.changes` and `README.md`
   into the flat OBS package checkout. The audit wrapper is not an OBS build
   source and must not be copied without its companion `scripts/` directory.
5. Run the local validation workflow above, including the installed round-trip
   test. Build every repository and architecture enabled in the OBS project;
   record failures or unavailable gates as such.
6. Review `osc diff`, confirm that no RPM or other binary was added as a source,
   and commit to OBS only after the required gates pass.

For future releases, increment the stable patch version, create a new immutable
tag, update the matching revision/version in `_service`, spec and changes, run
the source-only scanner, regenerate the handoff, and repeat every OBS gate.
Never move an existing tag or consume forge release binaries as `Source0`.
