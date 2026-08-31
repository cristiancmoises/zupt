<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ZUPT 5.2.3 audit guide and finding history

This document describes review surfaces and reproducible checks. It is an
upstream self-review, not an independent audit, certification, or guarantee.
`SECURITY.md` defines reporting policy and `THREAT_MODEL.md` defines the
security boundary.

## 5.2.3 scope

The baseline scope is the source-only CLI and its bundled source codec:

- first-party C and headers under `src/` and `include/`;
- textual architecture-specific source under `jasmin/`, distinguishing
  compiler-generated output from separately identified hand-written assembly;
- VaptVupt codec source at release 2.65.3, with provenance and licensing in
  `THIRD-PARTY-NOTICES.md`;
- CLI tests, source scanner, build system, CI, and packaging recipes;
- the Python GUI source as a caller of the CLI.

The baseline is built with `WITH_SDK=0 WITH_PQBOX=0`. The optional system
`libvuptsdk` and `libpqvaptvupt` implementations are outside this scope unless
their exact source packages and versions are added to an assessment. Assembly
under `jasmin/` is disabled by default and is a separate `WITH_JASMIN=1` build
choice on supported x86_64 compiler targets. Generated files must record their
compiler provenance; hand-written files must not be represented as compiler
output.

## Source-only review

The 5.2.3 baseline retains the source-only boundary introduced in 5.2.2, which
removed incomplete SDK/PQBOX header snapshots and local precompiled-library
expectations. Git and new upstream source
archives are intended to contain no compiled executable, object, shared/static
library, distribution package, unsafe symlink, or unresolved Git LFS pointer.

Run the same scanner over each representation:

```sh
# tracked files and working tree
scripts/check-source-only.sh

# committed Git tree or immutable tag
scripts/check-source-only.sh --tag HEAD
scripts/check-source-only.sh --tag v5.2.3

# generated source archive
scripts/check-source-only.sh --archive /path/to/zupt-5.2.3.tar.gz
```

The scanner checks extensions and magic bytes, nested archives, symlink targets,
LFS pointers, generated compiler output, and stale vendor-library references.
It reports paths without printing file contents. Its negative tests include
renamed ELF, ar, PE/MZ, versioned `.so`, RPM/DEB/AppImage, escaping symlinks,
and LFS pointers; textual assembly is a permitted source type.

Archive inspection must also fail closed at bounded recursion depth, member
count, individual expanded size, and total expanded size so a nested archive or
decompression bomb cannot turn the release scanner into an unbounded resource
consumer. On committed Linux candidate `ff99770`, this hardening and its
adversarial fixtures passed all 39 source-only scanner cases, including GNU
thin-archive and safe-diagnostic-path cases.

An unknown `.bin` fails by default. A necessary binary data fixture can be
declared only through `--data-manifest`, with four tab-separated fields for
path, purpose, provenance, and SPDX license. That manifest does not override a
compiled/executable magic finding.

An artifact is not clean merely because it has a harmless extension. Conversely,
binary image data is not executable code: the documented GUI icon assets are
necessary data and are reviewed separately for purpose, provenance, and license.

## Reproducible project checks

The baseline gates are:

```sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)" \
  WITH_SDK=0 WITH_PQBOX=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 check
make WITH_SDK=0 WITH_PQBOX=0 test-all
```

Relevant review layers include:

| Layer | Evidence source | Interpretation |
|---|---|---|
| Source boundary | `scripts/check-source-only.sh`, `tests/test_source_only.sh` | Fails on prohibited artifacts or unsafe source layout |
| Primitive vectors | `tests/test_vectors.c` | Known-answer regression for implemented primitives |
| ML-KEM interoperability | `tests/test_mlkem_fips203.sh` | Runs only with an ML-KEM-capable OpenSSL 3.5+; otherwise `SKIP` |
| Archive behavior | quick/regression, traversal, argument-order, block-swap, nonce, and exact-size tests | Exercises current parser, integrity, and round-trip properties |
| Password sources | `tests/test_password_sources.sh` | Exercises password-file, inherited-descriptor and explicit-prompt rejection paths without logging password contents |
| Key files | native key regressions | Exercises no-replace private-file creation, POSIX mode `0600`/Windows current-user-only DACL, failed-partial behavior, checksum, and exact ZKEY/ZPQK version/flags/reserved/size/role validation |
| Terminal output | archive-comment regression | Requires displayed untrusted comments to contain no raw terminal-control sequence |
| Prompt cleanup | PTY signal regression | Requires handled POSIX interruption to restore the saved terminal state |
| Sanitizers | `make test-asan-run` | Builds and executes separate ASan/UBSan/LSan evidence where supported; not a substitute for normal tests |
| Static analysis | compiler analyzer, cppcheck, scan-build, clang-tidy where installed | Tool-specific findings must be reviewed, not suppressed globally |
| Shell and metadata | shellcheck, SPDX/license checks, packaging syntax checks | Applies only when the named tool actually executed |
| Source reproducibility | two `make dist` runs with identical committed input and epoch | Requires equal SHA-256 digests and clean archive scans |
| Installed package | target-native package inspection and `scripts/test-installed-zupt.sh` | Applies only to the exact OS/release/architecture tested |

This table identifies evidence layers rather than results. Missing tools, OBS
access, other architectures, Leap, and SLE must not be reported as passing
without evidence.

## Prior 5.2.2 committed-candidate local Linux evidence

The following upstream self-audit results apply only to the 5.2.2 candidate at
commit `ff99770` on the recorded local Linux environments. The immutable 5.2.2
tag was not promoted after post-tag CI integration failures. These results are
not independent certification, a 5.2.3 result, or evidence that release assets
were published.

| Gate | Result | Recorded evidence |
|---|---|---|
| Full project gate | PASS | `make release-check` completed successfully on `ff99770`, including the late key-file, terminal-comment, password-prompt, explicit-Bash, and scanner-limit regressions. |
| Packaging policy/syntax | PASS | `PASS=49 FAIL=0 SKIP=0`. |
| Source-only scanner adversarial suite | PASS | 39/39, including GNU thin archives, bounded archive expansion, and safe diagnostic cases. |
| Strict compilers and compiler analyzer | PASS | GCC and Clang strict builds passed; GCC `-fanalyzer` passed. |
| Static-analysis suite | PASS | 9/9 in the full tool-enabled run. A separate reduced-environment `release-check` run completed six available checks and reported `cppcheck` unavailable; unavailable tooling was not relabelled as a pass. |
| Dynamic analysis | PASS | ASan, UBSan, and LSan runs passed. |
| Mutation fuzzing | PASS | 1,000 mutation iterations completed without a sanitizer-detected crash. |

An earlier off-screen GUI smoke run remains supporting evidence, but is not
represented as an exact-`ff99770` GUI-package result. The exact 5.2.3 candidate
must repeat the required suite. Native Windows and macOS gates, hosted GitHub CI
and release promotion, authenticated OBS validation, and resolution of the
openSUSE automatic `debugsource` rpmlint `no-binary` finding remain pending
until recorded otherwise.

## Cryptographic review boundary

The repository includes NIST/RFC known-answer tests and a conditional OpenSSL
ML-KEM interoperability check. These establish specific functional outputs in
the environments where they pass; they do not prove implementation security,
constant-time execution, or resistance to every malformed input.

Portable C is the default. Sensitive comparison/select code is written to avoid
secret-dependent branching, but compiler output remains platform-dependent.
Optional generated Jasmin functions have a narrower assurance scope and do not
formally verify the parser, codec, key management, or whole application. The C
AES implementation has documented cache-timing risk on hostile shared hardware.

## Historical findings

The following entries are retained as release history. Their regression tests
should be rerun, but the historical resolution does not itself constitute a
5.2.3 test result.

| First corrected | Severity | Finding | Resolution recorded at the time |
|---|---|---|---|
| 4.2.0 | Critical | AES-CTR nonce reuse across encrypted `--dedup` blocks | Changed to fresh random per-block nonces; older affected archives should be re-encrypted |
| 5.0.0 | High | Native ML-KEM used round-3 CRYSTALS-Kyber semantics while labelled FIPS 203 | Corrected matrix/KDF/rejection behavior and added OpenSSL interoperability regression; native PQ compatibility changed |
| 5.0.0 | High | A malformed password-option ordering could overwrite an input | Added output/self-overwrite and argument-order guards |
| 5.0.0 | High | A misplaced option could cause plaintext output when encryption was intended | Reject misplaced options unless explicitly escaped |
| 5.0.0 | Medium | AVX2 codec offset read could exceed a crafted input tail | Added the scalar-equivalent bound and exact-size regression |
| 5.2.2 | Build/supply chain | Build and packaging paths expected local precompiled optional libraries | Removed incomplete vendor trees; optional integrations now require explicit system development packages |
| 5.2.2 | High | Extraction used mutable string paths and could follow hostile parent/leaf links or publish partially verified output | Added strict index-path validation, descriptor/handle-relative traversal, no-replace atomic publication, exact size/hash validation, and hostile-archive regressions |
| 5.2.2 | High | Compression or disk backup could name its own input through an alternate spelling, hardlink, or symlink | Compare open-file identity before creating the output in normal, solid, and disk-image writers; `--force` cannot bypass the guard |
| 5.2.2 | High | Disk restore validated a pathname before destructively consuming it and did not prove raw-device capacity before writing | Snapshot the measured archive privately before target open, restore from the same stream, and fail closed on unknown or insufficient device capacity |
| 5.2.2 | High | Some decoders did not require DATA at every payload position, and legacy encrypted+dedup disk references used a different AAD sequence | Enforce frame types in serial, threaded, solid, test, and disk readers; reconstruct the exact v5.2.1 disk AAD sequence with an actual encrypted DATA/DATA/REF/DATA fixture |
| 5.2.2 | Medium | Benchmark scratch paths were predictable from the process ID | Create one random private scratch directory and clean it without following links |
| 5.2.2 | High | Native private-key output and ZKEY/ZPQK readers did not uniformly enforce no-replace private permissions and every structural field | Create without replacement using POSIX mode `0600` or a Windows current-user-only DACL; validate checksum, version, flags, reserved bytes, exact size, and public/private role before use; leave a failed exclusive partial for manual removal rather than risk unlinking a pathname replacement |
| 5.2.2 | Medium | An authenticated archive comment could still inject terminal control sequences when displayed | Render untrusted comment bytes in a terminal-safe form without changing the authenticated archive value |
| 5.2.2 | Medium | A signal during an interactive POSIX password prompt could leave terminal echo/state altered | Restore saved terminal settings on handled interruptions; cover the behavior with a PTY regression |
| 5.2.2 | Test reliability | `tests/regression.sh` used Bash syntax without making the interpreter contract explicit | Execute the suite explicitly with Bash and keep syntax/interpreter checks in release gates |
| 5.2.2 | Documentation/licensing | Current documentation incorrectly denied historical MIT grants visible in published Git history | Added a factual erratum: current source follows current SPDX notices, while earlier grants and immutable tags remain valid and unmodified |

See `CHANGELOG.md` for the complete per-release history and compatibility notes.
Old tags remain immutable and may contain artifacts or build assumptions removed
from current branches and new tags.

## Packaging review

The openSUSE package must build the immutable source tag with
`WITH_SDK=0 WITH_PQBOX=0`, preserve distribution flags and debuginfo, run a real
`%check`, install through `DESTDIR`, and omit the renamed-era `vaptvupt` alias from
the main package. Review the built RPM for dependencies, paths, permissions,
RPATH/RUNPATH, hardening, debug information, licenses, and unowned files, then
test it after installation in a disposable target environment.

Release-page DEB, binary RPM, SRPM, notice-bearing Linux tar.xz, Windows ZIP,
and macOS DMG packages are separate outputs, never members of Git or source
archives. Publish only formats built and tested for their stated target and
include SHA-256 checksums. The gated GUI set adds the architecture-independent
DEB, noarch/source RPM, and source-only portable GUI ZIP. Package gates include
exact payload/dependency and installed off-screen integration checks; the
portable ZIP additionally receives source scans, an exact safe-member allowlist,
and an extracted launcher test. An AppImage is not promoted by the 5.2.3
policy; AppDir and Flatpak bundles, GUI platform installers, and bare
Linux/Windows executables are also excluded. Windows ZIP and macOS DMG outputs
remain CLI-only.

No Wine result is retained as release evidence for 5.2.3. Cross-compilation
does not establish native-Windows behavior. Extended-length/device namespace
paths, raw UNC output roots, and mapped/network-drive output are unsupported;
the native Windows workflow remains a publication gate for the ZIP containing
the executable.

## Known limitations

- No independent security audit or certification has been performed.
- Fuzzing and sanitizers sample behavior; they cannot prove absence of memory or
  parser defects.
- Static analysis is tool-, configuration-, and path-dependent.
- Optional SDK/PQBOX code is outside the default assessment.
- Side-channel behavior is compiler-, CPU-, OS-, and workload-dependent.
- A clean source archive does not by itself establish that a binary was built
  reproducibly or on a trusted runner.
- Passing on one OS or architecture is not evidence for another.

Record exact commands, tool versions, target, exit status, and non-sensitive
logs for every release gate. Never convert an unavailable or unexecuted check
from `SKIP` to `PASS`.
