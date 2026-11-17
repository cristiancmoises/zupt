<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ZUPT audit guide

This document describes the review scope and reproducible checks for ZUPT
5.2.10, which uses desktop archive format 1.6. Published tags, packages and
checksums are listed on the [release page](https://github.com/cristiancmoises/zupt/releases).
This is an upstream self-review, not an independent audit, certification or
guarantee. [SECURITY.md](SECURITY.md) covers reporting and
[THREAT_MODEL.md](THREAT_MODEL.md) defines the security boundary.

## 5.2.10 scope

The default production CLI remains C11 with `WITH_SDK=0 WITH_PQBOX=0`.
Optional system SDK/PQBOX integrations, generated Jasmin code, different CPU
features and native packages require their own stated test scope. A successful
source check does not establish binary reproducibility or target-platform
acceptance. SPDX-marker checks do not establish complete provenance, patent
clearance or redistribution rights.

AppImage packages are outside the 5.2.10 release artifact matrix. Portable
executables are distributed in bundles with their required runtime notices;
bare Windows executables are not release assets.

## Reproducible project checks

Use a clean source copy for each compiler or instrumentation profile. Check
source and licenses before creating build output:

For an extracted `.zupt` source bundle, first follow the permission setup in
[INSTALL.md](INSTALL.md#build-and-test-from-source). The three self-executing
test wrappers need execute permission even when their initial invocation uses
`sh`. A Git checkout already preserves these tracked modes.

```sh
bash scripts/check-source-only.sh --tree .
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses
bash tests/test_source_only.sh
make clean
make -j2 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make sdk-test
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-asan-run
```

Repeat the applicable profile with `CC=gcc` and `CC=clang`. Building
`test-asan` alone does not execute sanitizer tests. Record complete diagnostics,
commands, tool versions, revision, target and exit status. `SKIP`, `NOT RUN`,
`BLOCKED` and a failed check are distinct outcomes; none is a passing required
gate.

In a Git checkout, also run `make source-audit` to check the index and committed
archive in addition to the working tree. This target requires Git metadata;
the explicit `--tree .` check above works with extracted source bundles.

To recheck cases skipped for missing tools in a CI image, run the relevant
commands below from the source checkout. OpenSSL must expose ML-KEM-768. The
completion and manual-page checks use Bash, Zsh, Fish, mandoc and GNU Make.
The Guix phase test needs Guile with the Guix modules and GNU Make on `PATH`.

```sh
bash tests/test_mlkem_fips203.sh
bash tests/test_completions_manpage.sh
nix-instantiate --parse packaging/nix/flake.nix >/dev/null
guile --no-auto-compile -q -s tests/test_guix_gui_install_plan.scm
```

**Português.** Execute esses comandos separadamente para verificar os casos
ignorados por falta de ferramentas na CI. O teste do Guix prepara a instalação
em diretórios temporários e verifica os arquivos, o launcher e a propagação
de falhas do processo filho.

| Review layer | Public entry point | Scope and prerequisites |
|---|---|---|
| Source and licenses | `audit-licenses`, `source-audit`, `tests/test_source_only.sh` | Scan clean source representations and retain failures; generated binaries are not source. |
| CLI and archive behavior | `check`, `test-all`, `scripts/test-installed-zupt.sh` | Parser, integrity, traversal, round trips, password input, key-file and terminal-state regressions. |
| In-tree SDK | `sdk-test` | Callback and file-I/O tests, atomic key publication and path/permission regressions; distinct from external SDK integration. |
| Sanitizers | `test-asan-run`, focused exact-size and ANS targets | Execute instrumented code and retain diagnostics; instrumentation and platform scope must be explicit. |
| Static analysis | `CC=gcc bash tests/test_static_analysis.sh` | Compiler analysis and installed optional analyzers; tool absence is not a clean result. |
| GUI | `check-gui`, `test-portable-gui` | Requires a working supported Qt binding and matching CLI; offscreen checks do not replace installed native package tests. |
| Installed documentation | `test-installed-docs` and package checks | Exact required English/Portuguese guides, licenses and source/document byte comparisons. |
| Formal and generated assembly | Targets below | Selected C models and five Jasmin modules; separate prerequisites and open obligations apply. |
| Source reproducibility | Two `make dist` runs with identical committed input and epoch | Require matching digests and clean source scans; the public full-source `.zupt` has a separate raw-Git content contract. |
| Native packages | Platform CI and `scripts/test-installed-zupt.sh` | Inspect, install, test and remove the exact packages on each claimed OS/release/architecture. |

The aggregate `release-check` requires a Git checkout and additionally runs the
maintained formal and assembly gates. `check` and `test-all` remain
distribution-friendly entry points and do not replace those release conditions. See
[DISTRIBUTION.md](DISTRIBUTION.md#release-page-artifacts) for the complete
publication requirements.

## Source-only review

Audit both committed source and exported inputs before compilation:

```sh
bash scripts/check-source-only.sh --tree .
bash scripts/check-source-only.sh --tag HEAD
bash scripts/check-source-only.sh --archive /path/to/zupt-5.2.10.tar.gz
```

The archive option checks internal/forge tar inputs. Verify and extract public
`.zupt` bundles with a trusted desktop CLI, then compare their contents against
the signed raw Git source as described in [DISTRIBUTION.md](DISTRIBUTION.md#source-bundle-and-reproducible-build-inputs).
The scanner rejects compiled artifacts, unsafe links and unresolved LFS
pointers. It does not establish complete provenance, concurrent-tree safety or
binary acceptance. Repeat source-only scans on clean source copies after
runtime work; generated build output is an expected finding.

## Timing measurement profile

`make test-ct-timing` collects 400,000 observations per class for each
comparator in all five rounds. Production, label-only, libc and early-exit
comparisons use the same sample count and input preparation. The 10% crop,
minimum control statistic of 400 and maximum target/control ratio of 0.20
remain unchanged. All five matched control tuples must qualify; the target is
decided from the median statistics. Weak or non-qualifying controls return 77;
measurement or statistic errors return 2. Both outcomes fail `test-all`.

This describes the maintained test update; the immutable `v5.2.10` source
bundle retains its original 200,000-sample test. Use a checkout containing
the expanded test when reproducing this profile. Application code and the
archive format are unchanged.

The earlier 200,000-sample Clang profile in
[CI run 43812347201](https://github.com/cristiancmoises/zupt/actions/runs/43812347201)
was inconclusive: one control statistic was 399.55. That failure remains in
the CI record. The expanded profile completed once with GCC 14.3 and Clang
22.1.8 locally; both accepted the real comparison and rejected a deliberately
leaky target with exit 1. Those runs do not qualify different compilers,
machines or workloads, or establish a constant-time proof. Sampling storage
grows from 12.8 MB to 25.6 MB; repeat the measurement in the target environment.

## Formal verification

The maintained profiles use Frama-C 29.0, Why3 1.7.2 and recognized Z3 4.12.2
with their required GCC machine model, and Jasmin 2026.09.0. Follow each script's
version and architecture checks. The ordinary Jasmin runtime fixtures need the
required AES-NI and OS-enabled AVX features on x86_64 Linux. A missing tool,
unrecognized prover or unavailable required CPU feature is a blocker for that
profile.

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-frama-ans-decode-bounds test-frama-ans-reader \
  test-frama-ans-frequencies test-frama-ans-logarithm \
  test-frama-ans-log-bounds test-frama-aes-nist
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-jasmin-source-wrapper test-jasmin-wipe-checker test-jasmin-source
```

| Frama-C target | Analyzed scope | Important boundary |
|---|---|---|
| `test-frama-ans-decode-bounds` | Actual scalar sequence match-copy path with exact-output-tail fixtures under Eva | Selected scalar paths and input geometry, not every SIMD path or arbitrary decoder input. |
| `test-frama-ans-reader` | Conditional reader init/take WP contracts; 30 exact non-smoke goals | Buffer, bit-state and caller preconditions remain obligations outside the model. |
| `test-frama-ans-frequencies` | Actual frequency validator; 23 exact non-smoke WP goals | Requires 256 readable initialized frequencies and a separate writable output integer. |
| `test-frama-ans-logarithm` | Scalar shift-based logarithm for `0 <= v < 4096`; 64 exact non-smoke WP goals | Bounded helper theorem; does not prove that every caller supplies the modeled domain. |
| `test-frama-ans-log-bounds` | Eva checks of logarithm ranges used by ANS | Selected range assertions and preconditions, not complete table construction. |
| `test-frama-aes-nist` | Portable AES on four fixed NIST blocks, with 64 output-byte checks | Fixed-vector execution/model coverage, not arbitrary-key AES or the full archive pipeline. |

The five Jasmin units are `mac_verify`, `mlkem_select`, `aes_ctr`, `aes_ctr4`
and `x25519_fe`. The source gate runs its safety, constant-time, DOIT and lowering
checks, compares regenerated instructions with checked-in assembly, and executes
generated AES fixtures against reference outputs. Caller preconditions, buffer
sizes and aliasing assumptions remain part of the result. Wipe-store checking
covers the pinned emitted sequence, not register erasure or physical side
channels. C sanitizer fixtures do not instrument assembly or provider programs.

`WITH_JASMIN=1` runtime integration must be qualified separately. Neither that
flag nor an assembly-only test establishes source verification, and source
verification does not qualify every final packaged binary.

### ANS exact-output bounds

Run `make test-ans-decode-bounds` for native exact-tail regressions and
`make test-ans-allocation` for allocation, reader and table checks. The tests
cover the maintained malformed metadata cases, two-symbol frequency splits and
a uniform 256-symbol table. They do not prove arbitrary three-or-more-symbol
tables, all source spans or every caller contract.

General table construction, width/count invariants, source spans, refill and
caller obligations still need a traceable disposition. An exploratory broader
ANS WP analysis retained timeouts and warnings; a valid postcondition does not
close unproved loop invariants. Unknowns, alarms and open obligations must be
resolved or explicitly justified in the formal review before publication.

## Test-fixture file handling

Maintained fixtures use private temporary directories, reject unsafe links and
preserve meaningful child/tool failures. Result-parser and injected-failure
controls test the test infrastructure; they are not substitutes for real
compiler, sanitizer, analyzer, package or GUI execution.

Useful focused entry points include `test-fuzz-harness`,
`test-native-key-read-errors`, `sdk-test-read-stop`, `test-packaging-failures`
and `test-dist-source-state`. The in-tree SDK callback tests are part of
`sdk-test`. Run the actual tool or native workflow in addition to any wrapper
or compiler-double regression.

## Experimental Rust varint

The gradual Rust work is limited to `rust/varint`, a separate experimental
`no_std` canonical unsigned base-128 integer library. It has no external crates,
allocation, FFI, build scripts or unsafe code. It is not an archive verifier and
is not linked into the production C11 CLI or installed packages. Normal builds,
`check` and installation do not require Rust.

With Rust/Cargo 1.93 or newer, rustfmt, Clippy, Bash and a C compiler/linker with
function/data-section garbage collection available, run:

```sh
make test-rust-varint
make audit-rust-varint
```

The test target builds an oracle from the actual `src/zupt_format.c` translation
unit, then runs locked/offline Cargo tests in debug and release with two jobs.
It compares successful C/Rust encodings, values and consumed lengths; errors
compare acceptance/rejection rather than C partial-output or stream-position
state. The audit target runs the public Cargo checks:

```sh
cargo fmt --manifest-path rust/varint/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/varint/Cargo.toml \
  --locked --offline --all-targets --jobs 2 -- -D warnings
```

Use the Make test target to prepare the required C oracle. These checks are not
coverage-guided fuzzing or formal verification. Miri, RustSec scanning and a
Rust formal verifier are outside the recorded profile; Frama-C and Jasmin do
not prove this Rust implementation.

<!-- Stable fragment links from earlier editions. -->
<a id="zupt-5210-audit-guide-and-finding-history"></a>
<a id="current-validation-reviewed-2026-11-12"></a>
<a id="earlier-formal-evidence-reviewed-2026-10-30"></a>
<a id="local-precommit-checks-2026-10-28"></a>
<a id="fortified-sdk-test-coverage-2026-10-29"></a>
<a id="earlier-gcc-and-gui-runtime-checks-2026-10-23"></a>
<a id="ans-frequency-validation-checks"></a>
<a id="bounded-ans-logarithm-proof"></a>
<a id="earlier-2026-10-23-qualification-repeat"></a>
<a id="prior-522-committed-candidate-local-linux-evidence"></a>
<a id="prior-524-exact-tag-integration-evidence"></a>
<a id="prior-525-exact-tag-native-gate-evidence"></a>
<a id="prior-526-exact-tag-native-gate-evidence"></a>
<a id="prior-527-exact-tag-native-gate-evidence"></a>
<a id="528-codeql-high-path-race-corrections"></a>


## Recorded validation and historical results

The following records have revision-specific scope. They are not approval of a
later source tree, package set or platform, and do not replace a release's
signed source, current CI and artifact checks.

| Record | Observed result | Limit |
|---|---|---|
| 5.2.10 source `31fb1d6`, [Linux CI](https://github.com/cristiancmoises/zupt/actions/runs/43746152365) and [native package CI](https://github.com/cristiancmoises/zupt/actions/runs/43746354466) | 13 Linux jobs and the two native Windows/macOS package jobs completed successfully. | Separate diagnostic jobs/wrappers were skipped; these results predate subsequent documentation changes. |
| 5.2.10 source `31fb1d6`, local maintained formal checks | Six Frama-C targets and the five-source Jasmin gate completed within the recorded aggregate source check. | Only the models and assumptions above; optional/platform skips and final-artifact obligations remain separate. |
| 5.2.10 follow-up at `7c7fff7`, Linux with Guix | Three ML-KEM-768 interoperability checks passed against OpenSSL 3.5.9. All 45 completion and manual-page checks passed with zero skips. The Nix and Guix recipes parsed, and the Guix staged CLI/GUI phase test passed. The ML-KEM and completion inputs match the release tag. | The separate bounded run of the full packaging suite timed out. External SDK/PQBOX and privileged loop-device cases were outside this follow-up. |
| Earlier bounded continuous-fuzz campaign | Failed its resource limit; individual replay inputs later completed. | A replay is not a successful continuous campaign, and later passes do not reclassify that failure. |
| Broader exploratory ANS table WP analysis | Incomplete: timeouts and warnings remained. | Not a general decoder/table proof; unproved invariants remain open. |
| 5.2.2–5.2.7 candidates | Not promoted after the recorded source-policy, service-directory or native fixture failures/cancellations. | Immutable historical candidates, not substitutes for current source or package evidence. |
| 5.2.8 [exact-tag CI](https://github.com/cristiancmoises/zupt/actions/runs/33456209269) and [promotion](https://github.com/cristiancmoises/zupt/actions/runs/33457868306) | The recorded 15-job matrix passed and the tested asset set was promoted. | Applies to that release's source, signatures and original formats only. |

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
5.2.8 test result.

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
| 5.2.2 | Documentation/licensing | Earlier documentation incorrectly denied historical MIT grants visible in published Git history | Added a factual erratum: current source follows current SPDX notices, while earlier grants and immutable tags remain valid and unmodified |
| 5.2.8 | High | CodeQL #5: SDK key copies changed permissions through a re-resolved destination path | Publish through the core atomic output object and apply permissions to its open descriptor; run link-target/mode regressions through `sdk-test` |
| 5.2.8 | High | CodeQL #6: POSIX disk restore classified a pathname before reopening it destructively | Open without truncation or symlink following, classify with `fstat`, and retain the same device descriptor through write |
| 5.2.8 | High | CodeQL #7: benchmark cleanup classified entries before recursively resolving their path | Traverse pinned descriptors/handles, refuse link/reparse traversal, remove entries relative to pinned parents, and verify Windows directory identity before handle deletion |
| 5.2.8 | High (test-only) | CodeQL #8/#9/#10: the new SDK regression inspected paths before later reads or cleanup | Open each fixture without following links, inspect/read through `fstat` and the same descriptor, and reject path-level `stat`/`lstat` in the static gate |

See `CHANGELOG.md` for the complete per-release history and compatibility notes.
Old tags remain immutable and may contain artifacts or build assumptions removed
from current branches and new tags.

## Packaging review

Build packages from the signed source revision with declared system dependencies,
preserve distribution flags and debuginfo, run a real package check, and install
through `DESTDIR`. Inspect dependencies, paths, permissions, RPATH/RUNPATH,
hardening, debug information, licenses and unowned files. Test installation,
round trips and removal in a disposable native target environment.

The five public bundles use genuine unencrypted level-9 `.zupt` containers;
DEB/RPM/SRPM retain their native formats. Internal tar/ZIP/DMG inputs and CI
artifacts must be bound by hashes to the final assets. A cross-build, extracted
package check, offscreen GUI run or Wine result does not replace the required
native platform/package gate. Unsupported Windows extended/device paths, raw
UNC output roots and mapped/network-drive outputs remain outside the support
boundary.

See [DISTRIBUTION.md](DISTRIBUTION.md) for source exports, required notices,
artifact types and release conditions.

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
