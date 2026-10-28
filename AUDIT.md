<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ZUPT 5.2.10 audit guide and finding history

This document describes review surfaces and reproducible checks. It is an
upstream self-review, not an independent audit, certification, or guarantee.
`SECURITY.md` defines reporting policy and `THREAT_MODEL.md` defines the
security boundary.

## 5.2.10 scope

Fresh local candidate checks on 2026-09-30 passed the source-only `make check
sdk-test`, `make test-asan-run` ASan/UBSan smoke test, and all 54 packaging
syntax checks. The canonical allocator-limit regression was compiled against
this consumer's codec and passed all 432 cases, including NULL empty inputs.
Optional dependency and unavailable platform SKIPs are not passes. These
results are local candidate evidence, not signed release-asset approval.

The baseline scope is the source-only CLI and its bundled source codec:

- first-party C and headers under `src/` and `include/`;
- textual architecture-specific source under `jasmin/`, distinguishing
  compiler-generated output from separately identified hand-written assembly;
- VaptVupt codec source at release 2.65.13, commit
  `e30dc9329be7cf9f233b1ac0b1fc9ed31f530391`, with provenance and licensing in
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

## Current formal evidence, reviewed 2026-10-28

The 2026-10-24 UTC runs of all six maintained Frama-C targets pass on the
frozen 294-file source after the five ANS guard corrections: decoder bounds,
reader, frequencies, logarithm, logarithm bounds and fixed-vector AES. The
tools are Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 and recognized Z3 4.12.2.
Each target retains its own model, caller assumptions and exact result
checks; these conditional results do not prove the whole application.

The 2026-10-27 UTC ordinary Jasmin 2026.09.0 repeat on the same source
passes compilation, safety, CT, DOIT, lowering and generated/runtime
instruction comparisons for all five selected sources. Seven tools/libraries
match the pinned package members. Two environment rejections, four warning
controls, seventeen wipe controls, 1,026 AES/OpenSSL blocks and 1,539 CTR4
cases pass. This is selected source qualification under the documented
preconditions, not whole-program verification, final-package acceptance or
the separate `WITH_JASMIN=1` application integration check. Raw logs and
source/tool integrity checks are retained. Later documentation edits are
outside the measured snapshot.

## Local precommit checks, 2026-10-28

On the subsequent 294-file source snapshot, the actual static-analysis script
passes nine checks with GCC 14.3.0; its three optional cppcheck scans are
`NOT RUN` because cppcheck is absent. Distribution-state controls pass 17
cases, publication tests pass 21, and DEB/RPM helper controls pass 20/55.
The source-policy scan passes over 294 files and zero archives. Source, tool
and supervisor integrity checks pass before and after execution. Package
helpers use tool doubles; these results do not qualify native installations.
Later documentation and signing-key instructions are outside that snapshot.

## ANS exact-output bounds

Five sequence-copy guards now compare the remaining destination length before
forming wide-copy pointers. API and frame grammar are unchanged. The retained
three malformed metadata fixtures and five exact-output sequence cases pass
`test-frama-ans-decode-bounds`: Frama-C 29.0, production scalar path,
`gcc_x86_64`, 558/983 statements in 16/95 functions, zero alarms and 63 valid
preconditions with zero unknowns or invalids. Six exact fixture witnesses
exclude allocation-only or pruned-success approvals. All 82 synthetic result
controls pass. Restoring only the four old match guards in a private control
produces four invalid-pointer alarms and the Makefile target rejects it.

The analysis uses Frama-C libc models and raw-literal sequences with
single-symbol sequence tables. It is not a general decoder, Huffman or SIMD
proof; native and sanitizer runtime checks remain separate. Reproduction
commands and assumptions are in the [English guide](docs/USER_GUIDE.md#ans-exact-output-bounds)
and [Portuguese guide](docs/GUIA_USUARIO.pt-BR.md#limites-ans-com-saída-de-tamanho-exato).
The corrected 294-file source passed strict GCC 14.3.0 and Clang 22.1.8
`test-all` plus the in-tree SDK, license and symbol targets on 2026-10-27 UTC.
Both compilers also passed focused native and scalar/AVX2 ANS exact-output
ASan/LSan/UBSan tests. A separate GCC `WITH_JASMIN=1` build passed the full
suite and SDK targets with verified `Jasmin AES-NI` vector dispatch. Each
profile records 15 explicit skips and passed isolation, real sanitizer
negatives, diagnostic and source/input-integrity checks. No product stage
recorded OOM, a PID-limit event or a surviving descendant. These are bounded
self-review results; full `release-check` and final-package acceptance remain
pending. The guides record reproduction commands, omissions and retained
earlier image/time-limit failures.

The following earlier full-suite results predate these five guard changes.
Full `release-check` and final-package acceptance remain separate requirements.

## Earlier GCC and GUI runtime checks, 2026-10-23

On 2026-10-23 UTC, the actual strict GCC 14.3.0 `test-all` passes on a frozen
294-file source snapshot in the disposable 2-CPU/2-GiB VM. Its 15 explicit
skips cover native Windows, privileged devices, unavailable shell/manual
tools, the Clang-specific ABI model and optional external integrations.
The run includes 81 ASan exact-size cases, 1,024 BCJ bijections, byte-exact
BCJ L5/L9 round trips, timing regression and three ML-KEM/OpenSSL comparisons.
The ordinary CLI is not wholly instrumented by that ASan test.

A separate VM passes 64 current GUI tests, 33 historical reference tests and
six bootstrap controls with PySide6/Shiboken6/Qt 6.9.2. The compiler is kept
outside this smaller guest: a bounded compile-only namespace produces the
byte-identical CLI and sanitizer controls, which execute only in the VM.
All 16 isolation controls, three real sanitizer negatives, ordered completion
records, diagnostic gates and source/input checks pass. The target envelope
remains 768 MiB, 16 tasks and 512 MiB of scratch space.

The old Qt inputs are absent. A full Qt image hit the existing 128-MiB file
limit before VM creation; that failed attempt remains recorded. The smaller
runtime image fits without increasing any limit or dropping runtime library
dependencies. An earlier comparison against a decoder predating the current
literal bounds also failed; the corrected private reference tests only the
cast changes and retains all four bounds. No executable project code changed.
These are automated self-review results, not an independent audit. Final
documentation follows the runtime snapshot. Fresh Clang repetition, broader
formal review, full `release-check` and final-package acceptance remain pending.

## ANS frequency-validation checks

`make test-frama-ans-frequencies` is a required `release-check` dependency.
The 2026-10-22 Frama-C 29.0/recognized Z3 4.12.2 run passes 23 exact WP JSON
goals, including three unsigned-overflow conditions, under initialized,
readable and separated-input assumptions. The guarded annotations do not
change the C body or replace caller analysis in other profiles. Reader and
metadata gates retain their previous exact results. A private acceptance
mutation is rejected with one unproved postcondition; that is not a solver
counterexample or proof of caller safety.

Strict scalar GCC 14.3.0/Clang 22.1.8 tests pass eight new frequency vectors
and 80 synthetic reporting controls. The direct 79,560-state ANS suite and
eight vectors also pass ASan/LSan/UBSan in the bounded disposable VM, with
real negatives and exact source/object/ordered-completion checks. Separate
CLI/SDK/interoperability checks pass in their stated profiles. A private
16-bit accumulator mutation passes old tests and fails the new wrap case.
See the English/PT-BR user guides for reproduction commands and assumptions.
Final documentation is outside these runtime snapshots. These checks do not
establish general ANS caller safety or qualify full suites, final packages,
the complete program or production release. The earlier 14-unknown count is
historical, not a refreshed inventory of today's tree.

The subsequent decode-table test checks 16,785,408 entries over all 4,097
frequency splits between symbols 0/255 and a uniform 256-symbol table. Strict
scalar GCC/Clang and bounded-VM ASan/LSan/UBSan runs pass; a targeted private
width mutation passes old tests and fails the expanded test. The private WP
table experiment is not adopted: 109 valid JSON goals, 17 timeouts and three
`memset`/Typed-model warnings remain. A dependent postcondition marked valid
does not discharge unproved loop invariants. These are proof gaps, not 17
confirmed vulnerabilities. The new runtime coverage is finite-family
characterization, not a general table, caller or complete-decoder proof.

## Bounded ANS logarithm proof

`make test-frama-ans-logarithm` is now a required `release-check` dependency.
It analyzes the original shift-based `ilog2`, not the rejected division
variant. Guarded annotations require an input below 4096 and establish zero
handling, result range 0–11 and the exact power-of-two interval for each
positive input. They do not change the helper's runtime behavior or impose a
new public caller contract. Callers outside this bounded profile still need
their own analysis.

Frama-C 29.0, Why3 1.7.2 and recognized Z3 4.12.2 pass all 50 exact JSON
goals and the 52/52 console summary. The redundant OR-bound loop invariant
exposes WP's existing mask/addition relation. Its establishment and
preservation are separately proved through the native bit-range tactic;
neither is assumed. Raw scripts and JSON remain in the gate output.
An intentionally false postcondition is rejected with analyzer status zero
but gate status one. Reader and frequency profiles retain their 30 and 23
exact valid goals.

The result validator now rejects non-integer, zero or multiple `subgoals`
when a row claims just one proved goal. The actual two-line omission fails
nine of 132 synthetic controls; the corrected gate passes all 132 with GCC
and Clang. These controls reject an unknown mask invariant even while the
postcondition rows remain valid. Synthetic reports are not C proofs.

Strict GCC 14.3.0 and Clang 22.1.8 `check` plus installed-CLI functional smoke
pass on the integrated 294-file snapshot, with 11 and 10 explicit skips.
Each run first rejects a real fatal UBSan overflow control. This qualifies
the contained UBSan fuzz-build checks, not a fully instrumented CLI or new
ASan/LSan campaign. Skips cover native Windows, five external-SDK cases,
privileged loop devices, unavailable zsh/fish/manual tools and, for GCC only,
the Clang-specific bionic model. GCC preprocessing remains byte-identical
across default/frequency/logarithm profiles. Scalar whole `-O2 -g0` objects
match baseline with each selected compiler, GCC and Clang.
Runtime C, API, ABI and wire format are unchanged. Table construction,
general callers, whole-program correctness, complete `test-all`/
`release-check`, platform packages and production approval remain separate.
Final documentation is outside the runtime snapshot. See the EN/PT-BR user
guides for the commands and exact proof assumptions.

## Earlier 2026-10-23 qualification repeat

The ordinary Jasmin 2026.09.0 source gate passes again on the captured
294-file source snapshot. The five safety/constant-time/DOIT analysis groups
and regenerated/runtime instruction comparisons pass, as do 1,026 AES block
cases and 1,539 AES4 cases. Three executables and four APRON libraries match
the retained hash-pinned package members. Two exact environment rejection
controls, four synthetic warning-screen controls and seventeen wipe-checker
controls also pass. The namespace retains two-CPU affinity, 1 GiB per-process
address space, 120 CPU seconds, a 125+5 second outer deadline and 128 MiB
scratch. These are not aggregate cgroup quotas. No tools were installed.
This repeat is not new UBSan coverage, application integration, a fresh
upstream signature audit, a C caller proof or final-package qualification.

At that earlier checkpoint, the ANS floor-log investigation remained private
and incomplete. A bounded
division-by-two variant passes 48 exact WP JSON goals (50/50 console), but
its GCC whole object differs from the maintained shift variant under the
same `-O2 -g0` profile. It was not adopted. A deliberately false postcondition
is rejected by the exact-result gate despite analyzer exit zero. Object
inequality alone is neither a functional failure nor a measured performance
regression. The maintained C, API and wire format remain unchanged.

With the original shift restored, scalar GCC/Clang ANS tests pass again,
including the 79,560-state reader and 16,785,408 table entries. Preprocessed
C and whole objects match the baseline in their stated comparison profiles.
The private reporting extension passes 120 synthetic controls; those test
the supervisor, not the C theorem, and are not a new published proof gate.
At that snapshot the stronger shift-based proof still timed out on bit-mask
reasoning, so no experimental annotations or refactorings were adopted.
The later bounded proof above resolves this helper profile only.
Historical results remain separate; these checks do not close general table
or caller obligations, full release checks, packages or production approval.
Final documentation is outside these runtime snapshots.

## Source-only review

The 5.2.10 baseline retains the source-only boundary introduced in 5.2.2, which
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
scripts/check-source-only.sh --tag v5.2.10

# generated source archive
scripts/check-source-only.sh --archive /path/to/zupt-5.2.10.tar.gz
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
make sdk-test
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
| SDK key publication | `make sdk-test` | Exercises atomic descriptor/handle-backed key copies, POSIX private/public modes, and symlink/hardlink target preservation; this now runs in `release-check` and hosted GCC/Clang Linux CI |
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
not independent certification, a 5.2.8 result, or evidence that release assets
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
represented as an exact-`ff99770` GUI-package result. The immutable 5.2.3
candidate was not promoted because its source-policy test assumed LF for a
Windows `.bat` checkout that correctly used CRLF.

## Prior 5.2.4 exact-tag integration evidence

GitHub Actions exact-tag run `33431386002` completed 12 jobs successfully. Its
sole failed job was the openSUSE gate: the standalone `Serviceinfo` harness did
not change into the directory containing `_service` before executing the
service chain. Dependent native Windows and macOS jobs were therefore skipped,
and v5.2.4 was not promoted. The tag and its record remain immutable.

A separate local openSUSE Tumbleweed reproduction resolved the explicit
`refs/tags/v5.2.4` revision to the tagged commit and, after
`os.chdir(service_dir)`, completed `obs_scm`, `tar`, and `recompress`. It
produced exactly one `zupt-5.2.4.tar.gz`, which passed the source-only scanner.
This isolates a release/test harness defect; it is not evidence of a product,
archive-format, cryptographic, codec, or SDK ABI change. It also does not turn
the skipped native jobs into passes or transfer any result to 5.2.8.

## Prior 5.2.5 exact-tag native-gate evidence

The immutable `v5.2.5` candidate was not promoted. Exact-tag GitHub Actions run
`33434986357` completed 13 jobs successfully, while its native Windows and
macOS jobs failed. The Windows regression did not preserve every requested
hostile path byte across its command-line boundary. The macOS gate exposed both
an unavailable `explicit_bzero` assumption and Bash 3.2 empty-array behavior in
the source scanner exercised by `make check`.

The 5.2.6 corrections select the existing compiler-resistant volatile wipe on
Darwin and NetBSD, guard every relevant scanner array, and make the Windows
fixture accept explicit hexadecimal bytes, verify the full requested path in
the archive, and reject each dangerous raw byte fragment anywhere in diagnostic
output. These changes do not alter the archive format, cryptography, bundled
codec, or SDK ABI.

A separate local compatibility run executed the corrected scanner with genuine
GNU Bash 3.2.57 in a clean clone. All four exercised modes completed: the
repository audit reported 609 files and one archive; `--tree` reported 204/0;
`--archive` reported 201/1; and `--root` plus `--tag v5.2.5` reported 810/2.
This is targeted scanner compatibility evidence only, not exact-v5.2.6 or
v5.2.8 hosted CI, package, native-platform, or promotion evidence.

## Prior 5.2.6 exact-tag native-gate evidence

The immutable `v5.2.6` candidate was not promoted. Exact-tag GitHub Actions run
`33442264243` completed 13 jobs successfully and failed two native jobs. On
macOS arm64, the strict SHA-NI regression build diagnosed x86-only helper
declarations as unused under `-Werror`. On Windows, argv transcoding of the safe
printable UTF-8 fixture caused the path regression to abort before its intended
archive and diagnostic assertions.

The 5.2.7 changes scope those helper declarations to supported x86 builds and
carry the safe UTF-8 fixture across the Windows argument boundary without
locale-dependent byte conversion. These are test/release integration changes,
not archive-format, cryptographic, codec, or SDK ABI changes.

## Prior 5.2.7 exact-tag native-gate evidence

The immutable `v5.2.7` candidate was not promoted. Exact-tag GitHub Actions run
`33445470664` concluded `cancelled` at `2026-08-31T23:11:19Z`, with 13
successful jobs, one failed macOS job, and one cancelled Windows job. The macOS
runner filesystem rejected creation of the
raw-C1 filename fixture with `EILSEQ`. The hosted Windows job stalled in `make
check`; a MinGW/Wine reproduction isolated the cause to
`test --password-prompt ... </dev/null` entering `_getch`, and the remaining
native job was cancelled.

The 5.2.8 fixture treats that creation refusal as an explicit `SKIP`; on a
filesystem that accepts the byte, the scanner must still reject the compiled
magic and render the path without emitting the raw C1 byte. No result from the
immutable tag transfers automatically to 5.2.8. The Windows prompt correction
rejects a redirected/non-console standard input before entering `_getch` and
adds a native EOF regression; it also requires fresh exact-candidate evidence.

## 5.2.8 CodeQL High path-race corrections

CodeQL High #5 identified SDK key-copy publication that reopened the output
path and then applied `chmod` to that mutable name. The copy now uses the core
atomic publisher, sets POSIX mode on the open temporary descriptor, checks
read/close/publication failures, and replaces only the destination directory
entry. `sdk-test` covers symlink and hardlink sentinels and expected key modes.

CodeQL High #6 identified the POSIX disk-restore `lstat`-then-`open` sequence.
Restore now opens once with `O_NOFOLLOW` and without truncation, classifies that
descriptor with `fstat`, and retains the same raw-device descriptor through
capacity checks and writes. Regular-file destinations retain the existing
atomic publisher.

CodeQL High #7 identified benchmark cleanup's `lstat`-then-recursive-path
sequence. POSIX cleanup now pins each component with `openat` and removes leaves
with `unlinkat`; Windows pins ancestors/children, opens reparse points without
following them, recurses only into a plain directory held against rename, and
after emptying a directory reopens it relative to the pinned parent, verifies
its volume and file index against the traversal handle, and marks only that
identity-checked handle for deletion. The live-workspace
regression injects a directory symlink and verifies that its external sentinel
survives. These are reviewed fixes and regression coverage, not independent
certification by themselves; the exact-tag evidence is recorded below.

The C/C++ default-branch analysis of commit `69fc26b` closed #5, #6, and #7,
then reported High #8, #9, and #10 solely in the newly added SDK regression:
its sentinel and mode checks used `stat`/`lstat` before later path operations.
Each individual content or metadata check now opens without following links
and uses `fstat` or reads through that already-open descriptor. A static guard
rejects a return to path-level `stat`/`lstat` in this test. The subsequent
C/C++ default-branch scan run `33452563116` completed successfully at commit
`7a8e5c5`; alerts #5 through #10 are fixed, and the authenticated
code-scanning API reported zero open alerts.

Manual pre-tag CI run `33452602634` at the same functional commit completed 14
of 15 jobs successfully. Linux compilers, analyzers, sanitizers, source policy,
reproducibility, DEB, RPM/SRPM, portable bundles, and the native macOS DMG gate
passed. On Windows, source audit, build, and `make check` passed; the subsequent
smoke failed only when the old MSYS `grep` tried to match a literal non-BMP
filename after ZUPT had compressed and verified all five inputs. Independent
MinGW/Wine reproduction confirmed that the redirected ZUPT listing contained
the exact UTF-8 bytes. The gate now creates the non-BMP name through byte
escapes, verifies Latin-1/BMP/non-BMP listing bytes without locale-sensitive
matching, and requires extraction plus a full tree diff. The path-confinement
regression independently constructs the BMP/non-BMP archive name from ASCII
hex and requires byte-exact listing and extraction.

Because that pre-tag run failed, it remains diagnostic evidence rather than
release approval. The immutable `v5.2.8` tag at
`ebb9ab3aa1d42c50030ca02883f6162dc4771fe1` repeated the complete suite in
manually dispatched run `33456209269`: all 15 jobs passed, including native
Windows/macOS, the pinned local OBS service chain, source reproducibility,
DEB/RPM/SRPM, installed-package, sanitizer, analyzer, and source-only gates.
The canonical source archive was reproduced at 798296 bytes with SHA-256
`378b9506211545b9594cf0d38ac8955d9b1cac34eb6b379ae0ec26b84edb65f7`.

Initial promotion run `33457344882` stopped before release creation because
its validator incorrectly assumed that an SRPM's `%{ARCH}` must be `src`.
Both artifacts were genuine source packages: `%{SOURCEPACKAGE}` was `1`,
`%{SOURCERPM}` was absent, each payload was exactly its Source0 plus spec, and
each binary RPM referenced the matching SRPM. Commit `33eb904` changed the
gate to those canonical metadata and payload checks. Corrected promotion run
`33457868306` then validated the same tag-bound artifacts and published exactly
13 assets. No asset was rebuilt to pass promotion. These are reproducible
project records, not independent certification.

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
| 5.2.2 | Documentation/licensing | Current documentation incorrectly denied historical MIT grants visible in published Git history | Added a factual erratum: current source follows current SPDX notices, while earlier grants and immutable tags remain valid and unmodified |
| 5.2.8 | High | CodeQL #5: SDK key copies changed permissions through a re-resolved destination path | Publish through the core atomic output object and apply permissions to its open descriptor; run link-target/mode regressions through `sdk-test` |
| 5.2.8 | High | CodeQL #6: POSIX disk restore classified a pathname before reopening it destructively | Open without truncation or symlink following, classify with `fstat`, and retain the same device descriptor through write |
| 5.2.8 | High | CodeQL #7: benchmark cleanup classified entries before recursively resolving their path | Traverse pinned descriptors/handles, refuse link/reparse traversal, remove entries relative to pinned parents, and verify Windows directory identity before handle deletion |
| 5.2.8 | High (test-only) | CodeQL #8/#9/#10: the new SDK regression inspected paths before later reads or cleanup | Open each fixture without following links, inspect/read through `fstat` and the same descriptor, and reject path-level `stat`/`lstat` in the static gate |

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

New public source and Linux CLI archives use verified, unencrypted `.zupt`
files with signed SHA-256 manifests. Fresh DEB/RPM/SRPM outputs require their
own builds, payload/dependency checks and extracted or installed smoke tests.
Internal RPM/OBS tarballs and CI artifacts are build/audit inputs rather than
new public release downloads. AppImage is not promoted by the 5.2.10 policy;
unbuilt GUI installers, bare executables and untested Windows/macOS binaries
are excluded. Historical platform evidence is not inherited by this version.

No Wine result is retained as release evidence for 5.2.10. Cross-compilation
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
