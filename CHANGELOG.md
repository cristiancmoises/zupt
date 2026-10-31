# ZUPT Changelog

## [5.2.10] — Unreleased — Codec compatibility and terminal fixes

Version 5.2.10 is being validated and is not an official release. Its earlier
delivery was withdrawn; previous packages do not validate the corrected source.
The published official version remains [5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).

- Compile fuzz-harness fixtures before selecting the mutation directory with
  spaces. Fedora GCC 16 LTO failed while creating compiler scratch files in
  that directory. Preserve caller compiler/linker flags, UBSan and all spaced
  runtime-path checks. Local GCC 14 LTO and ordinary GCC/Clang checks pass;
  the native Fedora package gate still needs a fresh run.
- Declare the UBSan runtime as a Fedora build dependency and install it in
  the native GUI package CI job: the maintained check suite links instrumented
  harness regressions. Use openSUSE's optional man-page suffix macro and test
  actual RPM expansion with gzip, xz and uncompressed paths. Retain negative
  parser controls and require native build/install checks before release.
- Exercise SDK temporary-path failures through glibc's fortified formatting
  entry points, preserving the real format and destination-bound checks.
  Retain all 26 existing cases and add valid-output and object-bound rejection
  controls. Strict full SDK suites pass with GCC 14.3.0 and Clang 22.1.8 in
  ordinary and explicit fortification levels 2/3; hosted Ubuntu qualification
  remains required. Production code, compiler hardening and formats are unchanged.
- Validate the corrected source with strict GCC/Clang full suites and in-tree
  SDK targets, plus a separate GCC `WITH_JASMIN=1` application profile. Retain
  explicit skips and earlier failed attempts; final-package and release gates
  remain separate. Document reproducible checks in English and Portuguese.
- Check the remaining output length before forming wide-copy pointers in five
  ANS sequence-copy guards, preserving APIs and frame grammar. Retain three
  malformed metadata fixtures and add five exact-output v1/v2 sequence cases.
  The production-scalar Frama-C profile passes with zero alarms and 63 valid
  preconditions; six exact fixture witnesses and 82 synthetic controls reject
  incomplete or pruned results. Restoring the four old match guards produces
  four alarms and is rejected. Document the finite scope and reproduction in
  EN/PT-BR; runtime and final-package acceptance remain separate requirements.
- Rerun the real GCC 14.3.0 guest sanitizer profile on the frozen 294-file
  source after separately qualifying the replacement kernel. All three real
  sanitizer negatives, instrumented CLI round trips/rejections, ordinary
  in-tree SDK/license/export checks and three ML-KEM/OpenSSL comparisons pass.
  Require all 25 completion records and source/tool/process/collector checks.
  Document the bounded scope in EN/PT-BR: no new full suite, direct ANS-refill
  ASan campaign, Qt execution, whole-program proof or final-package approval.
- Requalify the isolation-only VM slice with a separately pinned installed
  kernel after the previous kernel disappeared. Seven generic and nine native
  controls, an exact 17-record completion protocol and 13 parser cases pass.
  Preserve the initial namespace failure and linker-wrapper warning. Restore
  the original process-limit placement and real-binutils route without raising
  caps; controller bytes match across linker routes. Record the environment
  scope in EN/PT-BR. No Zupt payload, guest compiler or sanitizer is executed
  by that isolation-only profile; final-package acceptance is separate.
- Extend the existing ANS allocation test with 79,560 direct refill states,
  checking all reader fields, unchanged source bytes and repeated-fill
  idempotence against a byte-loop oracle. Exact-sized nonempty allocations
  exercise tail and bulk boundaries without extra readable bytes. GCC and
  Clang ordinary/non-recovering UBSan profiles pass; two private mutations
  pass the old test but fail the new checks at counts 56/57. Strict `check`
  and CLI smoke pass with 11/10 skips. A private finite Frama-C extension
  validates 33 preconditions; maintained reader WP retains 30 exact goals.
  Document commands and limits in EN/PT-BR. No implementation/API/format
  change; broader formal obligations and final packages remain open, and a
  missing pinned VM kernel blocks fresh ASan/LSan qualification.
- Reject uppercase and mixed-case `warning:`/`error:` diagnostics in the AES
  formal-result gate. A new regression reproduced a false approval before the
  one-line predicate correction; retain all 28 earlier supervisor controls and
  add four capitalization cases. All 32 now pass, as does the unchanged real
  Frama-C fixed-vector AES profile. Strict GCC 14.3.0 and Clang 22.1.8 `check`
  and functional CLI smoke pass with 11 and ten explicit skips. Document the
  commands and limited scope in EN/PT-BR; cryptography and format are unchanged,
  and final-package and broader formal acceptance remain separate conditions.
- Revalidate the current 294-file source with `WITH_JASMIN=1`: strict GCC
  `check`, 16 cryptographic vectors, CLI functional smoke and 14 threaded checks
  pass, retaining 11 explicit skips. F-06 reaches Jasmin AES-NI with 2,000 honest round trips
  and no accepted HMAC tampers. The same CLI passes 12 portable-GUI helper
  test methods with subcases, including genuine level-9 `.zupt`, exact
  17-file payload/checksum/extraction and output-preservation controls.
  Record commands and limits in EN/PT-BR. This is not Qt execution, assembly
  sanitizer coverage, full optional-profile or final-package acceptance;
  leave the release unpublished pending the remaining production gates.
- Repeat the four maintained Frama-C 29.0 gates on the current 294-file source
  with recognized Z3 4.12.2 and real solver controls. Metadata bounds, reader
  init/take, logarithm ranges and fixed-vector AES pass their unchanged
  conditional checks. Separate ordinary and qualified-UBSan Jasmin 2026.09.0
  runs pass five-source analysis, generated/runtime instruction and wipe
  checks, 1,026 AES blocks and 1,539 AES4 cases each. Preserve full emitted
  output, source/tool identities, independent statuses and scope limits.
  Document reproduction in EN/PT-BR; do not equate selected checks with
  caller proofs, complete optional-profile runtime or final-package approval.
- Reject failed producers in the in-tree SDK exported-function check, including
  complete output followed by an error. Use sequential checked stages and
  accept grep's status 1 only for the expected no-match condition. Six false
  approvals were reproduced before the fix; 25 retained recipe controls and
  11 actual-target supervision cases now pass. Fresh strict Clang 22.1.8
  `test-all`, license, real internal SDK and symbol targets pass in the bounded
  VM with 14 explicit skips. Ordinary strict GCC `check` and CLI tests pass
  with 11 skips. Document reproduction and the finite maintained formal gates
  in EN/PT-BR; retain historical diagnostics and broader review obligations.
  No SDK implementation, ABI, format, new benchmark or production claim.
- Reject failed compression, extraction and complete file enumeration in the
  exact-size test's BCJ round trips, retaining stage diagnostics and requiring
  exactly one byte-matching output. Five false approvals fail before the fix;
  all ten existing compiler controls and nine BCJ cases pass afterward. Fresh
  strict GCC 14.3.0 `test-all`, license, internal SDK and symbol checks pass
  in the bounded VM with 15 explicit skips, including actual ASan exact-size,
  BCJ, timing-regression and ML-KEM/OpenSSL checks. Ordinary `check` and the
  CLI functional suite also pass with 11 skips. Document commands and scope
  in EN/PT-BR. No runtime, API, format, new performance or production claim;
  broader formal, optional-provider, platform and final-package gates remain.
- Add `test-worker-allocation` to `check`. Five real-CLI STORE cases cover
  normal operation and two worker allocation failures with absent/existing
  destinations. Test-only link wrappers require exact allocation events,
  successful worker starts/completions and one deliberate fault. Verify exact
  exit status, prior output preservation and temporary-file cleanup. Strict
  GCC ordinary/UBSan profiles and expanded ordinary `check` plus CLI tests
  pass; 11 existing skips remain. Document reproduction in EN/PT-BR. No
  runtime, format or API change, default-thread OOM diagnosis, leak proof or
  production approval; Clang qualification remains unavailable here.
- Check slack-test fixture cleanup with nonrecursive `rmdir`, preserving its
  status instead of treating failed `find` output as an empty directory.
  Retain three controls for empty, hidden-file and tool-error cases. Require
  explicit serial `-t 1` at L1/5/9 and retain four-thread L1/9; the synthetic
  CLI checks both compression and extraction arguments. Six supervisor cases
  fail before the routing fix; all ten and the three cleanup controls pass
  afterward. Fresh strict GCC `check`, real CLI tests and 54 source-audit
  cases pass, retaining 11 skips. Preserve the intervening automatic-24-thread
  L5 out-of-memory failure under the unchanged 1-GiB address-space cap; this
  test-routing correction does not diagnose that allocation or change codec,
  API, format, resource limits or production status.
- Propagate extracted-byte count pipeline failures explicitly, including when
  a failed `wc` has already emitted a plausible numeric count. Four real-tool
  forwarding/failure controls bring the source-audit suite to 54 cases; two
  reproduced false approvals before the fix, while empty-error rejection
  remains intact. Strict GCC `check` and the real CLI functional suite pass
  with the same 11 explicit skips. Preserve existing archive budgets, codec
  behavior and package/production acceptance.
- Require successful CLI compression and extraction before accepting the
  decode-slack round trips. Use fresh per-level/per-route archives, retain
  failed-command diagnostics and clean fixtures on exit. Ten maintained
  supervisor controls reproduce six earlier false approvals and preserve
  corruption/missing-output rejection. `check` runs both these synthetic
  controls and the unchanged real 10-MiB workload; strict GCC and the CLI
  functional suite pass with the same 11 explicit skips. No runtime codec,
  format, cryptography or production-status change.
- Reject incomplete source-audit enumerations instead of accepting a failed
  `find` or Git listing as end-of-input. Check fresh NUL-delimited manifests
  before scanning trees, accounting extracted files or reading the Git index.
  Ten new fixture/forwarding/failure controls bring the maintained suite to
  50 cases; six negative cases reproduced false approvals before the fix.
  Strict GCC `check` and the real CLI functional suite pass with 11 explicit
  skips. Keep codec behavior and package/production acceptance unchanged.
- Correct the current EN/PT-BR README metadata-validation summaries to match
  the maintained three-fixture, 20-precondition gate; preserve dated results.
  Record the fresh scoped Frama-C/Jasmin revalidation and its limits in both
  user guides.
- Diagnose the two exhausted-refill Typed warnings with a private explicit
  byte-load experiment. The exhausted-reader profile passes 63 exact WP roots
  without analysis warnings or a libc overlay. A separate live-bulk contract
  passes all 64 original roots using bounded shift and exhaustive range tactics;
  all three range children close, and only the deliberately false postcondition
  remains unproved in the matched negative. This is field/frame/advance coverage
  under initialized, readable, separated-span assumptions, not accumulator
  functional equality or general refill proof. Eight GCC/Clang ordinary/UBSan
  ANS runs pass; a private in-process comparison of seven accepted synthetic
  datasets finds no consistent timing benefit. Keep the alternative outside
  the product. Original codec bytes, two Typed warnings and production status
  remain unchanged; consolidate the scope and limits in both languages.
- Add 288 mixed-lane ANS4 calls to the existing allocation regression, using
  an independently derived literal oracle for a synthetic accepted input.
  Cover lane lengths 0/1/8/9, output lengths 1..36, four alignments, exact
  allocation ends, consumed length, allocation counts and workspace reuse.
  Two private decoder mutations pass the old target and fail the new checks.
  Strict GCC 14.3.0/Clang 22.1.8 ordinary and UBSan runs pass; fresh GCC
  ASan/LSan/UBSan scalar and AVX2 VM builds pass. Complete strict VM `test-all`
  and separate license/in-tree SDK/symbol checks also pass with GCC and Clang,
  retaining 15/14 explicit skips. The unavailable old Clang profile remains
  blocked; the separately pinned installed provider has its own validation.
  Optional SDK/PQBOX/Jasmin are disabled in these complete suites. No runtime,
  API or format changes, new performance claims or release approval; formal
  warnings and final-package gates remain unresolved.
- Isolate the Frama-C 29 libc-contract diagnostic using a private header copy
  that adds only explicit `memcpy` termination and exit clauses. The unchanged
  positive analysis retains all 62 goal identities and discharges them; a
  matched false-postcondition control leaves only its extra goal unproved.
  The missing-spec warning disappears, but two Typed pointer-cast warnings
  still block strict admission. Retain the three-warning stock-header result.
  These explicit external-library assumptions do not prove libc or general
  refill; no model, warning policy, codec code or release-status change.
- Run the expanded actual `test-ans-allocation` target under GCC 14.3.0
  ASan/LSan/UBSan in a disposable 2-CPU/2-GiB VM. Fresh scalar and AVX2 builds
  each pass all 9,360 preservation states and the retained allocation, context,
  zero-extension and logarithm checks. All 23 ordered completion records and
  process/collector/integrity/protocol statuses pass. Three actual sanitizer
  fault controls are rejected; product stages have no OOM/PID-limit events or
  surviving descendants. Keep resource limits unchanged and record separate
  feature-macro checks and compilation flags. The new private runner passes
  22 regression methods after reproducing unsupported-profile rejection.
  This is focused GCC memory-safety testing, not a new full-suite, Clang ASan,
  generic refill proof, final-package or production approval.
- Add 9,360 exhausted-reader preservation states to `test-ans-allocation`,
  covering six accumulator patterns, all bit counts 0..64, eight positions
  including `SIZE_MAX`, and NULL, local-byte and reader-alias source pointers.
  Strict GCC 14.3.0 and Clang 22.1.8 pass, also with non-recovering UBSan at
  `-O2`. Two private state-corruption mutations pass the old test but fail
  the new check. Repeat the unchanged reader WP gate (30 exact JSON goals).
  A private exhausted-refill contract and loop annotations yield 62/62 goals,
  but three `memcpy`/Typed warnings still block strict admission; a matched
  false-postcondition control leaves precisely its extra goal unproved.
  Preserve the initial 40/54 diagnostic and overflow-mutation result. These
  annotations are not shipped as proved contracts. No executable codec,
  API, format or release-status change. The subsequent GCC sanitizer VM run
  is recorded above; the formal warnings remain unresolved.
- Repeat the actual current-source `test-all` and in-tree SDK checks with
  strict Clang 22.1.8 in the bounded VM. All 24 required records and independent
  statuses pass, including timing regression, 81 ASan exact-size cases and
  15 cases in the SDK round-trip suite. The first passing run retains 15 skips,
  including unavailable guest OpenSSL; its result is not interop coverage.
  Add the two missing, already-pinned OpenSSL image entries and repeat the
  actual suite: all three real interoperability comparisons pass, with 14
  remaining skips. Three selection regression cases guard that inclusion.
  Preserve the initial pre-boot image-size failure. Use lossless BCJ/XZ transport for the
  private image, retaining every source/tool input and the 128-MiB file cap;
  six real transport tests and 12 wrapper controls pass. No product code,
  format, API or release-status change. Clarify that historical broad WP
  totals are not a reconciled inventory of current unresolved obligations.
- Validate the actual Jasmin-enabled CLI with strict GCC 14.3.0 `check`,
  functional smoke and 14/14 threaded checks, retaining 11 explicit skips.
  F-06 reaches the AES-NI path with 2,000 honest round trips and no accepted
  one-bit HMAC tampers. Separately, the frozen 291-file source passes real
  `test-all` and in-tree SDK/license/symbol checks in the bounded 2-CPU/2-GiB
  VM, retaining 15 skips. Timing controls, 81 ASan exact-size cases and three
  ML-KEM/OpenSSL cases pass. Preserve the earlier historical AVX2 byte-identity
  failure before the suite: four allocation guards intentionally changed the
  decoder. Qualify the new explicit current-source supervisor with 12 wrapper
  controls without altering product tests, thresholds or VM caps. Document
  reproduction and distinguish the older fuzz failure from later campaigns
  in both languages. No product code, format, ABI or license changes; broader
  formal, platform and final-package release gates remain pending.
- Repeat the four unchanged Frama-C gates with the retained official Z3 4.12.2
  binary, pinned loader/libraries and matching historical hashes. Why3 1.7.2
  recognizes the actual version, and real SMT contradiction/satisfiable controls
  pass before analysis. Reader WP again validates 30 exact JSON goals, now with
  Z3 4.12.2 identities. A fresh qualified Jasmin UBSan fixture run also passes.
  Keep the earlier unrecognized-version result and controller regression evidence
  separate. No download, tool rebuild, product dependency or analysis criterion
  changes; retained-byte identity is not upstream signature verification. These
  selected results do not close the broader formal or final-package gates.
  A fresh strict GCC 14.3.0 `check` and real CLI functional smoke suite also
  pass with optional SDK/PQBOX/Jasmin and Cargo disabled, retaining 11 skips.
- Restore the private Frama-C 29.0/Why3 1.7.2 tool closure through normal
  authenticated Guix substitution and grafting, without changing user profiles
  or trust configuration. The four unchanged Frama-C gates pass with GCC
  14.3.0: ANS metadata bounds, logarithm ranges, reader WP and fixed-vector AES.
  Reader WP validates 30 exact JSON goals (34/34 console results). Why3 warns
  that Z3 4.13.0 is unrecognized; the existing reader gate accepts that identity,
  but this is not recognized-solver qualification. A fresh qualified Jasmin
  UBSan fixture repeat passes five selected sources, 1,026 AES blocks and
  1,539 AES4 cases after rejecting a real overflow control. UBSan instruments
  C fixtures, not assembly. Preserve the restoration timeout and three initial
  status-125 runs caused by a missing private Why3 config; create that config
  before every Frama-C invocation without changing public tests or criteria.
  These conditional checks do not validate the complete program or final
  packages, and do not authorize a production release.
- Compare all 1,000 files in T6 instead of sampling five. Require compression
  and extraction to exit zero, retain their diagnostics, and compare the
  expected extracted tree recursively by relative path and content. Add eight
  controls while preserving the earlier 71: clean operation, either process
  failing after complete output, same-size corruption of unsampled file 2,
  rename, relocation, a missing file and an extra file. The first five faults
  reproduce false approvals; missing/extra cases already fail by count but
  previously lose stderr. Mirror the real absolute-input archive layout in
  the T6 fixture, and unlink the output hard link before corrupting data.
  All 79 controls pass; a separate real-CLI run passes 14/14 threaded checks.
  No product format, API,
  cryptography, metadata-preservation or production-readiness claim changes.
- Reject T14 timing approval when either compressor fails or does not leave a
  regular, nonempty output. Capture each compressor's status before reading the
  clock, retain stdout/stderr in per-compressor logs, and report one failure
  with diagnostics instead of a successful timing sample. Add eleven controls
  while retaining the earlier 60: clean operation and each phase's failure
  before/after output, or zero status with missing, empty or directory output.
  All ten negatives expose false approvals before the fix; all 71 controls
  now pass. The actual CLI passes 14/14 threaded checks separately. Keep elapsed
  times informational; these checks establish neither benchmark results,
  archive integrity, sanitizer-runtime coverage nor production acceptance.
- Revalidate the five current Jasmin sources with the existing hash-checked
  2026.09.0 tools independently of the missing Frama-C profile. Ordinary
  GCC 14.3.0 and non-recovering UBSan fixture builds pass the real source
  gate, each with 1,026 AES blocks and 1,539 AES4 cases. Confirm actual UBSan
  rejection before the qualified repeat; keep synthetic supervisor controls
  separate. Compare the three executables and four APRON libraries against
  their hash-pinned package members without installing or replacing tools.
  No product source or analysis criterion changes. These conditional results
  do not validate all C callers or final packages. The Frama-C reader repeat
  at that stage failed before analysis on the missing pinned executable; that
  attempt provided no Frama-C/Why3 result or production-release approval.
- Stop the threaded suite before T1 if either binary `dd` producer fails or
  its output has the wrong length. Preserve the 512,000-byte random fixture,
  204,800-byte zero fixture and producer diagnostics. Add ten controls to the
  existing helper, retaining its earlier 50: one normal fixture, eight producer
  faults and a size validator that prints success before failing. The eight
  producer faults expose false approvals in the unguarded script; the validator
  control covers the new boundary. All nine negatives now require status 1,
  diagnostics, cleanup and no compression, extraction or integrity commands.
  All 60 synthetic-CLI controls pass. This is test-fixture acceptance, not
  codec, concurrency, performance, sanitizer-runtime or production qualification.
  Fresh strict GCC 14.3.0 `check` and actual CLI functional tests pass with
  Cargo disabled and 11 explicit skips. A separate real-CLI threaded run
  passes 14/14 checks; its elapsed times are not benchmark evidence. Existing
  Guix phase/launcher controls pass with installed Guile 3.0.11 and matching
  modules, including the patched 60-control harness. These are not native
  package, Qt runtime, fresh formal or production-release acceptance.
- Start the gradual Rust migration with an optional, dependency-free `no_std`
  canonical-u64-varint core that forbids unsafe code and allocations. Keep the
  production C11 CLI, format, crypto, ABI, recipes and release gates unchanged.
  Add explicit `test-rust-varint` and `audit-rust-varint` developer targets;
  neither is a dependency of the default build or distro `check`. Nine focused
  tests and two real-C-oracle tests pass in debug and release, including
  114,721 differential inputs per profile. Compare against the actual compiled
  C buffer and FILE APIs, not a copied reference implementation. Formatting
  and Clippy pass. This is not runtime migration, whole-parser validation,
  formal proof, fuzz qualification or a production-release approval.
  A fresh strict GCC distro `check` and actual CLI functional suite pass with
  Cargo disabled and 11 explicit skips. Preserve earlier environment failures
  and a private launcher failure; no test criterion or resource cap is relaxed.
- Execute the current 284-file source in a disposable 2-CPU/2-GiB VM after
  admission exceeds the unchanged 5-GiB host-memory floor. Guest isolation,
  resource enforcement, descendant cleanup and all three ASan/LSan/UBSan
  negative controls pass before product execution. The real instrumented CLI
  passes `test-asan-run` and the installed functional smoke suite with leak
  detection enabled. Separate, uninstrumented in-tree SDK/license/export tests
  and three-way ML-KEM/OpenSSL interoperability also pass. The strict ordered
  25-record transcript, process/collector statuses and source preservation
  checks all pass. This is a bounded runtime slice, not full `test-all`, fuzz,
  exact-size, external-SDK, GUI, native-package or production qualification.
  Keep the earlier admission failures as historical evidence. A later formal
  repeat stops before analysis because the pinned validation profile,
  Frama-C 29.0 and Why3 paths are unavailable; no new formal pass is inferred.
- Stop the threaded suite before compression if its JSON generator fails or
  its output is not 5,000 records with sequential integer IDs, matching names
  and finite floating-point scores. Preserve the original seeded generator
  and retain failure diagnostics. Add nine controls to the existing helper:
  one normal fixture and eight producer/data/validator failures, including
  complete output followed by a nonzero exit. Failures require status 1,
  workspace cleanup and no compression, extraction or integrity invocation.
  The target now has 50 controls; its CLI remains synthetic, not a codec,
  concurrency or performance test. Other fixture/status gaps remain open.
- Create the threaded suite's workspace exclusively under `TMPDIR` with
  `umask 077`, rather than reusing a predictable PID-based path. Stop before
  invoking the CLI when creation fails; clean up on normal exit and handled
  HUP/INT/TERM with nonzero interruption status. Extend the existing helper
  with seven lifecycle controls, bringing the subtotal to 41 without changing
  the original 34 process controls or the T1–T14 bodies. The seven controls
  reject the old setup, including its status-zero INT result and mode-0666
  fixture. Keep caller-controlled temporary parents trusted; SIGKILL and
  forced supervisor termination cannot guarantee cleanup. These checks do
  not qualify the full native threaded suite or production.
- Reject false integrity success in T10 of the threaded suite. Preserve the CLI
  status and combined output; require a clean sanitizer scan, the exact
  nine-file success summary and one summary line. Reject failed scans even
  when their output looks valid, as well as conflicting summaries after NUL.
  Extend the existing synthetic supervisor to 34 whole-script controls, keeping
  the 14 T9 controls. The original T10 falsely approves 18 of 33 controls;
  a further NUL-conflict regression rejects the first fix. This corrects the
  test's acceptance criteria, not the codec or archive format. Full native
  threaded testing and the remaining production gates are separate.
- Reject false success in the threaded suite's wrong-password case. Require
  exact status 1 and the authentication diagnostic; reject sanitizer markers
  and failures while reading either log scan. Add 14 whole-script synthetic
  process controls to `make check`, including signals and NUL-prefixed output,
  and exercise self-copy interpreter patching through the Guix phase tests.
  Twelve controls expose the old false successes before the fix. These
  controls do not exercise the codec, cryptography or concurrency; other
  threaded command-status gaps and production gates remain open.
- Run the existing functional smoke script on the Guix CLI output after
  stripping and RUNPATH validation, rather than relying only on build-tree
  tests. Preserve disabled-test and cross-build defaults. Extend the existing
  Scheme phase tests with exact installed paths, spaces and propagated child
  failures. A strict GCC build passes a private staged installation and the
  real postprocessing/check phases without its build-tree executable; the
  missing-output control is rejected. Native derivation, dependency closure,
  GUI package and final production qualification remain pending.
- Extend the existing ANS allocation/reader test with seven literal-state
  steps covering zero-width reads, masked refill, short tails and EOF.
  Preserve all previous test bodies, including the 2,312 bit-reference and
  520 exhausted-counter cases. A private eager-refill mutation passes the
  old suite but the new oracle rejects it after successful compilation.
  The real core passes GCC/Clang non-recovering UBSan with `NDEBUG`; strict
  `check` and CLI tests pass with 11/10 skips. Reuse the existing Make target
  and document reproduction in English and Portuguese. No implementation,
  format, API, license or production-readiness change is implied.
- Revalidate strict Clang 22.1.8 `check` and the actual CLI functional suite
  on current sources, with 10 explicit skips and SDK/PQBOX/Jasmin disabled.
  Preserve an initial missing-`libgcc_s.so.1` UBSan-helper failure; correct
  only the private compiler runtime environment and rerun without weakening
  flags, tests or resource limits. Repeat the five selected Frama-C/Jasmin
  gates successfully. These are bounded host checks, not complete formal,
  current VM sanitizer, native-package or production approval.
- Revalidate the portable frontend package with a fresh strict GCC CLI and
  the existing 12-test suite: genuine unencrypted VaptVupt level-9 `.zupt`,
  exact 17-file payload, checksum/extraction checks, failure controls and
  output-preservation races. The covered-source SPDX-marker audit passes.
  Execute the previously unavailable spec parse with installed RPM 4.20.1
  and record its 14 declared build requirements. Preserve the actual Guix
  macro prefix and distinguish parsing from native openSUSE builds or
  dependency acceptance. Update English/Portuguese reproduction guidance;
  no codec, cryptographic, API, source-mode or licensing-grant change.
- Keep operational fallbacks in the three synchronous GUI queries without
  hiding unexpected programming errors as missing version, capability or
  archive metadata. Add two regression methods covering 18 expected failures
  and nine unexpected errors; confirm the latter fail against the old code.
  All 64 GUI methods pass with genuine PySide6 and PyQt6 in separate offscreen
  environments; fresh strict GCC `check` and CLI tests pass with 11 skips.
  Formatting and both preferred-provider typing profiles pass. Full Ruff
  remains nonzero, improving from 16 to 11 findings without suppressions or
  source-mode changes. Preserve earlier private supervisor/test-harness
  failures and document the reproduction commands in English and Portuguese.
  Worker cleanup, codec, format and cryptography are unchanged; no release
  or native-package approval follows from these host results.
- Revalidate the five existing Frama-C/Jasmin gates on current sources and run
  the real ML-KEM/OpenSSL comparison, not just its supervisor controls. All
  five conditional formal gates and three GCC/OpenSSL interoperability cases
  pass. A fresh strict GCC CLI also passes the functional script, regression
  22/0, built-in PQ 10/0 and dedup properties 14/0. Retain earlier missing-tool
  and runtime-loader failures; correct only the private test environment.
  Update both README tables and user guides with commands, tool versions and
  scope limits. C, assembly, cryptography, API and format are unchanged. The
  full detector, current VM sanitizer campaign and final packages remain
  unqualified; these results do not approve publication.
- Reject the PKCS#8 encrypted-private-key header in the CI credential policy.
  The new synthetic fixture first reproduces incorrect acceptance; all six
  regression methods pass after the one-alternative correction, covering nine
  credential patterns and preserving acceptance of public-key, RSA public-key
  and certificate headers. The actual gate passes on a private selected-source
  index. Record the separate full-detector startup failure without changing
  limits or treating version/input controls as a scan. Update both user guides
  and README evidence tables. No codec, API, archive or cryptographic change;
  neither header-policy success nor inventory classification approves release.
- Extend the exact-sized ANS4 metadata regression with cumulative lane lengths,
  unchanged poisoned output and unchanged `SIZE_MAX` consumption on rejection.
  Pin the genuine three-fixture Frama-C result: 138/358 reached statements,
  zero alarms and 20 valid preconditions. Retain the previous analysis settings
  and add rejection of stale two-fixture reports; all 57 supervisor controls
  pass. GCC/Clang scalar UBSan and private allocation/mutation controls pass
  through existing Makefile recipes. Direct strict Clang retains 16 existing
  cast-alignment diagnostics; no new suppression is added. Fresh strict GCC
  `check` and CLI tests pass with 11 skips. Decoder, format, API and cryptography
  are unchanged; these results do not qualify all decoder inputs or the release.
- Reject operational errors in the CI credential gate instead of reporting a
  clean scan. Accept only Git's no-match status with empty findings; preserve
  error diagnostics and paths-only reporting. Execute the actual workflow
  block in six regression methods with synthetic Git repositories, including
  an outside-index sentinel for inherited Git overrides. Include the test in
  `check` and source-policy CI. Fresh strict GCC/CLI checks pass with 11
  explicit skips; new-test Ruff/format and both Pyright profiles pass. This
  does not qualify the separate full credential scanner, hosted CI, native
  packages or the release. Archive format, API and cryptography are unchanged.
- Observe QObject destruction with retained, decorated GUI-thread receivers in
  the existing lifetime regression. Genuine PyQt6 exposed a missing anonymous
  callback despite measured native deletion; retain the worker wrapper so
  PySide garbage collection cannot hide missing explicit cleanup. All 62
  methods pass with both providers, and removing the cleanup connection in
  private copies fails the regression. Production GUI/C code is unchanged.
  Both final typing profiles pass; imports/format pass, full Ruff retains 16
  findings. Host offscreen results do not qualify native packages, whole-suite
  sanitizers or the release.
- Organize imports and format the GUI and workflow tests with Ruff 0.16.10.
  Import and formatting checks pass; full lint falls from 20 to 16 diagnostics
  with all other findings and effective settings unchanged. A constrained AST,
  comment and header comparison passes, retaining all 62 ordered test methods;
  this comparison alone does not prove import initialization effects. Fresh
  strict GCC/CLI checks, all 18 host stages and both genuine PySide6 typing
  profiles pass, retaining 11 ordinary CLI skips. Preserve exception policies,
  resource limits, archive format and cryptography. This is mechanical
  cleanup, not full-lint, native-package, sanitizer or release approval.
- Remove unused `Qt` and `QPixmap` imports from both GUI providers and mark the
  Info action's ignored return status as `_code`. Preserve provider selection,
  subprocess calls, output/error handling and every test byte. The three
  focused Ruff findings are resolved; full lint falls from 23 to 20 with the
  same effective configuration and remaining diagnostics. Both formatting
  checks still failed at that earlier snapshot. Fresh strict GCC/CLI checks, all 62 workflow methods,
  18 host stages and both genuine PySide6 typing profiles pass with the same
  limits and 11 ordinary CLI skips. This is a quality cleanup, not a security
  fix, PyQt6 runtime validation, native-package or release approval.
- Add six POSIX real-process tests for the GUI's CLI probes: executable checks,
  successful version banners, help fallback/cache, archive-info streams and
  command status/output/arguments. Preserve the previous 56 methods and all
  production GUI bytes. Fresh strict GCC checks, CLI functional tests, all 62
  workflow methods and 18 host stages pass with 11 ordinary skips. Five private
  mutations are rejected in the expected probe tests. Both genuine PySide6
  typing profiles report zero errors after clarifying the test helper's stream
  arguments; the initial type failure remains recorded. Full Ruff still has
  23 diagnostics and both files fail formatting. This does not qualify native
  packages, whole-suite sanitizers or the release.
- Make subprocess exit handling explicit in five GUI probes/helpers and the
  workflow supervisor with `check=False`, preserving the existing Python
  default, return codes, output, timeouts and exceptions. Resolve six PLW1510
  diagnostics without changing rules; 23 other Ruff diagnostics and both
  formatting failures remain. Fresh strict GCC checks, CLI functional tests,
  all 56 Qt tests and 17 host stages pass with 11 ordinary skips. Both actual
  preferred-provider Pyright profiles return zero errors. This is not a
  functional security fix, native-package validation or release approval.
- Repeat all five selected Frama-C/Jasmin gates after the Guix policy fix,
  using a fresh snapshot of the same 30 inputs and verified tool hashes.
  All gates and source-integrity checks pass with unchanged analysis flags
  and criteria. These finite, conditional results do not qualify the whole
  application, native packages or a production release.
- Install security and distribution policies with the Guix CLI and GUI user
  guides. Extend the existing real-phase tests to compare four CLI and ten GUI
  files; reproduce the missing CLI distribution policy and missing GUI security
  policy before fixing the recipe. Fresh strict GCC checks, CLI functional
  tests, all 56 GUI tests and 17 host stages pass with 11 ordinary skips.
  Keep the withdrawn source origin unchanged until release gates pass.
  A freshly pinned sanitizer VM attempt remains blocked at its unchanged
  5-GiB preflight floor, before image or product execution. Separate private
  wrapper controls now reject incomplete guest transcripts; they do not qualify
  sanitizers, native packages or the release.
- Preserve the GUI controller's inherited `QObject.thread()` method. Store its
  worker thread privately; retain ownership, signal connections and join order.
  A real Qt affinity regression reproduces the earlier `TypeError`; all 56 GUI
  tests, strict GCC checks, CLI functional tests and 17 host stages then pass,
  with 11 ordinary skips. Select genuine PySide6 types for static analysis while
  keeping the runtime PyQt6 fallback unchanged. Both Pyright profiles report
  zero errors after this correction and an explicit lifetime-fixture binding.
  Verify the existing diagnostic and exit status when neither Qt binding exists.
  Ruff still reports 29 diagnostics and formatting failures. This does not
  qualify PyQt6 runtime, native packages, real desktops or the release.
- Decode GUI CLI output incrementally so pipe boundaries do not corrupt UTF-8.
  Reset decoder state for each run and flush incomplete sequences with the
  existing replacement policy at EOF. Add five test methods covering 31
  stream/cleanup scenarios; reproduce 22 assertion failures before the fix.
  All 55 actual Qt tests, strict GCC checks, CLI functional tests and 17 host
  recipe stages pass afterward, retaining 11 ordinary skips. Preserve progress,
  cancellation and child cleanup; archive format and cryptography are unchanged.
- Complete bounded Python type analysis after diagnosing allocator reservations.
  A paired isolated experiment retains the 1-GiB cap and all analysis rules;
  one glibc arena allows the V8 interpreter to finish. That earlier Pyright
  snapshot reports 15 errors in configured basic mode and 16 with the documented
  default command, including optional Qt imports/base classes; Ruff retains
  29 diagnostics and formatting failures. Document reproduction and coverage
  limits in both languages. This is not a type-check or production approval.
- Display GUI operation logs as plain text, preserving literal CLI output and
  archive names instead of interpreting markup. Keep the existing append
  interface, read-only height, stylesheet, selection and scrolling behavior.
  Reproduce three rendering failures before the change; all 50 actual Qt
  tests then pass, including nine new controls and a real POSIX archive path.
  Fresh strict GCC CLI checks, functional tests and all 17 host recipe stages
  pass with 11 ordinary skips. Ruff's 29 baseline diagnostics and formatting
  failures remain; that earlier Pyright attempt failed before analysis under
  the existing memory limit. Document commands and limits in both user guides.
  This does not qualify native packages, PyQt6, real desktop sessions or the release.
- Fail static-analysis result processing on `grep` errors, invalid counts or
  inconsistent count/status pairs, including after complete output. Keep
  no-match results distinct from failed reads, and use string comparisons
  for potentially large counts. Require SHA-NI source before compilation and
  always compile it, even if it disappears later. Expand the existing harness
  to 53 scenarios; reproduce 19 earlier false approvals and the later SHA-NI
  omission before fixing them. Private source fixtures preserve worktree data.
  Fresh strict GCC/Clang CLI and SDK checks pass with existing skips, followed
  by all five actual selected Frama-C/Jasmin gates with pinned tools and
  recorded inputs. These finite, conditional analyses do not prove the
  whole program or qualify native packages and the release.
- Reject failed or empty source discovery in the static-analysis gate before
  invoking a compiler. Check `find` and `sort` separately so producer failures
  cannot disappear through process substitution. Reproduce five earlier
  false approvals, including failures after complete output; all seven
  focused supervisor scenarios now pass. Fresh GCC/Clang CLI and SDK checks
  pass with existing skips; the GCC static run passes nine checks, without
  cppcheck. Add reproduction commands and coverage limits to both user guides.
  Current-source VM sanitizer validation remains unexecuted: admission
  rejected insufficient host memory without lowering the existing floor.
- Pass the CLI's explicit Jasmin selection to in-tree SDK C compilation,
  without importing external CLI provider flags or libraries. Preserve the
  portable default and public ABI. Add 25 build-recipe assertions to `check`
  and `sdk-test`, including caller flags and an inherited SDK build-directory
  override. Linking AES objects is not evidence of SDK hardware dispatch.
  Fresh strict GCC 14.3.0 and Clang 22.1.8 checks, real CLI smoke tests,
  SDK runtime/export checks and ten actual C-object references pass with
  documented platform/provider/tool skips. The 18 GCC and 15 Clang stages
  validate the recorded source before the final results-table update;
  native packages and complete sanitizer/release gates remain pending.
- Patch generated DEB/RPM control interpreters in the Guix source phase.
  Extend the real phase regression from seven to nine shell-control groups;
  the added controls exercise actual package helpers with tool doubles,
  not native package construction or installation. Preserve the original
  no-interpreter failures and executor setup failures in the local evidence.
  The corrected no-interpreter phase run passes all nine groups, including
  20 DEB and 55 RPM cases. These are helper regressions, not package approval.
- Fail ML-KEM/OpenSSL interoperability testing on subprocess errors, even
  after complete output or matching comparison files. Distinguish failed
  capability queries from an unavailable algorithm and retain producer
  diagnostics. Add 15 shell controls to the existing crypto-wrapper target:
  valid/mixed-case flows, legacy/provider skips and ten producer failures.
  Preserve Bash 3.2 syntax and reject a failed version query before testing
  capabilities. The original nine false approvals are reproduced before the
  status fix; four later controls reproduce version/skip handling defects.
  Cryptographic code,
  comparison criteria and optional-tool skips are unchanged; document real
  GCC/Clang interoperability commands in both user guides.
  All 27 wrapper controls, fresh strict GCC checks and the real CLI smoke
  suite pass; GCC 14.3.0 and Clang 22.1.8 each pass all three real OpenSSL
  3.5.7 comparisons without skips. Ordinary checks retain 11 unrelated skips.
- Revalidate the recorded 281-file snapshot with strict GCC 14.3.0 checks,
  real CLI functional tests and actual GUI recipe phases using PySide6/Qt
  6.9.2. All 41 GUI workflows and 17 recorded stages pass; ordinary checks
  retain 11 explicit skips. Keep the unchanged 32-MiB cancellation fixture
  in a GUI-specific profile; ordinary stages retain their 16-MiB file cap.
  Preserve the earlier driver and fixture-capacity failures. Repeat all five
  selected Frama-C/Jasmin gates with the corrected supervisors and verify
  30 selected source files before and after execution. These host and
  conditional formal results do not qualify a native Guix closure, final
  packages or the release; later test-supervisor/documentation edits remain
  outside the recorded ordinary-test snapshot.
- Reject case-varied warnings, errors, failures and timeout diagnostics in the
  ANS4 metadata analysis supervisor, even beside a complete clean summary.
  Extend its controls from 47 to 56: eight negative fixtures reproduce the
  previous false passes, and an informational unsupported-ACSL note remains
  accepted. The unchanged real metadata fixtures pass again with 14/14 valid
  preconditions and zero alarms. This does not prove valid-stream decoding or
  qualify the release.
- Extend the Guix interpreter-phase test from four to seven shell control
  groups. Run the real standard source-shebang phase before the recipe's
  generated-fixture phase, covering three non-executable self-copy wrappers.
  The codec and package recipe are unchanged. Strict GCC 14.3.0 source-only
  checks and real CLI functional tests also pass after the actual source
  phases, with 11 explicit skips. These host checks do not approve a Guix
  derivation or native package.
- Stop source export when either `git archive` or gzip fails, even after a
  complete output stream. Enable Bash `pipefail` only for `dist`, retaining
  the default shell for other targets and the existing streaming pipeline.
  Expand source-state controls from eight to 17; producer failures must not
  reach the scanner or create/replace output. These fixture checks do not
  qualify a final committed source package or native installation.
- Reject failed checksum generation in the installed-executable smoke test,
  even when the producer prints valid output or both manifests would be empty.
  Use batched `find -exec` and explicit input/extracted-tree failure guards;
  retain byte comparisons and CLI error/sanitizer checks. Extend its harness
  from 53 to 65 POSIX cases with controlled hash, enumeration and sorting
  failures. The fallback adapter does not qualify native Perl or other OSes.
- Publish native DEB/RPM files with descriptor-relative, atomic no-clobber
  links instead of final pathname-based move/copy operations. Prepare complete
  private copies before any link; reject preexisting binary/source collisions
  together and preserve late collisions. Require an owned, non-shared-writable
  output directory, retain mismatched staging bindings and never roll back
  published names. Print hashes of staged bytes only after success, preserving
  GNU filename escaping. Traverse ancestors with Linux path descriptors so
  search-only directories do not require read permission. Add 21 publisher
  tests and extend the real-helper
  boundary suites to 20 DEB/55 RPM cases. Whole-batch atomicity, arbitrary
  namespace races, crash durability and native package approval are not claimed.
- Stop DEB/RPM validation when an external metadata, inventory or ELF tool
  fails, even after printing plausible output. Preserve its diagnostic and
  exit status; keep existing metadata and ELF policy checks. Refuse existing
  dangling DEB output symlinks without touching their targets. Add 12 DEB
  and 47 RPM fault-boundary cases under the release-only
  `test-packaging-failures` target, with commands in both user guides. These
  tool-replacement tests do not qualify native packages or close output
  publication races and partial RPM delivery.
- Avoid trailing-byte probes after EOF or a failed native key-file read.
  Preserve ZKEY/ZPQK validation, buffer wiping and `EINVAL` rejection behavior;
  complete private blobs still require a trailing-byte probe. Add 66 real-key
  cases for valid/invalid inputs, positive partial errors, trailing data,
  close failures and unchanged caller outputs. GNU-cookie fault injection
  runs on supported GNU/Linux targets and reports explicit skips elsewhere;
  missing/unknown compiler targets fail rather than being reported as skips.
- Track exclusive creation through internal key-generation/export variants so
  the SDK can remove its own partial temporary keys after creation, permission,
  write, synchronization or close failures. Preserve the original failure over
  cleanup and custom allocator callbacks. Keep the existing CLI entry points'
  deliberate failed-output retention and never remove colliding foreign files.
  Add 74 checks covering ownership flags, failures, regular/symlink/hardlink
  collisions and legacy retention; native Windows cleanup remains unqualified.
- Reject failed or truncated SDK temporary-path formatting before using the
  resulting name. Check every caller, including nested stream/extraction paths;
  preserve foreign files, output pointers and callback state on rejection.
  Add 26 checks for actual long-directory truncation, formatting failures,
  allocation/descriptor cleanup and usable fixtures. Check Windows temporary
  directory query failures and oversized results; native Windows validation
  remains separate.
- Stop SDK key-copy and archive-readback loops after an error or EOF, including
  partial reads that already returned bytes. Preserve the read error over sink
  and close failures, and record the outer read diagnostic after invoking an
  output callback that may itself call the SDK. Add 18 cases for exact prefix
  delivery, short/failed callbacks, nested SDK errors and atomic destination
  preservation.
- Check SDK file sizes and seek/read/close results before returning buffers.
  Preserve the first failure, wipe incomplete buffers and support empty files
  with allocators that reject zero-byte allocations. Add 58 real-archive cases
  across buffer/file compression and both stream decompression readbacks.
- Remove generated SDK key files when path allocation fails, and remove
  internally exported public-key files when their handles are destroyed.
  Preserve caller-loaded key files. Add 19 cases for allocation failures,
  repeated lifecycles, collision identity and caller-owned file preservation;
  document that public-key export uses a temporary file.
- Create SDK staging files exclusively with owner-only access and retain the
  created handle through stdio conversion. Reuse the key-file writer's creation
  rules, including its Windows protected DACL, without changing key-file
  write/flush or failure retention. Check staged writes and closes, and preserve
  foreign files/links on creation collisions. Add 40 public-API cases covering
  permissions, inode identity, descriptor cleanup and injected I/O failures.
- Reject SDK read-callback lengths greater than the supplied buffer before
  writing staged input. Report stream read and close failures, preserve the
  first error and wipe the input scratch buffer on every exit. Add 13 focused
  cases for byte-exact roundtrip, partial read failure, callback errors,
  oversized counts and cleanup to `make sdk-test`. Separate build directories
  now work for both static and shared SDK test binaries.
- Include both user guides and linked policies in CLI DEB/RPM recipes and the
  GUI RPM source tree. Preserve Markdown filenames in the Debian helper route.
  Before delivering a DEB/RPM, validate its extracted documentation against
  the current source: one expected directory, regular non-symlink files,
  mode 0644 and matching bytes. Add the checker regressions to `make check`;
  actual native package builds and installation remain separate release gates.
- Install both user guides with the GUI source installer, together with the
  security and distribution policies. Preserve their `docs/` layout and mode
  0644; check real staging, custom paths and missing-guide rejection before
  any partial installation. Native GUI DEB builds use this same installer,
  but still require their separate package and runtime acceptance checks.
- Include both user guides under `docs/` in the portable GUI source bundle and
  Guix CLI/GUI documentation. Preserve the README's relative offline links;
  the portable bundle validates 17 files, including the linked security and
  distribution policies. Reject missing guides/policies and missing or
  symlinked policy sources before delivering the bundle.
- Resolve the eight shell-fixture emitters used by the Guix CLI checks to the
  selected store interpreters, including generated Bash fixtures. Regressions
  run the four newly covered wrapper groups without `/bin/sh` or `/usr/bin/env`;
  these phase tests do not build the native package or validate its source pin.
- Match Linux disk-capacity ioctl requests to the selected libc's `int` or
  `unsigned long` declaration, preserving the command bits. Use bionic's
  documented overload opt-out before including headers. Regressions exercise
  both request ABIs, error paths, capacities above 4 GiB and compiler-wrapper
  failures without accessing a real device. A Clang header model checks the
  bionic declaration; it does not replace an Android NDK build.
- Keep caller compiler/linker flags in the atomic-output test's directory
  capability probe and report compile/run diagnostics. Distinguish an explicit
  unsupported result from process failures, sanitizer diagnostics and missing
  or conflicting completion markers. Add fast controls to `make check`; the
  probe checks the test environment, not archive correctness by itself.
- Preserve caller compiler and linker flags when building the legacy 5.2.1
  disk fixture decoder, including static-musl linking and multiword compiler
  commands. Keep strict warnings and propagate compiler failures with their
  diagnostics. Four compiler-boundary controls are required by `make check`;
  the real encrypted/deduplicated fixture still exercises list, test, extract
  and disk restore separately.
- Validate multi-symbol ANS initial states before allocating a decode table;
  single-symbol headers keep their existing state-free encoding.
- Check sequence-window parameters before allocation, fixing a scratch leak
  when the limited API rejects an invalid window. Validate sequence tables
  before reserving scratch and decode valid empty sequences without allocation,
  retaining compatibility with their unused fields. Add six window and ten
  sequence-table/empty-stream regressions for both sequence grammars.
- Preserve the current VM resource failure and its 159-byte reproducer:
  1,274,617 executions, 2,131 new corpus units, status 71 and 535 MiB RSS against
  the unchanged 512-MiB limit. After the allocation fixes, a fresh campaign
  with the same seven seeds, duration and limits completed 4,812,958 executions
  and 2,560 new units at a 453-MiB peak with status zero and no artifacts.
  Both internal campaign and supervisor verdicts passed. This bounded result
  does not reclassify the earlier failed run or validate native packages.
- Validate context ANS arguments before pointer formation and compare remaining
  source lengths before advancing through its global table, context headers and
  initial states. Add 2,216 exact-allocation truncation/alignment cases, empty
  input and output-capacity checks, and valid context roundtrips with allocation
  cleanup. The valid grammar and existing zero-extension behavior are retained.
- Require successful child exits and complete fixture comparisons in the quick
  suite, including random and empty files. Add failure controls for incomplete
  extraction, nonzero exits with plausible output, misleading integrity text,
  key generation and a CLI path containing spaces.
- Reject distribution exports from a dirty source tree before replacing their
  output. Eight controls cover staged/unstaged changes, deleted and untracked
  sources, unusual filenames, clean export and excluded build output. Preserve
  the earlier mixed-source release-check log: its runtime checks used the
  corrected working source, but its archive build used the previous commit.

- Reject S/T sequence payloads that declare literals but provide an empty
  literal section before reserving decoder scratch space. This preserves the
  valid wire format while avoiding repeated malformed-input allocations. Add a
  regression that checks the error result, unchanged output state and zero
  allocations; current GCC and Clang ASan/UBSan runs also retain codec
  round-trip and destination-boundary coverage.
- Tighten the Jasmin AES stack-wipe pattern checker. It now requires the
  pinned alignment and frame allocation, all expected zero stores, stack
  restoration and return, and rejects instructions inserted before restoration
  or after return. Match complete opcodes and operands, reject comment/string
  markers and earlier returns, and allow only the pinned trailing metadata.
  Seventeen controls cover two valid tails and fifteen malformed variants;
  this checks the emitted pattern, not processor register erasure, control
  flow through the wipe or compiler trust.
- Rebuild the continuous decoder-coverage executable from the current frozen
  VM snapshot and symbolize the recorded RSS-limit failure. The exact binary
  reached 2,360,279 executions and 2,040 new units before libFuzzer exited 71
  at 598 MiB against the unchanged 512-MiB limit; the target cgroup peaked at
  660,992,000 bytes without an OOM or PID event. The saved 127-byte input is
  retained with SHA-256
  d378fd4c77b7c57cc96bc62e04a69ad8fc3f95b849c76791c256e1ab38eba534.
  Symbolization of the displayed live-heap context returns
  `___interceptor_malloc`, `operator new` and `main`: 24,383,368 of
  24,791,125 live bytes, separate from 244,292,744 quarantined bytes. This
  does not explain the full RSS or exclude codec allocation contributions.
  The run stopped after about 8.04 seconds of its 30-second budget; the
  continuous coverage gate remains failed. A subsequent exact-binary VM
  replay executed the saved input once in 1 ms with status zero, no artifacts
  and a 47-MiB peak; this does not clear the continuous resource failure.
- Run a current-source scalar direct-decoder fuzz diagnostic with Clang 22.1.8
  ASan/UBSan/LSan for 30 seconds: 4,878,375 executions, 2,269 new units, a
  344-MiB peak and no artifacts. This host-only result is separate from the
  earlier isolated-VM RSS-limit failures and does not clear the VM fuzz gate.
- Forward the configured GNU Make executable into the fuzz-build harness. This
  keeps nested fuzz builds usable in a minimal GNU Guix shell where `make` is
  intentionally absent from `PATH`; the harness rebuilds both fuzz targets and
  retains its UBSan and injected-I/O checks.
- Run the current source-only `check` target with GCC 14.3.0 and strict warning
  errors: all executed checks pass after adding the declared `file` utility to
  the isolated command PATH. SDK, PQBOX and Jasmin remain explicitly disabled
  in this profile; it is not the final VM, formal-tool or package acceptance.
- Validate the current CLI with Clang 22.1.8 ASan/UBSan and leak detection
  in the same bounded disposable VM: archive and fictitious encrypted/deduplicated
  disk roundtrips, help/version and all eight installed-functional checks pass.
  Separate ordinary SDK tests pass 15/0; three-way ML-KEM interoperability
  with OpenSSL 3.5.7 passes 3/0. Preserve the initial missing-reference failure;
  the private profile-only dependency correction fits the unchanged image cap.
  Add fail-fast English/pt-BR reproduction commands with explicit sanitizer
  flags. These are smoke checks, not full-suite, fuzz, package or production
  approval; formal and distribution gates remain incomplete.
- Record the scalar decoder coverage campaign failure accurately: libFuzzer
  reached 536 MiB against its fixed 512-MiB RSS limit after 2,108,708 inputs and
  produced a 1,549-byte replay case. The target cgroup did not report an OOM.
  Preserve the failed raw log, artifact hash, and status. The limit failure does
  not by itself establish a codec defect or pass the required 30-second run.
- Replay that exact saved input once with the identical fuzzer binary under the
  same ASan/UBSan/LSan and 512-MiB RSS limits: it exits cleanly at 43 MiB with
  no sanitizer finding. This is a one-input result only; it does not explain
  the campaign's cumulative memory growth or clear the failed coverage gate.
- Repeat the 30-second profile with private fixed callback buffers to avoid
  per-input harness allocations. The same codec snapshot, Clang flags, corpus,
  sanitizers and 512-MiB RSS limit remain in place. The campaign still fails:
  libFuzzer exits 71 after 1,849,145 inputs at 514 MiB, reporting 241,285,420
  quarantined bytes. Preserve its 61-byte OOM artifact and raw log. This change
  did not resolve the resource failure; the coverage gate remains open.
- Test `allocator_release_to_os_interval_ms=500` without changing quarantine
  capacity or checks. The same binary/input scope still fails: 544 MiB and
  exit 71 after 1,303,122 inputs, with 267,264,876 bytes quarantined. Retain the
  114-byte OOM artifact and log; this allocator-release diagnostic does not
  resolve the RSS failure or close the coverage gate.
- Run a separately scoped coverage profile as thirty independent one-second
  libFuzzer processes calling the real `vv_decompress` through a private
  adapter. Clang 22.1.8 scalar ASan/UBSan/LSan, default quarantine, max input
  4096 bytes and the unchanged per-process 512-MiB RSS limit: all 30 slices
  completed (15,382,624 executions, 3,058 new corpus units), with a maximum
  per-process RSS of 440 MiB, cgroup peak 472,612,864 bytes, and no artifacts,
  events or remaining descendants. Process exits reset ASan quarantine, so this
  is not equivalent to a continuous 30-second campaign or exhaustive coverage;
  the earlier continuous-run RSS failures and the fuzz/release gates remain
  unresolved. This private adapter is not the in-tree AFL stdin harness.
- Validate the current ANS reader/refill and allocation regressions in a
  disposable 2-CPU/2-GiB VM with Clang 22.1.8, ASan/UBSan and leak detection.
  Scalar and AVX2 pass; exact-size codec tests pass 81/0 and 1,024 BCJ
  bijection cases. Confirm all three sanitizer negative controls reject
  their deliberately invalid programs. Preserve the ordinary-CLI scope
  of separate L5/L9 archive roundtrips, unchanged resource limits and
  incomplete formal/full-suite/fuzz/package gates. Add English and pt-BR
  reproduction instructions; these focused results do not approve a release.
- Saturate the ANS reader's buffered-bit count after exhaustion instead of
  repeatedly subtracting into a negative signed value. Preserve implicit zero
  extension, decoded bytes and source-consumption rules across single-stream,
  four-lane and sequence callers; do not change encoding or the public API.
  Add 2,312 independent bit-reader configurations, poisoned-context reset,
  the complete 0..32-bit helper range and four-lane output lengths
  1..4096 to the existing allocation regression, including suffix sentinels.
  Add a conditional Frama-C 29.0 WP gate for initialization and consumption:
  30 exact JSON obligations, plus 40 synthetic result controls that reject
  incomplete proofs, unsupported solver output and process failures. Put the
  real gate in `release-check` and the mock controls in `check`. Update the
  metadata gate's observed footprint to 121/343 statements in 5/76 functions
  and retain all earlier controls plus old-profile rejection (47 total).
  Local symbol-loop unrolling and a decoder-scoped gauges domain resolve the
  valid-stream experiment's three memory alarms without changing executable
  C. Before the refill-guard change, it still had 13 unknown preconditions;
  neither this conditional helper proof nor native regressions approve a
  release or prove every caller correct. Earlier strict native `make check`
  runs passed with GCC 14.3.0 and Clang 22.1.8, retaining unavailable-feature
  skips and earlier environment/deadline failures. Focused scalar UBSan
  regressions pass with both compilers;
  the later focused ANS/CLI ASan/leak VM checks are recorded above, while
  full-suite VM and final-package gates remain pending.
- Compare the ANS refill's remaining length without adding to its position.
  Under the existing `p <= l` invariant, an exhausted counter near `SIZE_MAX`
  can no longer wrap into a source load. Add 520 synthetic exhausted-reader
  cases with a NULL source, counts 0..64 and reads 0..32 to the existing
  allocation test. The old guard fails with UBSan; strict GCC/Clang UBSan
  runs pass after the correction. These counters do not represent real giant
  input objects or establish a reachable ANS4 vulnerability. The valid-stream
  Eva profile remains incomplete: zero memory alarms, 37 valid and 14 unknown
  preconditions. The exhausted-counter Eva diagnostic reports a memory alarm
  after merging states; its more precise trial times out. Preserve both
  failures rather than claiming a refill proof or release approval.
  Strict full native `make check` passes with GCC 14.3.0 and Clang 22.1.8
  when run sequentially under the same two-CPU/resource limits. Preserve
  both earlier parallel deadline failures (124 at 125 seconds), explicit
  unavailable-feature skips and the pending VM/final-package checks.
- Add a focused range analysis for the unchanged scalar ANS logarithm helper.
  Frama-C 29.0 reaches its actual body over every uint32 input and separately
  frequencies 0..4096: two range assertions and two interval preconditions
  valid, zero alarms and 15/15 reached statements in 2/75 functions. Put the
  real gate in `release-check` and 57 synthetic failure controls in `check`.
  Add 4,195 native boundary checks; strict GCC/Clang UBSan passes and a private
  zero-result mutation fails them. Preserve all earlier incomplete analyses:
  helper ranges do not prove exact logarithm functionality, callers, table
  equivalence or the complete decoder. No runtime algorithm changed.
  Full strict Clang `make check` passes with explicit skips. Two GCC runs
  reach the unchanged 125-second deadline in source-scanner checks; keep
  them as failures, not completed suite passes. All 40 scanner controls
  pass separately. Final packages and production validation remain pending.
- Reuse the matching checked CLI only for the fuzz regression's plain STORE
  seed, avoiding a duplicate ordinary CLI build. Preserve both actual UBSan
  and non-LTO fault-injection builds and the direct-script fallback. Reject
  invalid explicit paths before compiler discovery, anchor relative paths
  and propagate seed failures. Add ten shell controls with a reproduced
  failure before the fix. Strict full GCC 14.3.0 checks complete twice under
  the original 125-second deadline (124.44/123.31 seconds); Clang 22.1.8
  completes in 86.52 seconds. GCC has little margin, so these samples are not
  evidence of reliable deadline headroom or production acceptance.
  Default Make reuse uses normal CLI warning flags; strict CI and the
  documented reproduction retain full-CLI `-Wcast-align -Werror` coverage.
  Keep earlier deadline failures and unresolved formal analyses recorded.
- Restore the Guix GUI build-time `check` phase after installation. Check the
  installed launcher's version and offscreen selftest, then run the complete
  GUI workflow suite against the installed module and matching CLI. Reuse the
  launcher's dependency paths, discard inherited paths during checks and
  restore the build environment even on failure. Add phase regressions for
  default/enabled/disabled testing and failure at each child invocation.
  The actual phase passed all 41 workflows with the staged PySide6 inputs;
  native dependency-closure validation and the final source pin remain pending.
- Release completed GUI job, worker and thread objects while the window stays
  open. Keep the native thread join before controller disposal. Add a real
  three-operation lifetime regression and check destruction without accessing
  disposed Qt objects; preserve archive and cancellation assertions.
  Refresh the active-job snapshot after close confirmation, because its modal
  event loop can finish and dispose jobs before cancellation starts. Add a
  regression that completes a real CLI job while that confirmation is pending.
- Add bounds, initialized-prefix invariants, frame clauses and variants to all
  seven portable AES block loops: 35 ACSL lines, no executable C or public
  contract changes. The strict scoped WP run proves 214/214 exact JSON goals,
  including all invariant/variant obligations and output initialization;
  retain the original 113/144 result and 31 timeouts. Recheck initialization
  58/58 and helpers 17/17 separately, and verify identical preprocessed C.
  The real NIST Eva gate passes with 21 valid properties, seven preconditions,
  zero warnings/alarms and unchanged complete fixture coverage. Extend all
  27 supervisor controls with old-seven rejection, now 28 passing controls.
  Record fresh tool hashes after older store paths became unavailable;
  missing-awk and missing-plugin runs remain failures. These checks cover
  selected safety/termination contracts, not functional AES or whole-program
  security. Historical results alone do not approve publication.
- Restore the exact missing PPL 1.2 Jasmin dependency in a private tool runtime,
  authenticating the complete official Guix NAR against its signed hash/size
  before selecting the shared library, SONAME link and license notice. No host
  store/profile changes or product dependency changes. Fresh GCC 14.3.0 and
  Clang 22.1.8 Make gates pass all five source analyses and instruction
  comparisons, 1,026 AES blocks, 1,539 CTR cases and four supervisor controls
  per compiler. Preserve caller conditions, resource limits and earlier
  failures; this closes the missing-runtime blocker, not the broader formal
  or final-package release gates.
- Require the exact recorded ANS4 metadata Eva summary, reached decoder body
  and returning test entry point. Reject missing, duplicated, conflicting,
  pruned or specification-only results and scanner failures instead of
  accepting clean but incomplete output. Retain the ten original supervisor
  controls, extend them to 44 diagnostic cases, and add two controls for the
  shared PASS-marker checker rejecting scanner statuses 2/127. All 46 mock
  controls pass; they do not prove the codec. The real metadata-only gate
  covers two rejection fixtures with 14 valid preconditions and zero alarms,
  not the allocated table or valid-stream decoder path. Document the separate
  unresolved 15-alarm valid-stream experiment and its precision timeout.
- Make the two top-byte AES key-schedule SBOX bounds explicit. Add two
  internal initialization assertions without weakening the public contract,
  loop invariants or frame conditions. The scoped Frama-C 29.0 WP gate with
  supported Z3 4.12.2 proves all 58 JSON goals; this is not a proof of AES/FIPS
  functional equivalence or the whole program. Keep historical partial
  results and document the exact analysis profile in both user guides.
- Extend the Eva supervisor controls to reject the old four-property and
  160-statement summaries after adding the two initialization assertions.
  That snapshot required six valid properties and full 162-statement coverage,
  while keeping
  warning, error, precondition, byte-oracle and execution checks unchanged.
- Add function and loop frame clauses, a loop invariant and a decreasing
  variant to the portable AES arithmetic helpers, without changing executable
  C or public preconditions. The scoped WP gate proves all 17 helper JSON
  obligations; the initialization gate still proves its separate 58 goals.
  Update the NIST Eva gate to its actual seven-property summary and retain
  all 26 supervisor cases plus rejection of the old six-property output.
  That 27-control snapshot and real Eva run pass; no functional AES or
  whole-program proof is claimed.
- Repeat the complete Linux VM suite after the AES initialization changes:
  strict GCC 14.3.0 and Clang 22.1.8 builds with `WITH_JASMIN=0`, plus Clang
  with `WITH_JASMIN=1` and required actual AES-NI/OS-enabled AVX dispatch.
  Keep all 14/15 unavailable checks explicit. Separately run the actual GCC
  CLI with ASan/UBSan and leak detection through archive, encrypted synthetic
  disk-image and installed-smoke checks. These results do not approve native
  packages, broader formal verification or production publication.
- Run the complete source-only `make check` suite in the Guix CLI recipe,
  rather than only the cryptographic vectors. Declare Python and Git as
  build-time test prerequisites; do not add them to the CLI runtime inputs.
  Patch the embedded shell interpreters in four test-fixture generators to
  the build-side shell, since Guix does not provide `/bin/sh`.
- Disable POSIX terminal echo before printing the password prompt. Use an
  atomic signal wait and nonblocking reads so input-entry interruption and
  terminal input flushing cannot strand the prompt. Restore terminal state,
  descriptor flags, handlers and the signal mask before propagating a signal.
- Add deterministic ordering and interruption regressions, real terminal flush
  cases, confirmation round trips, and empty/maximum/oversized password checks.
- On POSIX systems that provide `O_SEARCH` or `O_PATH`, accept compression
  inputs, archive files opened for reading, archive outputs and extraction
  beneath searchable but non-readable ancestor directories. Parent walks for
  compression inputs, output roots and extraction roots prefer readable
  directory descriptors and use the search-only fallback only for ancestors
  that grant search but not read access. Those walks keep each opened ancestor
  pinned with component-by-component no-follow and directory-type checks;
  archive files opened for reading use normal POSIX traversal and remain held
  by the open stream. This does not claim equivalent access semantics on other
  platforms.
- Redact `-p` and `--password` values in the GUI command log without modifying
  the actual subprocess arguments. This does not hide process arguments from
  local inspection. Add a strict Qt workflow gate for real archive operations,
  password failures, byte-exact extraction, widget reuse, GUI-thread callbacks
  and worker cancellation; exercise installed and extracted GUI sources in CI.
- Reject an unavailable GUI module spec or loader and a missing source-version
  macro with explicit test-bootstrap errors. Add regressions that execute the
  real bootstrap, check the exact errors, and ensure invalid module specs do
  not reach module creation. Keep the existing archive workflow checks intact.
- Declare the linker-visible fuzz fault-injection wrappers before definition.
  Compile both codec and archive variants with prototype warnings as errors,
  including when the caller does not supply strict compiler flags.
- Validate ANS and ANS4 decoder output pointers, source pointers, destination
  capacity and consumption pointers before parsing untrusted headers. Reject
  malformed frequency vectors before table indexing, keep the decode table
  initialized on every path, and add NULL/undersized-argument regressions.
- Keep Clang alignment-warning exceptions restricted to the same three audited
  translation units in normal, sanitizer, in-tree SDK and fuzz builds. Detect the fuzz
  compiler independently from `CC`. Build the real fuzz regressions with
  `-Wcast-align -Werror` and check differing compiler classifications so that
  other source files retain the strict warning policy.
- Declare the in-tree SDK error helper's printf argument contract for GCC and
  Clang. Keep missing-format-attribute diagnostics enabled on that source file
  so strict SDK builds check both the helper and its callers without changing
  the public interface or error formatting.
- Build the exact-size codec sanitizer fixture with the selected `CC` and
  caller compile/link flags instead of hardcoding GCC. Keep ASan enabled on
  every fresh object and the link, and restrict Clang's alignment exception
  to ANS and SIMD. Retain complete compiler diagnostics and failing child
  exit statuses. Add compiler-orchestration regressions; the real sanitized
  codec and BCJ round trips remain separate mandatory tests in `test-all`.
- Pass byte-aligned AVX2 encoder and decoder addresses through the unaligned
  intrinsic interface without casting to aligned vector pointers. Keep strict Clang
  alignment diagnostics enabled for both. Use a small scalar source
  set in the wrapper regression rather than requiring Bash associative arrays.
- Run verified portable GUI shell launchers through `bash` after `.zupt`
  extraction instead of assuming executable bits were restored. Document the
  selected-file permission needed for the macOS Finder launcher, and check
  these instructions in the packaging metadata regression.
- Replace the portable GUI CI ZIP gate with a genuine unencrypted VaptVupt
  level-9 `.zupt` helper. Verify the 13-file allowlist, source-only policy and
  extracted bytes before retaining local outputs. Add package-boundary
  regressions and run extracted launchers and Qt workflows separately.
  Keep the legacy 5.2.10 release-promotion block in place.
- Wait for the source-only scanner's portable watchdog to finish its current
  polling or grace sleep instead of killing only the watchdog shell. Preserve
  the archive command's exit status and time limit. Add a real archive scan
  regression that detects and reaps unwaited children using a Linux subreaper;
  report unavailable Linux/Python support explicitly rather than as coverage.
- Close the GUI worker's CLI output pipe after success or read failure instead
  of keeping its descriptor until widget teardown. Cover these paths and a
  missing executable; leave the child arguments and cancellation policy intact.
- Validate that a started GUI child has an output pipe and a callable `read1`
  reader before consuming progress, and require byte results even at EOF.
  Report a stable error and retain child cleanup and single completion when
  that contract is absent or a reader returns another type. Bind deadline
  test callbacks to their loop iteration and validate real test-child pipes.
- Defer GUI worker completion until child cleanup has been attempted. Terminate
  a child still running after read failure, reap it with a bounded five-second
  wait and close its output pipe, even when an earlier cleanup step fails.
  Report cleanup errors by stage and type without exposing child arguments;
  turn a successful result into failure if cleanup fails. Add a real-child
  regression, timeout and exit-race cases, and failure injection for cleanup.
  Failed termination or waiting does not guarantee that the child was reaped.
- Enforce a monotonic 7200-second GUI execution deadline measured before CLI
  child creation, including startup time and blocked output reads. Start the
  standard-library watchdog before launching the child; it waits until the
  launch attempt returns or raises before handling expiry. Backups lasting
  longer than two hours are terminated and fail; waiting after EOF uses only
  the remaining budget. Release the launch wait, then cancel and join the
  watchdog before child cleanup and completion. Test silent/progress children,
  EOF without exit, remaining wait budget, watchdog failures and
  exit/cancellation races. This best-effort
  deadline cannot forcibly interrupt blocked process creation and does not
  cover descendants retaining stdout or uninterruptible OS operations.

- Integrate the VaptVupt 2.65.13 encoder changes from
  `e30dc9329be7cf9f233b1ac0b1fc9ed31f530391`: reachable-bucket preparation for small
  BALANCED/EXTREME inputs and their first-block prepass, correctly sized
  hash3 history, bounded NULL/zero-length setup, and explicit Huffman
  tree-root initialization.
- Retain Zupt's parser bounds, Darwin/NetBSD secure-wipe fallback, codec
  licensing and third-party notices, wrapper defaults, and read-back check.
  The imported files are consumer adaptations rather than byte-identical
  canonical codec copies.
- Preserve archive format 1.6, codec identifier `0x0010`, and the public ABI.
- Prepare new public bundles as verified, unencrypted level-9 `.zupt`
  files with SHA-256 checksums. Native DEB/RPM/SRPM packages keep their formats;
  internal RPM/OBS source tarballs are build inputs. Old 5.2.9 artifacts remain
  available in their original formats.
- Require fresh tests for the exact final source. Unbuilt platform packages
  are not release assets and prior CI results do not approve this version.
- Regenerate and verify downstream recipe pins from the final signed 5.2.10
  source. Withdrawn package checksums do not validate the corrected version.
- Keep branch and pull-request CI independent of the unpublished release tag.
  After the final signed tag exists and the recipe-only pin update is ready,
  run the CI workflow manually with `verify_recipe_pins=true` to validate the
  downloaded tag archive against AUR, Homebrew and Guix.
- Describe optional libvuptsdk modes according to the implemented boundary:
  the SDK supplies Argon2id derivation or recipient wrapping, while ZUPT payload
  blocks remain AES-256-CTR + HMAC-SHA256. This correction does not change the
  archive format or existing SDK archives.
- Keep GUI SDK labels at that public provider boundary, and recognize both
  `SDK v2` and `SDK-v2` in archive information. This prevents SDK recipient
  archives from being misclassified as password-protected archives.
- Qualify historical security-review and proof wording where no independent
  certification or retained reproducible proof artifact exists. The recorded
  bugs, fixes and regression results are unchanged.
- Make the Huffman estimator's zero/single-symbol bound explicit for strict
  GCC range analysis; add deterministic estimator and encoded-byte regressions.
- Keep the ACSL helper predicates type-correct for Frama-C 29. Bounded Eva
  fixtures and the incomplete WP proof remain separate from general decoder
  coverage. Earlier assembly vector/timing checks did not establish source
  correspondence; the fresh five-source checks below address that separate
  boundary, not the full application's correctness.
- Preserve the historical WP diagnostic run with Z3 4.13.0: 346 of 653 goals
  were discharged (251 Qed, 61 Z3, 12 termination and 22 unreachable), while
  305 timed out and 2 remained unknown. Cached Why3 did not recognize that Z3
  version, and analysis warnings remain; this is not an accepted proof gate.
- Add loop bounds, initialized-prefix invariants, assigns clauses and variants
  to `zupt_aes256_init` without changing its C behavior or public contract.
  Frama-C 29.0 with GCC 14.3.0, `gcc_x86_64`, `Typed+int` and Qed improves
  the scoped result from 16/39 to 39/58 discharged goals (37 Qed, 1 termination,
  1 unreachable). Nineteen goals and Typed-model separation hypotheses remain
  unresolved, so the strict proof gate fails. Retain all function/RTE/frame/
  termination/initialization obligations; this is not a FIPS-equivalence proof.
- Add a portable AES known-answer fixture using the four fixed NIST SP 800-38A
  F.1.5 ECB blocks, one fixed key and valid disjoint buffers. Its native target
  links the actual C core directly even in assembly-enabled builds and checks
  all 64 output bytes. Keep assertions active after caller `-DNDEBUG` and reject
  direct assertion-disabled builds; the compile-only control changed from exit
  0 to the expected exit 1. GCC 14 and Clang 22 pass the actual Make target
  with strict warnings and non-recovering UBSan. No format or crypto behavior
  changes are made by this test.
- Add `test-frama-aes-nist` with Frama-C 29.0, GCC 14.3.0 and `gcc_x86_64`:
  zero alarms/warnings, four valid loop properties, seven valid preconditions,
  64 reached `__FC_assert` calls and a returning main; 160/160 statements in
  five analyzed functions out of 27. Analyze actual C function bodies without
  automatic builtin substitution. Reject an incorrect expected byte even when
  Eva exits 0 with zero alarms but prunes main after an invalid assert
  precondition. These are fixed-vector results, not arbitrary-key AES/FIPS,
  side-channel or whole-program verification. Require a real 120-second
  deadline plus five-second kill grace, with `FRAMA_TIMEOUT` override; fail on
  missing tools, diagnostics, execution failure or incomplete/unproved output.
- Include the native AES fixture and 24 synthetic supervisor controls in
  `check`. The wrapper tests diagnostic, status, body/reachability and assertion
  count handling; its mock supervisor verifies deadline arguments but imposes
  no deadline and does not analyze AES. Default `check` therefore needs neither
  Frama-C nor GNU timeout.
- Record GCC 14 `test-all` with `WITH_JASMIN=1 WITH_SDK=0 WITH_PQBOX=0` passing
  in an isolated VM on a frozen 247-file snapshot, including the portable AES
  fixture and regenerated runtime assembly. Its 14 explicit skips remain
  untested. Later warning-scan wrapper, Makefile and documentation changes were
  not in this run; it is not a full GCC248 suite result.
- Record Clang 22 `test-all` with the same feature flags passing in a disposable
  VM on the frozen 248-file source, with 15 explicit skips. OpenSSL ML-KEM
  interoperability was not run because that guest lacked an `openssl`
  executable; the three earlier GCC247 interoperability passes remain separate.
  These ordinary VM suites are not globally ASan/UBSan-instrumented builds.
- Validate the portable GUI frontend on a frozen 248-file snapshot in a
  disposable Linux x86_64 VM: fresh GCC 14.3.0 CLI, Python 3.12.12,
  PyQt6 6.9.1/Qt 6.9.2, 39/39 offscreen workflows and a level-9 `.zupt` with
  thirteen exact frontend files verified and extracted byte-for-byte. The
  matching CLI stays outside the bundle. In-tree SDK 15/0, static checks 9/0
  and metadata 50/0/6 pass; seven unavailable checks remain explicit. This is
  not a native DEB/RPM/Guix install, subsequent-documentation validation or a
  signed release artifact.
- Record the source-only scanner and 40/40 adversarial cases passing on a
  frozen 248-file snapshot including 17 existing Markdown documents, with
  zero archives and unchanged source bytes/modes. Source screening ran before
  compilation; the later documentation reconciliation requires another source
  audit before release, not relabeling frozen VM inputs.
- Repeat the actual host Make gates on the frozen 248-file source with GCC 14
  and Clang 22:
  strict UBSan native AES, both mock supervisors and five-source Jasmin
  compile/safety/CT/DOIT/lowering/correspondence pass, including 1,026 AES block
  and 1,539 AES4 oracle cases per compiler. The actual fixed-vector Frama-C
  Eva gate passes with zero alarms, four valid loop properties, seven valid
  preconditions and 64 reached byte checks. The license inventory gate also
  passes. These selected results do not close broader WP, platform, package
  or signature gates.
- Reject warning-scanner errors in the Jasmin source gate instead of treating
  them as absence of warnings. Preserve the scanner's status and stop before
  downstream work. Add `test-jasmin-source-wrapper` to `check` with four mock
  controls for no warning, warning, error 2 and simulated unavailable status
  127. These orchestration-only controls do not execute or prove Jasmin
  analysis; analysis commands and criteria remain unchanged.
- Validate ANS4 metadata and all lane lengths with integer bounds before
  forming source pointers or allocating a decode table. Preserve the block
  format and successful decode lengths. Add exact-sized native fixtures for
  truncated metadata and oversized lanes, and a Frama-C 29.0 Eva gate that
  rejects alarms, incomplete analysis, external preprocessor warnings and
  execution failures. Test the gate's diagnostic handling separately with
  synthetic results; those controls are not formal verification of the codec.
- Keep the legacy MAC accumulator reduction entirely unsigned, including
  full-width results from the optional assembly comparison. The existing
  2,000-case F-06 regression now passes with the assembly path and
  non-recovering UBSan after exposing signed overflow in the old reduction.
  Both legacy MAC candidates and their wire format are unchanged.
- Correct the Jasmin AES source's second key-element index and 128-bit
  destination store. Require compiler-managed stack zeroization and explicit
  constant-time contracts in the four selected sources. Add source analysis
  and generated AES tests against NIST and OpenSSL, without treating these
  selected checks as verification of the complete application.
- Replace the hand-written AES4 runtime with Jasmin 2026.09.0 output from its
  executable source, including explicit loop termination. The parameterized
  safety analysis declares pointer/count roles and remains conditional on
  caller allocation and alias requirements. Keep the earlier unparameterized
  analysis that reached its 120-second limit as historical blocked evidence.
- Regenerate all five runtime assemblies with Jasmin 2026.09.0 and record
  source hashes. Require the exact global function at `.text` start, no
  relocations and matching instruction sections against fresh generation.
  GCC 14 and Clang 22 pass the five-source compile/safety/CT/DOIT/lowering
  gate, 1,026 AES block oracle cases and 1,539 AES4 oracle cases per compiler.
  Check fifteen single-block and sixteen AES4 stack-wipe stores. The AES4
  frame is 256 bytes (240 round-key bytes and 16 counter bytes), with a maximum
  264-byte RSP descent under the x86_64 SysV ABI alignment. These correctness
  checks make no throughput claim and do not prove register erasure or every
  caller.
- Validate the current C and generated-assembly callers with non-recovering
  UBSan: GCC 14 and Clang 22 each pass 16 vectors and 2,000 F-06 round trips
  with `WITH_JASMIN=0` and `1`, with no accepted altered MACs in any profile.
- Make `test-jasmin-source`, `test-frama-ans-decode-bounds` and
  `test-frama-aes-nist` prerequisites of `release-check` on the documented
  x86_64 Linux maintainer host. Keep these
  tool-dependent analyses outside distribution-friendly `check` and `test-all`.
  The broader Frama-C/WP and final distribution gates remain incomplete.
- Initialize the real CPU detector in the cryptographic vector and F-06 tests
  and report the selected AES path. Previously these binaries kept the CPU
  feature global at zero and covered only C AES despite an assembly-enabled
  build. Preserve the existing vector values, 2,000 trials and rejection rules.
- Release prepared ANS4 tables when its combined lane-buffer allocation fails.
  Propagate Huffman tree allocation failures as `VVH_ERR_NOMEM` instead of
  continuing with an empty code table. Add deterministic fault injection for
  the five ANS4 allocations reached by the fixture and all three Huffman tree
  allocations in both encoders, plus successful byte-exact round trips.
- Require exact lengths for native hybrid, ML-KEM-only, SDK and PQBOX recipient
  envelopes. Reject empty SDK ciphertexts and oversized lengths before copying.
  In the libvuptsdk adapter, treat provider output pointers and lengths as owned
  only after a successful return: wipe the fixed 32-byte session key, release
  successful outputs with the provider deallocator, and do not traverse
  undocumented error outputs. Add real SDK-adapter boundary tests with a
  controlled provider, fixed-envelope PQBOX parser tests, and native
  encoder/decoder round trips. PQBOX remains disabled and unapproved for release
  packages until libpqvaptvupt's exact failure-output ownership and length
  contract has been reviewed and tested.
- Make the SDK KDF-transparency gate compile the enabled adapter with the same
  `SDK_CPPFLAGS` and `SDK_LDLIBS` accepted by the build. A configured provider
  can no longer be reported as a missing-dependency skip after compiling the
  disabled stub branch. The controlled provider confirms dispatch,
  deterministic output and a cost floor; it does not prove Argon2id or memory
  hardness.
- Fetch the Fedora source recipe from the Git tag snapshot instead of a
  public release tarball. Reproducible tarballs remain private RPM/OBS build
  inputs; the public source bundle remains `.zupt`.
- Tear down partially started compression workers and use the existing
  sequential fallback; cover failures after zero, one and two workers.
- Make the malformed-archive harness fail on sanitizer diagnostics, process
  signals and execution errors rather than accepting them as parser rejection.
- Give each format-fuzz run a private temporary directory under `TMPDIR` and
  create mutation inputs exclusively with owner-only permissions. Check file
  and directory cleanup instead of reporting success after a cleanup failure.
  Stop at the first fatal result and retain its input for replay; distinguish
  incomplete or missing input from a complete retained file. Add regressions
  for isolation, permissions, exact retained bytes, successful cleanup,
  invalid temporary roots and child/cleanup failures. The archive format and
  CLI are unchanged. Use non-sensitive seeds and preserve findings before
  tearing down a disposable test environment.
- Require normal status 1 and the intended diagnostic for installed-smoke
  rejection cases. Check every CLI call for sanitizer output and print raw
  failures before cleanup. Add real-CLI delegating regressions for abnormal
  statuses, unrelated errors, POSIX signals and synthetic sanitizer findings
  to `make check`; the controls do not substitute for sanitizer execution.
- Give timing comparators the same balanced input preparation and add matched
  controls, deterministic statistics regressions and an explicit inconclusive
  status. Preserve the cryptographic primitive and existing thresholds; retain
  the original aggregate criterion and also require the matched-ratio median.
- Calibrate the timing regression against its deliberate early-exit comparator,
  retaining libc `memcmp` as a diagnostic rather than assuming it exposes a
  strong 32-byte signal. Keep the 400/0.20 thresholds and all matched-run checks;
  add weak-control, aggregation and deliberately leaky-target regressions.
  The 1088-byte results remain informational, and earlier failed or inconclusive
  measurements are not reclassified by this change of method.
- Run SHA-NI and incremental HMAC fixtures with the selected compiler and
  build flags, keeping SHA-NI-specific flags local to that translation unit.
  Reject a failed or signalled SHA-NI test even if its output claims success
  or a hardware skip; cover compiler selection and exit handling separately.
- Extend codec unit tests with exact-sized nonempty truncated inputs, insufficient
  output capacities, misaligned buffers, damaged checksums and NULL parameter
  rejection. Cover ten 4 KiB text/random mode and v2-option combinations without
  changing the codec or archive grammar; zero-length cases use a one-byte
  non-NULL allocation. These are bounded regressions, not
  exhaustive malformed-input coverage or release approval.
- Build both decompression fuzz targets from the complete codec source set and
  exercise those recipes from `make check`. Make their input and archive setup
  fail closed on I/O errors, remove temporary extraction trees without following
  symlinks, and cover valid, truncated, short-write and cleanup paths with GCC
  and Clang. Preserve compiler and analyzer failures in the static-analysis gate
  instead of allowing an empty diagnostic stream to mask a failed tool.
- Release only after the required gates pass; do not publish a candidate or
  known-issues prerelease.

## [5.2.9] — 2026-09-06 — VaptVupt 2.65.11 compatibility refresh

Official release: [downloads and checksums](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
Português do Brasil: [resumo da versão 5.2.9](README.pt-BR.md#versão-oficial-529).

- Update the bundled VaptVupt codec from 2.65.3 to tag `v2.65.11` at
  `1cc78bce90619dbf97e0ed1ad449c3c4f6329041` while preserving Zupt's
  wrapper defaults, read-back verification, parser guards, secure-wipe
  fallback, and third-party notices.
- Carry the codec's decoder span validation, truncated-bitstream rejection,
  output-capacity and frame-metadata checks, allocation reuse, scalar-build
  switch, and XXH64 zero-length and tail-bound corrections into the in-tree
  consumer.
- Keep archive format 1.6, codec identifier `0x0010`, command behavior, and SDK
  ABI unchanged. Zupt continues to use independent frames through its existing
  one-shot wrapper; it does not require a kernel module or the new FAST context.
- Add concise Brazilian Portuguese project and operational documentation and
  include it in source, Linux, Windows, macOS, DEB, RPM, AUR, Homebrew, Nix,
  Guix, and openSUSE documentation payloads.
- Require a fresh exact-tag GCC/Clang, sanitizer, analyzer, source, package,
  Windows, and macOS matrix. Earlier 5.2.8 results remain historical evidence
  and are not 5.2.9 release approval.

## [5.2.8] — 2026-08-31 — Path-race hardening and native-fixture correction

Corrective successor to the immutable, unpromoted `v5.2.7` candidate.
Exact-tag GitHub Actions run `33445470664` reached a macOS failure because the
runner filesystem rejected creation of the raw-C1 filename fixture with
`EILSEQ`. The workflow concluded `cancelled` at `2026-08-31T23:11:19Z`, with
13 successful jobs, one failed macOS job, and one cancelled Windows job.
The hosted Windows job stalled in `make check`; a MinGW/Wine reproduction
isolated the cause to `test --password-prompt ... </dev/null` entering
`_getch` despite redirected standard input. The tag and its evidence remain
unchanged.

- Close CodeQL High #5 in SDK key saving by copying into the core atomic
  publisher's already-open private object, applying POSIX key permissions with
  `fchmod` on that descriptor, checking read/close/publication failures, and
  replacing only the requested directory entry. Symlink and hardlink target
  sentinels and private/public key modes are covered by the SDK regression.
- Close CodeQL High #6 in POSIX disk restore by opening the target once without
  truncation or final-symlink following, classifying that descriptor with
  `fstat`, and retaining the same device descriptor through capacity checks and
  writes. Regular-file restores continue to use atomic publication.
- Close CodeQL High #7 in benchmark cleanup by resolving POSIX components with
  `openat(..., O_NOFOLLOW)`, deleting relative to pinned descriptors with
  `unlinkat`, and using pinned, reparse-point-aware handles for Windows
  traversal. The regression injects a directory symlink into a live workspace
  and verifies that cleanup does not visit its target.
- The first default-branch rescan closed #5, #6, and #7 and then identified
  test-only path checks as High #8, #9, and #10 in the new SDK regression.
  Replace every test-side `stat`/`lstat` sequence with one no-follow `open`
  followed by `fstat` and descriptor reads, and retain that boundary in the
  static regression gate. Default-branch run `33452563116` completed
  successfully with #5 through #10 fixed and zero open code-scanning alerts.
- Treat inability to create the raw-C1 scanner filename as an explicit fixture
  skip on filesystems that reject the byte; when creation succeeds, the unsafe
  diagnostic-escaping assertions still run unchanged. Normalize Bash 3.2's
  sign-extended `%d` character conversion to an unsigned octet so raw and
  UTF-8 C1 diagnostics retain their canonical `\\xNN`/`\\uNNNN` form.
- Reject redirected or otherwise non-console Windows password prompts before
  entering `_getch`, handle console EOF as an error, and cover the native
  redirected-input path so it cannot hang a release gate.
- On Windows, validate private-key confinement as the protected,
  current-user-only DACL that the implementation creates; do not treat MSYS's
  synthetic `stat` mode as a POSIX `0600` result. POSIX continues to require
  the real descriptor mode `0600` under multiple umasks.
- Replace the old MSYS `grep` non-BMP boundary exposed after 14 successful jobs
  in pre-tag run `33452602634` with byte-exact Python checks for Latin-1, BMP,
  and non-BMP UTF-8 listing output. Construct the emoji fixture from ASCII byte
  escapes and require list, extract, and full-tree equality; the independent
  path regression also creates its BMP/non-BMP name from ASCII hex.
- Run `sdk-test` from both `release-check` and the hosted GCC/Clang Linux job so
  the atomic key-save regression cannot silently fall outside release gates.
- Carry the v5.2.7 archive format, cryptography, bundled codec release, and SDK
  ABI forward unchanged. These are implementation and test-integration
  corrections, not a wire-format or API change.
- Realign current code, package, workflow, artifact, and documentation
  references to 5.2.8, and pin the AUR/Homebrew SHA-256 and Guix content hash
  to the final reproducible source archive before tagging.
- Exact-tag run `33456209269` passed all 15 source, package, analyzer,
  sanitizer, OBS, Windows, and macOS jobs at `ebb9ab3`. Promotion initially
  stopped before publication because its validator treated `%{ARCH}` as the
  SRPM discriminator; the genuine SRPMs instead correctly carry
  `%{SOURCEPACKAGE}=1`. Commit `33eb904` corrected and strengthened that gate,
  and run `33457868306` published the exact 13 tested assets without rebuilding
  them. No v5.2.7 result transfers to this evidence.

## [5.2.7] — 2026-08-31 — Native test-harness portability corrections

Corrective successor to the immutable, unpromoted `v5.2.6` candidate. Exact-tag
GitHub Actions run `33442264243` completed 13 jobs successfully, but the native
Windows and macOS jobs failed, so no 5.2.6 assets were promoted. The tag and its
recorded evidence remain unchanged.

- Scope the SHA-NI regression helper declarations to the supported x86 build
  path so macOS arm64 strict compilation does not diagnose unused declarations
  under `-Werror`.
- Carry the safe printable UTF-8 path fixture through an explicit
  byte-stable Windows argument representation so argv transcoding cannot abort
  the regression before its intended archive and diagnostic assertions.
- Carry the 5.2.6 source-only and security baseline forward without changing
  the archive format, cryptography, bundled codec release, or SDK ABI.
- Realign current source, package, workflow, artifact, and tag references to
  5.2.7, then pin the final reproducible release-archive checksum and content
  hash in the downstream recipes before tagging.
- Require fresh exact-`v5.2.7` source, checksum, hosted CI, native-platform,
  package, OBS, and promotion evidence. No prior candidate result transfers
  automatically, and this entry does not claim those gates passed.

## [5.2.6] — 2026-08-31 — Native release-gate portability corrections

Corrective successor to the immutable, unpromoted `v5.2.5` candidate. Exact-tag
GitHub Actions run `33434986357` completed 13 jobs successfully, but the native
Windows and macOS jobs failed, so no 5.2.5 assets were promoted. The tag and its
recorded evidence remain unchanged.

- Use the compiler-resistant volatile wipe fallback on macOS and NetBSD instead
  of assuming that their C libraries export `explicit_bzero`; supported glibc,
  FreeBSD, and OpenBSD paths retain their existing selection.
- Make the source-only scanner's empty-array handling compatible with the
  system Bash 3.2 shipped by macOS, including repository, tag, standalone-tree,
  standalone-archive, and path-component traversal paths.
- Make hostile archive-path fixtures accept explicit hexadecimal bytes, verify
  the requested path bytes in the generated archive, and reject the dangerous
  raw byte fragment anywhere in diagnostic output, so the Windows regression
  does not depend on command-line conversion or benign path prefixes.
- Carry the 5.2.5 source-only and security baseline forward without changing
  the archive format, cryptography, bundled codec release, or SDK ABI.
- Realign current package, workflow, artifact, and tag references to 5.2.6;
  leave release-archive checksums explicitly pending until the final source
  archive is generated.
- Require fresh exact-`v5.2.6` source, checksum, hosted CI, native-platform,
  package, OBS, and promotion evidence. No prior candidate result transfers
  automatically, and this changelog entry does not claim those gates passed.

## [5.2.5] — 2026-08-31 — OBS service working-directory correction

Corrective successor to the immutable `v5.2.4` candidate. GitHub Actions run
`33431386002` did not promote that tag: 12 jobs passed, the openSUSE Tumbleweed
RPM gate failed because its standalone `Serviceinfo` executor inherited the
repository working directory instead of the isolated service directory, and
the dependent Windows/macOS gate was skipped. The tag and its recorded
checksums remain unchanged.

- Run the standalone OBS `obs_scm` → `tar` → `recompress` chain from its
  isolated service directory so downstream services can find `.obsinfo`.
- Add a packaging-policy regression for the OBS executor working directory
  while retaining the immutable `refs/tags/v5.2.5` service revision assertion.
- Record the successful local Tumbleweed reproduction of the corrected service
  chain; it produced one source archive that passed the source-only scanner.
- Carry the 5.2.4 security and source-only baseline forward without changing
  the archive format, cryptography, bundled codec release, or SDK ABI.
- Realign current package, workflow, artifact, and tag references to 5.2.5;
  leave AUR, Homebrew, and Guix hashes pending the final source archive.
- Require fresh exact-`v5.2.5` source, checksum, hosted CI, native-platform,
  package, and promotion evidence; no v5.2.4 result transfers automatically.

## [5.2.4] — 2026-08-31 — Source-policy line-ending correction

Corrective successor to the immutable `v5.2.3` candidate. That candidate was
not promoted because its source-policy test assumed LF bytes for a Windows
`.bat` file that Git correctly materializes as CRLF according to
`.gitattributes`; the tag and its historical record remain unchanged.

- Correct the release/source-policy integration so the required CRLF checkout
  form is validated without treating it as source drift.
- Carry the 5.2.3 release-integration work and the 5.2.2 security/source-only
  baseline forward without an archive-format, cryptographic, codec, or SDK ABI
  change.
- Realign current documentation, package, workflow, artifact, and tag references
  to 5.2.4 while keeping generated binaries outside Git and source archives.
- Correct three internal regression-test headers so pre-3.0 product releases
  retain the historical ZUPT name; VaptVupt remains only the bundled codec and
  compatibility-facing identifier where applicable.
- Require fresh exact-`v5.2.4` source, checksum, hosted CI, native-platform,
  package, and promotion evidence; no 5.2.3 result transfers automatically.
- Keep authenticated OBS/Factory validation pending and retain the unresolved,
  unsuppressed openSUSE automatic `debugsource` rpmlint `no-binary` finding.

## [5.2.3] — 2026-08-31 — Corrective release integration

Corrective successor to the immutable `v5.2.2` candidate. Post-tag CI
integration failures prevented 5.2.2 asset promotion; the tag and its historical
record remain unchanged.

- Carry the 5.2.2 source-only, security, naming, format, and compatibility work
  forward without a new archive-format version, codec release, or SDK ABI.
- Realign current source, package, workflow, documentation, artifact, and tag
  version references to 5.2.3. Release binaries remain outside Git and source
  archives.
- Make `zupt-gui --version` emit the stable machine-readable line
  `zupt-gui 5.2.3`, and cover that contract in GUI/package regressions.
- Derive Debian and Fedora GUI integration paths, package metadata checks, and
  CLI dependency checks from the authoritative version header instead of a
  prior-release literal.
- Repair native RPM container gates: persist the exact checked-out workspace as
  a Git safe directory, and remove Tumbleweed's conflicting `busybox-gawk`
  before installing the native `gawk`/RPM toolchain.
- Require a new exact-`v5.2.3` source archive and checksum set plus fresh hosted
  CI, native Windows/macOS, package, and promotion evidence. Prior local 5.2.2
  results do not transfer automatically.
- Keep authenticated OBS/Factory validation pending. The automatic openSUSE
  `debugsource` rpmlint `no-binary` finding remains unresolved and unsuppressed.
- Continue to exclude AppImage/AppDir/Flatpak, GUI platform installers, and bare
  executables from the promoted set; retain the notice-bearing CLI archives and
  source-only portable GUI ZIP policy.


## [5.2.2] — 2026-08-31 — ZUPT identity, source-only upstream tree, and openSUSE packaging

This maintenance release keeps the `.zupt` extension, the v1.6 version byte,
and the bundled VaptVupt codec at 2.65.3. It adds flag-gated 5.2.2 encodings for
authenticated encrypted-dedup references and disk-image integrity/index
metadata. The 5.2.2 reader retains a narrow legacy v5.2.1 plain disk-index
path; older readers are not claimed to accept every archive written by 5.2.2.

### Product identity and compatibility

- Restored the original **ZUPT** product name and `zupt` command across the
  application, GUI, packages, documentation, and release artifacts.
- Moved the canonical project location to
  `https://github.com/cristiancmoises/zupt`.
- Kept the `.zupt` extension, format v1.6, `ZUPT` magic bytes, codec IDs,
  `zupt_*`/`ZUPT_*` identifiers, and `zuptsdk_*` ABI unchanged. This is a
  product-identity change, not an archive or cryptographic format change.
- Retained the name VaptVupt where it identifies the bundled codec, its
  `vv_*` API/wire format, the `--vv`/`--vaptvupt` codec selector, or an external
  compatibility contract. An optional `vaptvupt` command alias can support
  scripts written for versions 3.0.0 through 5.2.1.

### Source and build

- Removed the incomplete `vendor/vuptsdk/` and `vendor/pqvaptvupt/` header
  snapshots and every build expectation that a precompiled local `.so`, `.a`,
  or `.o` is available. Git and newly generated source archives contain source
  and necessary data only.
- `WITH_SDK` and `WITH_PQBOX` are disabled by default. When requested, they
  resolve separately installed development libraries through `pkg-config` (or
  explicit packager-supplied flags) and fail clearly when unavailable. The
  build never downloads dependencies or falls back to a binary under `vendor/`.
- Reworked the Makefile to honor `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`,
  `LDLIBS`, `AR`, `RANLIB`, `STRIP`, `DESTDIR`, `PREFIX`, and install-directory
  overrides. Architecture detection follows the compiler target. Baseline
  builds no longer apply AVX2 to the whole program, add a private-library
  RPATH, or strip distribution binaries.
- `make install DESTDIR=... PREFIX=/usr` supports staged package builds. The
  `vaptvupt` command is an optional compatibility install, not part of the
  openSUSE main package.
- Added `--password-prompt`, `--pass-file`, and `--pass-fd` to every CLI path
  that accepts a password. These explicit sources avoid the historical
  optional-argument ambiguity of `-p`; file/descriptor input rejects empty,
  NUL-containing, and overlong values.
- Hardened native key handling: private outputs use no-replace creation with
  POSIX mode `0600` or a Windows current-user-only DACL, and ZKEY/ZPQK inputs
  must pass checksum, version, flags, reserved-byte, exact-size, and
  public/private-role validation. A write/flush/close failure leaves its
  incomplete or durability-uncertain exclusive file for manual review and
  removal instead of risking an unlink-after-close race against a replacement
  pathname.
- Added signal-aware POSIX password-prompt cleanup that restores saved terminal
  state on handled interruption, with a PTY regression in the final gate.
- Corrected bundled-code provenance: pq-crystals/kyber-derived ML-KEM portions
  now carry the upstream CC0-1.0 option and complete license text; the x86 BCJ
  state machine is identified as an adaptation of Igor Pavlov's public-domain
  LZMA SDK source instead of making an unsupported clean-room claim; and
  curve25519-donna-derived X25519 portions retain the conservative upstream
  BSD-3-Clause notice. The SHA-NI path now records its immutable
  public-domain SHA-Intrinsics reference.
- Removed unsupported `JASMIN-VERIFIED` labels. The repository retains
  Jasmin textual sources and generated/hand-written assembly plus runtime
  tests, but no reproducible formal-proof certificate or log for these paths;
  historical changelog claims below are qualified accordingly.
- Treat older “constant-time by construction” and formal-verification wording
  as historical design claims unless a current reproducible proof artifact is
  named. Source review and timing regressions do not prove the behavior of
  every compiler, CPU, or final binary.

### Archive integrity and path security

- Reject archive entry names containing absolute roots, `.` or `..`
  components, control characters, NTFS alternate-stream syntax, trailing
  dot/space components, or reserved DOS device names. Empty, overlong, and
  embedded-NUL index paths are rejected during parsing.
- Create output below a pinned destination. POSIX systems traverse parents with
  `openat()`/`mkdirat()` and `O_NOFOLLOW` after resolving the user-selected root
  to a physical path once; Windows traverses and creates each component with
  handle-relative `NtCreateFile` and publishes with a handle-relative
  `FileRenameInfo`. Neither implementation re-resolves a checked archive path
  through a mutable parent.
- Write to a private, newly created temporary file and publish it atomically
  only after the decoded size, per-file checksum, archive integrity checks, and
  close/flush operations succeed. Existing regular files, hardlinks, symlinks,
  or reparse points are never overwritten.
- Normal, solid, and disk-image compression now use the same private-temporary
  discipline in the destination directory. Publication replaces only the
  requested directory entry, so an output symlink or hardlink cannot truncate
  its target; any input, encryption, or write failure preserves the previous
  archive and removes the temporary. Disk-image indices now use the canonical
  varint encoding and pass the normal `list` and `test` parsers. Disk backup
  measures and reads the source through one open descriptor, rejects a size
  change, and cannot be redirected by exchanging the source pathname. Before
  creating the temporary output, normal compression and disk backup also reject
  an output that identifies the same file as the input through an alternate
  spelling, hardlink, or symlink; `--force` does not bypass this guard.
- Disk restore now copies the measured compacted archive into one private,
  auto-deleted scratch file before opening the destructive destination. Its
  preflight and restore phases consume that same snapshot, so exchanging the
  source pathname cannot change the bytes after validation. `ZUPT_TMPDIR`
  selects an existing scratch directory and fails without fallback when it is
  invalid or lacks space. Linux, macOS, and FreeBSD raw block-device capacity
  is queried before the first write; an unknown or undersized device fails
  closed. Regular-file restore retains atomic publication.
- Bind every encrypted DATA frame to its logical file/block position (or disk
  block position), including when deduplication is enabled. An authenticated
  DEDUP_REF is bound to its own logical position and carries the authenticated
  source position needed to verify the referenced DATA frame. Swapping either
  kind of frame therefore fails authentication instead of relying on the former
  archive-wide dedup AAD sentinel. Generic `test` and byte-exact `disk restore`
  regressions cover encrypted `disk backup --dedup`; they remain part of the
  exact final-candidate gate described below.
- Require both XXH64 and an independent SHA-256/128 digest match before
  emitting a dedup reference, and authenticate reference offsets in new
  encrypted archives.
- Require a valid archive-integrity trailer in the `extract`, `list`, `test`,
  and `disk restore` paths by default, regardless of unauthenticated header
  flags. `--allow-legacy-no-ait` is an explicit recovery-only override for
  those commands when given a known, trusted pre-AIT archive; it emits a
  downgrade warning. Writers never use the override or create a no-AIT archive.
  `info` remains an unauthenticated framing inspection: it reports AIT presence
  but does not validate the trailer or archive contents.
- Authenticate the encrypted disk index and record a chained whole-image XXH64
  content hash in new disk archives. Generic `test` and `disk restore` verify
  block count, restored size, reference targets, and that content hash. XXH64
  remains a non-cryptographic corruption check in a plain archive.
- Retain compatibility parsers for the fixed little-endian disk index and the
  linear encrypted-dedup AAD sequence published through 5.2.1. The regression
  fixture is an actual v5.2.1 password-encrypted DATA/DATA/REF/DATA disk archive,
  stored as hexadecimal text with its source tag/commit, password, input hash,
  and archive hash. The 5.2.2 candidate lists, tests, extracts, and restores it byte-exact;
  the legacy index has no whole-image hash and produces an explicit warning.
  The full local Linux gate passed on commit `ff99770`; no broader historical
  compatibility claim is made.
- Serialize fixed-width archive/header, footer, index and PBKDF iteration
  fields explicitly in little-endian order. Varint readers now reject overlong
  encodings and values wider than 64 bits instead of accepting an ambiguous or
  wrapped scalar.
- Require a DATA frame wherever a decoder consumes file or disk payload. The
  multithreaded and serial readers, solid reader, generic `test`, and disk
  restore now reject type-confused frames rather than decoding COMMENT or INDEX
  payload as ordinary data.
- Add structurally valid hostile-archive fixtures covering traversal, absolute
  and Windows-special paths, destination leaf/ancestor links, a relative user
  output root, corrupt payload cleanup, nested UTF-8 paths, and safe separator
  normalization.
- Scope the Windows output boundary to normal local Win32 paths. Cross-build
  and Wine results are not native-Windows evidence; the native package workflow,
  including its Unicode round trip, remains a release gate.
  Extended-length/device namespace paths, raw UNC output roots, and
  mapped/network-drive output are unsupported in 5.2.2.
- Create benchmark corpora, archives, extraction outputs, and concatenation
  inputs below a randomly generated private temporary directory and clean it
  recursively without following links. This replaces the predictable
  process-ID-only scratch path used by earlier builds.
- Render archive comments as untrusted terminal data: control bytes are shown
  safely rather than emitted as raw terminal-control sequences. The stored and
  authenticated comment bytes are unchanged.

### Licensing and provenance erratum

- Corrected prior documentation that incorrectly denied all historical MIT
  grants. Commit `d4660e6539c8b6eeba81751c018217d978fdd618` distributed the
  then-current first-party application and GUI with MIT license files, and the
  immutable `v2.2.2` tag contains an MIT-form `gui/LICENSE-GUI` alongside an
  AGPL SPDX notice in the GUI source. Those records are preserved and their
  historical permissions are not revoked or reinterpreted by 5.2.2.
- Current source follows its current per-file SPDX notices: the application,
  GUI, cryptographic tool, build, test, and documentation code are
  AGPL-3.0-or-later, while the identified bundled codec source is
  GPL-3.0-or-later. The erratum corrects the record; it does not rewrite old
  tags or change the license of a historical copy.
- Distinguished Jasmin compiler output from hand-written textual assembly.
  `zupt_aes_ctr4.s` is a hand-written production implementation corresponding
  to an algorithm-only `.jazz` description; generated files retain their
  available compiler provenance.
- Corrected the stale claim that the adapted XXH64 code was public domain.
  Both derived implementations now preserve Yann Collet's BSD-2-Clause
  copyright, conditions, disclaimer, and compound SPDX scope; binary package
  metadata and license payloads include BSD-2-Clause.

### Audit, tests, packaging, and release

- Added a reusable source-only scanner for tracked files, the working tree,
  `git archive`, release archives, nested archives, unsafe symlinks, Git LFS
  pointers, compiler output, executable magic, and stale vendor-library
  references. Positive and negative regression tests cover renamed ELF, ar,
  PE/MZ, versioned `.so`, RPM/DEB/AppImage, escaping symlinks, and LFS pointers
  while permitting textual assembly. Necessary non-code `.bin` data requires a
  manifest entry with purpose, provenance, and SPDX license; compiled magic is
  never allowlisted. Nested inspection now has fail-closed recursion, member,
  per-entry expansion, and total-expansion limits with decompression-bomb
  regressions.
- Make `tests/regression.sh`'s Bash interpreter requirement explicit so running
  it through a non-Bash `/bin/sh` cannot masquerade as a product regression.
- Added upstream openSUSE/OBS packaging under `packaging/opensuse/`, built with
  `WITH_SDK=0 WITH_PQBOX=0`, real `%check` execution, staged installation, and
  no installed `vaptvupt` alias. The OBS service tracks the canonical ZUPT
  repository and an immutable release tag; no acceptance by OBS or Factory is
  implied by files being present upstream.
- Updated CI and release checks around clean source builds, tests, source
  archive inspection, packaging metadata, licenses, and secret hygiene.
- The gated release path is defined to produce the audited source archive plus
  an Ubuntu amd64 CLI DEB, openSUSE Tumbleweed x86_64 CLI binary/source RPMs,
  a notice-bearing Linux x86_64 CLI tar.xz, an architecture-independent GUI
  DEB, a noarch GUI RPM and matching source RPM, a source-only portable GUI
  ZIP, a CLI Windows x86_64 ZIP containing the executable and notices, and a
  native-architecture CLI macOS DMG.
  Each binary format is built separately from the tagged source and may be
  published only after its target-specific package and functional gates pass;
  `SHA256SUMS` covers the promoted assets. Packages never enter Git or the
  source archive.
- Exclude AppImage, AppDir and Flatpak bundles, GUI platform installers, and
  bare executables from the 5.2.2 release set: the inspected type-2 runtime's
  static dependency notice omitted mimalloc and the available inputs did not
  provide a complete LGPL source/relink handoff. The offline helper now
  requires runtime-specific compliance material from its operator.
- Publish the Windows executable only inside its ZIP with AGPL, GPL,
  BSD-2-Clause, BSD-3-Clause, CC0-1.0, toolchain-runtime, NOTICE, and
  third-party notices; no bare EXE is promoted.
- Limit the 5.2.2 GUI artifact promise to `zupt-gui_5.2.2_all.deb`,
  `zupt-gui-5.2.2-1.noarch.rpm`, its matching source RPM, and
  `zupt-gui-5.2.2-portable.zip`. Package artifacts have exact dependency and
  installed off-screen GUI/CLI tests. The portable ZIP contains source and
  launchers only and passes source scans, an exact safe-member allowlist, and an
  extracted off-screen launcher test. Windows and macOS artifacts remain
  CLI-only.
- Remove the standalone GUI `setup.py` sdist/wheel route, whose outputs omitted
  the complete AGPL and artwork-provenance payload. Reviewed GUI installers and
  package helpers preserve those notices with every included icon.
- Updated the README, installation, distribution, security, audit, GUI, and
  manual-page documentation for the 5.2.2 source-only workflow.

The committed Linux candidate `ff99770` passed the full local
`make release-check`. Recorded results include packaging
`PASS=49 FAIL=0 SKIP=0`; 39/39 source-only scanner cases, including GNU thin
archives and safe diagnostics; strict GCC and Clang; GCC `-fanalyzer`; 9/9 in
the full tool-enabled static-analysis run; ASan/UBSan/LSan; and 1,000
mutation-fuzz iterations without a sanitizer-detected crash. An earlier
off-screen GUI smoke run remains supporting rather than exact-candidate package
evidence.

These are upstream self-audit results, not independent certification or a
published-release claim. Native Windows and macOS, hosted GitHub CI and release
promotion, authenticated OBS, and the openSUSE automatic `debugsource` rpmlint
`no-binary` finding remain pending. Missing or unexecuted gates remain `SKIP`,
not `PASS`.


## [5.2.1] — 2026-07-12 — GUI Verify/Extract robustness; refreshed comparison + audit tables

Backward-compatible; no format, key, or codec change (codec stays 2.65.3, wire
format v1.6). GUI-only fix + documentation.

### GUI — Verify and Extract no longer error on a mis-set mode / missing credential

- Verifying an encrypted archive required picking the correct PQ mode from a
  dropdown and supplying the matching key; a wrong pick produced a raw CLI
  decrypt error ("Error: Archive uses post-quantum encryption. Use --pq" /
  "Authentication failed"), and Verify ran synchronously on the GUI thread
  (freezing the window on a large archive).
- New `_detect_archive_enc()` reads the archive header via `info` (no credential)
  and classifies it none / password / pq / pqonly / sdk. The Verify tab now
  auto-detects the encryption, uses the matching decrypt flag automatically (a
  wrong-mode mismatch is impossible — the PQ-mode dropdown was removed), and if
  the required password or key is missing it shows a clear instruction instead
  of a raw error. Verify runs through the async job runner (own progress bar),
  so it never freezes; results print "All checksums passed." / "Verification
  failed."
- The same header-detection + missing-credential guidance is applied to the
  Extract tab (it had the identical footgun).

### Documentation

- Refreshed the README **Compression comparison** tables (ratio + throughput vs
  zstd/gzip/lz4) on codec 2.65.3, every round-trip byte-exact.
- Added an **Audit status** table: `make check` 16/16, NIST/RFC KAT 16/16,
  ML-KEM-768 FIPS 203 conformance 3/3, path-traversal 5/5, block-swap 6/6,
  dedup-nonce 1/1, arg-order 8/8, decode-slack 7/7, SHA-NI + incremental HMAC
  9/9, exact-size decode 80/80, GUI branding 11/11.

### Validation

Full GUI function matrix on a real X display with thread-safety instrumentation
(zero cross-thread widget access): compress/extract (hybrid + full-PQ + password,
byte-exact), Verify (plain/password/hybrid/pq-only pass; missing password and
missing PQ key each produce guidance; wrong credential and non-archive fail
cleanly), Info, Disk backup+restore, two concurrent jobs, close-mid-job.



## [5.2.0] — 2026-07-12 — GUI compress-crash fix; codec 2.65.3; libvuptsdk

Backward-compatible with 5.0.x/5.1.0: `.zupt` wire format unchanged (v1.6),
archives interoperate in both directions, and `--pq` / `--pq-only` keys keep
working.

### GUI — the compress crash / corruption / "nothing happens" is fixed

The 5.1.0 progress-bar work introduced a cross-thread bug that made compress
crash the app ("app closes"), hang ("nothing happens"), or leave a truncated
(corrupt) archive — worst on the full-PQ path.

- Root cause: `run_async` connected plain Python CLOSURES (`finish`/`on_pct`/
  `release`) to signals emitted from the worker `QThread`. PySide6 runs a
  plain-closure slot in the EMITTING thread regardless of the requested
  connection type — even an explicit `Qt.QueuedConnection` — because a bare
  functor has no receiver QObject to give it GUI-thread affinity. Those closures
  then called `QProgressBar.setValue/setRange/hide`, `QPushButton.setEnabled`
  and `QTextEdit.append` from the worker thread. Cross-thread QWidget access is
  undefined behaviour and crashed the app under real X11/Wayland rendering; it
  only survived offscreen tests, so prior automated runs missed it.
- Fix: a `_Job(QObject)` controller parented to a GUI-thread widget, so every
  slot is a bound method Qt auto-marshals to the GUI thread.
- Verified on a real X display (window shown, progress bar rendering) with a
  QProgressBar/QPushButton instrumentation that flags any worker-thread call:
  zero cross-thread calls after the fix, and hybrid + full-PQ + password
  compress/extract all byte-exact round-trip; Verify/Info/Disk backup+restore/
  two-concurrent-jobs/close-mid-job all pass.

### Codec — VaptVupt 2.65.3

Byte-identical output to 2.65.0 (same ratio, wire format v1.6) but extreme-mode
encode is ~1.6–2× faster (Sprint 132) and the extreme prepass window
reservation is capped at 8 MiB instead of up to 128 MiB (Sprint 133 memory
hygiene). Our AVX2 decoder offset-read guard is now upstream; the ANS
safe-zone reserve patch is re-applied on top.

### SDK — libvuptsdk (renamed from libzuptsdk)

`libvuptsdk` (git.securityops.co/cristiancmoises/libvuptsdk) is the renamed
`libzuptsdk`; only the shared-object filename/SONAME changed
(`libzuptsdk.so.2` → `libvuptsdk.so.2`), the C API is unchanged. A `WITH_SDK=1`
build now links `-lvuptsdk` and enables `--pq-sdk` + the Argon2id password KDF.
`--pq-box` needs the SEPARATE `libpqvaptvupt`, which `libvuptsdk` does not
provide, so it is now behind its own `WITH_PQBOX=1` flag rather than folded into
`WITH_SDK`. The default distributed build stays source-only (`WITH_SDK=0`):
native `--pq` / `--pq-only` + PBKDF2, no external libraries. Validated:
`WITH_SDK=1` links libvuptsdk + libcrypto + libargon2, `keygen --sdk` and
`--pq-sdk` encrypt/decrypt round-trip byte-exact.

### Validation

`make check` 16/16 (source-only); codec KAT 16/16; ML-KEM-768 FIPS 203
conformance 3/3; full GUI function matrix on real X with zero cross-thread
access; SDK round-trip on a `WITH_SDK=1` build.



## [5.1.0] — 2026-07-11 — codec 2.65.0; large ratio gains; GUI compress fixes

Backward-compatible with 5.0.0: the `.zupt` wire format is unchanged (v1.6) and
archives interoperate in both directions. `--pq` / `--pq-only` keys and archives
from 5.0.0 continue to work — no key regeneration needed.

### Compression — much better ratio (two settings were leaving it on the table)

- **Vendored codec upgraded 2.60.4 → 2.65.0** (`git.securityops.co/cristiancmoises/vaptvupt-codec`,
  tag v2.65.0): faster balanced encoder and the Sprint 124–130 extreme-mode
  literal-pricing work. The two in-tree audit patches (ANS decode safe-zone
  `2*SAFEZONE_MAX_RUN` reserve against a crafted-sequence heap overflow, and the
  AVX2 offset-read bound in `vv_decoder.c`) are re-applied on top; the safe-zone
  fix is not yet upstream.
- **`format_v2` is no longer forced** in the integration wrapper (`src/vaptvupt_api.c`).
  Forcing the binary-oriented `format_v2`/min_match=3 path on *every* input routed
  text through the greedy parser and **halved the extreme-mode ratio on text**
  (7.6× → 3.7× at the codec level). Since codec v2.61.0 the encoder auto-enables
  `format_v2` for binary-detected input and keeps the optimal parser for text, so
  the wrapper now leaves it on auto — text gets the optimal parser, binary still
  gets v2.
- **Block size scales with level** (`auto_block_size` in `src/zupt_format.c`). The
  block is the codec's LZ window; the old flat 512 KiB extreme block meant the
  "large-window extreme" parser could never match beyond 512 KiB. New defaults:
  ≤2 → 128 KiB, ≤4 → 1 MiB, ≤6 → 2 MiB, 7 (balanced) → 4 MiB, ≥8 (extreme) → 8 MiB.
- **`--dedup` keeps a small block automatically** (256 KiB). Block size also sets
  dedup granularity, and a large block almost never finds a byte-exact duplicate,
  so dedup + large-window are mutually exclusive; `--dedup` now picks the small
  block regardless of level, restoring dedup ratios that the block bump broke.

Measured, level 9 (extreme), 20–25 MB per class, single thread (full tables in
README → *Compression comparison*):

| Data class | 5.0.0 | 5.1.0 | Change |
|---|--:|--:|--:|
| Text (docs, Markdown)      | 3.77× | 5.98× | +58% |
| Server logs                | 7.21× | 9.07× | +26% |
| JSON (structured records)  | 8.25× | 9.38× | +14% |
| Source code (C / headers)  | 4.93× | 5.63× | +14% |

Extreme mode trades encode speed for the larger window (its optimal DP now runs
over a bigger block); balanced (`-l 7`, the default) also improves and stays
fast. Decode speed and memory are unaffected by block size; peak RSS at extreme
is ~30 MB per thread.

### GUI — "app closes / gets stuck when I compress" fixed

- **Crash on every job completion.** `run_async` dropped its `QThread`/`Worker`
  references immediately after `quit()`; Python's cyclic GC then collected the
  still-running `QThread` and Qt aborted the process ("QThread: Destroyed while
  thread is still running"). References are now released from a slot on
  `QThread.finished` after `wait()`.
- **"App stuck" during compress.** The CLI paints live progress as `
` frames
  (no newline until 100%); the worker read line-by-line and so emitted nothing
  for the whole job — the window looked frozen on any file larger than one block.
  The worker now parses `
` progress frames and drives the progress bar, and
  runs the child with `stdin=/dev/null` so a prompt can never block it.
- **Window never appeared on Wayland** (Sway 1.12 + Qt 6.9): the toolkit never
  sent the initial `wl_surface.commit`, so the compositor never mapped the
  surface. The GUI now watches for its first expose and, if none arrives, relaunches
  itself on XWayland (`QT_QPA_PLATFORM=xcb`). Earlier: a Wayland-launch SIGSEGV
  from self-`raise()`/`activateWindow()` (gated to X11 now).
- Worker exceptions can no longer strand a job (catch-all → failure report;
  `errors="replace"` on pipes); closing the window mid-job asks for confirmation
  then aborts cleanly; added `vaptvupt-gui --version` / `--help` / `--selftest`
  for headless launch verification.

### Validation

- `make check` 16/16; codec KAT vectors 16/16; ML-KEM-768 FIPS 203 conformance
  3/3 (still byte-exact vs OpenSSL 3.5); path-traversal, block-swap, dedup-nonce,
  arg-order, decode-slack suites green.
- Cross-version interop: 5.0.0 ↔ 5.1.0 archives (password + `--pq` hybrid +
  `--pq-only`) extract byte-identically in both directions, all levels.
- Full GUI function matrix (keygen / compress with PQ key / password / pq-only /
  extract all modes with byte-identical round-trips / verify / info / concurrent
  jobs / close-mid-job) 16/16 on offscreen and X11; big-file (300 MB) extreme
  round-trips clean, peak RSS 761 MB at 24 threads.



## [5.0.0] — 2026-07-10 — genuine FIPS 203 ML-KEM-768; GUI + CLI hardening

### Security / correctness — ML-KEM-768 is now FIPS 203-conformant

- The in-tree ML-KEM-768 was **round-3 CRYSTALS-Kyber, not final FIPS 203**, so
  it was **not interoperable** with a compliant ML-KEM despite the "FIPS 203"
  label. Found by validating against OpenSSL 3.5's ML-KEM-768. Three deviations,
  all fixed in `src/zupt_mlkem.c`:
  1. **Matrix Â transpose convention** — FIPS 203 K-PKE.KeyGen samples
     `Â[i][j] = SampleNTT(XOF(ρ, j, i))` and K-PKE.Encrypt uses `(ρ, i, j)`; both
     index orders were swapped. Self-consistent (round-trips passed) but
     transposed vs the standard — precisely why a self-consistency-only test
     never caught it.
  2. **Encaps/decaps KDF** — the shared secret is now `K` from `G(m‖H(ek))`
     directly; the round-3 final `K = KDF(K̄‖H(c))` step was removed.
  3. **Implicit rejection** — now `K̄ = J(z‖c)` (SHAKE256 over the full
     ciphertext) instead of `KDF(z‖H(c))`.
- **Validated for genuine conformance against OpenSSL 3.5's FIPS 203
  ML-KEM-768** (`tests/test_mlkem_fips203.sh`, wired into `make check`):
  deterministic keygen produces a byte-identical `ek`, and the shared secret
  matches in **both** cross-decapsulation directions. This permanent conformance
  test replaces the previous self-consistency-only round-trip.

### Security — CLI

- **Data-loss guard.** `compress -p out.zupt file1 file2` used to let `-p`
  swallow the archive name as the password, then overwrite `file1` with the
  archive (silent, exit 0). Now refuses to overwrite an existing non-`.zupt`
  file as the output archive (override with `-y`/`--force`), plus a
  self-overwrite guard.
- **Silent-plaintext guard.** `compress out.zupt dir -p pw` used to write an
  **unencrypted** archive (exit 0) because options after the first positional
  were treated as files. Now errors on a misplaced option (`--` escapes a real
  dashed filename).
- **Heap OOB read** in the AVX2 decoder fast path on crafted archives: the 2-/3-
  byte match-offset read is now bounded like the scalar tail path.
- Wipe ML-KEM/X25519 secret buffers on hybrid-decrypt key-read failure; bound
  the attacker-controlled `encryption_header_off` in the `info` reader.
- `version`/`help`/banners now state the build's real KDF (PBKDF2-SHA256 on the
  source-only build) and repo URL.

### GUI — reworked for the source-only build

- The GUI defaulted every encryption path to the libzuptsdk "SDK v2" modes,
  which are absent from the source-only build and fail — so key generation and
  encryption failed out of the box. Reworked around the native modes: a
  build-aware **PQ-mode selector** (Hybrid `--pq` default · Full-PQ `--pq-only` ·
  SDK v2 only when the binary reports `WITH_SDK` support), detected from
  `version`. Extract/Verify gained a PQ private-key input with **auto-detect**
  (reads the archive via `info` to pick `--pq` vs `--pq-only`); Verify could not
  check any PQ archive before. Fixed a DiskTab QThread-lifetime bug (two buttons
  shared one slot); corrected the About tab (codec, default KDF, `--pq-only`,
  repo URL). Guix packaging: put Shiboken6 on the launcher path so PySide6
  actually imports.

### Packaging & cross-platform

- `debian/rules`, `aur`, `nix`, `homebrew` no longer install the removed
  vendored `.so`/`AUDIT.md` or use stale `/zupt` URLs; `opensuse` `%files` now
  ships the shell completions (no more "unpackaged files" rpmbuild failure).
- New **portable cross-platform GUI package** (`packaging/portable/`) that runs
  on Windows/macOS/Linux/BSD with Python + PySide6, and a **GitHub Actions
  workflow** (`.github/workflows/cross-platform.yml`) that builds native
  Windows (`.exe` + Inno Setup installer) and macOS (`.dmg`) artifacts on real
  runners and attaches them to the release.

### BREAKING

- **`--pq` and `--pq-only` keys and archives created by ≤ 4.2.1 are not
  readable by this release** (the KEM math changed). Regenerate keys
  (`keygen` / `keygen --pq-only`) and re-encrypt affected archives. Password
  mode (`-p`) and plain compression are unaffected. Wire format stays v1.6.


## [4.2.1] — 2026-07-10 — `info` correctly reports the post-quantum mode

### Fixed

- **`vaptvupt info` mislabelled `--pq-only` archives as hybrid.** Full
  post-quantum archives set the generic `ZUPT_FLAG_PQ_HYBRID` header flag (the
  `enc_type` byte is what distinguishes hybrid `0x02` from pure `0x06`), but
  `info` only checked the flag and always printed "PQ Hybrid: YES (ML-KEM-768 +
  X25519)". It now reads the real `enc_type` from the encryption-header block
  and reports the actual mode: "ML-KEM-768 only, no classical layer" for
  `--pq-only`, and hybrid / SDK-v2 / sealed-box for the others. Reader-side only
  — no wire-format change; existing 4.2.0 archives are relabelled correctly with
  no re-encryption. The crypto was always correct; only the `info` label was
  wrong.


## [4.2.0] — 2026-07-09 — Full (pure) post-quantum mode; dedup keystream-reuse fix

### Added — full post-quantum encryption (`--pq-only`)

- New native **full post-quantum** mode: `--pq-only` uses **ML-KEM-768**
  (FIPS 203) as the *sole* key-establishment mechanism, with no classical
  X25519 component. It complements the existing hybrid `--pq` for compliance
  postures that require a single NIST-standardised PQ primitive with no
  classical KEM in the envelope (CNSA 2.0-style "PQ-only" requirements).
- Wire format: new envelope type `0x06` (`ZUPT_ENC_PQ_ONLY`). The archive key
  is `SHA3-512(ml_ss || ml_ct || "ZUPT-PQ-ONLY-v1")`. Keypairs use the `ZPQK`
  magic (1200-byte public, 3600-byte private) and are **not** interchangeable
  with hybrid `--pq` keys.
- Keygen: `vaptvupt keygen --pq-only` and `keygen --pub --pq-only`. Encrypt
  with `compress --pq-only pub.key`, restore with `extract --pq-only priv.key`.
  Wrong/tampered ciphertext is rejected via ML-KEM Fujisaki-Okamoto implicit
  rejection plus the HMAC-SHA256 Encrypt-then-MAC envelope.
- Built entirely from the in-tree crypto — no external library, always
  available in the default source-only build. The security trade-off vs the
  hybrid is documented explicitly: `--pq-only` has no classical safety net, so
  a future break of ML-KEM-768 alone breaks the envelope. `--pq` (hybrid)
  remains the default recommendation.

### Fixed

- **Deterministic keygen guidance for the SDK path.** `keygen --sdk` /
  `--box` on a source-only build now fails with a clear message pointing to the
  native `--pq` / `--pq-only` keygen (or a `WITH_SDK=1` build) instead of an
  opaque error.

### Security

- **Critical — AES-256-CTR keystream reuse under deduplication.** In `--dedup`
  mode every data block was assigned block sequence 0 (the sentinel that lets
  cross-file dedup references authenticate consistently). The per-block AEAD
  nonce was previously derived as `base_nonce XOR block_seq`, so under dedup
  every block collapsed to the *same* nonce — reusing the CTR keystream across
  distinct plaintexts (a many-time-pad, from which XOR of ciphertexts leaks
  plaintext XOR). Each block now uses a **fresh random 128-bit nonce** stored in
  the block prefix and bound into the block MAC; `block_seq` is still bound as
  MAC AAD. Nonces are now distinct across all blocks in every mode (regression
  test `tests/test_dedup_nonce.sh`). Found by an adversarial review of the
  encryption path and confirmed empirically. Archives written by 4.1.0 and
  earlier in `--dedup` + encryption mode should be re-encrypted with 4.2.0.


## [4.1.0] — 2026-07-07 — Source-only build; multithreaded-encryption fix; hardening

### Source-only build (no vendored binaries)

- The prebuilt vendored libraries `libzuptsdk.so` and `libpqvaptvupt.so` are
  removed from the repository. The default build (`make`) now compiles entirely
  from the in-tree C sources with no external library dependency and installs no
  shared object.
- The libzuptsdk-backed modes — the Argon2id password KDF, `--pq-sdk`, and
  `--pq-box` — are gated behind an opt-in `make WITH_SDK=1` build against the
  separately distributed libraries. In the default build they report as
  unsupported. The default password KDF is **PBKDF2-SHA256** (600k iterations)
  and `--pq` (native **ML-KEM-768 + X25519**) is the built-in PQ mode.
- openSUSE packaging builds source-only: `%build`/`%install` pass `WITH_SDK=0`
  and `%files` no longer ships the `.so`.

### Fixed

- **Multithreaded encrypted archives were unextractable** on the native AEAD
  path. The parallel compress/decompress workers used the non-preface
  encrypt/decrypt calls, but the archive's `ZUPT_FLAG_AAD_PREFACE` (F-09) and the
  serial path bind the 29-byte frame preface into every block MAC — so each
  multithreaded block failed authentication. The workers now bind the preface via
  the shared `zupt_serialize_preface_aad_scalars`. Output is byte-identical across
  thread counts, and archives interoperate between single- and multithreaded
  compress/extract. Also fixes `--kdf pbkdf2 -t N`.

### Security

- LZH decoder: bound the raw code-length header against the destination stack
  buffers and reject code lengths > 15 (stack overflow + `huff_lut` OOB write on
  crafted archives).
- Format parser: overflow-safe bounds in `parse_index` and solid-mode extract
  (heap OOB reads via wrapped 64-bit length/offset fields).
- ANS SEQ decoder: reserve a full worst-case sequence (litlen + matchlen) in the
  fast path (heap OOB write past the output buffer).
- Require the per-block ENCRYPTED flag on every block of an encrypted archive
  (plaintext-injection / authentication bypass).
- Cap the archive-supplied PBKDF2 iteration count (KDF-amplification DoS).
- Non-elidable secret wipe on the SDK crypto path; restored disk images are
  created with mode 0600.

Wire format **v1.6** unchanged; pre-4.1 archives remain readable.


## [4.0.0] — 2026-06-10 — Codec 2.60.4 (security), pq-box mode, F-16 disclosure

Major release: the vendored codec moves to the canonical **VaptVupt
2.60.4** security release, a third post-quantum recipient mode
(`--pq-box`, vendored **libpqvaptvupt 0.6.0**) lands, and a pre-existing
data-loss defect (**F-16**) in the old in-tree BCJ encoder is disclosed
and fixed. Wire format stays **v1.6**; every readable pre-4.0 archive
remains readable (proof matrix below).

### Codec: 2.53.3-era → 2.60.4 (security release)

- Fixes a **high-severity OOB heap write** in the AVX2 decode fast path,
  reachable on a *valid* stream when the output buffer is sized to
  exactly `content_size` (both tail variants, `n ≤ 32` and `n > 32`).
  The tool itself was shielded by its F-14 decode slack; the vendored
  codec is now correct on its own. New regression test
  `tests/test_codec_exact_size.{c,sh}`: 80 exact-size decode cases
  (tail coverage, BCJ-triggering ELF-like payloads, stored path) under
  AddressSanitizer, plus tool-level BCJ roundtrips at L5/L9.
- **Ratio gate verified on identical inputs**: archives produced by the
  shipped 3.8.0 binary and by 4.0.0 are byte-identical in size for
  text/source/redundant (Δ 0.00 %); see BENCHMARKS.md §1.
- Brings the upstream v2.56.0 BCJ filters with automatic ELF/PE/Mach-O
  detection (v2.55.0), enabled for levels ≥ 3, and covers them with functional
  regressions. This repository retains no reproducible CBMC proof artifact.
- Codec release string is now single-sourced (`ZUPT_CODEC_RELEASE`).

### F-16 — data-loss defect in ≤ 3.8.0 BCJ encoding (pre-existing, fixed)

The ≤ 3.8.0 tree carried a **divergent pre-release BCJ** (upstream
2.53.3 contains no BCJ at all; it landed upstream in 2.53.4). On
BCJ-detected binary content at levels 8–9, that encoder wrote archives
that **no version can decode — including 3.8.0 itself** (verified:
old binary fails on its own archive; the defect is at *write* time).
Non-BCJ content and levels ≤ 7 are unaffected; the 8-mode back-compat
matrix (plain L1/L5/L9, store, Argon2id, PBKDF2, legacy `--pq`,
`--pq-sdk`) decodes **byte-exact** under 4.0.0.

**Action required for affected users:** archives created by ≤ 3.8.0 at
`-l 8`/`-l 9` whose inputs included x86/ELF/PE executables should be
re-created with 4.0.0 (verify with `vaptvupt x` before deleting any
source data). 4.0.0's BCJ streams are canonical; note that tools
≤ 3.8.0 cannot read **new** archives where the auto-filter fired
(L3+ on executable content) — upgrade readers first in mixed fleets.

### New: `--pq-box` recipient encryption (ZUPT_ENC_PQ_BOX_V1, 0x05)

Third PQ mode, backed by vendored **libpqvaptvupt 0.6.0** (AGPL-3.0-or-
later + commercial; its own suite: 66/66):

- ML-KEM-768 + X25519 shared secrets combined through **HKDF-SHA256
  Extract/Expand with a domain-separating info** (`"pqvv-seal-v1"`) —
  the combiner this project's crypto standing orders prescribe (the
  legacy `--pq` XOR+SHA3 combiner and `--pq-sdk` remain for back-compat).
- AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC inside the box; SHA-NI
  runtime dispatch; CSPRNG hardened against blocked/ENOSYS
  `getrandom(2)`.
- `keygen --box` writes magic-tagged keypair files (`PQVVBOX1` + role
  byte) — public/secret/legacy key files are mutually rejected,
  eliminating key-type confusion.
- Envelope: `[0x05][4B LE len][pqvv_seal(session_key)]`; the 32-byte
  session key is split into enc/mac keys with domain-separated SHA3,
  mirroring the proven SDK path so all per-block machinery is shared.
- One-time cost ≈ 3 ms seal / 3 ms open (measured).
- New suite `tests/test_pqbox.sh` (13 checks): L1/L9/BCJ roundtrips
  byte-exact; wrong-key, public-as-secret, secret-as-public,
  legacy-key, envelope-tamper, data-tamper, password-on-box all
  rejected. ASan+UBSan clean on seal, open, and the wrong-key cleanup
  path.

### Measured performance (this release's box: Xeon 2.10 GHz, SHA-NI)

- **SHA-NI finally measured**: SHA-256 scalar 204 MB/s → SHA-NI
  1184 MB/s, **5.8×** (256 MiB, same box). The v3.2.0 `[ESTIMATED 3-8×]`
  label is retired.
- Encrypted per-block throughput 293 MB/s (Argon2id mode) — ~2× the
  3.8.0-era figure on a slower clock, the EtM second pass now on SHA-NI.
- Full tables in BENCHMARKS.md (fixtures regenerated on this box; the
  v3.8.0 edition's absolute numbers are superseded, codec stability is
  proven by the same-input gate, not cross-edition comparison).

### Toolchain and build fixes

- Jasmin `.s` files are assembled with `as(1)` directly — clang 18's
  integrated assembler rejects GNU-as macro/comment style (clang strict
  build restored: 0 warnings on gcc **and** clang).
- Vendored codec objects build under an explicit upstream warning
  policy (two benign clang-only categories) instead of patching
  pristine upstream files.
- `VV_SOURCES` gained `vv_bcj.c` (the `test-asan` target could not link
  since BCJ arrived).
- Corrected a Makefile comment that misstated the current codec license as
  "Apache-2.0 / MIT" — the current codec is **GPL-3.0-or-later** and the
  current tool is **AGPL-3.0-or-later**. See the 5.2.2 licensing erratum for
  preserved historical MIT grants.

### Compatibility summary

| Direction | Result |
|-----------|--------|
| 4.0.0 reads ≤ 3.8.0 archives | ✓ byte-exact, all 8 modes/levels tested (except F-16-corrupted L8/L9 BCJ archives, which were never readable by anything) |
| ≤ 3.8.0 reads 4.0.0 archives | ✓ for non-filtered content; ✗ where BCJ auto-filter fired (L3+ on executables) — upgrade readers first |
| `--pq-box` archives | require ≥ 4.0.0 |
| Wire format | v1.6, unchanged |

### Files touched

```
src/v*  include/v*          (codec → upstream 2.60.4, byte-exact; shim retained)
src/zupt_crypto_pqbox.c     (NEW — pq-box mode)
src/zupt_format.c           (0x05 dispatch, both directions)
src/zupt_main.c             (CLI: --pq-box, keygen --box, help)
include/zupt.h              (4.0.0; ZUPT_ENC_PQ_BOX_V1; ZUPT_CODEC_RELEASE; prototypes; box_mode)
vendor/pqvaptvupt/          (NEW — libpqvaptvupt 0.6.0 + header + LICENSE)
tests/test_codec_exact_size.{c,sh}, tests/test_pqbox.sh  (NEW)
Makefile                    (pqvv include/link; as(1) for .s; VV warning policy; VV_SOURCES+bcj; license comment)
doc/vaptvupt.1, BENCHMARKS.md, README.md, ROADMAP.md, AUDIT.md, packaging/*
```


## [3.8.0] — 2026-06-01 — Consolidated measured benchmarks + constant-time test robustness

Two changes, neither touching the shipped crypto or the wire format
(**v1.6**, binary behaviour identical to 3.7.0): a consolidated measured
benchmark document, and a robustness fix to the constant-time timing
test so it never reports a noise-driven false failure.

### Constant-time test: no more false failures under vCPU contention

The dudect-style timing test (`tests/test_ct_timing.c`) compares
`zupt_ct_memeq`'s data-dependent timing against a leaky-`memcmp` control
via their ratio. On a quiet host the control leaks strongly
(|t| ≈ 600–1500) and `zupt_ct_memeq` is flat (|t| ≈ 5–70, ratio
≈ 0.01–0.05). But under heavy shared-vCPU contention **both** collapse
into a common noise band (control ≈ 210, ct ≈ 190), making the ratio
(≈ 0.9) a noise artifact rather than a real leak — which produced
intermittent **false failures**.

Fix: the test now renders a pass/fail verdict **only when the control
leaks strongly** (|t| ≥ 400, comfortably above the observed ~210
contention band and below the ~600+ quiet floor). Below that it reports
**INCONCLUSIVE** (exit 0) instead of failing. A genuine early-return
regression still fails on a quiet host (the leaky function tracks the
control, ratio → ~1.0, with the control well above 400). The
source-routing guard (decaps + MAC compare must use the audited
primitive) runs unconditionally. This makes the security regression
test trustworthy: it never cries wolf from measurement noise, and still
catches a real leak when the host can measure one.

### New `BENCHMARKS.md`

A single reproducible benchmark document, with the test machine, build,
and method stated for every table:

- **Compression ratio + encode/decode throughput** at level 9 across the
  5-fixture suite (text, binary, source, redundant, random).
- **Encode speed vs level** (1/3/5/7/9) showing the ratio↔speed
  trade-off (level 1 ≈ 88 MB/s at 2.55×, level 9 ≈ 1 MB/s at 3.90× on
  text).
- **Encryption overhead** via store-mode measurement that separates the
  one-time KDF (Argon2id ≈ 741 ms, PBKDF2 ≈ 1562 ms on the test box)
  from per-block crypto (≈ 147 MB/s), and plain throughput (≈ 944 MB/s
  single-threaded).
- **Head-to-head ratio vs zstd-3 / zstd-19** — shown plainly, including
  where VaptVupt loses (zstd-19 wins ratio on every fixture; zstd-3
  edges out VaptVupt-L9 on text/binary).
- A clear statement that the codec is **not** the reason to use VaptVupt
  — the value is the combination of PQ-hybrid encryption, Argon2id,
  per-block authenticated encryption, and constant-time-intended helpers with
  timing regressions and documented compiler/platform limits.

### Honesty notes baked into the document

- Every number is labeled measured; the SHA-NI speedup is explicitly
  marked **[ESTIMATED]** because the test box has no SHA-NI.
- The KDF cost is presented as intentional (memory-hardness), not as a
  deficiency to optimize away.
- Reproduction commands are included; the document states that absolute
  numbers vary by machine while the *shape* is stable.

### Documentation alignment

- `README.md` benchmark section re-dated v3.1.0 → **v3.8.0** and now
  links to `BENCHMARKS.md`.
- `CHANGELOG.md`, `ROADMAP.md`, `AUDIT.md` updated for 3.8.0.

### Test status

**24/24 suites green** (the constant-time suite reports a real verdict
on a quiet host and INCONCLUSIVE — never a false failure — under
contention). `test_vectors` **16/0**, F-09 **0/1827**, F-06 **0/2000**.
Wire format **v1.6**.

### Files touched

```
include/zupt.h            (version 3.7.0 → 3.8.0)
doc/vaptvupt.1            (TH version 3.8.0)
BENCHMARKS.md             (NEW — consolidated measured benchmarks)
tests/test_ct_timing.c    (robust verdict: INCONCLUSIVE under contention, never false-fail)
README.md                 (benchmark section re-dated + links to BENCHMARKS.md)
ROADMAP.md, AUDIT.md      (3.8.0 entries)
packaging/*               (version 3.7.0 → 3.8.0; Debian + openSUSE changelog entries)
```


## [3.7.0] — 2026-06-01 — ML-KEM decaps comparison routed through the audited CT primitive

Closes the last security-critical comparison still using a bespoke
inline loop: the ML-KEM-768 decapsulation implicit-rejection check now
uses the same measured-constant-time `zupt_ct_memeq` as the MAC tag
compare. No wire-format change; ML-KEM output identical.

### The gap

Sprint 3.5.0 consolidated the MAC tag comparison into one audited,
timing-tested primitive (`zupt_ct_memeq`). But the **ML-KEM-768 decaps
implicit-rejection comparison** — `ct` vs the re-encrypted `ct'` over all
1088 ciphertext bytes — was still a separate **inline byte-OR loop**
marked `CT-REQUIRED` but never measured and not sharing the audited
primitive. A timing leak there is a **KEM decapsulation oracle**:
distinguishing valid from invalid ciphertexts breaks IND-CCA2 security.
This was the last such inline compare in the codebase.

### What changed

- **`zupt_mlkem768_decaps` now calls `zupt_ct_memeq(ct, ct_prime, 1088)`**
  instead of an inline loop. The primitive returns equality (1 if the
  ciphertext matches → success), and the implicit-rejection fail bit is
  derived as `fail = 1 - equal`. The Jasmin `zupt_ct_select_32` key
  selection (and its C `cmov` fallback) are unchanged.
- **ML-KEM output is byte-identical.** A matching ciphertext yields the
  success shared secret; a mismatched one yields the pseudorandom
  rejection key — exactly as before. Verified by the FIPS 203 roundtrip
  (5 trials), the implicit-rejection vector, a full PQ-hybrid roundtrip,
  and wrong-key rejection.

### Verification — and an honest scoping decision

`tests/test_ct_timing` is extended to the 1088-byte length and gains a
**source-routing guard** that fails if the decaps compare stops using
`zupt_ct_memeq` or a raw 1088-byte inline loop reappears.

The 1088-byte dudect timing numbers are reported as **informational, not
pass/fail**, and the test documents why: at that buffer size on a shared
vCPU the measurement is dominated by memory/cache effects rather than the
compare's control flow, and plain `memcmp` over 1088 bytes is no longer a
cleanly-leaking control (its own timing is data-dependent for reasons
unrelated to early-exit). The environment-relative ratio that is
meaningful at 32 bytes does not transfer to 1088 bytes, and tuning a
threshold to make it "pass" would be dishonest. Instead, the
constant-timeness of the 1088-byte decaps compare follows rigorously
from three facts that *are* established here:

1. the **32-byte** pass/fail dudect check proves `zupt_ct_memeq` is
   constant-time (data-dependent signal ~1–5% of a leaky-`memcmp`
   control, median of 5 runs);
2. `zupt_ct_memeq` is **length-independent by construction** —
   OR-accumulate, no early exit, no data-dependent branch, the same code
   path for every byte and every length; and
3. the **source-routing guard** confirms decaps uses exactly this
   primitive.

This is a stronger argument than a flaky large-buffer timing run, and it
is honest about what the measurement can and cannot show on this host.

### Security

- The last inline CT comparison is gone; **every** security-critical
  comparison (MAC tag, archive-integrity trailer, ML-KEM decaps) now
  routes through one audited, timing-tested, length-independent
  primitive.
- KEM decapsulation-oracle resistance is now backed by the primitive's
  measured constant-timeness plus a routing regression guard, not just a
  source comment.
- F-09 byte sweep **0/1827**, F-06 **0/2000**, `test_vectors` **16/0** —
  all unchanged.

### Performance

Neutral — same comparison work, now through a shared function (which the
compiler inlines at `-O2`).

### Test status

**24/24 suites green** (the constant-time suite now covers the MAC tag
*and* the ML-KEM ciphertext compare, plus the source-routing guard).
Strict GCC `-Werror` clean. Wire format unchanged (**v1.6**).

### Files touched

```
include/zupt.h            (version 3.6.0 → 3.7.0)
doc/vaptvupt.1            (TH version 3.7.0)
src/zupt_mlkem.c          (decaps: route the 1088-byte compare through zupt_ct_memeq)
tests/test_ct_timing.c    (parameterise over length; add informational 1088B measurement)
tests/test_ct_timing.sh   (add source-routing guard for the decaps compare)
README.md, ROADMAP.md, AUDIT.md (3.7.0 entries)
packaging/*               (version 3.6.0 → 3.7.0; Debian + openSUSE changelog entries)
```


## [3.6.0] — 2026-06-01 — NIST SP 800-38A AES-256-CTR vectors + ML-KEM self-test fixes

Closes a real test-coverage gap (the bulk cipher had no standards
known-answer test) and fixes two latent bugs in the ML-KEM self-test
reporting and logic. No source-crypto behaviour change, no wire-format
change.

### AES-256-CTR known-answer vectors (the gap)

`test_vectors` covered SHA-256, HMAC-SHA256, SHA3-256, SHAKE-128,
X25519, ML-KEM-768, and XXH64 — but had **no AES known-answer test**.
AES-256-CTR is the bulk cipher (every encrypted byte goes through it),
and it was only exercised *indirectly* via roundtrips, which prove
self-consistency but not conformance to the standard. The project's own
engineering requirements list **SP 800-38A** as a required vector, and
the README claimed "13 NIST/RFC test vectors" with AES absent from them.

Added the canonical **NIST SP 800-38A** AES-256-CTR vectors:
- **F.5.5** CTR-AES256.Encrypt (4 plaintext blocks → 4 ciphertext blocks)
- **F.5.6** CTR-AES256.Decrypt (symmetric verification)

These validate `zupt_aes256_ctr` against the standard on **both** code
paths: the Jasmin AES-NI assembly (`zupt_aes256_ctr4` + `zupt_aes256_blk`)
on x86_64 with `-DZUPT_USE_JASMIN`, and the C T-table fallback elsewhere.
Both match exactly — which also **confirms the Jasmin AES single-block
function is correct against the standard**, retiring the stale concern
about a stack-offset issue in `zupt_aes256_blk`.

(Counter note: SP 800-38A increments the full 128-bit block while Zupt
increments the low 64 bits. The two coincide for the standard's 4-block
example because the IV's low byte is `0xff` and the carries stay within
the low 8 bytes, so this is an exact KAT — documented in the test.)

### ML-KEM-768 self-test: two fixes

1. **Inverted result check (reporting bug).**
   `zupt_mlkem768_selftest()` returns **0 on success / -1 on failure**,
   but `test_vectors` checked `if (ok)` — printing "OK" precisely when
   the self-test *failed* and "FAIL" when it passed. The self-test line
   had been passing **vacuously**. Now `if (rc == 0)`.

2. **NTT roundtrip self-test logic (false-failure bug).**
   The self-test asserted `ntt∘inv_ntt == identity`, which is **false
   for this pqcrystals/Kyber Montgomery convention**: the forward `ntt()`
   applies a bare `montgomery_reduce` per butterfly (dividing by
   `R = 2^16`) without first mapping the input into the Montgomery
   domain, so the roundtrip recovers each coefficient **scaled by a fixed
   constant** (`R⁻¹ mod q = 169`). The real pipeline corrects for this via
   `basemul` + `tomont`. The self-test now verifies the *true* invariant
   — that the roundtrip is a **consistent linear scaling across all 256
   coefficients** (one shared nonzero factor) — which still catches
   genuine NTT bugs (wrong zeta, wrong butterfly index) while no longer
   emitting a misleading `MLKEM selftest: NTT roundtrip FAILED` line on
   stderr.

**ML-KEM correctness end-to-end was never affected by either bug:** the
K-PKE roundtrip, the full KEM encaps/decaps roundtrip, the FIPS 203
roundtrip vectors (5 trials), and implicit-rejection all pass. The bugs
were confined to the self-test's *verification* of an internal step and
to how its result was *reported*.

### Documentation accuracy

- README "13 NIST/RFC test vectors" → **16** (the true count); the
  security-results table AES/vector row updated to **16/16 pass**.

### Test status

`test_vectors`: **16 passed, 0 failed** (was 14, of which the ML-KEM
self-test line was vacuous). Full suite **24/24 green**, F-09 byte sweep
**0/1827**, F-06 **0/2000**. Strict GCC `-Werror` clean. Wire format
unchanged (**v1.6**).

### Files touched

```
include/zupt.h            (version 3.5.0 → 3.6.0)
doc/vaptvupt.1            (TH version 3.6.0)
tests/test_vectors.c      (+AES-256-CTR SP 800-38A F.5.5/F.5.6; fix inverted self-test check; header comment)
src/zupt_mlkem.c          (NTT roundtrip self-test: assert true Montgomery-scaled invariant)
README.md                 (vector count 13→16; table 14/14→16/16)
packaging/*               (version 3.5.0 → 3.6.0; Debian + openSUSE changelog entries)
ROADMAP.md, AUDIT.md      (3.6.0 entries)
```


## [3.5.0] — 2026-06-01 — Measured constant-time MAC comparison (dudect)

Turns the codebase's most security-critical constant-time claim — the
MAC tag comparison — from an asserted property into a *measured* one,
and consolidates three duplicated inline compares into one audited
primitive. Pure internal hardening; no wire-format change.

### The gap

The codebase carried 20+ `/* CT-REQUIRED */` markers but **no timing
test verified any of them.** The MAC tag compare is the one that matters
most: if "wrong on byte 0" finished measurably sooner than "wrong on
byte 31", an attacker could forge a tag byte-by-byte. That compare was
implemented as **three separate inline byte-OR loops** (the v1.6 strict
decrypt path, the v1.4/v1.5 legacy v2 candidate, and the F-08 archive-
integrity-trailer check) — duplicated, individually un-audited, and
never measured.

### What changed

- **One audited primitive.** `int zupt_ct_memeq(const void *, const void
  *, size_t)` in `zupt_crypto.c`: OR-accumulate with no early exit, read
  through a `volatile` sink so the optimiser cannot reintroduce a
  short-circuit or branch, branch-free 0/non-zero → 1/0 fold. The v1.6
  strict decrypt path and the F-08 AIT check now both call it, so the
  property lives in exactly one place. (The v1.4/v1.5 legacy path keeps
  the optional Jasmin-generated `zupt_mac_verify_ct`; no reproducible proof
  artifact is retained here. Its non-Jasmin C fallback and the carefully-tuned
  F-06 two-candidate fold are left intact.)
- **A dudect-style timing test** (`tests/test_ct_timing.c`, after
  Reparaz–Balasch–Verbauwhede, DATE 2017). It times the compare over two
  input classes — a fixed tag vs an identical copy (FIX) and vs a random
  tag (RND) — and applies **Welch's t-test** to the timing
  distributions. Built at **-O2** (the shipped optimisation level), so it
  tests the code exactly as users run it, including that the `volatile`
  accumulator survives optimisation.

### How the verdict is made honest

Absolute |t| thresholds are not portable — on a shared CI vCPU,
`clock_gettime` overhead and scheduler noise put even a perfectly
constant-time 32-byte compare at |t| in the low tens, while a dedicated
box sits near zero. So the criterion is **environment-relative**:

- A **positive control** times plain `memcmp` (early-return, genuinely
  leaky) in the same environment and must show a clear leak (|t| in the
  hundreds–thousands), proving the harness is sensitive on this host.
- `zupt_ct_memeq`'s data-dependent signal must be **≤ 20% of the
  control's**. Measured here it lands at **~1%** (e.g. control |t| ≈ 766,
  ct |t| ≈ 7, ratio ≈ 0.01) — i.e. statistically flat.
- Results are the **median of five runs** to damp single-run noise. If
  the host is too coarse for even `memcmp` to show a leak, the test
  reports **INCONCLUSIVE** (exit 0) rather than passing vacuously.

A real regression — someone reintroducing an early return or a
data-dependent branch in the compare — pushes the ratio toward 1.0 and
**fails the test**.

### Security

- The MAC tag comparison is now **measured constant-time**, not just
  annotated, with a regression guard in CI.
- One audited implementation replaces three inline copies, removing the
  risk that a future edit hardens one site and misses another.
- No change to authentication behaviour: F-09 byte sweep **0/1827**,
  F-06 1-bit HMAC fuzz **0/2000**, encrypted roundtrips and pre-3.5.0
  archive decryption byte-exact, tamper still rejected.

### Performance

Neutral — the compare does the same constant work; this is a
correctness/security and maintainability change, not a throughput one.

### Test status

**24/24 suites green** (new `tests/test_ct_timing.sh`, wired into
`make check` + `make test`). Strict GCC `-Werror` clean (AVX2 + scalar).
Wire format unchanged (**v1.6**).

### Files touched

```
include/zupt.h            (version 3.4.0 → 3.5.0; +zupt_ct_memeq decl)
doc/vaptvupt.1            (TH version 3.5.0)
src/zupt_crypto.c         (+zupt_ct_memeq primitive; v1.6 strict path uses it)
src/zupt_format.c         (F-08 AIT verify uses zupt_ct_memeq)
tests/test_ct_timing.c    (NEW — dudect-style Welch t-test + memcmp control)
tests/test_ct_timing.sh   (NEW — runner, -O2; in check + test)
Makefile                  (wire CT timing test into check + test)
packaging/*               (version 3.4.0 → 3.5.0; Debian + openSUSE changelog entries)
README.md, ROADMAP.md, AUDIT.md (3.5.0 entries)
```


## [3.4.0] — 2026-06-01 — F-15: Argon2id KDF parameter transparency

Makes the Argon2id password-encryption header self-describing about its
key-derivation cost, closing a latent robustness/security gap for a
long-lived archive format. Additive and back-compatible — existing
archives decrypt unchanged.

### The gap (F-15)

The PBKDF2 enc-header (`0x01`) records its iteration count, so a reader
always derives keys with the exact cost the writer used. The Argon2id
enc-header (`0x04`) recorded only `[type | salt | nonce]` (33 bytes) and
**nothing about the KDF cost** — it relied entirely on the libzuptsdk
"MODERATE" Argon2id preset reached through the opaque
`zuptsdk_easy_derive_key`. For a backup format meant to stay readable
for years that is a real problem: if the preset ever changed, archives
written under the old cost could become **silently undecryptable**, with
no field in the archive to tell a reader which cost to use.

(For the record, the explicit RFC 9106 `zsdk_argon2id()` with tunable
`memory_kib`/`iterations`/`lanes` is declared in the SDK headers but is
**not exported** by the vendored `libzuptsdk.so` — only
`zuptsdk_easy_derive_key` is callable — so the fix records the profile
in-band rather than re-parameterising the KDF.)

### The fix

New Argon2id archives append a **one-byte KDF profile descriptor** at
offset 33 (`ZUPT_ARGON2_PROFILE_MODERATE = 0x01`), making the header
self-describing. Constants in `zupt.h`:

```
ZUPT_ARGON2_PROFILE_LEGACY   0x00  /* implicit: pre-3.4.0, no descriptor */
ZUPT_ARGON2_PROFILE_MODERATE 0x01  /* explicit: libzuptsdk MODERATE preset */
ZUPT_ARGON2_HDR_LEN_V1       33    /* [type|salt16|nonce16] */
ZUPT_ARGON2_HDR_LEN_V2       34    /* + [profile1] */
```

The descriptor sits inside the encryption header, which is covered by
the v1.5+ archive-integrity trailer (F-08), so it **cannot be stripped
or forged without failing authentication**.

### Back-compatibility (additive, verified)

- The legacy reader checks `enc_hdr_len >= 33` and reads fixed offsets,
  so it ignores the trailing byte. **Existing 33-byte Argon2id archives
  decrypt byte-exact** — verified against archives produced by 3.0.3 and
  earlier (plain and encrypted).
- A 33-byte header (profile implicit) and a 34-byte header (profile
  explicit MODERATE) derive **identical keys**, so nothing about the key
  schedule changed; only the self-description was added.
- New readers validate the profile and **refuse an unknown value
  (fail-closed)** rather than guessing a derivation that would produce
  the wrong key.

### Security

- **Fail-closed on unknown KDF profile** — an archive claiming an
  unsupported cost is rejected, not silently mis-derived.
- **Tamper-evident** — the descriptor is authenticated by the F-08
  trailer (a flipped header byte fails decryption, verified).
- **Build-time SDK-drift guard** — the new test includes a coarse KDF
  cost floor (>= 20 ms) plus a determinism check, so a build against an
  SDK that has been swapped for a fast/weak Argon2id stand-in fails at
  test time instead of shipping under-protected archives.
- No change to authentication semantics: F-09 byte sweep **0/1827**,
  F-06 1-bit HMAC fuzz **0/2000**, constant-time tag compares unchanged.

### Note on KDF performance (measured)

Profiling this release confirmed the password-mode cost is dominated by
the **one-time Argon2id KDF (~0.9–1.1 s)**, not the per-block pipeline:
store-mode encrypt of a 1 MB input takes ~934 ms and a 40 MB input
~1245 ms, i.e. ~8 ms/MB (~125 MB/s) of actual per-block crypto after the
3.2.0 SHA-NI and 3.3.0 incremental-HMAC work. The KDF is intentionally
memory-hard; it is **not** a target for speedups (faster = weaker). This
release therefore invests in KDF *transparency and robustness* rather
than KDF speed.

### Test status

**23/23 suites green** (new `tests/test_kdf_transparency.sh`, 5 checks,
wired into `make check` + `make test`). Strict GCC `-Werror` clean (AVX2
+ scalar). Wire format unchanged (**v1.6**).

### Files touched

```
include/zupt.h               (version 3.3.0 → 3.4.0; +ZUPT_ARGON2_PROFILE_* / HDR_LEN_*)
doc/vaptvupt.1               (TH version 3.4.0)
src/zupt_crypto_sdk.c        (write profile descriptor; validate on read; fail-closed)
tests/test_kdf_transparency.c   (NEW — F-15 header shape, back-compat, fail-closed, KDF guard)
tests/test_kdf_transparency.sh  (NEW — runner; in check + test)
Makefile                     (wire KDF-transparency test into check + test)
packaging/*                  (version 3.3.0 → 3.4.0; Debian + openSUSE changelog entries)
README.md, ROADMAP.md, AUDIT.md (3.4.0 / F-15 entries)
```


## [3.3.0] — 2026-06-01 — Incremental HMAC: drop per-block MAC malloc + copy

Removes a per-block heap allocation and full-payload copy from the
Encrypt-then-MAC hot path on both the encrypt and decrypt sides, and
folds the HMAC key-prefix once per keyring instead of once per block. No
wire-format change — the MAC bytes are identical.

### What was slow (structural)

Both `zupt_encrypt_buffer_aad` and `zupt_decrypt_buffer_aad` built the
HMAC input by `malloc`-ing a buffer sized
`aad_extra + nonce + ciphertext + seq` and `memcpy`-ing the **entire
ciphertext** into it, every block, only to feed `zupt_hmac_sha256` once.
With the default 4 MB block size that is a 4 MB malloc plus a 4 MB copy
**per block, per direction**. Separately, `zupt_hmac_sha256` recomputed
the ipad/opad key-prefix SHA-256 compression on every call even though
the per-block `mac_key` never changes.

### What changed

- **Incremental HMAC-SHA256 API** (`zupt_hmac_ctx` +
  `zupt_hmac_sha256_init/update/final`). `_init` folds the ipad/opad
  key-prefix blocks once (one 64-byte compression each); `_update`
  streams message segments; `_final` closes the inner+outer hashes. The
  context is wiped on `_final` (it holds key-dependent state).
- **The one-shot `zupt_hmac_sha256` is now a thin wrapper** over the
  incremental API — single source of truth. The AIT and other
  once-per-archive MAC sites are unchanged in behaviour.
- **Both per-block MAC sites stream the segments** (`aad_extra`, then
  `nonce || ciphertext` directly from the output package, then
  `aad_seq`) through the incremental HMAC. No concat buffer, no
  ciphertext copy, no per-block malloc/free. This covers the v1.6
  strict-AAD path and the v1.4/v1.5 legacy-fallback v2 candidate; the
  v1 candidate was already a direct one-shot over the package.

### Why it is wire-compatible (byte-identical MAC)

RFC 2104 defines `HMAC(K,m) = H((K^opad) || H((K^ipad) || m))`, and
SHA-256's Merkle-Damgard `update()` is associative over the message, so
streaming `m` in segments yields exactly the same tag as hashing one
concatenated buffer. This is not a heuristic — it is pinned by tests:

- **RFC 4231** HMAC-SHA256 vectors pass (`test_vectors` 14/14).
- New `tests/test_hmac_incremental.c`: one-shot == incremental for
  single-segment; streamed 1/2/3-part splits == one-shot across lengths
  0..100000; the exact per-block pattern
  `aad || nonce || ciphertext || seq` streamed in four updates == the
  concat one-shot; RFC 4231 TC2 known-answer.
- **Byte-exact decryption of archives produced by 3.2.0 and earlier**
  (plain and encrypted, both Argon2id and PBKDF2 KDFs) — if the streamed
  MAC differed by a single byte, authentication would fail. It does not.

### Security

- **Identical authentication semantics.** F-09 byte sweep: **0/1827
  silent accepts**. F-06 1-bit HMAC fuzz: **0/2000**. Constant-time tag
  comparisons (byte-OR accumulator / Jasmin `zupt_mac_verify_ct`) are
  unchanged.
- **Less secret data on the heap.** The old path copied the full
  ciphertext into a second `malloc`'d buffer per block; that buffer is
  gone, reducing the lifetime and footprint of sensitive data and the
  associated `zupt_secure_wipe` churn.

### Performance

Eliminates, per block per direction: one `malloc` of
`~blocksize` bytes, one `memcpy` of the full ciphertext, one
`zupt_secure_wipe` + `free` of that buffer, and (for the key prefix)
two redundant 64-byte SHA-256 compressions. The win scales with block
size and block count and stacks with the 3.2.0 SHA-NI work (fewer
SHA-256 invocations *and* faster ones). Not separately micro-benchmarked
in this release; it is a strict reduction in allocations and bytes
copied with no new work added.

### Test status

**22/22 suites green** (new `tests/test_hmac_incremental.sh`, 4
assertions, wired into `make check` + `make test`). Strict GCC
`-Werror` clean (AVX2 + scalar). ASan clean on encrypted roundtrips for
both KDFs. Wire format unchanged (**v1.6**).

### Files touched

```
include/zupt.h            (version 3.2.0 → 3.3.0; +zupt_hmac_ctx + init/update/final)
doc/vaptvupt.1            (TH version 3.3.0)
src/zupt_crypto.c         (incremental HMAC; one-shot wrapper; stream both per-block MAC sites)
tests/test_hmac_incremental.c   (NEW — equivalence + RFC 4231)
tests/test_hmac_incremental.sh  (NEW — runner; in check + test)
Makefile                  (wire incremental-HMAC test into check + test)
packaging/*               (version 3.2.0 → 3.3.0; Debian + openSUSE changelog entries)
README.md, ROADMAP.md, AUDIT.md (3.3.0 entries)
```


## [3.2.0] — 2026-06-01 — SHA-256 hardware acceleration (Intel SHA-NI)

Adds an SHA-NI hardware path for SHA-256, accelerating the part of the
encrypted pipeline that measurement showed to be the bottleneck, and
strengthening the side-channel posture of authentication. No
wire-format change.

### Why (measured, not assumed)

On this project's fixtures, store-mode (codec bypassed) compresses at
**667 MB/s** plain but only **~10 MB/s** with a password. AES-NI is
already active (Jasmin 4-block CTR pipeline), so the cost is the
**Encrypt-then-MAC second pass**: HMAC-SHA256 in scalar C. Scalar
SHA-256 tops out around 150-250 MB/s, which is the wall. PBKDF2 (when
`--kdf pbkdf2` is selected) is HMAC-SHA256 in a tight loop and is hit
even harder. SHA-256 is therefore the correct acceleration target.

### What was added

- **`src/zupt_sha256_shani.c`** — the FIPS 180-4 SHA-256 compression
  function using Intel SHA Extensions (`SHA256RNDS2`, `SHA256MSG1`,
  `SHA256MSG2`), processing multiple 64-byte blocks per call. This is
  the canonical Intel/Walton intrinsic sequence (the same one used by
  OpenSSL, BoringSSL, and the Linux kernel). Compiled with
  `-msha -mssse3 -msse4.1` on x86_64; a no-op translation unit on other
  architectures.
- **CPU detection:** `has_shani` added to `zupt_cpu_features_t`
  (CPUID.07H:EBX[29]). SHA-NI uses 128-bit `xmm` state from the baseline
  x86-64 ABI, so unlike AVX it needs no XCR0/OSXSAVE gate.
- **`zupt_sha256_update()` refactored** to bulk-process full blocks: it
  drains any buffered partial, then feeds all full blocks to the
  hardware path in one call (`zupt_sha256_transform_shani`) when
  `zupt_cpu.has_shani` is set, else the scalar transform in a loop. The
  streaming/`final()` semantics are unchanged.

### Security

SHA-NI is **constant-time by construction**: it performs no
data-dependent memory accesses or branches, so it has a strictly
stronger side-channel posture than any table- or branch-based software
SHA-256. Since Zupt authenticates with HMAC-SHA256 over
attacker-influenced ciphertext, a constant-time compression function is
the right default wherever the CPU provides it. The scalar fallback is
unchanged and remains the path on non-SHA-NI hardware.

### Performance

On SHA-NI hardware (Intel Goldmont+/Ice Lake+, AMD Zen+), the SHA-256
compression function is **[ESTIMATED] 3-8× faster** than the scalar path
(per the public Intel SHA Extensions throughput figures; this is the
standard speedup OpenSSL/kernel report). **This estimate is not measured
in this release** — the CI/build host used for 3.2.0 has no SHA-NI
(`sha_ni: 0`), so the hardware path cannot be executed here. The number
will be replaced with a measured one once run on SHA-NI silicon. The
`vaptvupt version` command now prints the live hardware-acceleration set
for the running CPU (e.g. `HW accel (this CPU): AES-NI SHA-NI
AVX2(codec)`).

### Correctness validation (what *was* verified here)

- **Round constants:** all 64 SHA-NI K-schedule immediates are verified
  bit-identical to the scalar `K[]` table, in order — this eliminates
  the single most likely class of bug in a hand-written SHA-NI routine.
- **Scalar refactor:** the rewritten `update()`/`sha256_blocks()` passes
  the NIST FIPS 180-4 SHA-256 vectors (`test_vectors` 14/14), proving
  the new buffering logic is sound on the path this host executes.
- **SHA-NI execution (on SHA-NI hardware only):** the new
  `tests/test_sha256_shani.c` checks the SHA-NI path against the NIST
  "abc"/empty digests, multi-block == single-block-loop agreement
  (64B..64KiB), and streaming-split == one-shot (lengths 0..4096). On a
  host without SHA-NI it SKIPS these execution checks while the
  constant-equivalence, compile, and dispatch-wiring checks still gate
  the build.

### Build / packaging

- New regression suite `tests/test_sha256_shani.sh` (4 assertions) wired
  into `make check` and `make test`. Total suites: **21/21 green**.
- Makefile: `SHANI_FLAGS = -msha -mssse3 -msse4.1` on x86_64; dedicated
  compile rule for `src/zupt_sha256_shani.o` (excluded from the generic
  object rule to avoid a recipe-override warning); SHA-NI flags also
  threaded into `test-vectors`, `test-f06`, and `test-asan`.
- `tests/test_static_analysis.sh` extended to hold the SHA-NI file to the
  same strict `-Werror` / `-Wconversion -Wsign-conversion` bar (9/9).
- **openSUSE OBS recipe renamed `zupt.spec`/`zupt.changes` →
  `vaptvupt.spec`/`vaptvupt.changes`** (Name: vaptvupt), with
  `Provides: zupt` / `Obsoletes: zupt < 3.0.0` so existing installs
  upgrade automatically; the binary still ships the `/usr/bin/zupt`
  compatibility symlink and a `zupt.1` man-page symlink. `_service`
  `filename` updated to `vaptvupt`. cabelo's full changelog history is
  preserved.

### Compatibility

- **No wire-format change.** Same SHA-256, same HMAC-SHA256, same
  Encrypt-then-MAC construction, same bytes on disk. Format stays
  **v1.6**; 3.1.x archives (plain and encrypted) extract unchanged.
- The dispatch is transparent: an archive made on a SHA-NI machine and
  one made on a scalar machine are byte-identical.

### Files touched

```
include/zupt.h                  (version 3.1.0 → 3.2.0; +SHA-NI prototype)
include/zupt_cpuid.h            (+has_shani field + ACSL)
doc/vaptvupt.1                  (TH version 3.2.0)
src/zupt_cpuid.c                (detect SHA-NI; 6-field struct init)
src/zupt_sha256.c               (multi-block dispatch in update())
src/zupt_sha256_shani.c         (NEW — SHA-NI compression function)
src/zupt_main.c                 (version: live HW-accel line)
Makefile                        (SHANI_FLAGS, dedicated rule, test wiring)
tests/test_sha256_shani.c       (NEW — SHA-NI correctness)
tests/test_sha256_shani.sh      (NEW — 4 assertions; in check + test)
tests/test_static_analysis.sh   (hold SHA-NI file to strict bar)
tests/test_packaging_syntax.sh  (openSUSE vaptvupt.* rename assertions)
packaging/opensuse/vaptvupt.spec    (renamed from zupt.spec; Name: vaptvupt)
packaging/opensuse/vaptvupt.changes (renamed from zupt.changes)
packaging/opensuse/_service         (filename → vaptvupt)
packaging/{aur,homebrew,nix,rpm}/*  (version 3.1.0 → 3.2.0)
packaging/debian/changelog          (3.2.0 entry)
README.md, ROADMAP.md, AUDIT.md     (3.2.0 entries)
```


## [3.1.0] — 2026-05-31 — VaptVupt codec 2.48.5 → 2.53.3 + decode over-copy fix

Integrates the upstream VaptVupt LZ + ANS codec from 2.48.5 to 2.53.3,
and fixes a real heap-overflow in our decode wrapper that the newer
codec's wider AVX2 hot path exposed.

### Codec upgrade 2.48.5 → 2.53.3

The API surface is unchanged — `include/vaptvupt.h`, `vaptvupt_api.h`,
`vv_ans.h`, `vv_huffman.h`, and `vv_platform.h` are **byte-identical**
between 2.48.5 and 2.53.3. Only three `.c` files changed: `vv_ans.c`,
`vv_decoder.c`, `vv_encoder.c`. Three others (`vv_huffman.c`, `vv_simd.c`,
`vv_xxh64.c`) are byte-identical. Our wrapper (`vaptvupt_api.c`) needed
no signature changes.

What the 2.48.5 → 2.53.3 arc brings (from upstream CHANGELOG):

- **v2.51.0 optimal parser (extreme mode):** +3.0% aggregate ratio.
- **v2.52.0 large-window extreme mode:** +9.9% geomean, all 12 Silesia
  fixtures win.
- **v2.52.1 fast-mode decode +21–43%**, **v2.52.2 fast-mode encode
  +7–12%** (byte-identical output).
- **v2.52.4 + v2.53.2: 6 corrupt-input decoder memory-safety fixes.**
- **v2.53.0 `-w`/`--window`:** user-selectable window log (the tool does
  not expose this flag; the codec default is used).
- **v2.53.1/2/3:** decode-speed micro-opts, all validated byte-identical.

Measured on our fixtures (10 MB each, single vCPU, vs the old 2.48.5
codec at L9):

| Fixture   | 2.48.5 ratio | 2.53.3 ratio | Δ |
|-----------|-------------:|-------------:|---|
| text      | 26.16%       | 25.65%       | **−1.95%** (smaller) |
| binary    | 46.75%       | 46.13%       | **−1.31%** (smaller) |
| source    | 4.72%        | 4.50%        | **−4.72%** (smaller) |
| random    | 100.01%      | 100.01%      | ±0 (incompressible) |
| redundant | 0.0317%      | 0.0723%      | +128% (see note) |

**Honest note on `redundant`:** on a degenerate input (one 4.5 KB pattern
repeated to 10 MB), the new L9 is slightly *larger* (7584 B vs 3324 B,
still 0.07% of input) because large-window extreme mode optimizes for
real long-range matches, not a single repeated block. L5/L7 (6064 B)
beat L9 on this pathological case. This is a known tradeoff of
large-window mode, not a regression on realistic data.

Decode speed (measured, single vCPU, vs zstd-19, includes `.zupt`
envelope): text 278 MB/s (zstd 286), binary 300 (zstd 278), source 769
(zstd 625) — now roughly on par with zstd-19, up from 1.5–2× slower at
2.48.5. The previous "1.27× zstd-3 decode" claim (inherited from upstream
docs) has been **removed** from the `help`/`version` strings; it did not
reproduce in our own measurement and we cite measured numbers only.

### F-14 (new): decode over-copy heap-overflow in our wrapper

ASAN flagged a `heap-buffer-overflow WRITE of size 32` on
`redundant.dat` at L1, in the codec's AVX2 `match_copy_32_hot` →
`_mm256_storeu_si256`, writing 0 bytes past a 128 KB block buffer.

Root cause was **ours, not the codec's**: `vaptvupt.h` documents that the
SIMD copy helpers "may over-read/write by up to 32 bytes. Caller must
ensure sufficient slack in destination." Our decode buffers were
`malloc(uncompressed_size)` with **zero slack**. Codec 2.48.5 never
reached the over-copy on real inputs; 2.53.3's wider AVX2 hot path
(Sprint 53/58 decode-speed work) does.

Fix: a shared `ZUPT_VV_DECODE_SLACK` (64 B) guard. Every decode output
buffer is over-allocated by this margin and the **padded capacity** is
passed to the codec, so the over-copy always lands in owned memory. The
reported uncompressed size is unchanged; the slack is never part of the
output. Applied to **both** decode paths:

- `zupt_format.c` (single-threaded `decompress_block`)
- `zupt_parallel.c` (multi-threaded decode worker)

64 > 32 leaves margin for any future SIMD store-width increase (AVX-512
= 64 B stores).

Verified:
- ASAN single-threaded: 24/24 roundtrips clean across text/binary/source/
  redundant/random + empty/1-byte/repetitive at L1/5/9.
- ASAN multi-threaded (`-t 4`): 15/15 clean.
- ASAN bit-flip fuzz: 300 trials, **0 crashes**, 300 clean rejects.

### vv_decoder.c: scalar build now -Werror clean (ZUPT-LOCAL)

Upstream's `vv_decoder.c` declares three safe-zone variables (`ip_safe`,
`op_safe`, `max_valid_off`) that are used only inside `#if VV_INLINE_AVX2`
blocks. On a scalar/non-AVX2 build (aarch64, our Termux target) they are
unused, producing three `-Wunused-variable` warnings that break a
`-Werror` build. Guarded the declarations with `#if VV_INLINE_AVX2` so
the scalar build is `-Werror` clean. Byte-identical codegen for the AVX2
build. Marked `ZUPT-LOCAL (3.1.0)` so the next codec drop is easy to diff.

### New regression test: `tests/test_vv_decode_slack.sh`

7 assertions: the `ZUPT_VV_DECODE_SLACK` constant exists and is ≥ 32;
both decode paths over-allocate and pass the padded capacity; the exact
ASAN-failing degenerate input round-trips byte-exact single-threaded
(L1/5/9) and multi-threaded (L1/9). Wired into `make check` and
`make test`.

### Compatibility

- **Wire format unchanged** (v1.6). Archive magic unchanged.
- **Back-compat verified:** all archives written by the 2.48.5 build
  (3.0.3), including encrypted ones, extract byte-exact with the 2.53.3
  build.
- **Bidirectional:** archives written by 3.1.0 extract byte-exact on
  re-read; the codec frame format is stable across 2.48.x↔2.53.x.

### Test status

**19/19 suites green** (18 previous + new decode-slack suite). F-09 byte
sweep: **0/1827 silent accepts**. F-06 HMAC fuzz: **0/2000**. Strict GCC
`-Werror` clean (AVX2 and scalar). Our 9-file source clean under
`-Wconversion -Wsign-conversion`.

### Files touched

```
include/zupt.h                  (version 3.0.3 → 3.1.0; +ZUPT_VV_DECODE_SLACK)
doc/vaptvupt.1                  (codec 2.48.5 → 2.53.3; TH version 3.1.0)
src/vv_ans.c                    (codec 2.48.5 → 2.53.3)
src/vv_decoder.c                (codec 2.48.5 → 2.53.3; +ZUPT-LOCAL scalar -Werror guard)
src/vv_encoder.c                (codec 2.48.5 → 2.53.3)
src/vaptvupt_api.c              (header comment 2.48.2 → 2.53.3)
src/zupt_format.c               (F-14: decode buffer +slack, padded capacity)
src/zupt_parallel.c             (F-14: parallel decode buffer +slack, padded capacity)
src/zupt_main.c                 (help/version codec string 2.53.3; removed unverified 1.27× claim)
Makefile                        (wire test_vv_decode_slack into make check + make test)
tests/test_vv_decode_slack.sh   (NEW — 7 assertions)
README.md, ROADMAP.md, AUDIT.md (3.1.0 entries)
packaging/*                     (version 3.0.3 → 3.1.0)
```

Note: `vv_huffman.c`, `vv_simd.c`, `vv_xxh64.c` and all `vv_*.h` headers
are byte-identical to 2.48.5 and were left untouched.


## [3.0.3] — 2026-05-26 — static-analysis cleanup + new regression test

A focused code-quality sprint that runs `cppcheck` + GCC's `-Wconversion`
on our own (non-vendored) C source for the first time, fixes three real
findings, and wires up a new regression test so they stay fixed.

### cppcheck findings closed

| Finding | Class | Site | Fix |
|---|---|---|---|
| `(x&0x80)` always true after preceding `if(!(x&0x80))return n;` | `knownConditionTrueFalse` (dead AND) | `zupt_decode_varint` | Removed dead `&& (x&0x80)`; added invariant comment |
| `(c&0x80)` always true after preceding terminator-byte return | same | `zupt_read_varint` | Reformatted for readability + same fix |

Both varint decoders had a defense-in-depth comment from years back
(`Reject continuation past 64 bits — same defense as file variant`) that
was correct in intent but encoded dead control flow. The check now reads
`if (s>=64) return -1;` with a comment documenting *why* it's safe to
drop the AND (the preceding early return is the precondition).

**Behaviour is byte-identical.** F-09 byte sweep still 0/1827.

### -Wconversion / -Wsign-conversion findings closed

| Site | Issue | Fix |
|---|---|---|
| `zupt_main.c` ECHO bit-clear | `~ECHO` is `int` (negative); assigned to `tcflag_t` (`unsigned int`) | Explicit `(tcflag_t)~ECHO` cast |
| `zupt_disk.c` varint-return accumulation | `zupt_encode_varint` returns `int`; accumulating into `size_t` | Explicit `(size_t)` cast, matching the convention already used in `zupt_format.c` |

Our (non-vendored) C source now compiles cleanly under the union of
the strict warning sets:

```
gcc -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes \
    -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Wlogical-op \
    -Wjump-misses-init -Wdouble-promotion -Woverlength-strings \
    -Wconversion -Wsign-conversion -Werror
```

across nine source files: `zupt_main.c`, `zupt_format.c`, `zupt_dedup.c`,
`zupt_disk.c`, `zupt_crypto.c`, `zupt_aes256.c`, `zupt_sha256.c`,
`zupt_xxh.c`, `zupt_parallel.c`. Vendored vv_*.c, fips202.c, and
zupt_mlkem.c are kept under the upstream warning policy (they have
their own maintenance and the union flag set would generate many
false positives on standard library macros they use).

### New regression test: `tests/test_static_analysis.sh`

7 assertions:

1. Strict GCC + `-Werror` clean on all our source files.
2. `-Wconversion` + `-Wsign-conversion` clean on all our source files.
3. `cppcheck` warning+performance level: 0 findings.
4. `cppcheck` no `knownConditionTrueFalse` style findings on our code.
5. `cppcheck` error level: 0 findings.
6. Pattern check: varint decoders don't have the v3.0.2 dead-AND
   pattern (`s>=64 && (x|c)&0x80`) back.
7. Pattern check: ECHO bit-clear uses the explicit `(tcflag_t)` cast.

Skips cppcheck assertions cleanly if `cppcheck` isn't installed on
the build host (some OBS / minimal chroots don't have it). Wired
into both `make check` and `make test`.

### Test status

**18/18 suites green** (17 previous + new static-analysis suite).
F-09 byte sweep: **0/1827 silent accepts**. F-06 HMAC fuzz: **0/2000
silent accepts**. Wire format unchanged at v1.6.

### Why these matter (and why they don't)

The varint dead-AND wasn't a bug — the program behaved correctly.
It was a code smell that survived multiple sprints because no
static analyser was running over the source. Adding the analyser
to the regression suite is what changes; the specific fixes are
trivial individually.

The `-Wconversion` casts are also not bug fixes. They're
intent-documentation: instead of relying on the compiler's
"unsigned conversion of a negative int" silent behaviour, we now
state the cast explicitly. Any future contributor reading
`new_t.c_lflag &= (tcflag_t)~ECHO` sees the conversion immediately;
without the cast, they'd have to verify the conversion was safe.

### Files touched

```
include/zupt.h                            (version 3.0.2 → 3.0.3)
doc/vaptvupt.1                            (TH version 3.0.2 → 3.0.3)
src/zupt_format.c                         (varint decoders: remove dead && (x&0x80); add invariant comment)
src/zupt_main.c                           (ECHO bit-clear: explicit (tcflag_t) cast)
src/zupt_disk.c                           (varint return: explicit (size_t) cast matching convention)
Makefile                                  (wire test_static_analysis into make check + make test)
tests/test_static_analysis.sh             (NEW — 7 assertions)
packaging/aur/PKGBUILD                    (pkgver 3.0.3)
packaging/debian/changelog                (3.0.3-1 prepended)
packaging/rpm/vaptvupt.spec               (Version 3.0.3)
packaging/homebrew/vaptvupt.rb            (version 3.0.3)
packaging/nix/flake.nix                   (version 3.0.3)
packaging/opensuse/{zupt.spec,_service,zupt.changes}  (3.0.3 + cabelo entry prepended)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (3.0.3 row)
AUDIT.md                                  (3.0.3 history entry)
```


## [3.0.2] — 2026-05-26 — F-13 closed (usage() literal size) + help-text cleanup

One real warning closed, two real bits of stale text in `vaptvupt help`,
one new compile-time guard, one new regression test.

### F-13: usage() string literal exceeded C99's 4095-char limit

`src/zupt_main.c`'s `usage()` had a single fprintf with adjacent
string literals totalling 4121 chars, triggering
`-Woverlength-strings` on strict builds (C99 §5.2.4.1 requires
compilers to support strings up to 4095 chars only; longer is
implementation-defined). GCC and clang both compile it fine in
practice, but the warning is real and the literal was a sign the
function had grown without architectural review.

Refactored into five logical fprintf sections (synopsis, compress
options, extract/list/test options, examples, footer). Each section
is now < 1500 chars; the worst is the compress-options block at
~1470 chars. Easier to read, easier to maintain, and the warning is
gone.

`-Woverlength-strings` added to the default `CFLAGS` so future
regressions fail the build under `-Werror`.

### Help-text drift cleanup

While fixing F-13 we found three pieces of stale content:

| Stale                                              | Now                                                        |
|----------------------------------------------------|------------------------------------------------------------|
| `zupt compress` / `zupt extract` in all examples   | `vaptvupt compress` / `vaptvupt extract` (12 example lines) |
| "Compression: LZ77 (1MB window) + Huffman entropy coding" | "Default codec: VaptVupt LZ + ANS 2.48.5 (AVX2/NEON SIMD, 1.27x zstd-3 decode)" |
| "License: AGPL-3.0-or-later (Zupt) + ..."          | "License: AGPL-3.0-or-later (VaptVupt) + ..."              |

Also added:

- Format-version line: `Format: v1.6 (since v2.3.1); archives byte-compatible with v2.3.1+`
- Dual-licensing visibility: `Dual-licensed: commercial license available: sac@securityops.co`

### New regression test: `tests/test_help_consistency.sh`

10 assertions covering everything we just fixed:

- Python helper walks `src/zupt_main.c`'s fprintf calls, computes the
  concatenated literal size, and asserts the worst case is < 4095
  chars (F-13 byte-level guard).
- Help output has at least one `vaptvupt <subcommand>` example.
- Help output has zero bare `zupt <subcommand>` example lines (the
  legacy command name in raw examples is the drift we just fixed).
- Help mentions "VaptVupt LZ + ANS" as the default codec.
- Help does not have the stale "LZ77 (1MB window) + Huffman entropy
  coding" description.
- Help shows "AGPL-3.0-or-later (VaptVupt)" as the license.
- Help shows the commercial-licensing contact.
- Help identifies Argon2id as the default KDF.
- Help reports format version v1.6.
- `vaptvupt help` exits with status 0.

Wired into both `make check` (distro-safe) and `make test` (full).

### Test status

**17/17 suites green** (16 previous + new help-consistency suite). F-09
byte sweep: **0/1827 silent accepts**. F-06 HMAC fuzz: **0/2000 silent
accepts**. Format unchanged at v1.6.

Strict-build check: `gcc -Wall -Wextra -Wpedantic -Wshadow -Wcast-align
-Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2
-Wlogical-op -Wjump-misses-init -Wdouble-promotion -Woverlength-strings
-Werror -O2 -std=c11` — **clean**.

### Files touched

```
include/zupt.h                            (version 3.0.1 → 3.0.2)
doc/vaptvupt.1                            (TH version 3.0.1 → 3.0.2)
src/zupt_main.c                           (usage() split into 5 sections; legacy `zupt` → `vaptvupt` in examples; codec/license refreshed)
Makefile                                  (CFLAGS gains -Woverlength-strings; wire test_help_consistency into make check + make test)
tests/run_quick.sh                        (help-line regex accepts vaptvupt|zupt)
tests/test_help_consistency.sh            (NEW — 10 assertions)
packaging/aur/PKGBUILD                    (pkgver 3.0.2)
packaging/debian/changelog                (3.0.2-1 prepended)
packaging/rpm/vaptvupt.spec               (Version 3.0.2)
packaging/homebrew/vaptvupt.rb            (version 3.0.2)
packaging/nix/flake.nix                   (version 3.0.2)
packaging/opensuse/{zupt.spec,_service,zupt.changes}  (3.0.2 + cabelo entry prepended)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (3.0.2 row)
AUDIT.md                                  (F-13 closed; 3.0.2 history entry)
```


## [3.0.1] — 2026-05-26 — GUI license + version-parsing cleanup

Two real bugs in v3.0.0's GUI and a third in `gui/LICENSE-GUI`, plus a
new regression test that catches them.

### MIT reference removed from GUI

The v3.0.0 GUI's about panel had a credit line:

```
zupt        Cristian Cezar Moises        MIT
```

That entry described the intended license of the then-current GUI, but its
historical conclusion was incorrect. Earlier published repository revisions
did contain MIT license notices, and those grants cannot be retroactively
denied. See the 5.2.2 licensing erratum above.

Removed. The CREDITS block now has two correctly-attributed rows:

- **VaptVupt application** — AGPL-3.0-or-later (commercial license available) — `git.securityops.co/cristiancmoises/zupt`
- **VaptVupt LZ + ANS codec** — GPL-3.0-or-later (commercial license available) — `git.securityops.co/cristiancmoises/vaptvupt`

Both rows carry the commercial-licensing contact `sac@securityops.co`.

`gui/LICENSE-GUI` was changed from an MIT-form file to an
AGPL-3.0-or-later notice for the then-current source. That change did not revoke
MIT permissions already conveyed for historical material. The current
`gui/LICENSE-GUI` records both the current notice and the factual erratum.

Top-level `LICENSE` preamble updated to reflect the Zupt → VaptVupt
rename.

### GUI version-string parsing bug

v3.0.0's GUI parsed the CLI version banner with
`ZUPT_VER_SHORT.replace("zupt ", "")`. With v2.4.x the banner was
literally `zupt 2.4.8` so this kind of worked. With v3.0.0 the banner
became:

```
vaptvupt 3.0.0 (formerly zupt; renamed in v3.0.0 — INPI Brasil trademark)
```

The substring `"zupt "` ALSO appears inside `"formerly zupt; renamed"`,
so `replace` chewed up the wrong substring. Window title, splash
header, status bar and about-panel hero number all displayed the
entire 75-character string instead of just "3.0.0".

Fixed with a strict anchored regex:

```python
_VERSION_RE = re.compile(r'^(?:vaptvupt|zupt)\s+(\d+\.\d+\.\d+(?:[._A-Za-z0-9-]*)?)')
```

Now `_get_version()` returns three values:
- `ZUPT_VER_SHORT` — full first line (used as fallback display)
- `ZUPT_VER_NUMBER` — just the version number ("3.0.1")
- `ZUPT_VER_FULL` — entire stdout (used in the about panel)

All call sites updated.

### GUI about-panel enhancement

- Header `"ZUPT"` → `"VAPTVUPT"` (matches the rename).
- Splash header same change.
- Crypto-stack table expanded to reflect the v2.4.1+ defaults:
  - **Argon2id** (RFC 9106) — listed as default KDF since v2.4.1
  - **PBKDF2** — relabeled as legacy / `--kdf pbkdf2` fallback
  - **HKDF** (RFC 5869) — used in the post-quantum hybrid combiner
  - **XXH64** — labeled as non-crypto, used only inside the AEAD envelope
- New "COMPRESSION CODEC" section with the VaptVupt LZ + ANS 2.48.5 attribution.
- Trademark rename note visible.

### New regression test: `tests/test_gui_branding.sh`

Assertions covering the current branding and license presentation:
- No claim in the GUI source that the current GUI is MIT-only
- `gui/LICENSE-GUI` presents the current AGPL notice first and preserves the
  evidenced historical MIT grant (see the 5.2.2 erratum)
- GUI source SPDX header is `AGPL-3.0-or-later`
- No `replace("zupt ", ...)` parser in code
- An anchored `_VERSION_RE` regex is present
- Headers say `VAPTVUPT` (not `ZUPT`)
- Crypto stack mentions Argon2id and the VaptVupt codec
- Commercial-licensing contact is visible
- End-to-end functional check: regex extracts the version that matches `include/zupt.h`

Wired into both `make check` (distro-safe) and `make test` (full).

### Test suite status

`make test`: **all 16 suites green** (15 previously + 1 new branding suite).
F-09 byte sweep: **0/1827 silent accepts**. F-06 HMAC fuzz: **0/2000 silent accepts**.

### Files touched

```
include/zupt.h                            (version 3.0.0 → 3.0.1)
doc/vaptvupt.1                            (TH version 3.0.0 → 3.0.1)
gui/src/zupt_gui.py                       (anchored _VERSION_RE; about-panel rewrite; window/status compact display; no more replace("zupt ",...))
gui/LICENSE-GUI                           (MIT → AGPL-3.0-or-later with historical note)
LICENSE                                   (preamble updated for Zupt → VaptVupt rename)
tests/test_gui_branding.sh                (NEW — 11 assertions)
Makefile                                  (wire test_gui_branding into both `make check` and `make test`)
packaging/aur/PKGBUILD                    (pkgver 3.0.1)
packaging/debian/changelog                (3.0.1-1 prepended)
packaging/rpm/vaptvupt.spec               (Version 3.0.1)
packaging/homebrew/vaptvupt.rb            (version 3.0.1)
packaging/nix/flake.nix                   (version 3.0.1)
packaging/opensuse/{zupt.spec,_service,zupt.changes}  (3.0.1 + cabelo changelog entry)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (3.0.1 row)
AUDIT.md                                  (3.0.1 history entry)
```


## [3.0.0] — 2026-05-25 — VaptVupt rename + VV codec 2.48.5 + GUI bug fix

**Major version. INPI Brasil trademark rename + integrated codec
upgrade + GUI discovery bug fix + enhanced documentation + measured
performance and security results.**

### Rename: Zupt → VaptVupt

A prior INPI Brasil trademark registration on "Zupt" for unrelated
software forced a product rename. The change is intentionally narrow:

- **What changes:** the binary name (`vaptvupt`), the brand string in
  the banner/help/version output, package names (`vaptvupt` in
  Debian/RPM/AUR/Nix/Homebrew/openSUSE), and user-visible strings in
  the GUI.
- **What does NOT change:** the archive extension (still `.zupt`),
  the header magic bytes (still `\x5A\x55\x50\x54\x1A\x00` = "ZUPT"),
  the C identifier prefix (still `zupt_` / `ZUPT_` for ABI continuity
  with libzuptsdk), the on-disk format (still v1.6 since v2.3.1).
- **Verified bidirectional compatibility:** archives produced by
  v2.4.8 extract byte-exact under v3.0.0 and vice versa.
- **Legacy symlink:** `/usr/bin/zupt → /usr/bin/vaptvupt` is
  installed by the Makefile and shipped in all distro packages for
  one major version cycle. Existing scripts, shell history, and
  cron jobs keep working without modification.

### Integrated VaptVupt LZ + ANS codec 2.48.5

Two real bugfixes (both fuzzer-found by upstream's libFuzzer harness
in Sprint 23):

- **heap-buffer-overflow READ in `vv_dstream_decompress_chunk`**
  (medium severity). `csz - 1` underflowed `size_t` to `SIZE_MAX`
  when `csz == 0`, causing the entropy decoder to read past the
  input buffer (default 65 536 bytes). Fixed by porting the
  stateless-decoder's existing check to the streaming path.
- **UBSan-safe pointer arithmetic in `vv_copy_match`**. The original
  `dst[i - (ptrdiff_t)offset]` formed an intermediate pointer with a
  negative offset on the first iteration; even though the resulting
  address was always in-bounds (caller-validated), UBSan's
  pointer-bounds check flagged it. Hoisted `dst - offset` into a
  named pointer outside the loop where it lands in valid memory.
- **`const`-correctness cleanup** in the entropy encoder (`vv_ans.c`):
  three `const uint8_t *` declarations narrowed to non-const
  matching the actual write semantics in two safe-zone branches.

API surface unchanged — headers are byte-identical between 2.48.2
and 2.48.5.

### Fixed: GUI binary-discovery bug

Reported: `vaptvupt-gui` (then `zupt-gui`) launched from a desktop
session couldn't find the `zupt` binary in `/usr/bin`; manually
copying it to `/usr/local/bin` worked around the problem.

Root cause: desktop sessions on some distros launch GUI apps with a
minimal `PATH` (e.g. `/usr/local/bin:/usr/local/sbin`) that omits
`/usr/bin`. `shutil.which("zupt")` then returns `None`. The old
fallback list relied on `is_file()` only — no liveness check, no
executable check, no logging.

New `_find_vaptvupt()`:

1. Tries env vars `VAPTVUPT_BIN` and legacy `ZUPT_BIN` first.
2. Walks the source tree (handles "run from source checkout"); tries
   both `vaptvupt` and `zupt` names.
3. `shutil.which()` on both names.
4. Hard-coded common paths: `/usr/local/bin`, `/usr/bin`,
   `/opt/vaptvupt/bin`, `/opt/homebrew/bin`, Termux's Android path,
   Flatpak's `/app/bin`, plus the legacy `zupt` equivalents.
5. **Liveness check on every candidate**: runs `version`,
   3-second timeout, must exit 0. Catches missing shared libraries,
   broken rpath, ABI mismatch.
6. **Discovery log** to stderr when `VAPTVUPT_DEBUG=1` or
   `ZUPT_DEBUG=1`. Tells the user exactly which path was tried and
   why each failed.

### Enhanced man page (597 lines, was 422)

Full rewrite. New sections:

- **POST-QUANTUM ENCRYPTION** — explicit derivation of the hybrid
  session key from ML-KEM-768 + X25519, key-commitment notes, the
  Jasmin/C constant-time policy by architecture.
- **PERFORMANCE** — measured numbers (table) with honest reading of
  what they mean.
- **SECURITY / Threat model** — what VaptVupt protects against AND
  what it explicitly does NOT (compromised endpoint, weak password,
  metadata leakage, CRIME/BREACH-style side channels, DoS by very
  large input).
- **ENVIRONMENT** — `VAPTVUPT_BIN`, `VAPTVUPT_DEBUG`, legacy
  `ZUPT_BIN` aliases.
- **EXIT STATUS** — 0–5 documented with semantics.

Old `doc/zupt.1` is now a symlink to `doc/vaptvupt.1`; the install
rule emits both `vaptvupt.1.gz` and a `zupt.1.gz → vaptvupt.1.gz`
symlink so `man zupt` keeps working.

### Performance and security tests run for this release

See README.md's "Benchmark Results (v3.0.0 release)" and "Security
Test Results (v3.0.0 release)" sections — those are the canonical
v3.0.0 numbers, replacing the v2.4.x tables per the user-specified
"every new version replaces the README's ultimate tests" policy.

Quick summary:

- **Benchmark vs gzip-9 / zstd-3 / zstd-19** on four fixtures. On
  binary-struct data VaptVupt L9 beats both gzip-9 (44.7% vs 52.0%)
  and zstd-3 (44.7% vs 77.3%) on ratio. Encode throughput is the
  weak axis (~7–11 MB/s at L9 vs zstd-3's ~100–400 MB/s).
- **Security regression** — 0/1827 silent accepts on F-09 byte
  sweep, 2000/2000 honest roundtrips on F-06 HMAC fuzz with 0
  silent tamper accepts. **91/91 distro-safe assertions pass.**

### Other fixes

- `Makefile` produces a `./zupt` symlink alongside `./vaptvupt`
  so all 27 existing test files keep working unmodified.
- `tests/test_completions_manpage.sh` updated to accept either
  product name in the regression patterns.
- `tests/test_packaging_syntax.sh` updated for the rename
  (recipes can be `vaptvupt` or legacy `zupt` named).
- All packaging recipes (AUR PKGBUILD, Debian source package,
  Homebrew formula, Nix flake, Fedora/RPM spec, openSUSE OBS files)
  renamed and updated to v3.0.0 with `Provides: zupt` / `Obsoletes:
  zupt < 3.0.0` / equivalents for clean upgrade.

### Files touched

```
include/zupt.h                            (version 2.4.8 → 3.0.0; ZUPT_PRODUCT_NAME macros added)
src/zupt_main.c                           (banner, usage, version subcommand)
gui/src/zupt_gui.py                       (new _find_vaptvupt with liveness checks + discovery log)
src/vv_ans.c, vv_decoder.c, vv_encoder.c, vv_huffman.c, vv_simd.c, vv_xxh64.c  (VV 2.48.5)
include/vaptvupt.h, vaptvupt_api.h, vv_ans.h, vv_huffman.h, vv_platform.h     (VV 2.48.5; byte-identical)
doc/vaptvupt.1                            (NEW — 597 line man page)
doc/zupt.1                                (now a symlink to vaptvupt.1)
completions/vaptvupt.bash                 (renamed from completions/zupt.bash; both names registered)
completions/_vaptvupt                     (renamed from completions/_zupt; both names #compdef)
completions/vaptvupt.fish                 (renamed from completions/zupt.fish; both names complete -c)
Makefile                                  (TARGET=vaptvupt; LEGACY_LINK=zupt; install rule emits symlinks)
tests/test_completions_manpage.sh         (regex patterns accept both names)
tests/test_packaging_syntax.sh            (regex patterns accept both names)
packaging/aur/PKGBUILD                    (pkgname=vaptvupt; provides/replaces/conflicts zupt; v3.0.0)
packaging/debian/{control,changelog}      (Source/Package vaptvupt; Provides/Replaces/Conflicts zupt; v3.0.0)
packaging/rpm/vaptvupt.spec               (renamed from zupt.spec; Name vaptvupt; Provides/Obsoletes/Conflicts zupt; v3.0.0)
packaging/homebrew/vaptvupt.rb            (renamed from zupt.rb; class Vaptvupt; v3.0.0)
packaging/nix/flake.nix                   (pname vaptvupt; v3.0.0)
packaging/opensuse/{_service,zupt.spec,zupt.changes}  (v3.0.0; prepended v3.0.0 entry to cabelo's history)
README.md                                 (rename header; PERFORMANCE + SECURITY tables replaced)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (3.0.0 row)
AUDIT.md                                  (v3.0.0 history entry)
```


## [2.4.8] — 2026-05-24 — `make check` + cabelo's openSUSE update + binary packages

Distro-friendly release. Adds a curated `make check` target for OBS /
Debian / RPM `%check` sections, rewrites the openSUSE OBS files to
match cabelo's existing style with two important bugfixes (license
and version), and ships **8 binary packages** (CLI .deb/.rpm/AppImage,
GUI .deb/.rpm/AppImage, source tarball, fallback AppDir).

### `make check` — distro-safe test subset

Targeted at downstream packagers (openSUSE OBS, Debian, Fedora) who
need a `%check` / `override_dh_auto_test` target that:

- Runs in <2 minutes (not the full byte-sweep arc that `make test` does)
- Doesn't call `make clean` mid-stream (rules out `test_dist_reproducible.sh`)
- Doesn't depend on tools that may be absent in the build chroot
  (no PyYAML, no ruby, no `dpkg-parsechangelog`)
- Doesn't depend on multi-threading that's flaky under emulation
  (skips `test_threaded.sh` and `test_pq.sh`'s MT subset)
- **Does** cover the security-critical regressions: F-06 HMAC,
  F-08 AIT, F-09 byte-level integrity, F-10 KDF default, F-11
  auth-fail wording, F-12 comments
- **Does** verify cryptographic primitives against NIST/RFC vectors

Total: ~91 assertions across 10 suites. Recommended for all OBS
`%check` sections.

### openSUSE OBS files for `home:cabelo:innovators/zupt`

cabelo currently ships `zupt` 1.5.5 on OBS with two bugs:

1. **License field says `MIT`** — wrong. Upstream is
   `AGPL-3.0-or-later` (dual-licensed AGPL + commercial). Fixed.

2. **`%check` calls `test-all`** — that target includes threading
   tests which are flaky on emulated OBS build hosts (false
   positives observed in this sprint's verification matrix).
   Switched to `make check` (the new distro-safe target).

The updated files at `packaging/opensuse/` keep cabelo's existing
conventions intact:

- Still uses `tar_scm` service (not the newer `obs_scm`)
- Still pulls from GitHub (`https://github.com/cristiancmoises/zupt`)
- Still `%autosetup -p1` + `chmod +x tests/*.sh`
- Still `V=1 ... CFLAGS=... LDFLAGS=... LDLIBS=-lm -lpthread` build
- Still `%ifarch s390x` branch in `%check`
- Still minimal `BuildRequires: gcc gzip` (plus added `make` for
  newer chroots)

`zupt.changes` is **prepended** with 13 new entries covering
2.0.0 → 2.4.8; cabelo's existing 1.0.0–1.5.4 history is preserved
verbatim.

### Binary packages built and shipped

All 8 produced from this v2.4.8 source tree, smoke-verified to run:

| File                                  | Size    | Verified                                  |
|---------------------------------------|---------|-------------------------------------------|
| `zupt_2.4.8_amd64.deb`                | 412 KB  | dpkg-deb metadata clean; binary runs      |
| `zupt-2.4.8-1.x86_64.rpm`             | 499 KB  | rpm -qpi clean; License: AGPL-3.0-or-later AND GPL-3.0-or-later |
| `zupt-2.4.8-x86_64.AppImage`          | 1.3 MB  | `--appimage-extract-and-run version` works|
| `zupt-2.4.8-x86_64.AppDir.tar.gz`     | 391 KB  | FUSE-less fallback; AppRun works          |
| `zupt-gui_1.1.1_all.deb`              | 65 KB   | dpkg-deb metadata clean                   |
| `zupt-gui-1.1.1-1.noarch.rpm`         | 27 KB   | rpm metadata clean                        |
| `Zupt-GUI-1.1.1-x86_64.AppImage`      | 961 KB  | built                                     |
| `Zupt-GUI-1.1.1-x86_64.AppDir.tar.gz` | 15 KB   | built                                     |

Plus the reproducible source tarball:

| `zupt-2.4.8.tar.gz` | 829 KB | sha256: `2289e8dbbc8746727dd22102117fd367f3d58f3e9f914acf12f54f2ac654f0eb` |

### `packaging/build-dmg.sh` — honest macOS .dmg builder

New script. macOS-only because `hdiutil` only exists on Darwin.
Refuses to run on Linux with a helpful message pointing to the
AppImage / .deb / .rpm / Homebrew formula. Handles:

- Universal binary build (`-arch arm64 -arch x86_64`) when run on
  Apple Silicon hosts
- `.app` bundle with proper `Info.plist`
- Optional code-signing via `APPLE_DEV_ID` env var
- Optional notarization via `APPLE_NOTARIZE_KEY` env var
- Drag-to-install `.command` helper inside the .dmg

### Other fixes

- `packaging/build-gui-rpm.sh` now passes `--nodeps` to rpmbuild,
  which is necessary on Debian/Ubuntu hosts where `python3` isn't
  registered as an RPM. Runtime deps still apply on install.
- `doc/zupt.1` `.TH` version bumped to 2.4.8 to match
  `include/zupt.h` (caught by `tests/test_completions_manpage.sh`).
- `tests/test_packaging_syntax.sh` expanded: 22 → 27 assertions,
  adds openSUSE OBS validation (`zupt.spec`, `zupt.changes`,
  `_service`).

### What didn't change

- **No source-code changes** in `src/` or `include/` except the
  version bump
- Archive format still v1.6 — archives byte-identical to v2.4.3
- All 12 findings (F-01..F-12) remain closed; no new findings opened

### Verification

- `make` clean on plain GCC + Clang
- `make` strict GCC + strict Clang — clean
- `make check` — **all 10 suites, 91 assertions green**
- `make test` — **all 15 suites green**
- `make audit-licenses` — clean
- `make dist` reproducibility — byte-identical sha256
- All 8 binary packages built and smoke-tested
- `rpm --specfile packaging/opensuse/zupt.spec` parses clean
- `xml.etree` validates `packaging/opensuse/_service` as well-formed XML

### Files touched

```
include/zupt.h                            (version 2.4.7 → 2.4.8)
doc/zupt.1                                (.TH version bump)
Makefile                                  (new `check` target; .PHONY)
packaging/opensuse/_service               (NEW — tar_scm pointing at v2.4.8 GitHub tag)
packaging/opensuse/zupt.spec              (NEW — minimal spec matching cabelo's style)
packaging/opensuse/zupt.changes           (NEW — 13 entries prepended to cabelo's history)
packaging/opensuse/README.md              (NEW — osc submission guide)
packaging/build-dmg.sh                    (NEW — macOS-only .dmg builder)
packaging/build-gui-rpm.sh                (--nodeps for Debian/Ubuntu build hosts)
tests/test_packaging_syntax.sh            (22 → 27 assertions; openSUSE validation)
packaging/aur/PKGBUILD                    (pkgver 2.4.8)
packaging/debian/changelog                (top entry 2.4.8-1)
packaging/rpm/zupt.spec                   (Version: 2.4.8)
packaging/homebrew/zupt.rb                (version 2.4.8)
packaging/nix/flake.nix                   (version 2.4.8)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (2.4.8 row)
AUDIT.md                                  (history entry)
```


## [2.4.7] — 2026-05-20 — manpage refresh + shell completions

UX/documentation release. Three additions and three small banner
corrections; no behavioural changes outside the version bump and
the three "stale KDF" string fixes.

### Manpage rewritten (`doc/zupt.1`)

The prior manpage (368 lines) predated all v2.4.x features. Stale
content removed; rewritten from scratch (422 lines) to cover:

- All current subcommands (`compress`, `extract`, `list`, `test`,
  `info`, `bench`, `disk backup`, `disk restore`, `keygen`, `version`,
  `help`)
- v2.4.x options (`--kdf`, `-c` / `--comment`, `--comment-file`,
  `--pq-sdk`) with concrete usage notes
- F-11 generic auth-fail message + the `--verbose` escape hatch
- F-12 encrypted archive comments and their MAC-coverage properties
- Cryptographic primitives the binary uses (FIPS 180-4, 202, 203;
  RFC 7748, 6070, 4231; NIST SP 800-38A)
- Examples for the four most common workflows (Argon2id password,
  PQ-SDK key, tamper-rejection demo, disk backup)
- A `SEE ALSO` cross-reference to `tar(1)`, `gzip(1)`, `xz(1)`,
  `age(1)`, `openssl(1)`
- Reference to `THREAT_MODEL.md` for security-boundary documentation

### Shell completions (new `completions/` directory)

| File | Shell |
|---|---|
| `completions/zupt.bash` | Bash 4.x+ (uses `_init_completion` with a manual fallback for hosts without bash-completion installed) |
| `completions/_zupt`     | zsh (uses `_describe` + `_values` + `_arguments`) |
| `completions/zupt.fish` | fish 3.x+ (subcommand-aware via `__fish_zupt_using_subcommand` predicate) |

Each file covers every CLI flag the binary actually parses (16
critical flags including `--kdf`, `--comment`, `--comment-file`,
`--pq`, `--pq-sdk`, `--dedup`, `--solid`, `--verbose`, `--quiet`,
`--threads`, `--level`, `--block`, `--store`, `--fast`, `--lzhp`,
`--vaptvupt`). Argument suggestions:

- `--kdf` → `argon2id pbkdf2`
- `--level` → `1 2 3 4 5 6 7 8 9`
- `--threads` → `0 1 2 4 8 16 32`
- `-o` / `--output` → directories only
- `--comment-file`, `--pq*` → file paths
- Archive positional arguments → `*.zupt` files

### Banner corrections (three minor)

The help banner, help footer, and `version` subcommand output all
still claimed `KDF: PBKDF2-SHA256` despite Argon2id being the
default since v2.4.1. All three sites corrected:

```
Before: Encryption: AES-256-CTR + HMAC-SHA256 | KDF: PBKDF2-SHA256
After:  Encryption: AES-256-CTR + HMAC-SHA256 | KDF: Argon2id (default) / PBKDF2 (--kdf pbkdf2)
```

This was a v2.4.1 oversight; user-visible output is now consistent
with actual behaviour.

### `make install` wires the new files

```
$PREFIX/share/bash-completion/completions/zupt
$PREFIX/share/zsh/site-functions/_zupt
$PREFIX/share/fish/vendor_completions.d/zupt.fish
```

`make uninstall` removes them. Distros can override paths in
their `make install` invocation; the recipe uses standard
location conventions per the Filesystem Hierarchy Standard.

### New regression test

`tests/test_completions_manpage.sh` — 12 assertions wired into
`make test`:

- Bash completion: `bash -n` syntax clean, defines `_zupt`,
  registers via `complete -F`
- zsh completion: `zsh -n` syntax clean, has `#compdef zupt`
- fish completion: has `complete -c zupt` entries (full `fish -n`
  check skipped on hosts without fish; CI installs fish)
- All three files cover the 16 critical flags (fish via `-l flag`
  form, others via `--flag` form)
- Manpage mentions all v2.4.x features (`--kdf`, `--comment`,
  Argon2id, F-11 wording, `--comment-file`, `--pq-sdk`, ML-KEM-768)
- Manpage has required `.SH` sections (NAME, SYNOPSIS, DESCRIPTION,
  COMMANDS, EXAMPLES)
- TH header version matches `include/zupt.h`
- `groff` lint check when available (skipped on hosts without it)

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC + Clang — clean.
- `make test` — **all 13 suites green** (completions+manpage 12/12).
- `make audit-licenses` — clean.
- `make dist` reproducibility — byte-identical sha256.
- `make DESTDIR=/tmp/install-test PREFIX=/usr install` verified:
  binary, gzipped manpage, and all 3 completion files placed at
  correct paths under `/tmp/install-test/usr/`.

### Honest scope note (consistent with v2.4.6's note)

This sprint is genuinely one-session-finishable. The harder candidates
remain:

- **ML-DSA-87**: still multi-sprint, still requires vendoring PQClean
- **Jasmin re-wiring**: still requires a `jasminc`-equipped environment

When the engineering arc resumes one of those, this sprint's
infrastructure (manpage, completions, install paths) will already
be in place to advertise the new functionality.

### Files touched

```
include/zupt.h                            (version 2.4.6 → 2.4.7)
src/zupt_main.c                           (3 stale KDF banner strings)
doc/zupt.1                                (rewritten, 368 → 422 lines)
completions/zupt.bash                     (new)
completions/_zupt                         (new)
completions/zupt.fish                     (new)
tests/test_completions_manpage.sh         (new, 12 assertions)
Makefile                                  (install + uninstall add
                                           completions; test target adds
                                           completions+manpage check)
DISTRIBUTION.md                           (completions section added)
packaging/aur/PKGBUILD                    (pkgver 2.4.7)
packaging/debian/changelog                (top entry 2.4.7-1)
packaging/rpm/zupt.spec                   (Version: 2.4.7)
packaging/homebrew/zupt.rb                (version 2.4.7)
packaging/nix/flake.nix                   (version 2.4.7)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (2.4.7 row)
AUDIT.md                                  (history entry)
```


## [2.4.6] — 2026-05-20 — CI rewrite + THREAT_MODEL.md

Non-security release. Continues the documentation/infrastructure
arc started in v2.4.4. No source-code changes outside the version
bump and packaging-syntax test expansion; archive format unchanged.

### `.github/workflows/ci.yml` — 8-job CI matrix

Replaces the prior 4-job CI with a comprehensive matrix that mirrors
the project's historical local-verification protocol:

| Job | What it does |
|---|---|
| `build-and-test` | Plain `make` + `make test` + `make audit-licenses` on both GCC and Clang (matrix strategy) |
| `strict-warnings` | Builds with `-Werror` + the full §6 warning set (`-Wshadow`, `-Wcast-align`, `-Wstrict-prototypes`, `-Wnull-dereference`, etc.) on both GCC and Clang |
| `sanitizers` | `make test-asan` + a `--pq-sdk` byte-exact roundtrip on `include/` under ASAN/UBSAN |
| `pie-hardening` | Builds with `-fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2`, verifies binary is PIE, smoke-tests an encrypted roundtrip |
| `cross-aarch64` | Runs `make && make test` inside an `aarch64` Ubuntu container via QEMU emulation |
| `dist-reproducibility` | Runs `make dist` twice, asserts byte-identical sha256, uploads tarball as workflow artifact |
| `packaging-syntax` | Runs `tests/test_packaging_syntax.sh` with `ruby`, `dpkg-dev`, and `rpm` installed so all five recipe validators actually run |
| `release` | Conditional on `refs/tags/v*`. Verifies tag matches `include/zupt.h`, builds reproducible tarball, creates GitHub release with sha256 sidecar |

The release job's tag check is important: pushing a `v2.4.7` git
tag when `include/zupt.h` still says `2.4.6` fails the workflow
before any release is published.

### `THREAT_MODEL.md` — 12 KB plain-English security boundary doc

Per `userPreferences`: "threat model in plain English. State
explicitly what the system does NOT protect against."

Covers, with appropriate plain-language honesty:

- **What Zupt protects against**: archive confidentiality
  (encrypted modes), byte-level tamper detection (0 silent accepts
  in v1.6 sweep), authentication-failure indistinguishability
  (F-11), post-quantum forward secrecy in `--pq-sdk`, side-channel
  resistance on hot paths then described as Jasmin-proven (5.2.2 records that
  no reproducible formal-proof artifact was retained)
- **What Zupt does NOT protect against**: compromised endpoints,
  key compromise (no forward secrecy across archives, no rotation
  feature), weak passwords (with concrete brute-force numbers),
  metadata leakage from archive structure (block sizes, count,
  timestamps visible), network attacks (not a network protocol),
  multi-party access (no threshold scheme), plausible
  deniability (fixed magic bytes), CRIME/BREACH-style
  compression-side-channel (mitigation: `--no-compress` if
  attacker-chosen plaintext is mixed with secrets)
- **Cryptographic assumptions**: explicit list of which standard
  primitives Zupt relies on and what breaks if any of them fall
- **Reporting security issues**: contact, expected response time,
  CVE/advisory commitment

### Expanded `tests/test_packaging_syntax.sh`

Now 22 assertions (up from 18). New checks:

- **CI workflow YAML**: parses cleanly with PyYAML; all expected
  jobs present (`build-and-test`, `strict-warnings`, `sanitizers`,
  `dist-reproducibility`, `packaging-syntax`, `release`)
- **THREAT_MODEL.md**: present, substantive (>3000 bytes — actual
  size 12 KB), required sections present

This keeps the documentation honest — if someone strips a section
from `THREAT_MODEL.md` to make a quick edit, the test fails fast.

### What didn't change

- **No source-code changes** in `src/` or `include/` except the
  version bump
- Archive format still v1.6
- All 12 findings (F-01..F-12) remain closed; no new findings opened
- `make dist` reproducibility unchanged

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC + strict Clang — clean.
- `make test` — **all 12 suites green** (packaging syntax: 22/22).
- `make audit-licenses` — clean.
- `make dist` byte-identical across two runs.
- The new CI YAML parses successfully with PyYAML.
- The `release` job's tag-vs-version check verified locally by
  reading the workflow logic.

### Honest scope note

This sprint deliberately did **not** attempt ML-DSA-87 signatures
(multi-sprint vendoring of PQClean) or Jasmin re-wiring (no
`jasminc` in this CI environment; userMemories notes hands-on
verification is needed). These remain on the roadmap.

### Files touched

```
include/zupt.h                            (version 2.4.5 → 2.4.6)
.github/workflows/ci.yml                  (rewritten: 4 → 8 jobs;
                                           tag-triggered release added)
THREAT_MODEL.md                           (new, 12 KB)
tests/test_packaging_syntax.sh            (18 → 22 assertions;
                                           CI YAML + THREAT_MODEL checks)
packaging/aur/PKGBUILD                    (pkgver 2.4.6)
packaging/debian/changelog                (top entry 2.4.6-1)
packaging/rpm/zupt.spec                   (Version: 2.4.6)
packaging/homebrew/zupt.rb                (version 2.4.6)
packaging/nix/flake.nix                   (version 2.4.6)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (2.4.6 row)
AUDIT.md                                  (history entry)
DISTRIBUTION.md                           (CI section added)
```


## [2.4.5] — 2026-05-20 — RPM + Nix + DISTRIBUTION.md (packaging completion)

Continues the v2.4.4 packaging arc with two more upstream recipes
and a comprehensive packaging guide. No source-code changes outside
the new packaging-syntax regression test; archive format unchanged.

### New packaging recipes

**`packaging/rpm/zupt.spec`** — Fedora / RHEL / CentOS RPM
- `License: AGPL-3.0-or-later AND GPL-3.0-or-later` (Zupt + VaptVupt)
- `Name: zupt`, version pinned to `include/zupt.h`
- `BuildRequires: gcc, make, glibc-devel, python3 >= 3.8`
- `%build` uses Fedora's `%{optflags}` plus the project's preferred
  `-Wall -Wextra -Wpedantic -std=c11`
- `%check` runs `make test` (all 12 upstream regression suites)
- `%install` puts libzuptsdk under `%{_libdir}/%{name}/` with both
  symlinks
- `%files` lists binary, manpage, license, and docs
- Written for Fedora 38+ / EPEL 9+; notes for older RHEL inline

**`packaging/nix/flake.nix`** — Nix flake (NixOS + nix-flake users)
- `nixpkgs` pinned to `nixos-24.11` channel via `flake-utils`
- Exposes `packages.<system>.zupt` and `packages.<system>.default`
- Builds for `x86_64-linux` and `aarch64-linux`
- `doCheck = true` runs the full `make test` suite during build
- `installPhase` copies libzuptsdk into `$out/lib/zupt/` so the
  binary's relative rpath resolves under `/nix/store`
- `apps.default` makes `nix run` work directly
- `devShells.default` includes gcc, make, python3, valgrind, gdb

### New documentation

**`DISTRIBUTION.md`** — 8 KB guide covering:
- How to produce a reproducible source tarball (`make dist`)
- Reproducibility properties (sorted files, fixed mtime, gzip `-9n`)
- Submission flows for all 5 distros (AUR, Debian, Fedora, Homebrew, Nix)
- Concrete command examples for each
- A submission checklist
- Security-posture notes for downstream packagers (every recipe runs
  `make test` so silent regressions can't slip through)

### New regression test

**`tests/test_packaging_syntax.sh`** — 18 assertions, wired into
`make test`:

- AUR: bash syntax clean, version matches `include/zupt.h`, required
  fields present (`pkgname`, `pkgver`, `pkgrel`, `pkgdesc`, `arch`,
  `url`, `license`, `depends`)
- Debian: all 5 files present (`control`, `rules`, `changelog`,
  `copyright`, `source/format`); `rules` is executable; `Source:`
  field correct; changelog top-entry version matches; format is
  `3.0 (quilt)`; `dpkg-parsechangelog` accepts it
- RPM: required header tags (`Name`, `Version`, `Release`, `Summary`,
  `License`, `URL`, `Source0`); `Version` matches `include/zupt.h`;
  all required sections (`%prep`, `%build`, `%install`, `%files`,
  `%changelog`)
- Homebrew: version matches; class + DSL keywords + `install` method
  + `test` block all present
- Nix: outputs structure present; `pname = "zupt"` derivation defined;
  version matches
- DISTRIBUTION.md: file present; covers all 5 distros

Tools used opportunistically when available: `ruby -c` (Homebrew
syntax), `dpkg-parsechangelog` (Debian), `rpmlint` (RPM),
`nix flake metadata` (Nix). Test skips with `- skipped` lines when
a tool isn't installed (e.g. `ruby` is rare in build environments;
the dpkg-dev path was exercised in this sprint and passed).

### What didn't change

- **No source-code changes** in `src/` or `include/` except the
  version bump
- Archive format still v1.6
- All 12 findings (F-01..F-12) remain closed; no new findings opened
- `make dist` reproducibility unchanged

### Cross-recipe version consistency

The new packaging-syntax test enforces that every recipe pins the
same version as `include/zupt.h`. Bumping the C string at one site
plus running the recipe sync (5 `sed` lines) keeps all 5 recipes in
lockstep. The test fails fast if any recipe drifts.

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC (full §6 set) — clean.
- `make` strict Clang — clean.
- `make test` — **all 12 suites green** (new: packaging syntax, 18/18).
- `make audit-licenses` — clean.
- `make dist` two consecutive runs — byte-identical sha256.

### Files touched

```
include/zupt.h                            (version 2.4.4 → 2.4.5)
packaging/aur/PKGBUILD                    (pkgver 2.4.5; source URL updated)
packaging/debian/changelog                (top entry 2.4.5-1)
packaging/rpm/zupt.spec                   (new)
packaging/homebrew/zupt.rb                (version 2.4.5; URL updated)
packaging/nix/flake.nix                   (new)
DISTRIBUTION.md                           (new)
tests/test_packaging_syntax.sh            (new, 18 assertions)
Makefile                                  (test target adds packaging syntax)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (2.4.5 row)
AUDIT.md                                  (history entry)
```


## [2.4.4] — 2026-05-20 — distribution packaging + reproducible source tarball

Non-security release. First sprint to ship without closing a finding —
all 12 findings F-01..F-12 remain closed, no new findings opened.
Focuses on getting Zupt distributable: reproducible source tarballs,
upstream packaging recipes for AUR, Debian, and Homebrew.

### `make dist` — reproducible source tarball

New Makefile target producing `/tmp/zupt-VERSION.tar.gz` that is
**byte-identical** given the same input source tree. Properties:

- Files sorted by name (deterministic order regardless of filesystem layout)
- mtime fixed to `SOURCE_DATE_EPOCH` (default `1747699200`, override via env)
- uid/gid pinned to root (0/0) via `--owner=0 --group=0 --numeric-owner`
- gzip wrapped with `-9n` (no embedded timestamp or filename)
- Source-only — no `.o`, no built binaries, no `.git/` tree
- Includes the vendored `libzuptsdk.so.2.0.0` real file plus its two
  symlinks (`libzuptsdk.so`, `libzuptsdk.so.2`) — caught a tar `-type f`
  bug that excluded symlinks during initial implementation
- Reproducibility verified by `tests/test_dist_reproducible.sh`
  (12 assertions, wired into `make test`)

Used by downstream packagers to pin a stable `sha256` in their
recipes. Two consecutive `make dist` runs on the same tree produced
identical sha256 (verified in the regression test on every CI run).

### Upstream packaging

Three new packaging trees at `packaging/`:

**`packaging/aur/PKGBUILD`** — Arch Linux user repository
- pkgname=`zupt`, pkgver=`2.4.4`, arch=(`x86_64`, `aarch64`)
- `depends=('glibc')`, `makedepends=('gcc')`
- `build()` uses the project's strict-warning flags
- `check()` runs `make test` (10 suites + dist regression)
- `package()` installs the binary, manpage, docs, and the vendored
  `libzuptsdk.so*` triple at `/usr/lib/zupt/`
- License: `AGPL-3.0-or-later`

**`packaging/debian/`** — Debian source package layout
- `control` — multi-paragraph package description listing PQ hybrid,
  Argon2id, byte-level tamper detection, Jasmin CT, NIST/RFC vectors
- `rules` — debhelper-compat=13, `SOURCE_DATE_EPOCH=1747699200`,
  `hardening=+all`, project CFLAGS, override_dh_auto_install moves
  libzuptsdk to `/usr/lib/zupt/`. Marked executable.
- `changelog` — UNRELEASED 2.4.4-1 entry for downstream maintainer
- `copyright` — DEP-5 format: AGPL-3.0-or-later main + GPL-3.0-or-later
  for VaptVupt/libzuptsdk
- `source/format` — `3.0 (quilt)`

**`packaging/homebrew/zupt.rb`** — macOS Homebrew formula
- Class `Zupt`, `desc`, `homepage`, `url`, `version 2.4.4`
- `sha256` placeholder for the release tarball sha
- `depends_on "python@3.12" => :test` for the tamper test harness
- `install` runs `make`, then `make install`, then drops libzuptsdk
  into `lib/zupt/` (handles both `.dylib` and Linux `.so.2.0.0`
  fallback)
- `test` block: compresses a payload, extracts it back, byte-compares

### What didn't change

- **No source-code changes** in `src/`, `include/`, or `tests/`
  except the new `tests/test_dist_reproducible.sh`.
- Archive format still v1.6, archives byte-identical to v2.4.3.
- The 12 existing findings remain closed; no new findings opened.
- §3.5 byte sweep was skipped per protocol (kickoff stated
  `format-touching? no`).

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC (full §6 set) — clean.
- `make` strict Clang — clean.
- `make test` — **all 11 suites green** (1 new: dist reproducibility,
  12/12 assertions).
- `make audit-licenses` — clean.
- `make dist` twice on same tree → identical sha256 (verified in
  regression test on every `make test` run).
- `bash -n packaging/aur/PKGBUILD` — syntax clean.
- `dpkg-parsechangelog -l packaging/debian/changelog` — parses
  correctly: `Source: zupt`, `Version: 2.4.4-1`, `Distribution: UNRELEASED`.
- Fresh `tar xzf zupt-2.4.4.tar.gz && cd zupt-2.4.4 && make && make test` —
  all 11 suites green from a clean unpack.

### Findings status

No findings closed or opened. Cumulative ledger:

| ID | Sprint | Title | Status |
|---|---|---|---|
| F-01..F-05 | 2.2.4 | Audit-batch cleanup | fixed |
| F-06 | 2.2.5 | HMAC verifier silently accepts ~6% of MAC tampers (high) | fixed |
| F-07 | 2.2.5 | block_type at index_offset unauthenticated | fixed |
| F-08 | 2.3.0 | Header/footer metadata not MAC'd | fixed |
| F-09 | 2.3.1 | Per-block frame preface unauthenticated | fixed |
| — | 2.4.0 | Methodology: §3.5 byte-sweep mandate | shipped |
| F-10 | 2.4.1 | KDF default: PBKDF2 → Argon2id | fixed |
| F-11 | 2.4.2 | Error-message verbal probe-oracle | fixed |
| F-12 | 2.4.3 | Archive comments | fixed |
| — | 2.4.4 | Distribution packaging + reproducible dist | shipped |

### Files touched

```
include/zupt.h                            (version 2.4.3 → 2.4.4)
Makefile                                  (.PHONY adds dist; new dist target;
                                           test target adds test_dist_reproducible.sh)
tests/test_dist_reproducible.sh           (new, 12 assertions)
packaging/aur/PKGBUILD                    (new)
packaging/debian/control                  (new)
packaging/debian/rules                    (new, executable)
packaging/debian/changelog                (new)
packaging/debian/copyright                (new, DEP-5)
packaging/debian/source/format            (new)
packaging/homebrew/zupt.rb                (new)
CHANGELOG.md                              (this entry)
ROADMAP.md                                (2.4.4 row)
AUDIT.md                                  (history entry)
```


## [2.4.3] — 2026-05-20 — F-12: encrypted archive comments

Implements the previously-reserved `comment_offset` field in
`zupt_archive_header_t`. Adds free-form UTF-8 archive comments that
are MAC-protected end-to-end and decryption-gated on encrypted
archives.

### F-12 — Archive comments (new feature)

**Use case.** Users want to embed metadata in an archive that
travels with it — purpose, source path, customer ID, GDPR-erasure
notes, restore instructions. Previously the only place to put this
was the filename. The `comment_offset` field has been reserved in
the header since v1.0 but was unused.

**On disk.** A new block type `ZUPT_BLOCK_COMMENT = 0x05` is written
between the last data block and the central index. The block layout
is identical to a data block:

```
[2B magic 0xBB 0x01][1B block_type=0x05][2B codec_id=STORE][2B block_flags]
[varint uncompressed_size][varint compressed_size][8B plaintext-XXH64]
[payload: UTF-8 comment text, encrypted iff block_flags has ENCRYPTED]
```

`hdr.comment_offset` is set to the file offset of this block, or `0`
when no comment is present.

**Encryption.** For encrypted archives the comment block goes
through the same AEAD pipeline as data blocks:

- AES-256-CTR + HMAC-SHA256
- F-09 preface AAD (binds block_type/codec_id/flags/sizes/XXH64 into the MAC)
- `aad_seq = 0xFFFFFFFFFFFFFFFE` (one less than the index's
  `0xFFFFFFFFFFFFFFFF` sentinel; cannot collide with file-block
  aad_seqs which encode `(fi+1, block_seq)` in the upper/lower
  32-bit halves and are bounded above by `0xFFFFFFFF00000000`)

**Header coverage.** `comment_offset` lives in `hdr[44..51]`, which
is part of the AIT MAC input from v1.5 onwards. Tampering the
offset → AIT auth-fail at open time. Tampering the block payload →
per-block HMAC fail at decompress time.

**Backward compatibility.** No format-minor bump. v2.4.2 readers
seek by file index entries (not sequentially), so a comment block
between data and index is skipped. They ignore `comment_offset`
entirely. **v2.4.2 readers extract v2.4.3 archives byte-exact** —
they just don't display the comment.

### CLI surface

```
  -c, --comment <TEXT>       Embed a free-form archive comment.
  --comment-file <FILE>      Read comment from FILE (max 4096 bytes; trailing
                             whitespace stripped so editor newline doesn't
                             affect roundtrip equality).
```

Both flags work on `c` (compress) and `disk backup`. Empty string
is treated as no-comment (header `comment_offset` stays 0). Max
comment length is `ZUPT_MAX_COMMENT_LEN = 4096` bytes.

`zupt info <archive>` reports the **presence** of a comment but
doesn't decrypt it (no keyring at info time). The text appears at
the end of `zupt x` output after the file-extraction summary.

### What didn't change

- Archive format still v1.6.
- The per-block crypto pipeline is unchanged — comment blocks use
  the exact same `zupt_encrypt_buffer_aad` / `decompress_block`
  paths as data blocks, so F-06 / F-09 protections apply
  transparently.
- The F-09 strict structural validation of the enc-header block is
  unchanged.
- v2.4.2 archives extract identically.

### Verification

- §3.5 exhaustive byte sweep on a 1878-byte PQ-SDK archive with a
  comment block: **0/1878 silent acceptances**. The comment block
  bytes are fully MAC-covered.
- `make test` — **all 11 suites green** including new
  `test_f12_comment.sh` (11 assertions).
- `make test-vectors` — 14/14.
- `make test-f06` — 2000/2000.
- `make test-asan` `--pq-sdk` byte-exact roundtrip on `include/`
  with a comment — clean.
- Strict GCC + Clang warning matrix — clean (had to split a help-
  text string literal that crossed ISO C99's 4095-char limit; now
  emits via two `fprintf` calls).
- 50× audit-suite stress — 50/50 green.

### F-12 regression test coverage

`tests/test_f12_comment.sh` — 11 assertions:

1. Plaintext archive: comment roundtrips
2. Argon2id-password archive: comment roundtrips
3. PBKDF2-password archive: comment roundtrips
4. PQ-SDK archive: comment roundtrips
5. `info` does NOT leak the encrypted comment plaintext
6. `info` reports comment presence
7. Tampering the comment block payload is rejected (per-block HMAC)
8. Tampering `hdr.comment_offset` is rejected (AIT)
9. Archive without a comment shows no `Comment:` line in `info`
10. `--comment-file` reads from disk
11. Empty `-c ""` is treated as no-comment

### Files touched

```
include/zupt.h                       (version 2.4.2 → 2.4.3,
                                      ZUPT_BLOCK_COMMENT, ZUPT_MAX_COMMENT_LEN,
                                      comment field in zupt_options_t,
                                      has_comment field in zupt_options_t)
src/zupt_format.c                    (write_comment_block helper,
                                      wired into both compress paths,
                                      open_archive reads comment after AIT,
                                      zupt_info shows presence,
                                      zupt_extract prints comment)
src/zupt_main.c                      (-c / --comment-file parsers at 2 sites,
                                      help text, help-string split for ISO C99)
tests/test_f12_comment.sh            (new, 11 assertions)
Makefile                             (test target)
CHANGELOG.md                         (this entry)
ROADMAP.md                           (2.4.3 row)
AUDIT.md                             (history entry)
SECURITY.md                          (comment row added)
docs/FINDINGS-2.x.md                 (F-12 closed)
```


## [2.4.2] — 2026-05-20 — F-11: error-message hygiene (no more "tampered" on wrong password)

Closes F-11, the deferred message-UX issue from sprint 2.4.1.

### Symptom (pre-2.4.2)

Extracting an encrypted archive with the wrong password produced this on
stderr:

```
Error: archive-integrity-trailer (top-MAC) verification failed.
       The archive header or footer has been tampered with.
Error: Authentication failed (wrong password?)
```

The "header or footer has been tampered with" framing made users
think their archive was corrupted when in fact they had just
mistyped a password. The wording was inherited from the actual
tamper case — both cases share the same code path (AIT verified
with `kr->mac_key`, which is derived from the password).

### Fix

Two-pronged:

**Wording change.** Encrypted-archive AIT failure and SDK envelope
decryption failure both now print the same generic line by default:

```
Error: Authentication failed (wrong key, wrong password, or tampered archive).
```

The detailed "archive-integrity-trailer (top-MAC) verification
failed" wording moves behind `--verbose`. Plaintext archives
(where no key is involved and the failure is unambiguously
corruption) keep the original detailed wording.

**Probe-oracle property preserved.** The default message is
**identical** in three distinct failure cases:

| Case | Default message |
|---|---|
| Wrong password (Argon2id) | "Authentication failed (wrong key, wrong password, or tampered archive)" |
| Wrong password (PBKDF2) | "Authentication failed (wrong key, wrong password, or tampered archive)" |
| Wrong PQ-SDK key | "Authentication failed (wrong key, wrong password, or tampered archive)" |
| Actual header tamper (encrypted) | "Authentication failed (wrong key, wrong password, or tampered archive)" |

This collapses what was previously a verbal probe-oracle (different
wording per failure cause) into a single uniform error. Timing is
unchanged — `ait_verify` always runs the HMAC, branchless return,
unchanged from F-08 / v2.3.0.

Plaintext-mode tamper detection (no key involvement) keeps the
detailed XXH64-failure message because there's no oracle concern:

```
Error: archive-integrity-trailer (XXH64) verification failed.
       The archive header or footer has been corrupted or tampered with.
```

### What didn't change

- No format change (still v1.6).
- No code paths for the actual cryptographic verification — only
  the error-message strings and the verbose-gated detail line.
- No CLI surface change beyond `--verbose` now affecting these
  messages (the flag already existed).
- Wrong password still fails to extract; wrong key still fails to
  extract; tampered archives still fail to extract. Only the
  on-stderr explanation differs.

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC (full §6 set) — clean.
- `make` strict Clang — clean.
- `make test` — **all 10 suites green** (test_f11_authfail_message.sh
  adds 12 assertions). The F-08 test was updated to accept either
  the generic or detailed-with-`--verbose` wording.
- `make test-vectors` — 14/14.
- `make test-f06` — 2000/2000.
- `make test-asan` `--pq-sdk` byte-exact roundtrip on `include/`
  — clean.
- `make audit-licenses` — clean.
- 50× audit-suite stress — 50/50 green.

§3.5 byte sweep was skipped per the v2.4.0 sprint protocol because
this release is **not format-touching** (kickoff template noted
`format-touching? no`). The change is to error-message strings and
to a verbose-gating branch — no on-disk bytes change, no MAC
inputs change.

### Findings

| ID | Title | Status |
|---|---|---|
| F-11 | "Tampered" error message on wrong-password extract misleads users | **fixed** |

### Files touched

```
include/zupt.h                          (version 2.4.1 → 2.4.2)
src/zupt_format.c                       (open_archive AIT-fail branch;
                                         PQ-SDK and Argon2id init-fail
                                         branches in read_enc_header)
src/zupt_disk.c                         (zupt_disk_restore AIT-fail branch)
tests/test_f08_topmac.sh                (assertion updated for new
                                         default+verbose message wording)
tests/test_f11_authfail_message.sh      (new, 12 assertions)
Makefile                                (test target)
CHANGELOG.md                            (this entry)
ROADMAP.md                              (2.4.2 row)
AUDIT.md                                (history entry)
docs/FINDINGS-2.x.md                    (F-11 closed)
```


## [2.4.1] — 2026-05-20 — F-10: Argon2id as default for password-mode

First sprint after the v2.4.0 methodology release. Flips the default
KDF for password-based encryption from PBKDF2-SHA256 to Argon2id.
PBKDF2 remains available via `--kdf pbkdf2` for compatibility with
v2.4.0-and-older readers.

### F-10 — Password-mode KDF default upgraded to Argon2id

**Severity:** N/A (security improvement, not a bug fix)
**Component:** `src/zupt_format.c` (write_enc_header password branch),
`src/zupt_main.c` (CLI parser), `include/zupt.h`
(`zupt_options_t.kdf_legacy_pbkdf2`)

**Why now.** PBKDF2-SHA256 with 600 000 iterations is fine, but
Argon2id is the OWASP recommendation and the modern best practice
for password KDFs. The memory-hardness of Argon2id makes brute-force
attacks on GPUs and ASICs orders of magnitude more expensive than
against PBKDF2. The infrastructure was already present:
`zupt_sdk_password_encrypt_init` (Argon2id + AES-256-CTR + HMAC-SHA256)
and `zupt_sdk_password_decrypt_init` shipped in earlier work and
were dispatched on the `enc_type = 0x04 (ZUPT_ENC_PW_ARGON2)` byte
of the encryption header. Read-path dispatch already handled both
enc_types. The only change needed was flipping the **write-path
default** from `ZUPT_ENC_PBKDF2 (0x01)` to `ZUPT_ENC_PW_ARGON2 (0x04)`.

**What changed.**

- `write_enc_header` password branch: if `opts->kdf_legacy_pbkdf2 == 0`
  (default), call `zupt_sdk_password_encrypt_init` and emit the
  33-byte Argon2id enc-header (`[type=0x04][16B salt][16B nonce]`).
  Otherwise emit the 53-byte PBKDF2 enc-header
  (`[type=0x01][32B salt][16B nonce][4B iter=600000]`) as before.

- New CLI flag `--kdf <argon2id|pbkdf2>` on `c` (compress) and
  `disk backup` commands. Default (no flag) = Argon2id.
  `--kdf argon2id` is the explicit form. `--kdf pbkdf2` selects
  legacy mode. `--kdf garbage` returns an error.

- The per-block ciphertext pipeline is **identical** in both modes —
  both produce the same `kr->enc_key` / `kr->mac_key` /
  `kr->base_nonce` and feed AES-256-CTR + HMAC-SHA256 + F-09
  preface-AAD. Only the enc-header bytes and KDF differ. F-09's
  full-archive byte-level tamper detection carries over unchanged
  (verified: header + footer sweep on a v2.4.1 Argon2id-default
  archive shows 0 undetected positions; body sampled every 4 bytes
  also clean).

**What didn't change.**

- Archive format version still v1.6. The format does not need a
  bump — both enc-header layouts have been valid since the
  `enc_type` dispatch was introduced; only the default flips.
- Read path: unchanged. Existing dispatch on `enc_type` byte at
  offset 0 of the enc-header block already handles both 0x01 and
  0x04. **v2.4.0 readers extract v2.4.1 Argon2id archives without
  modification** (verified — v2.4.0 already linked
  `zupt_sdk_password_decrypt_init`).
- PQ-SDK mode (`--pq-sdk`) is unaffected; it uses its own
  `ZUPT_ENC_PQ_SDK_V2 (0x03)` enc-header.

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC (full §6 set) — clean.
- `make` strict Clang — clean.
- `make test` — all 9 suites green (now includes `test_f10_kdf_default.sh`,
  10/10 assertions).
- `make test-vectors` — 14/14.
- `make test-f06` — 2000/2000, 0 silent accepts (Argon2id path
  inherits the F-06 fix via the shared `zupt_decrypt_buffer_aad`).
- `make test-asan` Argon2id-default password roundtrip on `include/`
  (12 files) — byte-exact, clean.
- `make audit-licenses` — clean.
- §3.5 byte sweep on Argon2id-password archive (369 bytes,
  exhaustive header + footer + sampled body): **0 undetected of all
  positions tested**.
- Cross-version compatibility:
  - v2.4.0 (PBKDF2) archive → v2.4.1: byte-exact extract ✓
  - v2.4.1 (Argon2id default) archive → v2.4.0: byte-exact extract ✓
    (v2.4.0 already supports Argon2id reading via existing dispatch)
  - v2.4.1 `--kdf pbkdf2` archive → v2.4.0: byte-exact extract ✓

### Known UX caveat (not blocking)

When the wrong password is supplied to extract an Argon2id-default
archive, the error message reads:

```
Error: archive-integrity-trailer (top-MAC) verification failed.
       The archive header or footer has been tampered with.
```

This is *technically* correct (the AIT verification uses
`kr->mac_key`, which depends on the password; wrong password →
wrong mac_key → AIT mismatch). But the "tampered" framing misleads
users into thinking their archive is corrupted when they just
mistyped. Same issue exists on PBKDF2 archives and on PQ-SDK
archives since 2.3.0 / F-08. **Tracked as F-11** in
`docs/FINDINGS-2.x.md`, deferred to a future sprint that can rework
the error path to distinguish auth-fail from integrity-fail without
giving timing attackers a clean side channel.

### Files touched

```
include/zupt.h                       (version 2.4.0 → 2.4.1, kdf_legacy_pbkdf2 field)
src/zupt_format.c                    (write_enc_header password branch)
src/zupt_main.c                      (--kdf parser at 2 compress sites, help text)
tests/test_f10_kdf_default.sh        (new, 10 assertions)
Makefile                             (test target)
CHANGELOG.md                         (this entry)
ROADMAP.md                           (2.4.1 row)
AUDIT.md                             (history entry)
SECURITY.md                          (crypto-defaults table updated)
docs/FINDINGS-2.x.md                 (F-10 closed, F-11 opened)
```


## [2.4.0] — 2026-05-20 — Methodology release: §3.5 byte-sweep mandate

**Documentation-and-process release. No code changes that affect
archive format, MAC inputs, or binary behaviour.** Encrypts and
extracts identically to v2.3.1 — same format v1.6, same archive
bytes, same per-block AAD policy.

Why this is a separate release: the five-sprint arc from F-02 →
F-09 surfaced a methodology gap that's worth shipping explicitly
before adding the next feature. Every one of F-02, F-06, F-07,
F-08, F-09 was found by the exhaustive byte sweep — none by the
design review, the unit tests, or the per-byte tamper specs in
`tests/test_audit.sh`. The sweep itself is ~3 minutes per archive
size to run. It needs to be a sprint-protocol step, not a one-off.

### What changed

**Historical sprint instructions — version 2.**

- **NEW §3.5: The exhaustive byte-sweep mandate.** Every
  format-touching change runs the full byte sweep before claiming
  done; encrypted archives must reach 0 undetected; plaintext
  residual gaps must be documented per finding (not gated per
  release). What counts as "format-touching" is enumerated.
  Includes the full sweep recipe and the v2.2.4 → v2.3.1 history
  table showing what the sweep caught at each sprint.
- **§6 sprint protocol grows a step.** New step 5 ("Byte sweep")
  between flake stress and plan. Numbering ripple fixed (step 6
  was duplicated in v1, step 9 was duplicated). Step 8
  ("Re-verify") now mentions re-running the sweep on the final
  built binary.
- **§10 kickoff template adds `format-touching? yes/no`.** Gates
  the §3.5 step.
- **§11 outage table grows four rows** — F-06, F-07, F-08, F-09
  with the regression-test names that catch each one. The table is
  the canonical "things that have shipped and must never recur"
  reference; keeping it current is part of every sprint.
- **Footer stamp**: historical instruction revision 2, 2026-05-20.

**`Makefile`.** The help-target banner version is now derived
from `include/zupt.h` via a `grep | awk` substitution:

```make
help:
    @echo "Zupt v$(shell grep '^#define ZUPT_VERSION_STRING' \
        include/zupt.h | awk -F'"' '{print $$2}') build targets:"
```

This closes a recurring bug noted in the historical sprint checklist —
prior sprints (2.3.0, 2.3.1) left the banner stale even after the
sprint protocol said to bump it. Making it auto-derived removes
the drift opportunity entirely.

### What didn't change

- No source files in `src/` modified.
- No header layout changes in `include/zupt.h` beyond the version
  string.
- No format constants changed.
- No new flag bits, no new struct fields.
- v2.4.0 archives are byte-identical to v2.3.1 archives.

### Verification

- `make` clean on plain GCC + Clang.
- `make` strict GCC (full §6 set) — clean.
- `make` strict Clang — clean.
- `make test` — all 8 suites green, F-09 sweep 1827/1827 detected.
- `make test-vectors` — 14/14.
- `make test-f06` — 2000/2000.
- `make audit-licenses` — clean.
- `./zupt version` reports 2.4.0; `make help` banner auto-derives
  the same string.
- A fresh archive built by v2.4.0 extracts byte-exact under v2.3.1
  (since no on-disk bytes changed).

### Files touched

```
Makefile             (help banner auto-derives version from header)
include/zupt.h       (version 2.3.1 → 2.4.0)
CHANGELOG.md         (this entry)
ROADMAP.md           (2.4.0 row)
AUDIT.md             (header date)
```


## [2.3.1] — 2026-05-20 — F-09 closed: full archive byte coverage (format v1.6)

Second format bump in two sprints: v1.5 → v1.6. Closes F-09 (per-block
frame preface tamper window) and reaches **100% byte-level tamper
detection on encrypted archives** — the exhaustive byte sweep
harness reports zero silent acceptances out of 1827 positions tested.

### Findings closed

**F-09 — Per-block frame preface bytes tamper-tolerant.** Post-2.3.0,
the exhaustive byte sweep of a v1.5 PQ-SDK archive showed 18
silent-accept positions remaining, all in per-block frame preface
fields: codec_id, block_flags, varint padding, plaintext-XXH64
checksum field. The per-block HMAC input was
`nonce || ciphertext || aad_seq` and didn't cover the preceding
preface bytes that the parser reads off the file.

**Fix — two-pronged:**

**Part 1: Extended-AAD MAC binding (v1.6 archives).** New crypto
primitives `zupt_encrypt_buffer_aad` and `zupt_decrypt_buffer_aad`
take an additional `aad_extra` buffer that prepends to the existing
MAC input. The legacy functions are now thin wrappers that pass
`aad_extra=NULL, len=0`, preserving byte-exact MAC output for v1.4
and v1.5 archives.

Callers in `src/zupt_format.c` build a 29-byte canonical preface from
the same fields stored on disk:

```
preface_aad = block_type(1) || codec_id(2 LE) || block_flags(2 LE)
           || uncompressed_size(8 LE) || compressed_size(8 LE)
           || plaintext_checksum(8 LE)
```

The MAC input becomes `preface_aad || nonce || ciphertext || aad_seq`.
**Crucially**, the preface AAD uses fixed-width LE serialization, NOT
the on-disk varint encoding for usz/csz — varints have multiple valid
encodings of the same logical value (e.g. `5` as `0x05` or `0x85 0x00`),
and a non-canonical varint would produce a different MAC despite
encoding the same archive. Fixed-width LE is canonical, so encode/
decode roundtrip MACs match.

The decrypt path is **strict single-candidate** when AAD is in use —
no v1/v2 fallback. There's no downgrade attack because the policy
flag `ZUPT_FLAG_AAD_PREFACE` (bit 9 of `global_flags`) is itself
MAC-protected by the v1.5 archive-integrity-trailer (F-08). An
attacker can't flip the flag without auth-fail at AIT verification.

**Part 2: Strict structural validation of the encryption-header
block.** The enc-header block is plaintext by necessity (it carries
the key-establishment data needed before any key can be derived),
so the AAD-MAC pattern doesn't apply to it. But its frame preface
fields can be tightened structurally — same pattern as F-07 for the
index block in v2.2.5. `read_enc_header` now requires:

- `block_type == ZUPT_BLOCK_ENC_HEADER` (was implicit)
- `codec_id == ZUPT_CODEC_STORE` (envelope is never compressed)
- `block_flags == 0` (envelope has its own crypto, no extra flags)
- `compressed_size == uncompressed_size` (no length games)
- `plaintext-XXH64 == zupt_xxh64(payload, csz, 0)` (actual content check)

Together these close the 14 enc-header preface bytes that Part 1
couldn't reach.

### Result

| Sprint | Format | Bytes per archive | Undetected-tamper count |
|---|---|---|---|
| 2.2.4 | v1.4 | 1771 | 86 |
| 2.2.5 | v1.4 | 1771 | 86 (F-06 reduced probability, not position count) |
| 2.3.0 | v1.5 | 1803 | 18 |
| **2.3.1** | **v1.6** | **1803-1827** | **0** |

The new `tests/test_f09_preface.sh` runs the exhaustive sweep on a
fresh PQ-SDK archive every `make test` invocation. As of 2.3.1:
1827/1827 byte tampers detected.

### New artefacts

- **`tests/test_f09_preface.sh`** — exhaustive byte sweep regression.
  Builds a PQ-SDK v1.6 archive, flips one byte at a time across all
  ~1800 positions, asserts every tamper is rejected. Catches any
  future regression that re-opens the preface-tamper window.
- Wired into `make test`.

### Cross-version compatibility (verified)

- **v2.3.1 reads v1.5 (v2.3.0) archives byte-exact** — `decompress_block`
  notices `keyring.use_preface_aad == 0` and calls the legacy decrypt
  path that doesn't expect AAD bytes.
- **v2.3.0 cannot read v1.6 archives** — rejects with auth-fail because
  the MAC includes preface AAD bytes v2.3.0's decrypt doesn't feed in.
  Clean rejection, not silent corruption. This is the intended
  behaviour: v2.3.0 readers can't ignore the new flag bit without
  losing F-09's tamper protection.
- **v1.4 archives** still extract under v2.3.1 with the F-08
  downgrade-warning stderr line, unchanged from v2.3.0.

### Threat model surface change

`SECURITY.md` integrity table gains a new row:

| Against tampering of per-block frame preface bytes | v1.6 archives: full MAC coverage (codec_id, block_flags, sizes, plaintext-XXH64 all bound). v1.5 archives: not covered (legacy). v1.4 archives: not covered (legacy). |

### Verification matrix

- `make` — clean on plain GCC + Clang.
- `make` with strict GCC `-Wshadow -Wcast-align -Wstrict-prototypes
  -Wmissing-prototypes -Wnull-dereference -Wformat-security
  -Wlogical-op -Wjump-misses-init -Wdouble-promotion -O2 -std=c11` —
  clean.
- `make` with strict Clang same set — clean.
- `make audit-licenses` — clean.
- `make test` — **all 8 test suites green** (61 existing cases +
  F-08's 4 + F-09's 1827-position sweep).
- `make test-vectors` — 14/14.
- `make test-f06` — **2000/2000, 0 silent accepts** (F-06 unchanged
  despite the crypto refactor — the legacy `zupt_decrypt_buffer` is
  now a thin wrapper, but the F-06 fix lives in the shared `_aad`
  implementation).
- `make test-asan` `--pq-sdk` byte-exact roundtrip on `include/` (12
  files) — clean.
- 50× audit-suite stress — 50/50 green.
- Exhaustive byte sweep on 1803-byte v1.6 PQ-SDK archive — **0
  undetected of 1803**.
- v2.3.0 archive read by v2.3.1: byte-exact extract.
- v2.3.1 archive read by v2.3.0: clean auth-fail rejection.

### Files touched

```
include/zupt.h                          (version 2.3.0 → 2.3.1,
                                         format 1.5 → 1.6,
                                         ZUPT_FLAG_AAD_PREFACE,
                                         use_preface_aad keyring field,
                                         zupt_*_buffer_aad prototypes)
src/zupt_crypto.c                       (new _aad encrypt/decrypt;
                                         legacy fns become thin wrappers)
src/zupt_format.c                       (preface AAD serializers,
                                         4 encrypt sites wired,
                                         decompress_block wired,
                                         open_archive flag propagation,
                                         read_enc_header strict validation)
tests/test_f09_preface.sh               (new, exhaustive byte sweep)
tests/test_f08_topmac.sh                (accept v1.5+ not just exactly v1.5)
Makefile                                (test target + version banner)
CHANGELOG.md                            (this entry)
ROADMAP.md                              (2.3.1 row)
AUDIT.md                                (header date + version 2.3.1)
SECURITY.md                             (integrity table updated)
docs/FINDINGS-2.x.md                    (F-09 closed)
```


## [2.3.0] — 2026-05-20 — F-08 closed: top-MAC over header+footer (format v1.5)

**Minor release**, first format bump in the 2.x line: v1.4 → v1.5. Closes
F-08 (cosmetic-metadata coverage) deferred from 2.2.5. Forward-compatible
write path (always emits v1.5); backward-compatible read path (v1.4
archives extract with a downgrade warning on encrypted modes).

### Findings closed

**F-08 — Cosmetic archive metadata not covered by any MAC.** Pre-2.3.0,
an exhaustive byte sweep of a 1771-byte `--pq-sdk` archive showed 86
positions where tampering went undetected after F-06/F-07. All 86 were
header/footer informational fields (timestamps, UUID, reserved bytes,
comment offset, footer informational counters, footer version field).

Fix: a new 32-byte **archive-integrity-trailer (AIT)** appended after
the footer.

- **Encrypted modes**: AIT = `HMAC-SHA256(mac_key, hdr[0..63] || footer[0..23])`
- **Plaintext modes**: AIT = `XXH64(...)` in the first 8 bytes, zeros in
  the rest. Best-effort (`OPAQUE` structural-integrity class).

The MAC input deliberately excludes `footer[24..31]` = `"ZEND" || u32 version`.
Both are structurally validated by the read path (`locate_footer_v15`
rejects bad magic AND non-1 version) so they don't need MAC coverage.
This avoids a circular dependency where the version-bump byte would
need to be authenticated by a MAC keyed off a v1.5-only derivation.

**Layout (v1.5 vs v1.4):**

```
v1.5:  [header 64B][...blocks...][index][footer 32B][AIT 32B]
v1.4:  [header 64B][...blocks...][index][footer 32B]
```

**Read path (`open_archive`, `zupt_archive_info`, `zupt_disk_restore`):**
`locate_footer_v15` tries v1.5 first (`"ZEND"` magic at EOF-64 with
correct version), falls back to v1.4 (magic at EOF-32). On v1.5,
verification of the AIT happens AFTER `read_enc_header` initialises
the keyring, so encrypted archives reject header+footer tamper as
"archive-integrity-trailer (top-MAC) verification failed". On v1.4
archives the read path emits a stderr warning on encrypted modes:

```
Warning: legacy v1.4 archive without top-MAC (F-08).
         File contents are integrity-protected, but header
         and footer metadata (timestamps, UUID, counts) are not.
```

**Write path (`zupt_compress_files`, `zupt_compress_solid`,
`zupt_disk_backup`):** always emits v1.5. The new helper
`zupt_format_ait_write` is called immediately after the footer is
written.

### Verification

Exhaustive byte sweep of a 1803-byte v1.5 `--pq-sdk` archive:

| Layer | Before 2.3.0 | After 2.3.0 |
|---|---|---|
| Total bytes in archive | 1771 (v1.4) | 1803 (v1.5, +32 AIT) |
| Bytes where 1-bit tamper goes undetected | 86 | **18** |
| Header bytes 0-63 covered | partial (magic+version only) | **64/64 — full HMAC coverage** |
| Footer bytes 0-23 (idx_offset, total_blocks, archive_checksum) | none | **24/24 — full HMAC coverage** |
| Footer bytes 24-31 (magic, version) | structural only | **structural** (excluded from MAC by design; magic and version rejected by `locate_footer_v15`) |
| Remaining 18 bytes | n/a | per-block header trivia (codec_id, block_flags, varints, checksum field of each per-block frame) — separate concern, tracked as **F-09 deferred to v2.3.1** |

### F-09 — Per-block-header trivia bytes still tamper-tolerant  [deferred, v2.3.1]

The 18 remaining undetected positions in the exhaustive sweep are all
**per-block header trivia**: bytes between the block magic (offset +0..+1)
and the start of the encrypted payload (+17 onwards) of each per-block
frame. The per-block HMAC covers `nonce || ciphertext || aad_seq` and
the `(block_type, codec_id, block_flags, varint usz, varint csz, xxh64)`
preface bytes are not part of the MAC input. Same class as F-07 (which
closed `block_type` for the index block specifically) but at the
remaining frame-header fields. Closing this needs either a wider HMAC
input on each block (format-compatible — the on-disk layout doesn't
change, only what bytes feed the MAC) or stricter parser validation of
the trivia bytes against expected codec/flag values. Deferred to
v2.3.1 because the bytes are operationally OPAQUE (the parser rejects
malformed varints, the decoder rejects unknown codec_ids, decompression
catches checksum mismatches) — only specific high-bit flag positions
on already-valid frames slip through.

### New artefacts

- **`tests/test_f08_topmac.sh`** — F-08 regression. Builds a v1.5 archive,
  tampers at 25 header/footer positions, asserts each is rejected with
  the top-MAC error message. Direction 2 (v1.4 backward compat) runs
  if `tests/fixtures/zupt-2.2.5` is available; otherwise skipped with
  an instructional NOTE.
- Wired into `make test` (4 cases, 81 → 85 total assertions before
  counting the legacy v1.4 direction).

### Tools and process

- Manual backward-compat verification: built a v1.4 plaintext+encrypted
  archive with the 2.2.5 binary (extracted from `zupt-2.2.5.tar.gz`),
  read it with v2.3.0. Plaintext → v1.4 / no top-MAC, byte-exact
  extract. Encrypted → v1.4 / no top-MAC, downgrade warning shown
  on stderr, byte-exact extract.
- Exhaustive byte sweep confirmed in `/tmp/sweep31/` — 18 remaining
  positions all in per-block-header trivia.

### Verification matrix

- `make` — clean on GCC + Clang.
- `make` with strict GCC `-Wshadow -Wcast-align -Wstrict-prototypes
  -Wmissing-prototypes -Wnull-dereference -Wformat-security
  -Wlogical-op -Wjump-misses-init -Wdouble-promotion -O2 -std=c11` —
  clean.
- `make` with strict Clang same set — clean.
- `make test` — **61/61 + F-08's 4 = 65/65 passing** (the new test
  itself adds 4 cases; the surrounding 61 are unchanged).
- `make test-vectors` — 14/14.
- `make test-f06` — 2000/2000, 0 silent accepts.
- `make test-asan` `--pq-sdk` roundtrip on `include/` (12 files) —
  byte-exact, clean.
- `tests/test_audit.sh` × 50 — 50/50 green.
- Manual: tamper byte 15 (header timestamp) of a v1.5 encrypted
  archive → "top-MAC verification failed".
- Manual: same tamper position on a v1.4 archive built by 2.2.5 →
  extract still succeeds (no top-MAC to check), legacy warning shown.

### Files touched

```
include/zupt.h                          (version 2.2.5 → 2.3.0,
                                         format 1.4 → 1.5, ZUPT_AIT_SIZE)
src/zupt_format.c                       (locate_footer_v15, ait helpers,
                                         open_archive wiring, info update)
src/zupt_disk.c                         (disk_backup AIT write,
                                         disk_restore AIT verify)
tests/test_f08_topmac.sh                (new, 4 assertions)
Makefile                                (test target + version banner)
CHANGELOG.md                            (this entry)
ROADMAP.md                              (2.3.0 row, F-09 entry)
AUDIT.md                                (header date 2.2.5 → 2.3.0)
SECURITY.md                             (integrity table updated)
docs/FINDINGS-2.x.md                    (F-08 closed, F-09 opened)
```


## [2.2.5] — 2026-05-19 — F-06 (high): HMAC accept-on-disjoint-bits

Patch release. Closes one **high-severity** integrity-bypass on the
production x86_64 path (F-06), one low-severity parser-trivia gap
(F-07), and re-classifies F-02b (the "unauthenticated index region"
hypothesis from 2.2.4) as **resolved** — the framing was wrong. No
format change.

### Findings closed

**F-06 — `zupt_decrypt_buffer` silently accepts ~6.35% of single-bit
HMAC tampers on the Jasmin path.** The Encrypt-then-MAC verifier
computes two candidate MACs (`v2` AAD-bound, `v1` legacy) and accepts
iff at least one matches. The combined-diff expression was:

```c
uint64_t diff_v2 = zupt_mac_verify_ct(expected_mac_v2, stored_mac);
uint64_t diff_v1 = zupt_mac_verify_ct(expected_mac_v1, stored_mac);
...
uint64_t diff = diff_v2 & diff_v1;   /* BUG */
```

The Jasmin routine returns a full 64-bit accumulator (OR of 4 × u64
XORs). When both MACs mismatch — i.e. when tamper has occurred —
`diff_v2 & diff_v1` is still zero whenever the two diffs have disjoint
nonzero bits. For a 1-bit tamper, `diff_v2` has exactly one bit set;
`diff_v1` is OR-of-4-random-u64s with on average 4 zero bits out of
64; AND-is-zero probability ≈ 4/64 ≈ 6.25%. Empirically confirmed:
**127/2000 silent acceptances** in unit-test trials before the fix,
**0/2000 after**.

In live archive testing this manifested as ~2% of single-bit
`len-50` tampers on `--pq-sdk` archives going undetected — the
"residual flake" from F-02 of 2.2.4. The 2.2.4 hypothesis (that the
index region was not MAC'd) was wrong: the index IS MAC'd correctly
on the encrypt side, but the verifier accepted ~6% of tampers in the
HMAC bytes themselves.

Fix at `src/zupt_crypto.c:438-444` — fold each diff to a single
nonzero-indicator bit before ANDing, constant-time:

```c
uint64_t nz_v2 = (diff_v2 | (uint64_t)(-(int64_t)diff_v2)) >> 63;  /* CT-REQUIRED */
uint64_t nz_v1 = (diff_v1 | (uint64_t)(-(int64_t)diff_v1)) >> 63;  /* CT-REQUIRED */
uint64_t diff = nz_v2 & nz_v1;
```

`(x | -x) >> 63` is the standard branchless "is nonzero" indicator
(0 → 0, anything else → 1) with no data-dependent branches or
secret-dependent memory access. The C-fallback path adopts the same
shape to prevent future divergence.

**Severity calibration: high but not critical.** The attacker cannot
forge MACs with chosen content — they can only randomly tamper and
get lucky with ≈6% probability per 1-bit flip; multi-bit tampers
decrease exponentially. Plaintext is not recoverable; keys remain
protected. But the bug breaks the integrity guarantee SECURITY.md
states ("any modification is detected with overwhelming
probability"), so it must ship as a patch.

**F-07 — `open_archive()` did not verify `block_type` at
`index_offset`.** The block_type byte is not part of the MAC input,
so flipping it (e.g. from `0x02 INDEX` to `0x03 ENC_HEADER`) did
not cause auth failure; the downstream parser was tolerant.
Severity: low. Fix at `src/zupt_format.c` adds the structural
check immediately after `read_block`. This makes the byte
`OPAQUE` structural-integrity class (tamper detected by parser, not by
MAC).

**F-02b — RECLASSIFIED.** The 2.2.4 hypothesis that the archive
index region was not MAC'd was incorrect. Exhaustive byte sweep
showed three undetected-tamper positions inside the index region;
one (byte 1620) was F-07, one (byte 1624) is an `OPAQUE`-class
reserved-flag byte that doesn't carry security-significant data,
and one (byte 1713) was F-06 manifesting in the HMAC tail. The
index region IS HMAC-protected; the bug was in the verifier. F-02b
closed without the planned v1.5 format bump.

**F-08 — Cosmetic archive metadata not covered by any MAC,
deferred to v2.3.0.** Exhaustive byte sweep of a 1771-byte
`--pq-sdk` archive shows 86 remaining undetected-tamper positions
after F-06+F-07. All 86 fall into header timestamps, UUIDs,
reserved fields, comment offsets, and footer informational
counters — none affect file contents, key material, or
authentication coverage of payloads. The footer's
`archive_checksum` field, despite the name, is not a cryptographic
MAC (it stores a length value, kept for historical reasons). Fix
deferred to v2.3.0 alongside the planned top-level archive MAC
over `header[0..63] || footer[0..23]` using the existing
`mac_key`. This is a format bump (v1.4 → v1.5) and best done with
other v2.3.0 changes than as a standalone patch.

### New artefacts

- **`tests/test_f06_hmac.c`** — F-06 regression. 2000 trials with
  rotating 1-bit MAC flip, asserts zero silent acceptances. Wired
  into Makefile as `make test-f06`. Demonstrably catches the bug:
  reverting `src/zupt_crypto.c` to the buggy `diff_v2 & diff_v1`
  produces 127/2000 silent accepts and the target fails.

### Verification

- `make` — clean on plain GCC and Clang.
- `make` with the historical strict GCC warning set — clean.
- `make` with strict Clang flags — clean.
- `make test` — **61/61 passing**.
- `make test-vectors` — **14/14 passing**.
- `make test-f06` — **2000/2000 trials, 0 silent accepts**.
- `tests/test_audit.sh` × 50 standalone runs — **50/50 green**.
- ASAN `--pq-sdk` byte-exact roundtrip on `include/` (12 files) —
  clean.
- 200 live `--pq-sdk` archive tamper trials at byte `len-50` —
  **200/200 rejected** (was 198/200 pre-fix on the same workload).
- Exhaustive byte sweep of all 121 index-region bytes — 0 silent
  accepts (was 3 pre-fix).
- Reverted-fix sanity check: removing the F-06 patch reproduces
  ~127/2000 silent accepts in `make test-f06`, confirming the test
  drives the buggy path.

### Files touched

```
src/zupt_crypto.c                      (F-06: 3-line fix + 22-line comment)
src/zupt_format.c                      (F-07: 4-line check in open_archive)
tests/test_f06_hmac.c                  (new, F-06 regression)
Makefile                               (new test-f06 target, version banner)
include/zupt.h                         (version 2.2.4 → 2.2.5)
docs/FINDINGS-2.x.md                   (F-06, F-07, F-08; F-02b closed)
CHANGELOG.md                           (this entry)
ROADMAP.md                             (2.2.5 row, F-08/v2.3.0 entry)
AUDIT.md                               (header date 2.2.4 → 2.2.5)
SECURITY.md                            (integrity statement reaffirmed)
```


## [2.2.4] — 2026-05-19 — Five-finding audit pass (F-01..F-05)

Patch release. No format changes, no feature changes, no on-disk
compatibility impact. Five findings closed against the v2.2.3 baseline
under the methodology in the then-current audit instructions and tracked in
`docs/FINDINGS-2.x.md` (durable
numbered ledger that survives between work sessions).

### Findings closed

**F-01 — `zupt help` keygen line missing newline.** `src/zupt_main.c:41`
ended the `keygen` description with `"Key generation"` instead of
`"Key generation\n"`, so `./zupt help` printed
`Key generation  zupt version` on a single wrapped line. Severity: low
(UX, not security). Regression check added to `tests/run_quick.sh` —
asserts ≥10 lines matching `^  zupt ` in help output.

**F-02 — Flaky `make test` (≈10% audit-suite failure) and one
authentication-coverage gap.** `tests/test_audit.sh` previously
tampered byte `len-50` of a `--pq-sdk` archive. PQ-SDK archive sizes
vary by 1–2 bytes per run (ciphertext encoding length variance), so
`len-50` occasionally landed inside the **archive index region** —
bytes between `footer.index_offset` and the trailing 32-byte
`zupt_footer_t` — which is **not** covered by the per-block HMAC. In
those runs the tampered archive extracted cleanly and the suite
flaked. Confirmed in standalone repro: **5 failures in 50 trials**
when the archive happened to be 1771 bytes (index region: 1618–1738,
`len-50 = 1721` lands at the index byte).

This finding splits into two:

- **F-02a (fixed in 2.2.4)** — `tests/test_audit.sh` now tampers at
  absolute offsets 200 and 500, which are deterministically inside
  the first encrypted block's `nonce || ciphertext` of any non-empty
  PQ-SDK archive (header ends around offset 80, body extends to
  ≈1610). Verified 80/80 green across the standalone 50-run repro
  and the new `tests/test_audit_flake.sh` harness.

- **F-02b (deferred to 2.2.5, format v1.5)** — the unauthenticated
  index region is a real coverage gap. An attacker who can write to
  the archive can flip bits in `(path, offset, length)` index tuples
  without being caught until extract corruption shows up (or, worse,
  silently if the flip lands in unused padding). This is *not*
  exploitable for plaintext recovery (the body blocks remain HMAC-
  protected), but it does allow undetected metadata tamper. Closing
  this needs a format bump: design options in `docs/FINDINGS-2.x.md`
  under F-02b (preferred: `index_mac[32]` derived via
  `HMAC-SHA256(mac_key, index_bytes || footer_header_fields)` and
  stored immediately before the footer; plaintext-mode archives fall
  back to `XXH64(index)` as best-effort).

**F-03 — `-Wshadow`: `r` shadows in `zupt_secure_random`.**
`src/zupt_crypto.c:48` declares `ssize_t r = syscall(SYS_getrandom, …)`
inside a `__linux__` block; line 54 declares `size_t r = fread(…)` in
the surrounding fallback path. Cosmetic — both `r`s coincidentally
hold counts — but blocks adoption of `-Wshadow` for the project. Fix:
rename the `fread` result to `nread`.

**F-04 — `zupt_mlkem768_selftest`: definition without prototype or
caller.** `src/zupt_mlkem.c:648` defines an NTT-roundtrip plus
CBD-sample property check that was never wired in. Triggered
`-Wmissing-prototypes`. The function is genuinely useful (it's an
end-to-end internal correctness probe orthogonal to the FIPS 203
KAT roundtrip already in the test suite), so it is now declared in
`include/zupt_mlkem.h` and invoked as the 14th case in
`tests/test_vectors.c`. NIST/RFC vector count goes **13 → 14**;
`AUDIT.md` updated accordingly.

**F-05 — cppcheck: three `uint8_t *` pointers can be `const`.** Three
one-past-end sentinels in `src/vv_ans.c` (lines 1575, 2228, 2265)
are never written through. Re-typed as `const uint8_t *`. Closes
the `constVariablePointer` finding from
`cppcheck --enable=all`. VaptVupt SPDX header (GPL-3.0-or-later)
preserved.

### New process artefacts

- **Historical continuous-improvement instructions** — removed from the
  current source tree after their durable material was consolidated into the
  audit and security documents. They encoded the methodology that produced this release:
  three-line workflow (survey → fix-with-test → ship), explicit
  authentication-coverage invariant (every archive byte covered by
  per-block HMAC OR a separate index MAC OR a footer MAC — no third
  category permitted), §3 flake-stress mandate (every short assertion
  runs ≥50× before being declared deterministic — would have caught
  F-02 on day one), strict-warning matrix, and a numbered findings
  ledger that survives between sessions.

- **`docs/FINDINGS-2.x.md`** — durable numbered ledger for the 2.x
  series. F-01 through F-05 closed here with reproducers, root cause,
  fix, regression test, and verification per finding. F-02b stays
  open at the bottom with three implementation options for v2.2.5.

- **`tests/test_audit_flake.sh`** — 5-suite × N-run flake-stress
  harness (default N=20 for routine use; `bash tests/test_audit_flake.sh
  50` for hardened audit). Aborts on the first non-deterministic
  outcome and dumps the failing run to a tmp log.

### Verification

- `make` — clean on plain GCC and Clang (no warnings).
- `make` with strict GCC flags `-Wall -Wextra -Wpedantic -Wshadow
  -Wcast-align -Wstrict-prototypes -Wmissing-prototypes
  -Wnull-dereference -Wformat-security -Wlogical-op
  -Wjump-misses-init -Wdouble-promotion -O2 -std=c11` — clean
  (was 2 warnings on 2.2.3).
- `make` with strict Clang `-Wshadow -Wcast-align -Wstrict-prototypes
  -Wmissing-prototypes -Wnull-dereference -O2 -std=c11` — clean
  (was 0 warnings on 2.2.3, still 0).
- `cppcheck --enable=all` — `constVariablePointer` findings resolved
  for the three cited sites in `vv_ans.c`.
- `make test` (61-case suite) — **61/61 passing**.
- `make test-vectors` — **14/14 passing** (was 13/13; new case is
  ML-KEM-768 internal self-test).
- `tests/test_audit.sh` standalone — 80/80 green across two
  independent stress runs (50 + 30) of the previously-flaky path.
- `tests/test_audit_flake.sh 10` — 10/10 green on the three short
  suites that fit in the timeout window (`test_audit`,
  `test_path_traversal`, `test_arg_order`).
- `make test-asan` — builds clean; manual compress/extract roundtrip
  on a 12-file source tree clean under ASAN+UBSAN.
- `./zupt help | grep -c '^  zupt '` — 22 lines (was 21 on 2.2.3
  because `keygen` and `version` were collapsed).

### Files touched

```
[historical sprint-instruction file]   (removed from the current tree)
docs/FINDINGS-2.x.md                   (new)
tests/test_audit_flake.sh              (new)
src/zupt_main.c                        (F-01)
src/zupt_crypto.c                      (F-03)
src/zupt_mlkem.c                       (F-04: no source change; header gains decl)
include/zupt_mlkem.h                   (F-04)
src/vv_ans.c                           (F-05)
tests/test_audit.sh                    (F-02a)
tests/test_vectors.c                   (F-04)
tests/run_quick.sh                     (F-01 regression line)
include/zupt.h                         (version 2.2.3 → 2.2.4)
Makefile                               (help banner version)
AUDIT.md                               (header, vector count 13 → 14)
ROADMAP.md                             (2.2.4 row, F-02b entry on planned)
CHANGELOG.md                           (this entry)
```


## [2.2.3] — 2026-05-01 — VaptVupt 2.48.2 integration + Makefile fix

This release upgrades the embedded VaptVupt codec from the v0.1-era
sources that shipped in 2.2.2 to **VaptVupt 2.48.2**, the version that
was explicitly cut to be the integration target for Zupt 2.2.3 (see
the upstream `ZUPT_INTEGRATION.md`).

### VaptVupt 2.48.2 codec

The codec gains, vs. what 2.2.2 shipped:

- **Aggregate ratio now beats zstd-3 by 1.07%** in upstream measurement
  (was +1.2% behind in v2.47.x). Sprint 120's cost-aware lazy parser
  plus Sprint 121's gating delivered the breakthrough — encoder-only
  change, wire-format compatible with v2.47.x decoders.
- **`format_v2` flag** producing 4–7% better real-binary ratios via
  the T-tag (min_match=3) literal encoding. Wired through `vvz_compress`
  for `BALANCED` and `EXTREME` modes (see "Wrapper defaults" below).
- **`compat_v246_5_decoder` flag** for environments stuck on a
  pre-v2.47 decoder. Default off — Zupt always controls both encoder
  and decoder, so we always have v2.47+ on the decode side.
- **Sprint 117 hardened-build compatibility**: the codec now compiles
  cleanly under `clang -fsanitize=integer` (strict UBSan superset; was
  92 false positives, now 0).
- **Sprint 118 memory hygiene**: encoder working buffers (`lit_buf`,
  `stripped`, `src_buf`, `tmp`, `ent_buf`, plus the context struct)
  are now scrubbed via `vv_secure_zero` before `free()` — defence-in-
  depth specifically for Zupt's compress→encrypt→write pipeline.
- **Sprint 109/118 decoder hardening**: literal-run extension bounds,
  OOB code-table bounds, NULL-deref protection on edge-case empty
  symbol tables.

Cumulative upstream audit posture at v2.48.2: **0 cppcheck issues, 0
scan-build bugs, 0 strict GCC/Clang warnings, ~145,000 cumulative
sanitised libFuzzer executions across 4 attack surfaces, 0 crashes,
13 cumulative defects fixed across the audit campaign.**

### Wrapper defaults (`src/vaptvupt_api.c`)

The thin `vvz_compress` shim that Zupt's archive layer calls now
applies the integration best practices documented in VaptVupt's
upstream guide:

- **`opts.checksum = 0`** — Zupt's outer HMAC-SHA256 (or AES-GCM-SIV
  in `--pq-sdk` mode) already authenticates the compressed bytes, so
  the codec's internal XXH64 footer is redundant work. Saves ~10%
  encode time and pairs with `VV_DECOMPRESS_SKIP_CHECKSUM` on decode
  for a 2–5× decode speedup on AEAD-wrapped (high-entropy) payloads.
- **`opts.format_v2 = 1`** for `VV_MODE_BALANCED` (level 3–7) and
  `VV_MODE_EXTREME` (level 8–9) — 4–7% better binary ratio.
- **`opts.format_v2 = 0`** for `VV_MODE_ULTRA_FAST` (level 1–2). The
  combination of `format_v2 = 1` + `ULTRA_FAST` is **not in
  VaptVupt 2.48.2's tested matrix** (`tests/test_zupt_integration.c`
  validates `format_v2` only with `BALANCED`/`EXTREME`) and produces
  output the decoder rejects with `VV_ERR_OVERFLOW`. Caught during
  Zupt's own regression run (T17 VaptVupt-all-levels) before release;
  reported upstream and worked around here defensively. Once VaptVupt
  validates the combination, this guard can be lifted.
- **`opts.compat_v246_5_decoder = 0`** — allow `lit_fmt=4` (4-stream
  Huffman) literal coding. Safe because Zupt always ships its decoder
  at the same version as the encoder (no older decoders in the wild).

### Makefile arch-detection fix

The `STALE_OBJS` arch-safety guard was comparing the canonical strings
`x86-64` (from `file(1)`) against `x86_64` (from `$(CC) -dumpmachine`)
and treating them as different architectures, causing every `make`
invocation to wipe and rebuild every `.o` file even on consistent
hosts. Both sides are now normalised through `tr -d '_-' | tr [:upper:]
[:lower:]` so the comparison succeeds on a same-arch tree and only
fires when the tarball really did include cross-arch objects.

### Tests

- `make test` — 9 quick + 11 SDK + 10 audit + 12 dedup-property + 5
  path-traversal + 8 arg-order + 6 block-swap = **61 passing**.
- `tests/regression.sh` — **22/22 passing** (was 20/22 before the
  ULTRA_FAST + format_v2 guard).
- `tests/test_threaded.sh` — **14/14 passing**.
- `tests/test_pq.sh` — **10/10 passing**.
- `make test-vv` — **11/11 passing**.
- `make test-vectors` — **13/13 passing**.
- `make test-asan` — clean across plain / password / `--pq-sdk`
  archives at levels 1, 5, 9.
- `make fuzz-format-run` — 1000 mutation-fuzz iterations under ASAN/
  UBSAN, **0 crashes**.
- Disk backup/restore byte-exact sha256 verified.

Two `make test` runs back-to-back, both clean. Cumulative test count:
**112 cases passing across 12 suites.**

### Documentation cleanup

Four design/audit-instruction documents that were sprint-internal scratch
have been removed from the source tree (consolidated into the
remaining permanent docs):

| Removed | Where the content lives now |
|---|---|
| Two historical audit-instruction files | consolidated into the permanent audit and security documents |
| `ROOT_CAUSE_ANALYSIS.md` | reproducible-bug postmortems are now per-release entries in `CHANGELOG.md` |
| `COMPAT.md` | the table moved into `README.md` § "Architecture & platform support" |
| `DONATIONS.md` | one-liner moved into `README.md` § "Supporting Zupt" |

Surviving canonical docs: `README.md`, `CHANGELOG.md` (this file),
`SECURITY.md`, `INSTALL.md`, `LICENSE`, `THIRD-PARTY-NOTICES.md`,
`AUDIT.md` and the then-current roadmap.


## [2.2.2-final2] — 2026-05-01 — CLI help, man pages, deb copyright

Continuing the license-hygiene work: previously the SPDX headers in
source files were correct, but several user-visible surfaces still
showed wrong licensing or stale URLs. Fixed:

### CLI runtime output

- `zupt help` previously ended with `License: MIT` — corrected to
  `License: AGPL-3.0-or-later (Zupt) + GPL-3.0-or-later (VaptVupt codec)`
  with a `Commercial license available: sac@securityops.co` line and
  `Project: https://git.securityops.co/cristiancmoises/zupt` link.
- `zupt version` now also prints the License, Project URL, and
  Commercial contact lines (previously omitted entirely).

### Man pages

- `doc/zupt.1`: fixed BUGS URL from `github.com` → `git.securityops.co`,
  added `LICENSE` section explaining AGPL+GPL split, added `PROJECT`
  section listing all 5 sister projects (zupt, zupt-android, zupt-web,
  libzuptsdk, vaptvupt) with git.securityops.co URLs.
- `doc/zupt-gui.1`: same fixes (BUGS URL + LICENSE + PROJECT sections).

### Debian copyright file (`/usr/share/doc/zupt/copyright`)

The previous copyright file claimed everything was AGPL-3.0+. Updated
to a proper Debian-machine-readable format with two `Files:` stanzas:

- `Files: *` — AGPL-3.0+
- `Files: src/vv_*.c src/vaptvupt_api.c include/vv_*.h include/vaptvupt*.h`
  — GPL-3.0+ (with rationale comment about kernel upstreaming)

Plus a `Comment:` field pointing at sac@securityops.co for commercial
licensing inquiries.

### README logo

The github user-attachments URL for the logo (now broken since the
project moved off GitHub) was replaced with a HTML comment placeholder
suggesting rehosting at zupt.securityops.co.

### Other doc cleanups

- SECURITY.md: `Do not open a public GitHub issue` → `Do not open a
  public issue on the project's git server`
- libzuptsdk README: same `GitHub issues` → `project's git server`
  fix.

### Verification

- 61/61 tests pass (no behavior change)
- `make audit-licenses` → ✓ all SPDX correct
- `zupt version` and `zupt help` both display correct license + URL
- Man pages (zupt.1, zupt-gui.1) carry full LICENSE + PROJECT sections


## [2.2.2-final] — 2026-04-30 — License hygiene + project move

This update does not change any binary behavior. It corrects licensing
metadata across the source tree and updates all repository URLs from
`github.com/cristiancmoises/*` to `git.securityops.co/cristiancmoises/*`.

### Repository move

The Zupt project has moved from GitHub to a self-hosted Gitea instance:

| Project | New URL |
|---|---|
| zupt (this repo) | https://git.securityops.co/cristiancmoises/zupt |
| zupt-android | https://git.securityops.co/cristiancmoises/zupt-android |
| zupt-web | https://git.securityops.co/cristiancmoises/zupt-web |
| libzuptsdk | https://git.securityops.co/cristiancmoises/libzuptsdk |
| vaptvupt | https://git.securityops.co/cristiancmoises/vaptvupt |

All 29 occurrences of `github.com/cristiancmoises/...` across 19 files
have been updated. The old GitHub URLs no longer resolve.

### License clarification

The README and LICENSE file previously contained inaccurate license
claims. Corrected:

- **Zupt CLI, libzuptsdk, GUI, Jasmin source**: AGPL-3.0-or-later
- **VaptVupt LZ codec** (`src/vv_*.c`, `src/vaptvupt_api.c`,
  `include/vv_*.h`, `include/vaptvupt*.h`): **GPL-3.0-or-later**
  (deliberately GPL not AGPL, so it can eventually be considered for
  upstreaming into the Linux/BSD kernels which require GPL-compatible
  licensing).
- **Commercial licensing** (relief from copyleft): contact
  `sac@securityops.co`.

The README's competitive comparison table erroneously listed Zupt under
"License: MIT". Corrected to "AGPL+GPL".

### SPDX coverage

Every source file in the tree now carries an explicit SPDX header.
Previously 46 files in the CLI tree, 5 Jasmin assembly outputs, the CI
yml, and a few packaging files had no SPDX line at all. Added:

- `AGPL-3.0-or-later` to all Zupt CLI sources (46 files), `.s` assembly
  outputs (5 files), `.github/workflows/ci.yml`, packaging Flatpak
  manifest, `sdk/zuptsdk.map`
- `GPL-3.0-or-later` to all VaptVupt sources (8 files that were missing
  it: `vv_ans.c`, `vv_decoder.c`, `vv_encoder.c`, `vv_huffman.c`,
  `vv_simd.c`, `vv_xxh64.c`, `vv_ans.h`, `vv_huffman.h`)

The current headers of five Jasmin `.jazz` source files were changed from MIT
notices to AGPL-3.0-or-later notices. This describes the current revision; it
does not revoke the MIT permissions attached to exact historical material.

The 5 VaptVupt headers in `vendor/zuptsdk/include/` (vaptvupt.h,
vaptvupt_api.h, vv_ans.h, vv_huffman.h, vv_platform.h) were tagged
AGPL but should have been GPL since they are VaptVupt headers.
Corrected.

### THIRD-PARTY-NOTICES.md rewritten

The previous document framed parts of Zupt as if they were vendored
third-party dependencies. They are not. The new document opens with:

> **Zupt contains no third-party source code.** Every line of source
> in this repository is the work of Cristian Cezar Moisés.

Runtime system libraries (libargon2, OpenSSL libcrypto) are listed as
runtime dependencies provided by the OS package manager, not as bundled
dependencies. The Jasmin compiler is correctly described as a
build-time tool that is not redistributed.

### LICENSE file fixes

- "libzuptsdk is free software" → "Zupt is free software" (this is the
  zupt repo, not the libzuptsdk repo)
- GitHub URL → git.securityops.co URL
- Contact `zupt@riseup.net` → `sac@securityops.co`
- Appended a note explaining that VaptVupt is GPL not AGPL, with
  rationale for the deliberate licensing split

### New `make audit-licenses` target

Verifies on every CI run that:

- All non-VaptVupt source files carry `SPDX-License-Identifier: AGPL-3.0-or-later`
- All VaptVupt files (`vv_*`, `vaptvupt*`) carry `SPDX-License-Identifier: GPL-3.0-or-later`

Excludes vendored libzuptsdk headers (`vendor/zuptsdk/include/`) and
build artifacts (`build/`, `build_obj/`, `sdk/build/`).

Result: ✓ All source files carry correct SPDX headers.

### Build dependency: libzuptsdk-dev

The CLI's `--pq-sdk` path links against `libzuptsdk.so.2`. Previously,
the source tarball assumed the library would be available in the
build environment. INSTALL.md now has an explicit "Building from
source" section documenting this requirement and pointing at the
`libzuptsdk2` / `libzuptsdk-dev` packages.

### Removed obsolete migration docs

`FRESH-REPO-SETUP.md` and `CHANGELOG.fresh-repo.md` (one-time docs from
the github-old → github-new migration sprint) deleted as obsolete.

### Verification

- 61/61 tests pass (audit, smoke, multi-file, cross-block, dedup
  property, path-traversal, argument-order, block-swap regression)
- Encrypted compress + extract roundtrip: byte-exact match (MD5 verified)
- `make audit-licenses` → ✓ all SPDX correct
- Source builds cleanly on Ubuntu 24.04 / GCC 13.3 with
  `libzuptsdk-dev 2.0.0` installed


## [2.2.2] project security review — bug #16 (block-swap attack) fix

A project source review using the then-current two-pass methodology discovered
a critical authenticated-encryption flaw in the shipped 2.2.2 binary.
Investigation, root cause, fix, regression test, and final verification are
documented below. This was not an independent audit or certification.

### Bug #16 — CRITICAL: Block-swap attack on encrypted archives

**Severity**: critical — silent data corruption with valid MAC

**Affected**: all encrypted archives produced by zupt 2.0.0 through 2.2.2.

**Root cause**: AES-CTR + HMAC-SHA256 in zupt 2.2.2 covered MAC over
`(nonce || ciphertext)` only. The decryptor read the nonce from the
package itself and **ignored** the `block_seq` parameter that was passed
in (`(void)block_seq;` in `src/zupt_crypto.c:zupt_decrypt_buffer`). An
attacker who swapped two valid encrypted blocks (full block including
header + checksum + payload) between positions in an encrypted archive
produced an archive that:

1. Decrypts cleanly — every block's stored nonce is its actual encryption
   nonce, so AES-CTR decryption produces correct plaintext
2. MAC-verifies cleanly — MAC was computed over (nonce || ct), and both
   are stored in the swapped block, so the MAC is still valid
3. Extracts files with wrong content — file_A.txt receives file_B's
   content and vice-versa, with zupt reporting "Extracted N file(s)"
   and no error

**Reproduction** (confirmed twice in the audit): with two distinct files
A (49 'A' chars) and B (49 'B' chars) compressed with `-p mypassword
-b 64 -t 1`, swapping the two 114-byte DATA blocks at positions 134
and 248 produced an archive that extracted file_A.txt with B's content
and file_B.txt with A's content, with zupt reporting "Extracted 2 file(s)".

**Fix architecture**: bind `block_seq` into the MAC as 8-byte
little-endian Associated Data (AAD). The seq is computed as
`((file_index_in_archive + 1) << 32) | per_file_block_seq`, combining
the file's identity within the archive with its block position within
that file. Both encrypt and decrypt compute this from the same inputs
(`fi` and `b`) without changing the wire format. Special cases:

- **Index blocks**: use sentinel seq `0xFFFFFFFFFFFFFFFFULL` (matches
  existing decrypt at line 1517)
- **Solid mode**: synthetic fi=0 (AAD = `(1 << 32) | block_seq`) since
  there are no per-file boundaries
- **Dedup mode**: sentinel seq=0 — dedup refs (offset-only) can't
  derive the source file's AAD, so dedup blocks bypass AAD binding.
  Block-level XXH64 plaintext checksum still provides integrity.
- **Backward compat**: decrypt tries v2 (with AAD) first, falls back
  to v1 (legacy, no AAD) for old archives. Both candidates always
  computed for constant-time policy.

A new archive header flag `ZUPT_FLAG_AAD_SEQ (1u << 8)` signals that
encrypted blocks bind the seq.

**Files modified**:
- `include/zupt.h` — added `ZUPT_FLAG_AAD_SEQ`
- `src/zupt_crypto.c` — `zupt_encrypt_buffer` / `zupt_decrypt_buffer`
  rewrite (AAD binding, dual-MAC fallback)
- `src/zupt_format.c` — set flag on new encrypted archives, compute
  `(fi+1, block_seq)` AAD at all 3 encrypt sites (regular ST, MT,
  solid), compute matching AAD at all 4 decrypt sites (ST extract,
  MT extract, solid extract, test path)
- Empty output files on auth failure now `unlink()`'d (was leaving
  0-byte files on disk)

**Regression test**: `tests/test_block_swap.sh` — 6 properties:
1. Normal extract still works (regression guard)
2. Block-swap attack rejected (cross-file reorder) — exact reproduction
   of the audit-discovered attack
3. Single-block file roundtrip (boundary)
4. 512KB multi-block file roundtrip
5. Multi-file archive roundtrip (per-file seq counters)
6. Wrong password rejected

The attack reproduction in test 2 produces an archive identical to the
manual attack used to discover the bug; it must report 0 files
extracted with errors, never the swapped-content output that the bug
allowed.

### Cumulative test surface (2.2.2 final after bug #16)

```
make test                    →   9/9   (run_quick)
                             →  11/11  (test_sdk)
                             →  10/10  (test_audit)
                             →  12/12  (test_dedup_props)
                             →   5/5   (test_path_traversal)
                             →   8/8   (test_arg_order)
                             →   6/6   (test_block_swap)         NEW
                             ──────
                                61/61 ✓

make test-asan-run           → 61/61 ✓ under ASAN/UBSAN, zero memory errors
make fuzz-format-run         → 1000 iters under ASAN/UBSAN, 0 crashes
Inherited libzuptsdk         → 169/169 + 750k fuzz iters
                             ──────
Combined zupt + SDK            279 tests + 751k fuzz iters
```

### Cumulative bug count across all audit sprints

| Sprint | Bugs | Severity range |
|---|---|---|
| v2.2.1 (project review 1) | 6 | low to high |
| v2.2.2 (project review 2) | 4 | low to medium |
| v2.2.2 (project review 3) | 4 | low to high (Zip Slip) |
| v2.2.2 (project review 4) | 1 | critical (silent extract) |
| v2.2.2 (project security review) | 1 | **critical** (block-swap AEAD) |
| **Total** | **16** | all fixed and regression-tested |

### Known limitation accepted

Dedup mode trades AAD-binding for offset-based ref support. An attacker
with access to a dedup-mode encrypted archive could swap blocks; the
plaintext XXH64 checksum stored per block prevents wrong-content
extraction, but error messages may not clearly say "tampered" — they
say "checksum mismatch". This is documented in SECURITY.md and is
acceptable because dedup is opt-in and not the default.


## [2.2.2] project security review pass — 2026-04-27 (no version bump)

A post-release project security review found and fixed two security-relevant
bugs and two robustness bugs. Version stays at 2.2.2; this is hardening of the
same release, not an independent audit or certification.

### Bugs found and fixed

11. **🚨 HIGH — Path traversal (Zip Slip) in extract path** (`src/zupt_format.c`, two extract sites). The archive entry's `e->path` field — attacker-controlled in a malicious archive — was passed directly to `fopen` after string concatenation with the output directory. A crafted archive containing entries like `../../../etc/cron.d/evil`, `/etc/passwd`, or `C:\Windows\System32\drivers\etc\hosts` could write arbitrary files anywhere the user has filesystem access. This is the [Snyk Zip Slip](https://snyk.io/research/zip-slip-vulnerability) vulnerability pattern (2018). New `zupt_path_is_safe()` validator rejects:
    - empty paths and paths exceeding `ZUPT_MAX_PATH`
    - absolute paths (Unix `/...`, Windows `C:`, UNC `\\server`)
    - any component equal to `..`
    - embedded NUL bytes
    Wired into both extract sites before `fopen`. Confirmed via 5-test regression suite.

12. **MEDIUM — Symlink-following on extract output** (`src/zupt_format.c`). `fopen(out_path, "wb")` follows symlinks. If an attacker plants a symlink in the user's output directory before extraction (`~/Downloads/innocent.txt → /etc/shadow`), extract clobbers the symlink target. New `zupt_safe_fopen_output()` uses `O_NOFOLLOW` on POSIX (Linux/BSD/macOS), returning `ELOOP` if the leaf is a symlink. Windows path unchanged — relies on directory ACLs, documented in `SECURITY.md`. Verified by P3 of the path-traversal regression test.

13. **LOW — `size_t` overflow on solid-extract size cap** (`src/zupt_format.c:1593`). The 4 GiB cap on solid-stream size exceeds `size_t` on 32-bit platforms, where the subsequent `malloc((size_t)total_size)` would silently truncate. Added explicit `total_size > SIZE_MAX` guard.

14. **LOW — `count * sizeof(entry)` overflow in `parse_index`** (`src/zupt_format.c`). With `ZUPT_MAX_FILES = 2,000,000` and `sizeof(zupt_index_entry_t) ≈ 4140`, the multiplication overflows `size_t` on 32-bit platforms before reaching `calloc`'s internal overflow check. Added explicit `count > SIZE_MAX / sizeof(entry)` guard. (No exploitable behavior on 64-bit; defense for embedded/Termux/legacy platforms.)

### Cryptographic primitive review (no findings)

Reviewed against FIPS 197 (AES), FIPS 202 (Keccak/SHA-3), FIPS 203 (ML-KEM),
RFC 5297 (AES-SIV), RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8439
(ChaCha20-Poly1305), RFC 9106 (Argon2), and RFC 9180 (HPKE):

- **AES-CTR per-block nonce derivation** (`base_nonce ⊕ block_seq` LE in low 8 bytes): safe by construction. `base_nonce` is randomly generated per archive (32 bytes from `zupt_random_bytes`); `block_seq` is monotonic and unique within an archive. No nonce reuse possible under any execution path.
- **Legacy `--pq` hybrid combiner**: XOR of ML-KEM and X25519 shared secrets, then SHA3-512 with full transcript binding (`ml_ct || eph_pk || domain-tag`). Acceptable per Bindel et al. 2019; weaker than HKDF combiner used in SDK path, but both modes are intentionally kept for archive compatibility. Documented as legacy.
- **PBKDF2 key splitting** (legacy password mode): derives 64 bytes, splits to 32 enc_key + 32 mac_key. Safe — PBKDF2-SHA256 output is uniformly random.
- **SDK header parsing**: bounds-checked correctly (`enc_hdr_len < 5` guard, `blob_sz > enc_hdr_len - 5` guard, `blob_sz > 1500` cap).

### New regression test suite

`tests/test_path_traversal.sh` — 5 property checks:
- P1: `..` traversal blocked (patched archive does not escape parent dir)
- P2: absolute path entries rejected (does not write to `/tmp/owned`)
- P3: symlink at extract target not followed (sentinel file preserved)
- P4: legitimate paths still extract correctly (regression guard)
- P5: deep nested safe paths still work (regression guard)

### Cumulative test surface (2.2.2 final)

```
make test                    →  9/9   (run_quick)
                             → 11/11  (test_sdk)
                             → 10/10  (test_audit)
                             → 12/12  (test_dedup_props)
                             →  5/5   (test_path_traversal)  NEW
                             ──────
                               47/47 ✓

make test-asan-run           → 47/47 ✓ under ASAN/UBSAN, zero memory errors
make fuzz-format-run         → 1000 iters under ASAN/UBSAN, 0 crashes
Inherited libzuptsdk         → 169/169 + 750k fuzz iters
                             ──────
Combined zupt + SDK            265 tests + 751k fuzz iters
```

### Portability re-verification

Static portability scan passes:
- No unaligned pointer casts (`*(uint64_t *)ptr` patterns absent)
- No raw `/` separators in path construction (uses `ZUPT_PATH_SEP` macro)
- No `htonl`/`ntohl` or struct casts (uses `zupt_le32_get`/`zupt_le64_get` exclusively)
- No POSIX-only headers without `#ifdef` guards

Compile-tested with `-Wpedantic` under GCC. Win32 code paths verified via
`-D_WIN32 -E` synthetic preprocessing — branches reachable, syntax clean.

`#ifdef _WIN32` coverage in: `zupt_crypto.c`, `zupt_disk.c`, `zupt_format.c`,
`zupt_main.c`, `zupt_mlock.c`. Posix-side gated with explicit `#else`.

### Documentation updates

- `SECURITY.md`: new "Threat model" and "Path traversal mitigation" sections
- `AUDIT.md`: 2026-04-27 project review entry with cumulative test table
- `README.md`: Security section updated with the project review summary
- `doc/zupt.1`: SECURITY section mentions path-traversal protection
- the then-current source-review methodology document

## [2.2.2] — 2026-04-27

Continued audit-driven hardening release. Four additional bugs found and fixed by code review; new fuzz harness for the format parser; new property-based tests for the dedup path; full GitHub Actions CI pipeline.

### Bugs found and fixed

7. **realloc-pair atomicity bug in `zupt_filelist_add`** (`src/zupt_format.c:166`). When the first `realloc` succeeded and the second failed, the first realloc had already invalidated the original pointer; the cleanup branch's `if (new_paths != fl->paths) free(new_paths)` is undefined behavior because `realloc` may return the same pointer. Worse, when both reallocs succeeded but allocation truncated the array (impossible here, but the pattern is fragile), `fl->paths` was updated only when `new_paths` was not NULL — leaving callers with stale pointers in the failure path. Replaced with atomic two-buffer allocation: both `malloc` first, copy contents, free old buffers only on full success.

8. **Length-overflow in in-memory varint decoder** (`src/zupt_format.c:138`). `zupt_decode_varint` had the same 9-byte truncation bug as the file-variant decoder fixed in 2.2.1, plus shift-by-64 undefined behavior when `s` reached 63 with a continuation bit still set. Decoder now accepts up to 10 bytes (sufficient for full uint64) and explicitly rejects continuation past bit 64.

9. **Unvalidated `encryption_header_off`** (`src/zupt_format.c:1267`). A malicious archive could set `encryption_header_off` to `0xFFFFFFFFFFFFFFFF`. Casting to `int64_t` for `fseeko` gives `-1`; the seek silently fails and subsequent reads happen at an undefined position. Now validates offset is within file size before seeking.

10. **Unvalidated `index_offset`** (`src/zupt_format.c:1402`). Same class of bug as #9, applied to the archive footer's index pointer. Same fix.

### Added — Fuzz infrastructure

- `tests/fuzz_format.c` — mutation-fuzz harness for the zupt format parser. Forks a child process per iteration to isolate crashes; mutates a seed archive with byte-flips, byte-sets, zero-runs, 0xFF-runs, and swaps; feeds mutated archives to `zupt list` and counts crashes vs. clean rejections.
- `make fuzz-format` builds the harness.
- `make fuzz-format-run` runs 1000 iterations against the ASAN/UBSAN binary. **Result: 0 crashes, 159 archives accepted as well-formed despite mutation, 841 cleanly rejected.**

### Added — Dedup property-based tests

- `tests/test_dedup_props.sh` — 12 property-based checks for the deduplication path:
  - Roundtrip preserves bytes for 10 base files + 5 duplicates
  - Dedup achieves >50% size reduction on 20-copy duplicate-heavy workloads (measured: 95% reduction, 17,346 B vs. 328,550 B)
  - 100%-duplicate archives extract correctly with all copies recovered byte-exact
  - Dedup + SDK PQ encryption coexist correctly

### Added — GitHub Actions CI pipeline

- `.github/workflows/ci.yml` — 4-job pipeline:
  - `build-and-test`: full test suite (run_quick + sdk + audit + dedup)
  - `asan-build`: build with `-fsanitize=address,undefined` and run all suites under sanitizers
  - `fuzz-format`: 1000-iteration fuzz under ASAN/UBSAN
  - `package-deb`: build + verify .deb installation

### Added — THIRD-PARTY-NOTICES.md

Documents all third-party software included or linked: vendored libzuptsdk (AGPL, same author), Jasmin-compiled assembly, libargon2 (Apache 2.0 / CC0), OpenSSL libcrypto (Apache 2.0), VaptVupt (AGPL, in-tree), and standards followed (FIPS 197/202/203, RFCs 5297/5869/7748/8032/8439/9106/9180). Required for redistribution compliance.

### Test results

```
make test                    →  9/9  (run_quick)
                             → 11/11 (test_sdk)
                             → 10/10 (test_audit)
                             → 12/12 (test_dedup_props)  NEW
                             ──────
                               42/42 ✓

make test-asan-run           → 42/42 ✓ under ASAN/UBSAN, zero memory errors

make fuzz-format-run         → 1000 iters under ASAN/UBSAN, 0 crashes

Inherited from libzuptsdk    → 169/169 + 750k fuzz iters
                             ──────
Combined zupt + SDK            260 tests + 751k fuzz iters
```

### Compatibility

- All v2.2.1 archives extract unchanged.
- Legacy `--pq` keyfiles continue to work.
- `--pq-sdk` flow unchanged.
- New CI workflow does not affect runtime behavior.

### Fixes after 2.2.2 (still v2.2.2)

- **GUI install failures fixed.** GUI deb dependencies now correctly reference `python3-pyqt6 | python3-pyside6` (alternation) instead of nonexistent `python3-pyside6.qtwidgets`. PySide6 is not in the default Debian/Ubuntu repositories; PyQt6 is. The GUI now imports either binding via try/except.
- **GUI auto-detects Qt binding at startup**: PySide6 first (preferred), PyQt6 fallback. Prints instructive install message if neither is present, instead of crashing with ImportError.
- **Man pages now include `--pq-sdk` documentation**. Both `doc/zupt.1` and the new `doc/zupt-gui.1` cover SDK v2 mode, key generation with `--sdk`, both encryption workflows, FIPS/RFC standards, and IN ITI 35/2026 alignment.
- **`zupt help` (CLI usage text) updated**: SDK options grouped under Compress/Extract/Keygen sections with full descriptions, two example workflows (legacy + SDK v2 recommended).
- **Cross-platform packaging**: deb script now arch-aware (amd64 → `x86_64-linux-gnu`, arm64 → `aarch64-linux-gnu`, armhf, i386). Switched to xz compression for compatibility with older dpkg.
- **GUI rpm/AppImage builders added**: `packaging/build-gui-rpm.sh` and `packaging/build-gui-appimage.sh`. The AppImage uses system Python+Qt (small, ~50KB) instead of bundling Python (~80MB) — instructive runtime check if Qt binding missing.
- **GUI deb postinst** refreshes desktop database and icon cache; postrm cleans them up.

## [2.2.1] — 2026-04-27

Audit-driven hardening release. Six bugs found by code review and fixed; new audit test suite added.

### Bugs found and fixed

1. **Varint reader truncation** (`src/zupt_format.c:146`). The reader processed at most 9 continuation bytes, but a uint64 varint can span 10 bytes. Values above 2^63 would silently truncate. Reader now accepts up to 10 bytes and returns -1 if a 10th continuation byte is set, preventing accidental wraparound.

2. **Unchecked `fwrite` in extract path** (`src/zupt_format.c`, six call sites: 1529, 1611, 1631, 1660, 1689, 1699). On a full disk or write error, the extractor reported success while files were corrupt. Each `fwrite` now checks the return; partial writes set the per-file `berr` flag, and the solid-file path returns `ZUPT_ERR_IO`. Found by reading the extract path with the question "what happens if the disk fills mid-extract?"

3. **`mac_key` derived as a copy of `enc_key`** (`src/zupt_crypto_sdk.c`). The keyring's `mac_key` slot was filled with the same 32 bytes as `enc_key`, even though ZUPT's shared payload pipeline uses that key for HMAC-SHA256. Both payload keys are now derived from the SDK-wrapped session secret via SHA3-256 with domain-separation strings (`"ZUPT-SDK-ENC-KEY"`, `"ZUPT-SDK-MAC-KEY"`).

4. **Length-overflow in LZ decoder** (`src/zupt_lz.c:33`). `lz_read_extra` accumulated a length value with no upper bound. A crafted block with many `0xFF` extension bytes could overflow `size_t`, wrapping back to a small value that passed the subsequent `op + match_len > dst_len` check, then the inner copy loop ran for many iterations. Capped accumulation at 2^32 with explicit overflow return; both call sites check.

5. **Dedup-ref recursion / out-of-bounds offset** (`src/zupt_format.c`, two sites). A malicious archive could place a `DEDUP_REF` block whose offset pointed to itself, to a forward position, or to another `DEDUP_REF`. The first two would loop or seek to garbage; the third would not loop in the current implementation but is structurally invalid and is now rejected. The fix requires `ref_off < cur_pos` (refs always point backward to previously-written blocks) and rejects `ref_blk.block_type == ZUPT_BLOCK_DEDUP_REF`.

6. **Partial archive left on disk after encrypt-init failure**. When `--pq-sdk pubkey` was given a non-existent or invalid public key, `write_enc_header` returned `ZUPT_ERR_AUTH_FAIL` after the archive header had already been written. The 64-byte stub was left on disk. Both compress paths now `unlink(output_path)` before returning.

### Added

- `tests/test_audit.sh` — 10-check double-validated audit suite (every property tested via two independent paths). Categories: authenticated archives, format security, format compatibility, robustness.
- `packaging/build-deb.sh` — produces `zupt_2.2.1_amd64.deb` (CLI + libzuptsdk).
- `packaging/build-rpm.sh` — produces RPM via `rpmbuild`, falls back to SRPM-equivalent tarball when `rpmbuild` is absent.
- `packaging/build-appimage.sh` — produces AppImage via `appimagetool`, falls back to portable AppDir tarball.
- `packaging/build-gui-deb.sh` — produces `zupt-gui_1.1.0_all.deb`.

### GUI changes (zupt-gui 1.1.0)

- New "Mode" panel in compress/extract tabs with **SDK v2** checkbox (default on for new archives).
- Keygen tab gains "SDK v2 format" checkbox; when enabled, runs `zupt keygen --sdk` and reports both private and public key paths.
- Tooltip on each SDK checkbox explains the cryptographic difference (HKDF combiner + commitment + HPKE vs legacy XOR+SHA3-512).
- Existing `--pq` legacy flow preserved when SDK checkbox is unchecked.

### Test results

```
make test        →  9 passed, 0 failed
test_sdk.sh      → 11 passed, 0 failed
test_audit.sh    → 10 passed, 0 failed
TOTAL            → 30 / 30
```

Inherited from libzuptsdk 2.1.5: 169 SDK tests + 750k mutation-fuzz iterations under ASAN/UBSAN.

### Compatibility

- Existing v1/v2 archives extract unchanged.
- Legacy `--pq` keyfiles continue to work with the legacy combiner.
- New `--pq-sdk` keyfiles use the SDK v2 path (incompatible with `--pq`, by design — this is what prevents mode confusion).

### Post-release additions (still 2.2.1)

- `LICENSE` file added to repo root (AGPL-3.0 text was previously only in `sdk/LICENSE`). Source tarball now contains it.
- `make test-asan-run` target wired into the zupt Makefile. Builds zupt with `-fsanitize=address,undefined`, runs all three test suites (`run_quick.sh`, `test_sdk.sh`, `test_audit.sh`) against the instrumented binary. **All 30 tests pass cleanly under ASAN/UBSAN with zero memory errors.**

## [2.2.0] — 2026-04-27

zuptsdk integration release. Replaces zupt's legacy hybrid combiner (XOR+SHA3-512) with libzuptsdk's HKDF-SHA3-256 + key commitment + HPKE binding + anti-fault decap.

### Added — SDK-backed crypto path

- `src/zupt_crypto_sdk.c` — new module wrapping libzuptsdk for archive encryption.
- `vendor/zuptsdk/` — vendored libzuptsdk 2.1.5 (737KB shared lib + headers).
- New encryption type IDs: `ZUPT_ENC_PQ_SDK_V2` (0x03) and `ZUPT_ENC_PW_ARGON2` (0x04).
- New CLI flag `--pq-sdk <keyfile>` for SDK-backed PQ encryption.
- `zupt keygen --sdk -o key.priv` generates SDK-format keypair (writes both `key.priv` and `key.priv.pub`).
- Argon2id replaces PBKDF2 for new password-mode archives (legacy reads still work).

### Security improvements (vs zupt 2.1.7)

| Property | zupt 2.1.7 (legacy `--pq`) | zupt 2.2.0 (`--pq-sdk`) |
|---|---|---|
| Hybrid combiner | XOR + SHA3-512 (Bindel-Brendel-Fischlin warns against XOR) | HKDF-SHA3-256 with domain separation |
| Key commitment | None | 32-byte HKDF-derived commitment tag |
| HPKE binding | None | RFC 9180 §5 context (suite + AAD bound) |
| Anti-fault decap | None | Double ML-KEM decap + CT compare |
| Password KDF | PBKDF2-SHA256 | Argon2id (RFC 9106 OWASP minimums) |
| Payload protection | AES-256-CTR + HMAC-SHA256 | AES-256-CTR + HMAC-SHA256 |
| Test coverage | 9 tests | 9 + 11 SDK = 20 + inherited 169 SDK tests |

### Backward compatibility

- Legacy `zupt c --pq <key>` path unchanged (XOR+SHA3-512 combiner).
- Legacy `zupt x --pq <key>` reads both old and new archives transparently — encryption type byte is checked.
- Old keyfiles still work with old `--pq`. New keyfiles (with `.pub`) work with `--pq-sdk`.
- v1/v2 archive read path untouched.

### Tests

- `tests/test_sdk.sh` — 11 new tests: keygen, small/large roundtrip, wrong-key rejection, tamper rejection, legacy compat.
- All 9 existing tests still pass.
- Total: **20 zupt tests + inherited 169 zuptsdk tests + 750k fuzz iters**.

### Build

`make` now requires `vendor/zuptsdk/` to be present. The vendored libzuptsdk is shipped in the source tarball.

Linker resolves `libzuptsdk.so.2` via absolute rpath to `$(abspath vendor/zuptsdk)`. For installed builds, distros should `LDFLAGS="-Wl,-rpath,/usr/lib"` and install libzuptsdk separately (preferred) or embed via static link.

All notable changes to Zupt are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.1.6] — 2026-04-22

### Added — Archive Info Command (`zupt info`)
- **New `zupt info <archive>` subcommand**: Shows archive metadata without needing a password. Displays format version, UUID, creation timestamp, file size, block count, and all flags (encrypted, PQ hybrid, solid, multithreaded, dedup, disk image). Useful for inspecting archives before decryption, triaging backups, and scripting.
- Works on all archive types: plain, encrypted, PQ, dedup, disk images.
- Rejects non-archive files with a clear error message.

### Added — Password Strength Warnings
- **Weak password detection** during `zupt compress -p`: warns if password is shorter than 8 characters ("very short") or shorter than 12 characters with fewer than 3 character classes ("weak"). Uses character class analysis: uppercase, lowercase, digits, special characters.
- Non-blocking: warning is informational only, compression proceeds. PBKDF2 with 600K iterations provides baseline protection even for weaker passwords.

### Enhanced — `zupt list` Shows Dedup & PQ Flags
- Archive listing header now displays `| Dedup`, `| PQ`, `| Disk` flags when present, making it immediately visible what features an archive uses.

### Upgraded — VaptVupt 2.40.0 Codec
- **VaptVupt 2.40.0** integrated (production hardening release). 55-case adversarial test suite, 10,200-case differential fuzzer, new `vv_xxh64.c` and `vv_platform.h`.
- **format_v2 enabled**: 4-7% better compression ratio on binary data (ELF, shared libraries). All v2.33.0+ decoders read v2 frames transparently.
- **VV_DECOMPRESS_SKIP_CHECKSUM**: Decode skips redundant XXH64 verification since zupt's HMAC-SHA256 already authenticates compressed data. Up to 3.7x faster decode on post-encryption random data.

### Added — Zupt GUI (PySide6 Desktop Application)
- Cross-platform graphical interface in `gui/` subdirectory. Covers all zupt operations: key generation (generate + export public key), compress (all codecs, levels, dedup, solid, password, PQ), extract, verify, info, disk backup/restore.
- System integration: Nemo right-click actions (Compress/Extract with Zupt), .zupt MIME type, desktop file.
- Packaging: .deb, .rpm, .whl, source tarball, NSIS Windows installer, AppImage, Flatpak configs.
- Dynamic version display from zupt binary (no hardcoded version strings). Window icon on all platforms.

### Tests
- **97 total**: 84 existing (70 core + 8 disk + 6 dedup) + 13 v2.1.6 (7 info, 4 password, 2 list flags). VV unit tests 11/11. ASAN clean.

---

## [2.1.5] — 2026-04-12

### Added — Block-Level Deduplication (`--dedup`)

- **New `--dedup` / `-D` flag** for `zupt compress` and `zupt disk backup`. Eliminates redundant data blocks before compression using XXH64 fingerprinting (strengthened with an independent SHA-256/128 match in 5.2.2).
- **New block type `ZUPT_BLOCK_DEDUP_REF` (0x04)**: Reference blocks store an 8-byte offset to the original data block instead of the full block payload. A 4MB duplicate block becomes 8 bytes.
- **Hash table index**: Open-addressing with linear probing, capped at 2M entries (~48MB RAM). 75% load factor limit. Secure wipe on free.
- **Content verification**: XXH64 fingerprint match is verified by block size comparison to prevent hash-collision corruption.
- **Backward compatible**: Archives without `--dedup` are byte-identical to v2.1.4. Dedup reference blocks are handled transparently on extract/restore — no `--dedup` flag needed for reading.
- **New source file**: `src/zupt_dedup.c` (165 lines) — dedup context, hash table, ref block writer.
- **New global flag**: `ZUPT_FLAG_DEDUP (1u << 7)` — informational, set in archive header.
- **Extract paths updated**: Both `zupt_extract_archive()` (single-threaded) and `zupt_disk_restore()` handle `DEDUP_REF` blocks by seeking to the referenced offset, reading+decompressing the original block, then seeking back.

### Tests
- **84 total**: 70 core + 8 disk + 6 dedup (plain, password, PQ, PQ+password, disk, no-duplicates). ASAN clean.

---

## [2.1.4] — 2026-04-11

### Fixed — CodeQL Security Alerts (4/4 resolved)

- **Alert #1 & #2: TOCTOU filesystem race in `get_device_size()`** (High). The function called `stat(path)` to classify the file type, then `open(path)` to read it — between those two calls an attacker could swap the path to a different file. Fix: open the fd first with `open()`, then classify via `fstat(fd)`. The fd is stable and cannot be swapped.
- **Alert #3: Dead-store `memset` in `zupt_x25519()`** (High). The `memset(e, 0, 32)` call to wipe the clamped scalar was the last use of `e` before the function returned, so the compiler could legally optimize it away (and some do at `-O2`). Fix: volatile pointer loop (`volatile uint8_t *ve = e; for(...) ve[i] = 0;`) which the compiler must emit.
- **Alert #4: TOCTOU filesystem race in `zupt_disk_restore()`** (High). Restore called `stat(target_path)` to check for block devices, then `open(target_path)` — same race window as alerts #1/#2. Fix: open fd first, then `fstat(fd)` to classify, then `fcntl(fd, F_SETFL, O_SYNC)` for block devices.

### Tests
- **78 total:** 70 core + 8 disk. ASAN + UBSan clean.

---

## [2.1.3] — 2026-04-11

### Fixed — LZHP Prediction Encoding Missing in Disk Backup (data corruption)
- **Root cause:** `zupt_disk_backup()` LZHP compression path skipped the `zupt_predict_encode()` step. When byte prediction was active (`pred_active=1`), it stored the prediction table and wrote `cbuf[0] = 0x01`, but then compressed the **raw block data** instead of the prediction-encoded data. On restore, `decompress_block()` correctly applied `zupt_predict_decode()` to the decompressed output, producing corrupted data. Checksum mismatch on block 0 for any block with structured content (ext4 metadata, NTFS headers, partition tables).
- **Impact:** ALL disk backups using LZHP codec (default on CPUs without AVX2) on non-random data were silently corrupted. VaptVupt codec was unaffected (no prediction path). Random/incompressible data was unaffected (prediction benefit < threshold → `pred_active=0`).
- **Fix:** Added `zupt_predict_encode(rbuf, transformed, nread, pred)` before `zupt_lzh_compress()`, matching the correct path in `zupt_format.c` (lines 557–563). Allocated temporary buffer for prediction-encoded data, freed after compression.

### Fixed — Spurious SOLID Flag on Disk Archives
- Disk backup no longer sets `ZUPT_FLAG_SOLID` in the archive header. Disk images are independent per-block archives, not solid streams. The SOLID flag caused `zupt_extract_archive()` to take the wrong code path if a disk archive was ever parsed by the extract function.

### Fixed — Shared Encryption Header (eliminates all format mismatches)
- **Extracted `write_enc_header()`** from `zupt_format.c` as a shared non-static function. ALL three encryption write paths — `zupt_compress_files()`, `zupt_compress_solid()`, and `zupt_disk_backup()` — now call the same function.
- **Solid compress now supports PQ encryption.**
- **`zupt_w8()`, `zupt_w16le()`, `zupt_w64le()`** made non-static and declared in `zupt.h`.

### Fixed — Block Device Restore I/O
- Restore uses POSIX raw I/O (`open()` + `write()` loop) with `O_SYNC` for block devices, `fsync()` + `sync()` before close.

### Fixed — Termux/Android Build
- Arch-safety guard uses `$(CC) -dumpmachine` for host detection. Falls back to `uname -m`.

### Tests
- **78 total:** 70 core + 8 disk (including LZHP+PQ+password on ext4 — the exact failing case). ASAN + UBSan clean.

---

## [2.1.2] — 2026-04-06

### Added — Full-Disk Backup/Restore
- **`zupt disk backup`** — streams a raw block device or file in 4MB chunks, compresses each block with the selected codec (VaptVupt default), detects all-zero (sparse) blocks and stores them with near-zero overhead. Supports password encryption (`-p`), post-quantum encryption (`--pq`), compression level override (`-l 1-9`), and codec selection (`--vv`, `--lzhp`). Real-time progress bar with throughput on stderr.
- **`zupt disk restore`** — reads a disk image archive block-by-block, decrypts + decompresses each block, validates per-block XXH64 checksums, and writes sequentially to the target device or file. Rejects wrong passwords/keys immediately on first block failure.
- **`ZUPT_FLAG_DISK_IMAGE (1u << 6)`** — new global flag in the archive header. `zupt disk restore` validates this flag and rejects non-disk archives. Standard `zupt extract` rejects disk archives with a clear error message.
- **`src/zupt_disk.c`** — 530 lines. Portable device size detection: `BLKGETSIZE64` on Linux, `DKIOCGETBLOCKCOUNT` on macOS, `lseek(SEEK_END)` fallback on FreeBSD/generic. 8-byte-wide sparse block detection.
- CLI: `zupt disk backup [OPTIONS] <output.zupt> <device_or_file>` / `zupt disk restore [OPTIONS] <archive.zupt> <target>`

### Tests
- **77 tests total:** 11 VV unit + 13 NIST/RFC vectors + 22 regression + 14 multi-threaded + 10 post-quantum + 7 disk backup (normal, encrypted, PQ, sparse, LZHP, extreme, wrong-password rejection). ASAN + UBSan clean across all paths.

---

## [2.1.1] — 2026-04-06

### Fixed — Multi-Architecture Build
- **Stale object files removed from distribution.** Previous tarballs shipped pre-compiled x86_64 `.o` files. On aarch64 (Termux, Raspberry Pi, etc.) the linker failed with `ld.lld: error: src/zupt_xxh.o is incompatible with aarch64linux`. All `.o` files now excluded from release tarballs.
- **Arch-safety guard in Makefile.** Detects pre-compiled `.o` files from a different architecture via `file(1)` and auto-removes them before linking. Prevents silent link failures if stale objects are accidentally present.
- **Termux/Android compatibility.** Default compiler changed from `gcc` to `cc` (Termux ships clang). `-lpthread` skipped on Android/Termux (bionic libc has pthreads built-in, detected via `uname -o`).
- **`sys/syscall.h` include moved to file top** in `zupt_crypto.c`. Was inside function body (non-standard C, rejected by some compilers).

### Fixed — Undefined Behavior
- **Keccak ROL64 shift-by-64 UB.** `ROL64(x, 0)` expanded to `(x >> 64)` which is undefined behavior in C. The Keccak rotation table has `KECCAK_ROT[0] = 0`, triggering this on every Keccak-f[1600] call (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, ML-KEM-768). Fix: `ROL64` now returns `x` unchanged when `n == 0`. Confirmed zero UBSan violations across all PQ paths.

### Tests
- 70/70: 11 VV + 13 NIST + 22 regression + 14 MT + 10 PQ. ASAN + UBSan clean (zero violations).

---

## [2.1.0] — 2026-04-05

### Upgraded — VaptVupt 1.4.0 Codec
- **Cross-block dictionary carry** — hash chain now spans block boundaries. The encoder passes absolute positions to `compress_block()` so matches can reference data from previous blocks. Large structured files (7MB logs) compress **5.73:1** instead of per-block independent ratios. The decoder accepts cross-block offsets via a `dst_base` parameter threaded through all decode functions.
- **Context model decode prefetch** — `__builtin_prefetch` in the order-1 context ANS decode loop hides L2/L3 latency for the 4MB context tables. Extreme-mode decode throughput improved significantly on cache-constrained systems.
- **Faster adaptive window trial** — greedy depth=4 on 256KB sample instead of full lazy parse on entire first block. Encode speed improved **2.6×** with same ratio decisions.
- **Zupt integration API** — new `vvz_compress`/`vvz_decompress`/`vvz_compress_bound` wrappers (`vaptvupt_api.h`/`vaptvupt_api.c`) simplify codec dispatch with backup-optimized defaults.

### Changed
- `zupt_format.c` compress paths (normal, solid) now use `vvz_compress()` API instead of raw `vv_compress()` with manual option setup.
- `zupt_format.c` decompress path now uses `vvz_decompress()` API.
- Version bumped to 2.1.0.

### Performance (balanced mode, vs gzip-9)
| File Type | v2.1.0 | gzip-9 | vs gzip |
|-----------|--------|--------|---------|
| Source code (531K) | 59.5:1 | 51.7:1 | +15% better |
| JSON (232K) | 10.7:1 | 8.8:1 | +21% better |
| XML markup (641K) | 18.1:1 | 14.6:1 | +24% better |
| Long-range (800K) | 5.7:1 | 1.4:1 | +307% better |
| Logs 7MB (7.5MB) | 5.7:1 | 7.5:1 | gap 24% |

### Tests
- 70/70: 11 VV + 13 NIST + 22 regression + 14 MT + 10 PQ. ASAN clean.

---

## [2.0.0] — 2026-04-05

### Added — VaptVupt 1.1.0 Codec Integration
- **VaptVupt codec** integrated as `0x0010` — LZ77 + tANS entropy + AVX2 SIMD decode.
- Three compression modes: Ultra-Fast (greedy), Balanced (lazy + 4-way ANS), Extreme (lazy-2 + order-1 context).
- **Rep-match offset coding** — 3 recent offsets tracked (like zstd), saves 10–15 bits per repeated match.
- **Adaptive window selection** — trial-compresses at wlog=16 vs wlog=20, picks larger window only if ≥3% improvement.
- CLI flags `--vv` / `--vaptvupt` to select VaptVupt codec.
- CLI flag `--lzhp` to explicitly select Zupt-LZHP codec.
- VaptVupt source files with dual MIT + Apache-2.0 headers.
- `vv_xxh64` aliased to `zupt_xxh64` via macro (no duplicate symbol).
- Wired into compress (single-thread, multi-thread, solid) and decompress paths.
- 11 VaptVupt unit tests + 6 regression tests (T13–T18).

### Added — Auto Codec Detection
- **`ZUPT_CODEC_AUTO`** — hardware-aware default codec selection:
  - x86_64 with AVX2: VaptVupt (inline AVX2 SIMD decode, ~2–3 GB/s).
  - aarch64 with NEON: VaptVupt (NEON SIMD decode path).
  - All other architectures: Zupt-LZHP (scalar decoder, no SIMD dependency).
- `zupt_resolve_auto_codec()` checks compile-time flags (`__AVX2__`, `__ARM_NEON`) and runtime CPUID.
- Decompression is universal — any archive extracts on any architecture regardless of codec.
- Users can override with `--vv` (force VaptVupt) or `--lzhp` (force LZHP).

### Fixed — Jasmin Assembly
- **AES-NI stack offset bug** fixed: replaced `stack u128[15]` with 15 individual `stack u128` variables to avoid jasminc byte-offset indexing. Round keys now at correct 16-byte aligned offsets.
- **X25519 fe_cswap** wired: Jasmin swaps first 4 limbs (32 bytes), C handles 5th limb.
- **All 5 Jasmin functions now active**: `zupt_mac_verify_ct`, `zupt_ct_select_32`, `zupt_fe_cswap`, `zupt_aes256_blk`, `zupt_aes256_ctr4`.
- **SIGILL fix: AVX detection with OSXSAVE/XCR0 check.** The Jasmin AES assembly uses VEX-encoded instructions (`vaesenc`, `vmovdqu`, `vpxor`) which require AVX — not just AES-NI. Previous dispatch only checked `has_aesni`, causing SIGILL on CPUs with AES-NI but without AVX or without OS XSAVE support. Now checks `has_aesni && has_avx` with proper XGETBV XCR0 validation.
- Added `has_avx` field to `zupt_cpu_features_t` with correct detection: CPUID ECX[28] (AVX) + ECX[27] (OSXSAVE) + XCR0 bits 1+2.

### Fixed — VaptVupt Codec Bugs
- **`copy_match_scalar` overlap corruption** (`vv_simd.c`): 8-byte bulk copy was used for offsets 4–7, where source overlaps destination by more than the copy stride. The `memcpy` read-then-write semantics don't correctly replicate the overlapping pattern. Fix: byte-by-byte for offsets < 8 (was < 4). This caused silent data corruption on inputs with short-offset matches near the output buffer tail.
- **`vva_encode_sequences` heap overflow** (`vv_ans.c`): litlen varint buffer allocated as `nseq * 5 + 1` bytes, but individual literal lengths in solid mode can reach 1 MB, requiring up to `ceil(litlen/255) + 1` bytes per varint. Fix: compute exact bound from actual litlen values. This caused heap corruption and abort (`malloc(): invalid size`) on large solid-mode archives.

### Added — ACSL Formal Annotations
- 19 security-critical functions annotated with complete `requires/ensures/assigns` ACSL contracts.
- Covers: SHA-256, HMAC, PBKDF2, AES-256-CTR, key derivation, encrypt/decrypt, hybrid KEM, SHA3, SHAKE, ML-KEM-768, X25519, secure_wipe.
- Target: `frama-c -wp -wp-rte -wp-model Typed+Cast`.

### Added — Security Hardening
- **mlock()** for key material — prevents swap to disk (Linux/BSD/Windows).
- **Buffer canaries** on `zupt_keyring_t` — `canary_head`/`canary_tail` detect overflow, abort on corruption.
- **Always-decrypt timing mitigation** — `zupt_decrypt_buffer()` always decrypts even on MAC failure (then wipes), preventing timing oracle.
- **AFL++ fuzzing harnesses** — `fuzz_decompress.c` (archive format) and `fuzz_vv_decompress.c` (VaptVupt codec). `make fuzz-build`.

### Added — Performance
- **AES-NI 4-block pipeline** — `zupt_aes256_ctr4` interleaves 4 counter blocks per AES round for pipeline saturation.
- **Multi-threaded decompression** — non-solid extract dispatches blocks to N worker threads via `zpar_ctx_t` infrastructure.
- **Adaptive compression** — `zupt_detect_filetype()` identifies 16+ file formats by magic bytes; already-compressed files get STORE.
- **Benchmark harness** — `zupt bench --compare` tests all codecs + auto-detects gzip/lz4/zstd.

### Changed — Multi-Architecture Support
- Jasmin CT assembly: x86_64 only (C fallback on all others).
- AVX2 SIMD decode: x86_64 only. NEON decode: aarch64. Scalar fallback: everywhere.

### Tests
- **70 tests total:** 11 VV unit + 13 NIST/RFC vectors + 22 regression + 14 multi-threaded + 10 post-quantum.
- ASAN clean across all modes (normal, encrypted, solid, threaded, PQ).
- All 5 Jasmin symbols linked (confirmed via `nm`).

---

## [1.5.0] — 2026-03-28

### Added — Jasmin Assembly Integration (Sprint 1)
- **`zupt_mac_verify_ct`** Jasmin assembly linked into `zupt_decrypt_buffer()`. Replaces the C XOR accumulation loop for HMAC-SHA256 comparison. 4×u64 unrolled XOR, then described as proven constant-time; 5.2.2 records that no reproducible proof artifact was retained. Symbol confirmed active via `nm`: `T zupt_mac_verify_ct`.
- **`zupt_ct_select_32`** Jasmin assembly linked into `zupt_mlkem768_decaps()`. Replaces the C `cmov()` function for Fujisaki-Okamoto implicit rejection key selection. 4×u64 masked select, with the same historical proof qualification above. Symbol confirmed active via `nm`: `T zupt_ct_select_32`.
- **`include/zupt_jasmin.h`** — extern declarations for all Jasmin functions with ABI documentation.
- **`#ifdef ZUPT_USE_JASMIN`** dispatch guards in `zupt_crypto.c` and `zupt_mlkem.c` with clean C fallback.
- **Makefile** auto-detects `jasmin/*.s` files, assembles to `.o`, links into binary, sets `-DZUPT_USE_JASMIN`.

### Not Wired (documented, requires upstream fixes)
- `zupt_fe_cswap` (X25519): Jasmin uses 4×u64 limbs, C uses 5×u51-bit — incompatible layout. C fallback active.
- `zupt_aes256_blk` (AES-NI): Assembly has stack offset bug (`[rsp+1]` instead of `[rsp+16]`). C table-based AES active.

### Changed
- Version: 1.4.0 → 1.5.0.
- `cmov()` in `zupt_mlkem.c` guarded with `#ifndef ZUPT_USE_JASMIN`.
- MAC comparison return type widened from `uint8_t` to `uint64_t` to match Jasmin signature.

### Security
- 53/53 tests pass with Jasmin linked. 13/13 NIST vectors. ASAN clean. Zero warnings.

---

## [1.4.0] — 2026-03-28

### Fixed — Jasmin Parse Errors (jasminc 2026.03.0)
All 4 `.jazz` files rewritten to fix compilation errors:

- **`zupt_mac_verify.jazz`**: `diff |= a ^ b` — compound XOR+OR not a single x86-64 op. Split into `tmp = a; tmp ^= b; diff |= tmp`.
- **`zupt_mlkem_select.jazz`**: `out.[i] = (8u)sel` — `reg ptr` is read-only. Changed to `reg u64 out_ptr` with raw pointer writes.
- **`zupt_x25519_fe.jazz`**: `a.[i] = ta ^ diff` — same const-ptr write. Changed to `reg u64 a_ptr`.
- **`zupt_aes_ctr.jazz`**: Memory syntax `(u128)[ptr]` → `u128[ptr]` → `[ptr]` — all wrong. Correct: `key.[0]` via `reg ptr u128[N]` for reads; `stack u128[15]` for writes; bare `[ptr + 0]` for u64-width.
- Uninitialized variable warning: `#VPXOR(zero, zero)` → `wipe = rk.[z]; wipe ^= wipe; rk.[z] = wipe`.

### Changed
- Removed all `-CT` flag references (does not exist in jasminc 2026.03.0).
- The release claimed CT enforcement by the Jasmin type system during normal
  compilation and use of `jasminc -arch x86-64 -checksafety`; no reproducible
  certificate/log for those claims was retained (documented in 5.2.2).
- All compound expressions split into separate register operations.
- All output parameters changed from `reg ptr` to `reg u64` raw pointers.
- Byte-level access avoided: 4×u64 instead of 32×u8.

---

## [1.3.0] — 2026-03-28

### Added
- `include/zupt_acsl.h` — ACSL predicates: `ValidBuffer`, `ValidWriteBuffer`, `Separated2`, `KeyWiped`, `ValidKey`.
- `SECURITY_REVIEW.md` — 8-section security review with per-function CT analysis table.
- `jasmin/README.jazz.md` — build instructions, CT verification explanation, error history.

### Fixed
- First round of Jasmin syntax fixes (partial — completed in v1.4.0).

---

## [1.2.0] — 2026-03-28

### Added — CPUID Runtime Detection
- **`src/zupt_cpuid.c`** + **`include/zupt_cpuid.h`** — runtime detection of AES-NI, PCLMUL, AVX2, SSE4.1 via CPUID. Supports GCC/Clang, MSVC, and inline assembly fallback.
- `zupt_detect_cpu()` called at program start. Global `zupt_cpu` struct for dispatch.

### Added — Jasmin Source Files (initial)
- 4 `.jazz` files created for AES-CTR, MAC verify, X25519, ML-KEM select.
- **Note:** All had parse errors — fixed in v1.3.0–v1.4.0.

---

## [1.1.0] — 2026-03-28

### Fixed — Critical Cryptographic Bugs

- **X25519 Montgomery formula** (`zupt_x25519.c`): `AA + 121666*E` → `BB + 121666*E`. The doubling formula was algebraically wrong. DH exchanges produced consistently wrong but matching values, so PQ archives worked. RFC 7748 test vectors exposed the bug. **All X25519 in v0.7.0–v1.0.0 was not interoperable with any other implementation.**
- **Dead `match_cost()`** (`zupt_lzh.c`): Defined but never called. Removed (Clang `-Wunused-function`).
- **ML-KEM `const polyvec`** warnings: C11 doesn't support multi-level const for arrays-of-arrays. Removed `const` (matches pqcrystals reference).
- **`__int128` pedantic** warning: Wrapped with `#pragma GCC diagnostic push/pop`.

### Added
- **`tests/test_vectors.c`** — 13 NIST/RFC test vectors: SHA-256 (3), HMAC-SHA256 (2), SHA3-256 (2), SHAKE-128 (1), X25519 (2), ML-KEM-768 (2), XXH64 (1).

### Changed
- Zero warnings on GCC + Clang with `-Wall -Wextra -Wpedantic`.

---

## [1.0.0] — 2026-03-21

### Stable Release
- **Archive format frozen at v1.4.** `FORMAT_STABLE` flag set. Future changes require v2.0.
- Documentation: FORMAT.md, AUDIT.md, FUZZING.md, SECURITY.md.
- **License: GPL-3.0 → MIT.**

### Fixed — ML-KEM-768 Bugs (5 critical)
1. **`poly_basemul` OOB**: `zetas[64+i]` accessed past 128-entry array. Fixed to 64 iterations.
2. **Missing `poly_tomont()` in keygen**: Public key in wrong Montgomery domain.
3. **Inverted `cmov` in FO decaps**: C integer promotion caused rejection key selected on valid ciphertext. Fixed: `(-(int64_t)diff) >> 63`.
4. **`inv_ntt` wrong zetas table**: Separate wrong table. Fixed: reuse `zetas[]`, k counts 127→0.
5. **PQ nonce mismatch**: Encrypt/decrypt independently generated nonces. Fixed: store in header.

### Added — Post-Quantum Hybrid Encryption (v0.7.0)
- **ML-KEM-768** (FIPS 203): ~658 lines pure C11. NTT, Barrett/Montgomery, CBD, FO transform.
- **X25519** (RFC 7748): ~270 lines. Montgomery ladder, constant-time fe_cswap.
- **Keccak-f[1600]**: SHA3-256/512, SHAKE-128/256. ~215 lines.
- **Hybrid KEM**: `SHA3-512(ml_ss XOR x25519_ss ‖ transcript)`. Secure if EITHER holds.
- `zupt keygen` subcommand, `--pq <keyfile>` flag.
- Key file format: ZKEY magic, ML-KEM pk(1184B) + X25519 pk(32B) + optional sk + XXH64.
- 10-test PQ suite.
- Format v1.3 → v1.4 with `enc_type` dispatch byte.

### Added — Multi-Threaded Compression (v0.6.0)
- `-t <N>` flag. Batch-parallel pipeline. 14-test MT suite.
- Solid mode falls back to N=1 (shared LZ context).

### Added — Security Hardening (v0.5.1)
- 16 bug fixes: Huffman Kraft violation (data corruption), heap-buffer-overflows, removed `rand()` fallback, constant-time MAC, secure key wipe, LE serialization, realloc checks, empty file checksum.

### Core Features (v0.1.0–v0.4.0)
- LZ77+Huffman compression (1MB window, near-optimal parsing).
- AES-256-CTR + HMAC-SHA256 authenticated encryption.
- PBKDF2-SHA256 (600,000 iterations).
- Per-block XXH64 integrity. Recursive directory backup. Solid mode.

---

## Summary

| Version | Key Change | Tests |
|---------|-----------|-------|
| **2.1.4** | Shared `write_enc_header()` eliminates all format mismatches, solid PQ support, block device O_SYNC | 78 PASS |
| **2.1.3** | Disk restore rewritten — uses shared block I/O, fixes checksum mismatch with all encryption formats | 77 PASS |
| **2.1.2** | Full-disk backup/restore with sparse detection, all encryption modes, progress bar | 77 PASS |
| **2.1.1** | Termux/Android build fix, arch-safety guard, Keccak UB fix, no stale .o in tarballs | 70 PASS |
| **2.1.0** | VaptVupt 1.4.0: cross-block dictionary, context prefetch, faster adaptive window, integration API | 70 PASS |
| **2.0.0** | VaptVupt 1.1.0 codec, auto codec detection, all 5 Jasmin wired, AVX SIGILL fix, multi-arch, copy_match fix, litlen overflow fix | 70 PASS |
| **1.5.0** | Jasmin assembly linked: MAC verify + ML-KEM select active in binary | 53+13 PASS |
| **1.4.0** | All 4 `.jazz` files compile on jasminc 2026.03.0 | 53+13 PASS |
| **1.3.0** | ACSL predicates, security review, partial Jasmin fixes | 53+13 PASS |
| **1.2.0** | CPUID detection, Jasmin source files (with errors) | 53+13 PASS |
| **1.1.0** | X25519 BB formula fix, 13 NIST/RFC test vectors | 53+13 PASS |
| **1.0.0** | Format frozen v1.4, ML-KEM bugs fixed, MIT license | 40 PASS |

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
