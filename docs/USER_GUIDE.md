# ZUPT user guide

This guide covers the supported command-line and graphical workflows for ZUPT.
Every example uses a disposable path, makes verification explicit, and keeps
passwords out of process arguments.

## Release status

The official public release is [ZUPT 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
Version 5.2.10 remains unpublished until the complete validation matrix passes,
including the required formal-analysis and assembly gates. A source checkout
whose version string says 5.2.10 is not an official download.

ZUPT Web is available at <https://zupt-web.securityops.co> for disposable,
non-sensitive examples. It is a separate deployment; its limits, version and
trust boundary must not be assumed to match a local installation.

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

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git checkout v5.2.9       # use v5.2.10 only after its official publication
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
permission only to a binary you have verified. For a source bundle, inspect
the extracted tree before building:

```sh
zupt test zupt-5.2.10-source.zupt
zupt extract -o source-check zupt-5.2.10-source.zupt
find source-check -maxdepth 2 -type f -print | sort
```

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
verified source modes before running build helpers. The recorded 281-file local
round trip passed on 2026-10-16, followed by strict Clang 22.1.8 `make check` and
the CLI functional suite from the extracted tree, with explicit skips. That
snapshot precedes this documentation update; it is not a signed release or
native package qualification.

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

The installer includes both guides and their linked SECURITY/DISTRIBUTION
policies. The regression checks real staged bytes, mode 0644, a custom data
directory and missing-guide rejection before any installation output. Native
GUI DEB builds use this installer, but these staging checks do not build or
validate the DEB. Other native packaging helpers have separate payload and
runtime gates. Source-header and test-script references need the checkout.

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

The helper checks the matching CLI, requests unencrypted VaptVupt level 9,
tests the container, verifies the exact 17-file inventory including both user
guides under `docs/` and their linked SECURITY/DISTRIBUTION policies in the
bundle root, scans both source
trees and compares all extracted bytes. It writes the `.zupt`, its SHA-256
sidecar and a retained `.extracted` directory. Existing output targets are
refused. A publication error can leave verified partial outputs for inspection;
the helper does not delete final paths that another process may have replaced.
This local rehearsal is not a signed release or native package approval.
Python, Qt and the independently tested CLI remain external dependencies.
Source-header and test-script links still require the checkout; this is not a
complete offline copy of the repository documentation.
Run an extracted shell launcher through `bash`, not by assuming executable
permissions survived extraction.

On 2026-10-18, a fresh strict GCC 14.3.0 CLI passes its functional script and
all 12 methods in `test-portable-gui`. The tests use real archive operations
and verify the current 17-file payload, checksum, extracted bytes, encryption
and codec settings, rejected CLI failures, altered members, symlinks and
output-publication races. The archives are temporary test data, not signed
release assets; the suite does not execute Qt. `make audit-licenses` also
passes its covered-source SPDX-marker checks, not a complete provenance,
REUSE, patent or redistribution-rights audit. Reproduce these separate gates
with the matching tested CLI and installed build tools:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-portable-gui
make audit-licenses
```

The 2026-10-07 Linux x86_64 VM run passed 39/39 tests with GCC 14.3.0,
Python 3.12.12, PyQt6 6.9.1 and Qt 6.9.2. It also created a level-9 `.zupt`
containing exactly 13 frontend files, verified the archive and compared all
extracted bytes with the assembled sources. The newly built matching CLI
remained outside that frontend bundle; Python and Qt are external dependencies.
Seven unavailable static/packaging checks were recorded separately. These
results cover the frozen 248-file snapshot, not subsequent documentation
changes, native package installation, desktop integration or release approval.

## Validation and reporting

Before a version can be published, the project runs strict GCC and Clang
builds, unit/integration tests, sanitizers, bounded fuzzing, source-only
content scans, package checks and disposable-VM workflows. `release-check`
depends on `test-jasmin-source`, `test-jasmin-wipe-checker`,
`test-frama-ans-decode-bounds`, `test-frama-ans-reader`,
`test-frama-ans-frequencies`, `test-frama-ans-logarithm`,
`test-frama-ans-log-bounds` and `test-frama-aes-nist` on an x86_64
Linux maintainer host with their required tools and AES-NI/OS-enabled AVX.
These analyses are not dependencies of distribution-friendly `check` or
`test-all`. Broader formal review remains required before publication;
missing tools or incomplete evidence are blockers, not passes. The standalone
wipe checker verifies only the pinned emitted assembly sequence; it is not a
substitute for the Jasmin safety and constant-time tools. See
[SECURITY.md](../SECURITY.md),
[DISTRIBUTION.md](../DISTRIBUTION.md) and the project test scripts for the
current command matrix.

### Portable check supervision and tool coverage

The Frama-C supervisors explicitly preserve analyzer/compiler version-query
failures before parsing the version. This addresses the missing-tool status
failure observed in the native macOS check. Run their maintained controls:

~~~sh
make -j1 test-frama-aes-nist-wrapper test-frama-ans-decode-bounds-wrapper \
  test-frama-ans-reader-wrapper test-frama-ans-log-bounds-wrapper
~~~

The 2026-10-31 Linux run passes 320 synthetic cases, including failed probes,
missing tools, timeouts, incomplete reports and parser failures. Four private
status-loss mutations are rejected. These are supervisor tests, not formal
analysis or evidence of a successful native macOS rerun.

`make test-sdk-build-flags` runs 36 SDK selection/export controls. Its generated
tool launchers use the running Bash's absolute executable path, which must not
contain whitespace. Installed utilities are invoked at their original quoted
paths so MSYS can find its runtime DLLs. The isolated tool `PATH` and all
after-output failure checks remain active. The no-`/bin` and executable-location
models each reproduce nine failures before the fix and pass all 36 checks
afterwards; they do not replace native Guix and Windows qualification.

Previously unavailable tooling checks were also executed on 2026-10-31.
With fish 4.9.3, zsh 5.9.2 and either mandoc 1.14.6 or groff 1.24.2,
`bash tests/test_completions_manpage.sh` passes 23 checks without skips in
each renderer profile. Ruby 3.4.7, Nix 2.32.8 and the pinned Guix reader
pass the syntax checks used by `bash tests/test_packaging_syntax.sh`.
Debian changelog parsing passes in GitHub run `41181738059`. Syntax checks
do not establish native package installation. Optional full SDK/PQ providers
and the privileged loop-device case remain separate requirements; the base
SDK is not a replacement for the full provider.

### Current formal evidence, reviewed 2026-10-31

The 2026-10-31 UTC repeat of all six maintained Frama-C targets passes on the
frozen 294-file source after the five ANS guard corrections: decoder bounds,
reader, frequencies, logarithm, logarithm bounds and fixed-vector AES. The
tools are Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 and recognized Z3 4.12.2.
Each target retains its own model, caller assumptions and exact result
checks; these conditional results do not prove the whole application.

The 2026-10-31 UTC ordinary Jasmin 2026.09.0 repeat on the same source
passes compilation, safety, CT, DOIT, lowering and generated/runtime
instruction comparisons for all five selected sources. Seven tools/libraries
match the pinned package members. Two environment rejections, four warning
controls, seventeen wipe controls, 1,026 AES/OpenSSL blocks and 1,539 CTR4
cases pass. This is selected source qualification under the documented
preconditions, not whole-program verification, final-package acceptance or
the separate `WITH_JASMIN=1` application integration check. Raw logs and
source/tool integrity checks are retained. Later documentation edits are
outside the measured snapshot.

With the exact tool versions, machine models and prerequisites described
in the audit sections below, run the maintained targets sequentially:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-frama-ans-decode-bounds test-frama-ans-reader \
  test-frama-ans-frequencies test-frama-ans-logarithm \
  test-frama-ans-log-bounds test-frama-aes-nist \
  test-jasmin-source-wrapper test-jasmin-wipe-checker test-jasmin-source
~~~

### Local precommit checks, 2026-10-28

The actual GCC 14.3.0 static-analysis script passes nine checks on the
subsequent 294-file snapshot. Its three optional cppcheck scans are `NOT RUN`
because cppcheck is absent. Distribution-state controls pass 17 cases,
publication tests pass 21, and DEB/RPM helper controls pass 20/55. The actual
source-policy scan passes 294 files and zero archives. Source, tool and
supervisor integrity checks pass before and after the bounded runs.

From a fresh source copy in an isolated builder, run:

~~~sh
CC=gcc bash tests/test_static_analysis.sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-dist-source-state test-packaging-failures
bash scripts/check-source-only.sh --tree .
~~~

The packaging controls use tool doubles and temporary fixtures, not native
DEB/RPM installations. The tree scan does not approve a tag or final archive.
Later documentation and signing-key instructions are outside that snapshot;
final signed-source and package gates remain separate requirements.

### ANS exact-output bounds

The sequence decoder checks the remaining destination length before forming
wide-copy pointers. This corrects five guards without changing APIs, the frame
grammar or which copy path is selected for valid buffers.

Use a fresh source copy for each compiler or sanitizer configuration. Run:

~~~sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-decode-bounds
make test-frama-ans-decode-bounds
make test-frama-ans-decode-bounds-wrapper
~~~

Inside a disposable VM, use another fresh source copy for scalar
ASan/LSan/UBSan validation. Local fixture runs record the qualified toolchain
and frozen source; this command uses your compiler's installed sanitizer
runtimes:

~~~sh
env \
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    make -j1 V=1 CC=clang WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
    CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror -DVV_DISABLE_SIMD=1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' \
    LDFLAGS=-fsanitize=address,undefined test-ans-decode-bounds
~~~

A sanitizer diagnostic or nonzero exit is a failure. Repeat with `CC=gcc`
from another fresh copy to qualify GCC separately. If the VM exposes AVX2,
repeat from a fresh copy, replacing only `-DVV_DISABLE_SIMD=1` with `-mavx2`.
Keep the other flags and options unchanged. Otherwise record the AVX2
configuration as `NOT RUN`.

The native test requires successful decoding into exact-sized destinations:
four literals, then v1/v2 match tails at distances 16 and 8. It retains the
three malformed ANS4 metadata rejection fixtures. The Frama-C 29.0 script
analyzes the actual scalar production match-copy path with invalid-pointer
warnings enabled, `gcc_x86_64`, `slevel=5000` and `plevel=4096`. Its observed
result is 558/983 reached statements in 16/95 functions, zero alarms and
63 valid preconditions with zero unknowns or invalids.

Six exact `Frama_C_show_each_*` witnesses follow the fixture assertions. They
prevent allocation-failure returns or pruned success paths from qualifying the
analysis. Allocation failure remains modeled; native builds require allocation
and decode success. Frama-C libc models express the C assertions as
preconditions, so the separate ACSL Assertions count is zero. The 82 synthetic
controls check result handling and required options; they do not execute the
decoder or Frama-C.

This profile covers raw-literal sequences with single-symbol sequence tables
and the three metadata cases. It does not establish general decoder, Huffman
or SIMD safety.

On 2026-10-27 UTC, the corrected 294-file source snapshot passed the actual
strict GCC 14.3.0 and Clang 22.1.8 `test-all`, `audit-licenses`, `sdk-test`
and `sdk-verify-symbols` targets in disposable 2-CPU/2-GiB VMs. Both compilers
also passed the focused native and scalar/AVX2 ANS exact-output tests with
ASan, LSan and UBSan. The full CLI builds are ordinary builds; these focused
sanitizer results do not instrument the entire application.

A separate GCC build with `WITH_JASMIN=1` passed the same full-suite and
SDK/license/symbol targets. Its vector test required the actual
`Jasmin AES-NI` dispatch with OS-enabled AVX state; it was not a portable
fallback. The prior Jasmin source analyses and instruction comparisons
remain separate checks.

Each full profile records 15 explicit skips. Clang lacks OpenSSL in its
selected guest; GCC instead skips the modeled bionic header case requiring
Clang. Native Windows, privileged loop devices, unavailable shell/manual
tools and optional system providers remain outside these results. Each
profile passed 16 isolation controls, three real sanitizer negative controls,
ordered completion and diagnostic checks. Product stages recorded no OOM,
PID-limit event or surviving descendant within the unchanged 768-MiB,
16-task target envelope.

Earlier compressed-image-limit failures and the GCC combined-stage timeout
are retained. The passing profiles preserve all selected inputs and global
caps; the focused GCC repetitions now have separate supervised stages while
the actual `test-all` retains its 300-second limit. Later documentation edits
are outside these runtime snapshots. Full `release-check`, native platform
and GUI/package acceptance, final archives and signatures remain pending.

From a fresh source copy, reproduce the ordinary GCC targets:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror' \
  test-all audit-licenses sdk-test sdk-verify-symbols
~~~

Repeat with `CC=clang` from another fresh copy. For a separate supported
x86_64 Jasmin build, use another fresh copy and `WITH_JASMIN=1`; inspect
the vector output for the selected AES path. Keep optional providers
disabled unless their system dependencies are explicitly qualified.

The earlier full-suite results below predate these five guard changes. Full
`release-check` and final-package acceptance remain separate requirements.

### Earlier GCC and GUI validation, 2026-10-23

The 2026-10-23 UTC run of the actual strict GCC 14.3.0 `test-all` passes on
294 frozen source files in the disposable 2-CPU/2-GiB VM, with 15 explicit
skips. It includes 81 ASan exact-size cases, 1,024 BCJ bijections, byte-exact
BCJ L5/L9 round trips, timing regression and three ML-KEM/OpenSSL comparisons.
The ordinary CLI is not wholly sanitized by the exact-size test.

A separate VM with PySide6/Shiboken6/Qt 6.9.2 passes 64 current GUI tests,
33 historical reference tests and six bootstrap controls. Its CLI has the
same bytes as the executable used by the passing full GCC suite. The CLI and
control artifacts are compiled without execution in an isolated host build;
sanitizer controls and GUI workflows execute in the guest. This is offscreen
Qt validation, not native desktop or final-package installation coverage.

These project entry points use the default compiler flags. The
[audit command matrix](#reproduce-the-audit-checks) describes strict flags,
tool versions and sanitizer settings. Run these checks in a qualified
disposable VM with the required compiler, sanitizer runtimes, Python and Qt binding:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
QT_QPA_PLATFORM=offscreen make -j1 CC=gcc \
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check-gui
~~~

Both recorded runs require real negative sanitizer controls, complete ordered
supervision and unchanged source hashes. The old Qt-input failure and the
full-image size failure remain recorded; the successful runtime profile keeps
all isolation/resource limits. Skips remain untested coverage. Final docs,
a fresh Clang full suite, broader formal review, complete `release-check` and
final packages still need their own acceptance.

### Bounded ANS logarithm proof

Analyze the actual scalar shift-based `ilog2` with Frama-C **29.0**, GCC
**14.3.0**, Why3 **1.7.2** and recognized Z3 **4.12.2** on `gcc_x86_64`:

```sh
make -j1 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-logarithm
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-reader-wrapper
```

The proof enables `VV_ANS_LOG_WP` annotations only for this explicit profile.
For `0 <= v < 4096`, it proves result 0 for zero, result range 0–11 and,
for positive values, `2^result <= v < 2^(result+1)`. The twelve explicit
intervals keep the recurrence linear. A redundant OR-bound invariant lets
WP relate the mask-zero exit condition to addition; both invariant goals
are proved with the native bit-range tactic. No new axiom or executable C
substitution is introduced. This does not restrict the userspace helper to
that input domain or prove that every caller supplies it.

The gate requires **50 exact, valid, non-smoke JSON goals** and the
**52/52** console summary, including the two implicit results. It retains
proof scripts and raw JSON. Each row must have one proved goal and, when
present, an integer `subgoals` count of exactly one. Partial, boolean and
zero totals fail, as do unknown loop invariants despite valid postconditions.
All 132 synthetic supervisor cases pass; removing the two subgoal checks
produces nine failures. These fixtures validate result handling, not C
semantics. A separate false-postcondition run confirms actual rejection.

The integrated source passes strict GCC/Clang `check` and CLI functional
smoke with 11/10 explicit skips. Real fatal UBSan controls precede each run;
the existing fuzz-build UBSan tests execute, not an ASan/LSan campaign.
GCC preprocessing matches baseline in the default/frequency/logarithm
profiles. Scalar complete `-O2 -g0` objects match with both GCC and Clang.
This is a bounded helper theorem and focused regression result,
not table/caller, whole-codec, package or production approval. The new formal
target is required by `release-check`, not distribution-friendly `check`.
Final documentation is outside the measured runtime snapshot.

### ANS frequency validation

The frequency profile checks the actual `validated_symbol_count` implementation,
not a substitute decoder. Use Frama-C **29.0**, GCC **14.3.0**, Why3 **1.7.2**
and recognized Z3 **4.12.2** on the tested little-endian `gcc_x86_64` target:

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-frequencies
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-ans-allocation test-frama-ans-reader-wrapper
```

The WP profile enables only guarded ACSL annotations and explicit unsigned
overflow checks. It requires 256 readable, initialized frequencies and a
writable, separate output integer. Its 23 exact non-smoke JSON goals prove
the return range and that a positive return implies every frequency is at
most 4096; the maximum possible sum is 16,776,960. The console includes two
additional termination/unreachable results (25/25). These assumptions are
not automatically proved for decoder callers or a general decoder proof.
The earlier count of 14 unknowns belongs to a historical valid-stream Eva
profile; it is not a refreshed inventory of the current tree. Other maintained analysis profiles do not
enable this contract or assume it instead of analyzing the body.

On 2026-10-22 UTC, that gate and the unchanged reader/metadata gates pass.
A private wrong-acceptance mutation leaves only the frequency postcondition
unproved and is rejected. Both reader/frequency result profiles pass 40
synthetic controls each; rejected results now retain the raw JSON. These
controls validate reporting, not C semantics. Strict scalar GCC/Clang runs
also pass eight direct frequency vectors. A private narrowing mutation
passes the old tests but fails the new `65535 + 4097` wrap regression.
GCC preprocessing matches the previous C exactly, with or without the
annotation macro; no runtime, API or wire-format change is introduced.

The 2026-10-22 294-file snapshot additionally passes the direct 79,560-state,
two-refill ANS test and all eight frequency vectors under ASan/LSan/UBSan in
the disposable two-CPU/2-GiB VM. Real sanitizer negatives precede the test;
the matching instrumented Huffman object, exact source digests, 25 ordered
completion records and process/collector/source postchecks are verified.
CLI sanitizer smoke and separate ordinary SDK/ML-KEM interoperability checks
also pass. Final documentation changes are outside that runtime snapshot.
This is not a fresh full `test-all`, Jasmin, Qt or final-package qualification,
a whole-program proof, or approval to publish/install the release.

### ANS decode-table entry bounds

The existing `test-ans-allocation` target also tests `build_dec_direct` over
every frequency split between symbols 0 and 255, including single-symbol
endpoints, and one uniform 256-symbol table. It checks **16,785,408 entries**:
initialized fields after poisoning the destination, widths at most 12,
`baseline + (2^nbits - 1) < 4096`, active symbols and exact multiplicities.
Width is checked before shifting; subtraction is checked without underflow.

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
```

On 2026-10-22 UTC, strict scalar GCC 14.3.0 and Clang 22.1.8 runs pass. The
same expanded test passes ASan/LSan/UBSan in the two-CPU/2-GiB disposable VM,
along with the existing 79,560-state reader test, eight frequency vectors and
CLI sanitizer smoke. The wrapper requires all three test markers, exact
source digests and the complete 25-record protocol. SDK/license/export and
three ML-KEM/OpenSSL comparisons pass in separate ordinary builds, not under
SDK/provider sanitizer coverage. Final documentation is outside that snapshot.
A targeted private width mutation is rejected only by the expanded test.
These bounded fixtures are not all arbitrary three-or-more-symbol tables,
decoder round trips for each split, wire-format equivalence or a general proof.

A separate private Frama-C 29.0/Z3 4.12.2 WP experiment remains incomplete:
109 valid JSON goals, 17 timeouts and three warnings concerning `memset`
specification/Typed pointer casts (console 111/128). Its annotations are not
part of the codec. A postcondition shown valid while its loop invariants
remain unproved is not an established theorem. The general width/count,
source-span, table construction and caller obligations still require a
traceable disposition; neither historical counts nor these test passes close
them automatically. This work does not approve production publication.

### Earlier maintained formal repeat, 2026-10-21

On 2026-10-21 UTC, all four maintained Frama-C gates pass once each on the
fixed 294-file source with Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 and recognized
Z3 4.12.2. Real unsat/sat controls and target-endianness checks precede every
run. Metadata reaches 138/358 statements with 20 valid preconditions; reader
init/take has 30 exact valid JSON goals (console 34/34); logarithm ranges
have two valid assertions and two preconditions; four fixed AES blocks reach
162/162 statements with 21 valid assertions, seven preconditions and 64 byte
checks. These Eva runs have zero alarms. The reader's exact raw JSON SHA-256
is `c166b4a85791e86a3884828ad9651699a9a9da37054dfed13eaacb3d98bd0cd0`.

Separate ordinary and qualified-UBSan Jasmin 2026.09.0 runs pass the five-source
gate, generated/runtime instruction comparison and wipe-store checks. Each
passes 1,026 AES blocks and 1,539 AES4 cases. Scratch-environment negatives
reject before each run; a real signed-overflow control rejects before UBSan.
UBSan instruments the C fixtures, not assembly or provider executables.
For all six runs, outer/process/collector statuses and source postchecks pass.
The namespace retains two-CPU affinity, 1-GiB per-process address-space and
120-second CPU limits, 125+5-second wall deadline, 128-MiB scratch and 1-MiB
emitted-output collector cap; these are not aggregate cgroup quotas. Named
tool hashes do not cover every host helper or complete dependency closure.

With the exact tool versions and prerequisites described in the formal
sections below, reproduce the maintained targets sequentially:

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-frama-ans-decode-bounds test-frama-ans-reader \
  test-frama-ans-log-bounds test-frama-aes-nist test-jasmin-source
```

Final documentation edits are outside these measured snapshots. Earlier
diagnostics retain their original scope. These checks do not prove the full
reader/refill or C callers, arbitrary-key AES, register erasure or physical
side-channel resistance. Required alarm/unknown disposition, actual
`WITH_JASMIN=1` runtime and final source/package/platform qualification remain
separate conditions; the repeat does not approve production or publication.

### CI credential-gate regression

Run the shipped test with Bash, Git and Python 3 in a disposable test environment:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ci-credentials
```

This target also belongs to `check` and source-policy CI. It extracts and
executes the actual literal Bash block from `.github/workflows/ci.yml`, without
requiring a YAML library. Six test methods cover a clean tracked fixture,
nine synthetic credential patterns, five erroneous/inconsistent Git outcomes,
invalid block layouts and inherited Git overrides. An outside synthetic
repository/index sentinel must remain unchanged. Fixtures use private
temporary repositories, no commits or real credentials; matched contents must
not appear in output.

The encrypted-private-key fixture failed against the previous workflow: it
returned success for the PKCS#8 `ENCRYPTED PRIVATE KEY` label specified in
[RFC 7468, section 11](https://www.rfc-editor.org/rfc/rfc7468.html#section-11).
The corrected expression rejects that header as well as the existing private
key forms. The clean fixture now also contains public-key, RSA public-key and
certificate headers, which must remain accepted. These are synthetic headers,
not usable keys or a PEM parser test. All six methods and the actual gate on a
private index of the selected 283-file source snapshot pass after the fix.

The gate accepts only `git grep` status 1 with empty findings. Matches,
operational errors and inconsistent results fail without printing a clean
message. Git's stderr remains visible. The original code falsely accepted
three injected outcomes; those failures and the inherited-environment failure
remain in the local evidence.

Before the encrypted-key extension, all six methods passed on 2026-10-17
with Python 3.12.12, Git 2.54.0 and the original eight credential patterns.
Fresh GCC 14.3.0 strict `check` and CLI functional tests passed on the recorded
283-file snapshot before the documentation update, with 11 explicit ordinary
skips. Ruff 0.16.10 checks/format and Pyright 1.1.403 basic/default profiles
passed for the new test; each typing profile analyzed exactly one file using
the Python 3.8 target. That is not Python 3.8 runtime validation or clean lint
for the existing GUI. Recorded executions used a networkless, read-only-source
namespace with private RAM scratch, two CPUs, a 1-GiB address-space limit and
at most 64 processes. This narrow pattern policy does not qualify the separate
full credential scanner, hosted CI, native packages or the release.

A separate pinned Gitleaks 8.30.1 startup check remains blocked: nonempty clean
input exits 2 with a detector error under the unchanged 1-GiB address-space
limit. The diagnostic records a 4-GiB virtual reservation; this is not evidence
of 4 GiB of resident RAM use. Version and invalid-input controls do not start
the detector and cannot qualify it. The pre-fix 283-file inventory classified
279 UTF-8 text files and four binary images, but no project file was scanned.
Per-file text scans would also need to state that stdin supplies no original
filename, so filename-dependent rules are not qualified; binary images and
decoded/archive contents require separate coverage. Keep this failure distinct
from the passing narrow CI pattern policy.

The distribution gate requires a clean committed source tree. `make dist`
rejects staged or unstaged changes, deleted tracked files, and untracked source
or tests before replacing any archive. Only `dist` uses Bash with `pipefail`:
both `git archive` and gzip must succeed before the content scanner runs or
the output is delivered. Other targets retain their existing shell.

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-dist-source-state
```

The target runs 17 controls: the existing eight clean/dirty-source checks,
a successful producer-shim control with byte comparison, and eight producer
failures covering Git/gzip, empty/complete output, and absent/existing
destinations. Failed producers must not reach the scanner; existing output
keeps its bytes and inode identity. Shims forward real Git/gzip output when
requested, but the scanner is a phase-order fixture. These tests do not
qualify its content policy, a final source commit or native packages.

For local work in progress, keep runtime checks separate from release-package
evidence; package validation must name the source snapshot actually archived.
The reproducible tarball remains an internal distribution-build input, not a
public release asset. Public bundles use genuine `.zupt` archives.

Run `make test-quick-harness` to check that the quick suite rejects child
failures and damaged or missing extracted files. The actual quick suite compares
the text, random and empty fixtures and requires successful compression,
extraction and integrity-check exits.

When reporting a failure, include the command, compiler/toolchain version,
commit or source digest, exit status and the raw log location. A successful
round trip is evidence for that fixture only; it is not a proof of safety or
of compatibility with every historical archive.

### Native package documentation checks

The DEB and RPM CLI/GUI helpers run `scripts/check-installed-docs.py` on the
actual extracted package before delivering it. It requires both user guides
under `docs/` plus SECURITY/DISTRIBUTION in their parent directory. The
documentation must match the source byte-for-byte, use mode 0644 and contain
no symlink components. Debian, Fedora and openSUSE documentation layouts are
supported, including the exact current version suffix where used. Missing or
duplicate package directories fail closed; stale version directories do not
substitute for the current package. Debian's helper route preserves `.md`
filenames instead of breaking relative links through automatic compression.

Run the focused checker tests without compiling the CLI:

```sh
make test-installed-docs
```

To inspect a private tree already extracted from a verified local build:

```sh
python3 scripts/check-installed-docs.py . /absolute/private/extracted-root zupt
```

Use `zupt-gui` as the last argument for the GUI package. The command is
read-only and checks documentation only; it does not extract archives,
authenticate packages, approve native dependencies or replace runtime tests.
The source and extracted tree must be private and not concurrently modified.
The regression tests use synthetic files and the real checker; the packaging
suite additionally checks a real source-GUI installation staging tree. Those
results are not a native DEB/RPM build or installation result.
These metadata fixtures require a POSIX package-build host; Windows, MSYS and
Cygwin runs report explicit skips rather than asserting Unix file modes there.
Use the existing `PYTHON` Make variable to select the installed interpreter.

### RPM spec metadata

With the distribution's actual RPM tools, inspect a reviewed spec in an
isolated package-build environment. Macro expansion can invoke helpers:

```sh
rpm --version
rpm --eval '%{_prefix} %{_bindir} %{_buildshell}'
rpmspec -P packaging/opensuse/zupt.spec
rpmspec -q --buildrequires packaging/opensuse/zupt.spec
```

Fedora build environments need `libubsan`: the maintained check suite links
and executes UBSan harness regressions. It is a build dependency, not an
additional runtime requirement of the installed CLI. The openSUSE spec uses
`%{?ext_man}` for the distribution's compressed man-page suffix. Run
`bash tests/test_packaging_syntax.sh` to check actual RPM expansion with `.gz`,
`.xz` and an undefined suffix; missing tools remain explicit skips. Local
parser checks do not replace native `spec-cleaner`, build or installation gates.

The 2026-10-18 check uses installed RPM 4.20.1 with explicitly selected Guix
`rpmrc` and x86_64-linux macro files, target `x86_64-unknown-linux`, and private
`_topdir`/`_tmppath`. Version, macro inspection, spec parsing and listing its
14 declared build requirements all return zero. The actual `_prefix` is
RPM's GNU-store directory; expanded build/install commands also reference
`/usr/bin` tools unavailable in that namespace. No `%prep`, build, check or
install section is executed. Do not override these differences or use
`--nodeps` to claim native openSUSE acceptance. Listing requirements does not
prove they are installed, and these results do not change an earlier full
metadata-suite count unless that suite is separately rerun.

### Package-tool failure regressions

Run the release-only DEB/RPM boundary tests without compiling or installing
packages:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-packaging-failures
```

This target is required by `release-check`, not distribution-friendly `check`.
It needs a Linux build host with Bash, GNU core utilities, `timeout`, `tar`,
`gzip` and Python 3. It runs private copies of the actual CLI/GUI package
helpers with controlled external-tool replacements. The DEB suite also runs
the real GUI installer and documentation checker in temporary staging trees.
It does not invoke a native package manager, build Zupt or change the host.

The tests require failed `rpm`, `find`, `sort` and `readelf` commands to stop
their helper even when they print plausible output first. They retain the
producer's diagnostic and exit status, check cleanup and reject advancement
past named validation checkpoints. Successful ELF inspection must still
reject RPATH/RUNPATH and optional vendored providers. DEB helpers must refuse
preexisting regular files and live or dangling output symlinks without
modifying their targets.

The target runs 21 publisher unit tests, 20 DEB cases and 55 RPM cases.
Metadata/ELF controls deliberately stop at named checkpoints; separate positive
controls exercise both complete RPM helpers through publication. These use
external-tool replacements and do not claim a successful native build.
Run each script directly to
retain per-case logs, traces and exit statuses in a new private directory:

```sh
env ZUPT_TEST_EVIDENCE_DIR=/absolute/new/private/deb-logs bash tests/test_deb_packaging_failures.sh
env ZUPT_TEST_EVIDENCE_DIR=/absolute/new/private/rpm-logs bash tests/test_rpm_packaging_failures.sh
```

These regressions do not qualify native dependencies, package installation,
signatures or a release.

The four native helpers require an output directory owned by the build user,
without group/other write permission. They hold a read-only directory
descriptor from before the build and use `scripts/publish-package.py` for
final publication. The descriptor is also inherited by build subprocesses;
it is not a security boundary against a malicious build tool or the same UID.
Path checks use Linux `O_PATH`, `O_DIRECTORY` and `O_NOFOLLOW`; ancestors need
search permission, not directory-list access, and symlinks are rejected.
Source files, their ancestors and private staging bindings must remain trusted.
Use a new private output directory for each attempt.

The publisher stages at most two regular packages, up to 1 GiB each, in a
private mode-0700 directory on the output filesystem. It checks copied lengths,
source metadata, writes and file synchronization before making mode-0644
artifacts visible. All basenames are preflighted before the first hard link;
each link then fails atomically if any final entry already exists, including
a dangling symlink or directory. Checksums describe staged bytes and are
printed only after the whole invocation succeeds, with GNU filename escaping.
No checksum sidecars are added by these helpers.

This is no-clobber publication per file, not a transaction for the complete
RPM pair or a crash-durability guarantee. A late failure may leave published
files; they are retained for inspection, never removed by final pathname.
Changed staging bindings are also retained. Namespace checks are snapshots,
not locks against arbitrary concurrent ancestor renames or privileged peers.
Inspect partial outputs and retry in a new directory rather than overwriting
them. Native package and release qualification remain separate.

### Linux disk-capacity ABI checks

These focused tests are also dependencies of `make check`:

```sh
make CC=gcc test-disk-ioctl-abi test-disk-ioctl-abi-wrapper
make CC=clang test-disk-ioctl-abi test-disk-ioctl-abi-wrapper
```

The C fixtures exercise the actual disk-capacity helpers with both libc ioctl
request types, capacities above 4 GiB, zero capacity and failed queries. Only
`fstat` and `ioctl` are replaced; the tests use a temporary regular file and do
not open a disk device. Caller compiler and linker flags are retained, assertions
stay enabled, and sanitizer diagnostics or child failures fail the check.
The 16 synthetic wrapper controls test the harness, not the product's C code.

With a selected Clang compiler, the script also checks the actual disk source
against a small model of bionic's signedness overload and documented opt-out.
Other compilers explicitly skip this header model without selecting a different
compiler from `PATH`. This model is not an Android/NDK build or runtime test.

### Archive-output capability checks

Run `make test-atomic-output-probe` for the 16 directory-capability supervisor
controls, also required by `make check`. They exercise caller flags, compiler
and child failures, sanitizer diagnostics and completion-marker validation
without replacing or running the CLI. The real archive-output test separately
runs the selected `zupt` binary and checks file preservation and cleanup.
The controls include empty caller flags and were executed with Bash 5.2.37;
older Bash runtime validation remains separate.

### Legacy disk fixture checks

Run `make test-legacy-disk-compiler` for four compiler-boundary controls,
also required by `make check`. They check caller flags, multiword `CC`,
empty/unset flags, strict warnings and visible compiler failures. A controlled
compiler failure stops before the CLI; these controls do not decode an archive.
The real compatibility test remains separate:

```sh
bash tests/test_legacy_disk_5_2_1.sh ./zupt
```

It decodes the checked-in encrypted/deduplicated 5.2.1 fixture and checks
`list`, `test`, generic extraction and disk restoration into temporary regular
files, comparing the restored bytes. It does not access a physical disk or
establish compatibility with every historical archive. Compiler and linker
flags must match the selected toolchain; static musl requires its normal
`LDFLAGS=-static` configuration.

### Reproduce the audit checks

Technical users can run the product checks from a fresh source-only checkout.
Run the license and source checks before compilation: the source scanner
examines the complete working tree, including ignored build output. Keep the
complete output and do not treat a skipped optional dependency as a pass:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 source-audit
bash tests/test_source_only.sh
```

The source-only regression runs 54 cases. Six inject failed tree, extracted-file
and Git-index enumeration after the real tool succeeds, with either no output
or one complete safe record. The scanner must return failure with a stage
diagnostic, not a PASS summary. Three pass-through controls and a rejected ELF
fixture check the setup. Enumeration uses fresh NUL-delimited manifests in
private scratch; partial output from a failed producer is never consumed.
The focused run and strict GCC 14.3.0 `check` passed on 2026-10-20; the latter
retains 11 platform/provider/tool skips. This verifies audit failure handling,
not concurrent tree mutation, complete codec safety or native packages.

Four additional cases check extracted-byte accounting using a 32-byte source
fixture. The real `wc` completes first; controls then return an error with
empty, zero or complete numeric output, or forward a successful count. Zero
and complete output reproduced false approvals before explicit pipeline-status
handling; empty-error rejection was already present. All four now pass, with
the existing 50 cases retained. The strict GCC `check` and real CLI functional
suite passed again on 2026-10-20 with the same 11 skips. The limits are unchanged;
this is not coverage of every accounting/tool failure or final packages.

After the source checks pass, compile and execute the runtime checks:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-asan-run
```

`test-asan-run` builds an AddressSanitizer/UndefinedBehaviorSanitizer binary
and executes a round-trip smoke test with leak detection. Building with
`test-asan` alone does not execute that test. To repeat the source scan after
runtime testing, use another fresh source-only checkout; generated binaries
are expected findings in the compiled tree.

#### Decode-slack test supervision

After building the CLI, run the supervisor controls and the real round trips:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-vv-decode-slack-harness
bash tests/test_vv_decode_slack.sh ./zupt
```

The first command runs ten synthetic CLI-boundary cases, including a path with
spaces, complete output followed by a nonzero exit, a failed later compressor
that leaves its earlier archive usable, and corrupt or missing extracted data.
Six cases reproduced false approvals before the fix. The real test now checks
every compression/extraction status before comparing bytes, uses separate
per-level/per-route files, prints failed-command diagnostics and cleans its
private fixtures on exit. The second command retains the 10-MiB repetitive
input at explicitly serial (`-t 1`) L1/5/9 and four-thread (`-t 4`) L1/9,
for both compression and extraction. The synthetic CLI rejects missing or
incorrect thread selections; six cases fail before the serial-routing fix.
Both commands are part of `check`.

Three further controls cover an empty directory, a preserved hidden file and
a cleanup-tool failure with empty stdout and status 73. The old output-only
`find` predicate incorrectly returned success for that failure. The checked
nonrecursive `rmdir` now propagates the error and diagnostic; it removes only
finished, owned fixture directories and cannot remove their contents.

An intervening complete check failed L5 compression with automatic 24-thread
selection under the unchanged 1-GiB address-space cap. Those purported serial
cases had omitted `-t 1`; this coverage correction does not identify the
failed allocation or repair automatic-thread memory behavior. On 2026-10-21
UTC, all ten supervisor cases, three cleanup controls and real round trips
pass in a fresh bounded strict GCC 14.3.0 `check`, followed by the actual CLI
functional suite. The 11 platform/provider/tool skips remain explicit, and
all 54 source-audit cases pass. The separate source scan covers 292 files.
Synthetic controls test shell supervision, not compression or cryptography.
This ordinary build is not a new whole-program sanitizer run, formal proof,
native-package validation or production approval.

#### SDK symbol-check supervision

Use a configured native GNU/Linux toolchain. Run the supervision controls
separately from the actual SDK build and runtime tests:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-sdk-build-flags
make CC=clang WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 sdk-test sdk-verify-symbols
```

The first target retains 25 compiler/recipe controls and adds 11 executions
of the real `sdk-verify-symbols` recipe against a synthetic prebuilt fixture.
It uses two literal expected exports, a synthetic `nm` and real forwarding
`awk`, `sed`, `sort`, `grep` and `tr`. Each injected error follows complete
output and the expected underlying status. Exact markers and traces ensure
an unrelated setup failure cannot satisfy a negative case. Normal operation,
missing/leaked functions, eight tool failures and checked temporary-directory
cleanup are covered. Six cases reproduced false approvals before the fix;
the two final-sort failures and missing/leaked functions already rejected.
All 36 controls pass after the recipe change. These controls do not compile
or execute the SDK, and do not establish runtime ABI compatibility.

The recipe now checks each producer separately instead of relying on the
last pipeline status. Its rejection scan accepts only grep's legitimate
no-match status 1, not tool errors. This retains the existing exported-text
(`T`) symbol policy, version map and portable shell; it is not an expanded
audit of every symbol class. The second command builds and exercises the
actual internal SDK and checks its exported functions. `WITH_SDK=0` disables
the external libvuptsdk adapter, not the internal SDK targets.

On 2026-10-21 UTC, the corrected 294-file snapshot passes strict Clang 22.1.8
`test-all`, followed by `audit-licenses sdk-test sdk-verify-symbols`, in the
qualified disposable VM. Use the complete flags under
[current-source suite](#jasmin-enabled-runtime-and-current-source-suite),
selecting the configured Clang for `CC`. All 24 ordered records and the
VM/collector/integrity/protocol statuses pass. This includes 81 ASan exact-size
cases, 1,024 BCJ bijections, byte-exact CLI BCJ round trips at L5/L9, three
actual ML-KEM/OpenSSL comparisons and 15 internal SDK cases. The timing gate
passes five runs with 200,000 samples per class and unchanged thresholds;
this is regression evidence, not a constant-time proof or codec benchmark.

Limits remain 2 CPUs/2 GiB, 768-MiB/16-task stages, 512-MiB scratch,
64-MiB files, 4-MiB stage output and 300-second product-stage deadlines.
Suite/SDK cgroup peaks are 233,459,712/33,243,136 bytes, without product-stage
OOM/PID-limit events or surviving descendants. Fourteen explicit skips
remain: native Windows, five external SDK cases, privileged loop device,
zsh/fish/manual tools, missing external SDK development package and three
disabled-provider integrations. SDK, PQBOX and Jasmin are disabled in this
full-suite profile; the selected-Clang bionic fixture runs. A separate ordinary
strict GCC 14.3.0 `check` and actual CLI suite pass with 11 skips. This is not
a globally instrumented build or new Frama-C/Jasmin qualification. Final
documentation edits are outside the VM snapshot. Complete raw VM transcript
SHA-256: `c3bc4b4264539b771eaa1a549efae830a9b57b26c36d367fbc17d87f73b2ca50`.

For release accounting, distinguish the six maintained Frama-C targets
(decoder bounds, reader initialization/extraction, frequency validation,
bounded logarithm, logarithm ranges and fixed-vector AES), the Jasmin
source/safety/constant-time/wipe checks, and
actual `WITH_JASMIN=1` runtime tests. Earlier measured results retain their
own source and tool identities. Historical research goal totals are not a
current pass/fail checklist. This does not waive review and resolution or
justification of required alarms/unknowns under the distribution policy,
broader formal scope, optional-provider coverage or final-package gates.
No selected target count alone establishes production readiness.

#### Exact-size and BCJ test supervision

After building the CLI, run the supervisor controls and the actual codec test
as separate targets:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-codec-exact-size-wrapper
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-codec-exact-size
```

The first target uses synthetic compiler/CLI processes and real file
enumeration. It retains ten compiler/status/signal controls and adds nine
BCJ cases: normal operation; compression/extraction that write complete output
then exit 73 at each of L5/L9; enumeration that emits a valid filename then
fails; and extra, missing or corrupt output. Five cases reproduced false
approvals before the fix. The other three negative cases already rejected
the old script. Failed stages must preserve all diagnostics, stop dependent
operations and never print a passing verdict; the other level still runs.

The actual supervisor now checks each stage's status before accepting its
output, reads a completed NUL-delimited manifest and requires exactly one
byte-matching extracted file. The existing ASan compiler/execution path is
unchanged. Synthetic controls do not execute the codec or sanitizer. The
second target needs an available ASan runtime and runs the real codec and
CLI BCJ checks; neither target alone establishes production readiness.

On 2026-10-21 UTC, the corrected 294-file snapshot passes strict GCC 14.3.0
`test-all`, followed by `audit-licenses sdk-test sdk-verify-symbols`, in the
qualified disposable VM. Use the complete flags and commands documented under
[current-source suite](#jasmin-enabled-runtime-and-current-source-suite).
All 24 ordered records and VM/collector/integrity/protocol statuses pass.
The real test reports 81 exact-size cases, 1,024 deterministic BCJ bijections
and byte-exact CLI round trips at L5/L9. The timing gate, 14 threaded checks,
ten PQ checks, 14 dedup checks, three actual ML-KEM/OpenSSL comparisons and
15 internal SDK cases also pass. Timing uses five runs and 200,000 samples
per class with unchanged thresholds; it is regression evidence, not proof
of constant-time execution. Threaded elapsed times are not codec benchmarks.

The VM retains 2 CPUs/2 GiB, 768-MiB/16-task stages, 512-MiB scratch,
64-MiB files, 4-MiB stage output and 300-second product-stage deadlines.
Product stages have no OOM/PID-limit events or surviving descendants.
The suite and SDK cgroup peaks are 236,765,184 and 95,404,032 bytes.
Fifteen explicit skips remain: native Windows, selected-Clang bionic fixture,
five external SDK checks, privileged loop device, zsh/fish/manual tools,
external SDK development package and three disabled-provider integrations.
SDK, PQBOX and Jasmin are disabled in this full-suite profile. A separate
ordinary GCC `check` and CLI suite pass with 11 skips. This is not a new
Clang, full-program sanitizer, Frama-C/Jasmin or final-package qualification.
Final documentation edits are outside the VM snapshot; production remains
unapproved. Complete raw VM transcript SHA-256:
`d88e75ad5903048f498f43043d780ce9f56aedd067bebed6cb7d458e3cff89b0`.

#### Worker allocation failures and archive preservation

Run the maintained target with a native Linux compiler and a GNU-compatible
linker supporting `--wrap`. It also needs GNU Make, Python 3 and `timeout`:

```sh
make CC=gcc CFLAGS='-O2 -g -Werror' \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-worker-allocation

make CC=gcc CFLAGS='-O2 -g -Werror -fsanitize=undefined -fno-sanitize-recover=all' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=all' \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-worker-allocation
```

The target builds a private CLI from the real core with test-only link
wrappers; normal binaries never link the injector. Caller flags are retained,
with explicit `-fno-lto` so interception remains visible. SDK, PQBOX and
Jasmin are disabled in this private build. Non-Linux/cross targets are skipped;
an unsupported linker on an eligible native target is a failure, not coverage.

A fixed 65,536-byte input uses STORE, two workers and 65,536-byte blocks.
Five cases cover normal operation and deliberate failures at worker 0's
initial compression buffer (76,288 bytes) and final payload (65,536 bytes),
each with an absent or existing destination. The test verifies the exact
allocation sequence, two successful thread starts, validated worker returns,
one injection, normal status 1 and the block out-of-memory diagnostic. Timeouts, signals,
fixture errors and sanitizer diagnostics fail the test. Existing destination
bytes must remain unchanged; absent destinations stay absent. Checked `rmdir`
rejects hidden temporary leftovers. The normal archive must verify and extract
byte-exactly. Complete command output and statuses are printed.

On 2026-10-21 UTC, all five cases pass with strict GCC 14.3.0 ordinarily and
with non-recovering UBSan under the unchanged bounded profile. The expanded
ordinary `check` and real CLI suite also pass, retaining 11 explicit skips.
This is regression coverage of existing failure handling, not a newly fixed
runtime bug. Clang was unavailable in the checked tool locations. These
STORE-only cases do not diagnose the earlier automatic-24-thread OOM, prove
leak freedom, cover encrypted allocation failures, or qualify native packages
or production. No new Frama-C/Jasmin proof or full VM sanitizer run is implied.

#### Static-analysis gate controls

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-static-analysis-harness
env CC=gcc bash tests/test_static_analysis.sh
```

The first command runs 53 supervisor scenarios. They cover source discovery,
silent compiler failures, `grep` errors before or after complete output,
invalid or inconsistent counts, very large counts, warnings and forbidden
source patterns. Missing SHA-NI source must stop before compilation; removing
it later must not silently omit its checks. Source changes in these controls
are confined to private fixtures, and assertions use the real `grep`.

These controls use compiler/analyzer doubles; they do not perform C analysis.
The second command runs the actual GCC warning policies and available cppcheck
passes. Missing cppcheck remains a skip, not a clean analysis result. Keep
complete logs and exit codes. A valid no-match status is distinct from a
failed tool or unreadable result, even when the latter already printed zero.

`source-audit` checks source-only content policy, not leaked credentials.
A secret detector that fails to initialize does not establish a clean scan.

#### SDK callback tests

The SDK and CLI share the explicit `WITH_JASMIN` selection. On supported
x86_64 builds, `WITH_JASMIN=1` selects the checked-in assembly in SDK C
callers as well as linking the assembly objects. The portable default remains
`WITH_JASMIN=0`; this does not enable external CLI providers in the SDK.

Check the build recipes without compiling:

```sh
make WITH_SDK=0 WITH_PQBOX=0 test-sdk-build-flags
```

Its 25 assertions check six C compilation rules with assembly disabled and
enabled, caller `CPPFLAGS`, and exclusion of external CLI provider flags and
libraries. It is also part of `check` and `sdk-test`. Recipe checks do not
replace runtime tests. For real assembly-enabled builds, start from a clean,
disposable checkout for each compiler:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 \
  SDK_BUILD_DIR=build/sdk-gcc sdk-test sdk-verify-symbols
```

Repeat with `CC=clang` in another fresh checkout. Separate SDK output
directories do not isolate shared CLI or Jasmin objects. The SDK currently
leaves CPU feature detection at its default state: linked AES assembly does
not establish SDK hardware AES dispatch. No SDK throughput improvement is
claimed from this build correction.

The in-tree `libzuptsdk` compatibility library has its own tests. Run the full
SDK suite or just the 13 callback cases:

```sh
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test sdk-verify-symbols
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-stream-errors
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-staging
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-file-reads sdk-test-key-ownership
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-read-stop sdk-test-temp-paths
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-key-write-errors
make CC=clang SDK_BUILD_DIR=build/sdk-ubsan \
  CFLAGS='-O1 -g -Werror -fsanitize=undefined -fno-sanitize-recover=all' \
  sdk-test sdk-verify-symbols
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:hard_rss_limit_mb=512 \
  UBSAN_OPTIONS=halt_on_error=1 \
  make CC=clang SDK_BUILD_DIR=build/sdk-asan \
  CFLAGS='-O1 -g -Werror -fsanitize=address,undefined -fno-sanitize-recover=all' \
  sdk-test sdk-verify-symbols
```

These use the real archive implementation with injected file-boundary failures.
They check byte-exact roundtrip, a read error after 17 delivered bytes,
short/negative callbacks, `max_bytes + 1` and `INT64_MAX` input counts,
close failures and first-error preservation. Streams are really closed even
when the test injects a close error. The fixture requires `fopencookie` and
linker `--wrap` support. An output callback can receive a partial archive before
an error; discard that output if the operation fails. The callback interface
stages files and is not an incremental decoder.

For SDK operations, select a caller-owned private temporary directory through
`TMPDIR` on POSIX, with mode `0700` and trusted ancestors. Cleanup and later
reopens assume other users cannot replace its entries. Exclusive creation
alone cannot enforce that assumption in an attacker-controlled parent.

The 26 original temporary-path checks include real long-directory truncation, injected
formatting failures at each of the 15 helper invocations, usable baseline
fixtures and final allocation cleanup. All nine public callers must reject a
failed/truncated name with `ZUPTSDK_ERR_IO` before using it. The tests preserve
foreign-file bytes and inode identity, output pointers and descriptor counts;
compression streams must not consume input before both names are ready.
Nested failures remove only staging files already owned by the operation.
Windows directory-query guards still require native Windows qualification.

On glibc, two additional controls verify valid checked formatting and actual
libc rejection of an inconsistent reported destination bound. The rejection
uses a physically sufficient buffer and requires the expected abort and libc
diagnostic; a sanitizer failure or unrelated signal cannot pass. Interceptors
cover plain and fortified formatting without dropping format flags or bounds.
The first hosted 5.2.10 run exposed the missing fortified interception; it was
a test-coverage failure, not an observed production formatting failure.

On 2026-10-29, strict full SDK suites pass locally with GCC 14.3.0 and Clang
22.1.8 in ordinary, `_FORTIFY_SOURCE=2` and `_FORTIFY_SOURCE=3` profiles,
including all 28 temporary-path cases each. A control mutation discarding the
forwarded bound fails the new rejection case while the original 26 still
pass. Hosted Ubuntu and final native-package qualification remain separate.
Use a fresh source copy for each compiler/profile:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  SDK_BUILD_DIR=build/sdk-fortify3 CPPFLAGS='-D_FORTIFY_SOURCE=3' \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror' \
  sdk-test
~~~

Repeat with `CC=clang`, with fortification level `2`, and with empty
`CPPFLAGS` for the ordinary profile. Keep optimization enabled for glibc's
fortification and use separate SDK build directories for distinct flags.

The 18 read-stop cases exercise key copying and archive delivery through the
output callback. They check that a positive partial `fread` with an error is
not followed by another read, and that exact prefix bytes are delivered once.
Read failures take precedence over short/failed output callbacks and close
errors. A nested failed SDK call inside an output callback must not replace
the outer read diagnostic. Failed key copies preserve the destination's bytes
and inode identity; partial callback output must be discarded.

`sdk-test` also includes 40 private-staging cases across compression streams,
buffer compression, directory extraction, verification and decompression
streams. These check mode `0600` and close-on-exec under `umask 000`, preserve
the contents and device/inode identity of colliding files and links, and inject
permission, stdio-conversion, write and close failures. The SDK retains the
exclusively created handle and removes only files it created on failure.
Ordinary GCC and separate Clang/UBSan and Clang/ASan/UBSan runs passed these
cases after integration. The rebuilt CLI also passed all 52 key-file checks
and eight functional checks. Windows COFF compilation
and six bridge-model cases are recorded separately; they do not validate
Windows linking, execution or DACL enforcement.

The file-read target adds 58 cases covering size/seek/read/close and allocation
failures in file/buffer compression, buffer extraction and both readbacks of
stream decompression. It checks unchanged outputs on failure, no premature
output callback, wiped incomplete buffers, closed handles and first-error
preservation when closing also fails. Empty-file extraction must work even
when the allocator returns `NULL` for a zero-byte request.

The key-ownership target adds 19 cases for generated-file cleanup after
allocation failure, repeated public-key export/destruction and preservation of
caller-loaded private/public files. Regular-file, symlink and hardlink
collisions retain both bytes and identity. Saved keys and loaded key paths
remain caller-owned. These tests do not validate every core key-write error;
the separate key-write regression checks the SDK's failure cleanup.

The 74 key-write checks inject creation, permission, negative/zero/partial
write, synchronization and close failures. Internal creation flags allow the
SDK to remove only its own temporary private/public keys; colliding regular
files, symlinks and hardlinks retain their bytes and identity. Cleanup and
custom allocator callbacks must not replace the first error. The existing CLI
key writer deliberately retains failed outputs for inspection; that contract
is tested separately and unchanged. These checks do not qualify Windows
cleanup of non-ASCII paths, failed handles or native DACL behavior.

On 2026-10-15, a fresh ordinary GCC 14.3.0 build and separate Clang 22.1.8
UBSan and ASan/UBSan builds passed the 15 SDK checks, all 13 stream cases and
the exported-symbol check. These host
tests do not replace VM, package-installation or whole-program formal gates.
An additional whole-core `-Wconversion -Werror` build failed on existing signed
index conversions in `src/zupt_lz.c`; that stricter exploratory build remains
failed. The new stream fixture itself passes those conversion/prototype flags.

#### Native key-file read tests

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-native-key-read-errors
```

This target is also part of `make check`. Its 66 cases exercise real ZKEY and
ZPQK generation, export, encryption and decryption with injected stream errors.
They check positive partial reads with an error set, public-key EOF, the
required trailing probe for full private keys, trailing junk/read errors,
close failures and malformed headers/checksums. Rejection preserves `EINVAL`
and caller outputs; streams close once. Internal buffer wiping is reviewed
in the implementation, not directly observed by this fixture.

The fault injection requires GNU/Linux cookie streams and linker wrapping.
Windows, Darwin, BSD and Android report an explicit skip; an empty or unknown
compiler target is an error. Recorded native runs use glibc, not musl or
Windows. The ordinary key-file tests remain necessary on every supported OS.

#### Threaded-suite password and integrity controls

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-threaded-harness
```

This target is also part of `make check`. It runs the actual threaded script
with a synthetic CLI. The original 14 controls remain: one positive and
13 T9 negatives cover status
0/2/127, unrelated status 1, child termination, four diagnostic markers,
NUL-prefixed output and operational failures in both log scans. Each negative
must fail specifically T9 while the other 13 cases pass; an arbitrary script
failure is not accepted as evidence. The former guard falsely accepts 12
controls. The corrected guard requires CLI status 1, a clean full-log scan
and `Error: Authentication failed`; a scan error is never a clean result.

Twenty more negatives exercise T10: nonzero status, child termination,
sanitizer text (also after NUL), unrelated output containing `0 failed`,
`10 failed`, a wrong file count, missing/duplicate/conflicting summaries,
a NUL-prefixed conflicting summary and failures in all three log scans.
Each must fail only T10 with the other 13 script cases passing, plus a fault
receipt; scanner faults also require a tool receipt. The original T10 falsely
accepts 18 of the first 33 controls. The next NUL-conflict control exposes
the first fix, which only counts summaries beginning with whitespace.

The final guard requires CLI status 0, no sanitizer markers and exactly one
line matching `  Test: 9 passed, 0 failed (9 files)` (including two leading
spaces). All nine regular files, including empty and nested entries, count;
directories do not. It counts every line containing `Test:` to reject
competing summaries regardless of their prefix. Both scan status and count
must be valid: a tool printing `1` before failing cannot approve T10.
This password/integrity group retains 34 controls. They are included in the
existing Guix interpreter/self-copy tests as well as `make check`.

Seven workspace-lifecycle controls bring the subtotal to 41. They
execute the real suite with an exclusive private temporary parent containing
spaces, restore caller `umask 000`, and check a real mode-0700 directory and
a suite-generated mode-0600 file. A precreated historical-name symlink points
only to a private dummy sentinel, which must remain unchanged. Other controls
require cleanup and status 129/130/143 for HUP/INT/TERM, or status 1 before
any CLI invocation for an unusable parent or failed `mktemp`. All seven fail
against the old setup; its INT control exits zero and its generated file
has mode 0666. The corrected setup passes all seven.

`TMPDIR` must name a trusted parent that another user cannot replace. The
suite now uses `mktemp -d`, stops on creation failure and cleans up through
its exit trap. SIGKILL and interruption of the supervisor itself can leave
temporary fixtures, including the test-only legacy-name symlink; cleanup is
not guaranteed in those cases. Do not use valuable data as test fixtures.

Nine JSON-fixture controls bring the subtotal to 50. The suite keeps
the original seed-42 generator but requires its successful exit and a separate
validation of exactly 5,000 records, sequential integer IDs, matching
`user_ID` names and finite floating-point scores. Empty, short, malformed,
overlong and schema-invalid output, non-finite scores, a generator emitting
complete data before failing, and a validator printing success before failing
must all stop with status 1 before the first compression. The controls require
the fault receipt, diagnostic, workspace cleanup and absence of compression,
extraction or integrity commands; an invalid interior record is checked too.
All eight negatives fail against the old unguarded producer. The normal
fixture is checked independently without regenerating scores. Its observed
SHA-256 matches the pre-fix output with the pinned Python; this is not a
cross-version determinism claim or validation of arbitrary JSON producers.

Ten binary-fixture controls bring the subtotal to 60. Before T1, both
`dd` producers must exit successfully and a separate validator must accept
exactly 512,000 bytes of random data and 204,800 bytes of zero data. The
normal control independently checks both sizes and the zero content at the
first compression. For each producer, controls inject complete output followed
by failure, or successful empty, short and oversized output. All eight expose
false approvals in the old script. A ninth negative makes the new size
validator print success before failing. Each negative requires status 1,
the fault receipt, diagnostic, workspace cleanup and no T1, summary or
compression/extraction/integrity calls. Producer diagnostics are retained.
At that fixture-only milestone, the original 50 controls and T1–T14 bodies
were unchanged. Random bytes are not deterministic, and these controls do
not validate arbitrary producers.

Eleven T14 controls bring the subtotal to 71. Both the N=1 and N=4
compressors must exit zero and leave a regular, nonempty output before any
timing-success report. The clean control verifies both calls in order;
ten negatives cover each phase failing before output, failing after complete
synthetic output, or returning zero with missing, empty or directory output.
All ten expose false approvals in the old script. Corrected failures require
status 1, exactly one T14 failure and totals of 13 passed/1 failed, retained
stdout/stderr diagnostic markers, invocation receipts and workspace cleanup,
without elapsed-time, speedup or timing-unavailable success output. The
earlier 60 control functions and calls remain unchanged. T14 now retains a
separate merged stdout/stderr log for each compressor and shows both on failure.
This file-type/length guard does not establish archive integrity; it does not
check clock/`awk` failures or sanitizer diagnostics from a zero-exit process.
Elapsed times remain informational, not reproducible benchmark evidence.

Eight T6 controls bring the current total to 79. T6 requires both compression
and extraction to exit zero, exactly 1,000 regular output files, and a recursive
path/content comparison of the complete small-file tree. The expected root
retains the absolute input prefix without its leading slash, as confirmed by
a real list/extract probe; the T6 fake now mirrors that layout. Five controls
expose false approvals in the old gate: complete output followed by compressor
or extractor failure, and same-size corruption, renaming or relocation of
unsampled `file_2.txt`. Missing/extra-file controls cover existing count
rejections whose stderr was previously discarded. Each negative requires
status 1, one T6 failure, 13/1 totals, both diagnostic markers and workspace
cleanup; the clean control requires 14/0. Earlier 71 control functions and
calls are unchanged. The corruption control unlinks its output before writing
and verifies that original `file_2.txt` bytes remain unchanged. This is not
a metadata/permission check, full parser audit or performance measurement.
All 79 controls pass; a separate real-CLI run passes 14/14 threaded checks.

The fixtures hardlink only generated private data to bound scratch usage.
They do not run the codec or encryption, and the script's synthetic timing
output is not a throughput measurement. Run the actual CLI separately:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' \
  CARGO=false WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
bash scripts/test-installed-zupt.sh ./zupt
sh tests/test_threaded.sh ./zupt
```

The recorded GCC 14.3.0 `check` and functional suite pass with Cargo disabled;
11 unavailable checks remain explicit (Windows, one modeled bionic-header
case, five external-SDK cases, a privileged loop device, zsh, fish and man-page
renderers). The separate real threaded run passes 14/14, including
1/2/4/8-thread round trips, encryption, wrong-password rejection and integrity.
Its elapsed times are not reproducible performance evidence. Other
command-status and fixture-generation gaps still need correction. Neither
this result nor the synthetic controls replace sanitizer-runtime, final
package or production validation.

#### Installed executable checks

Check the actual installed or staged executable separately:

```sh
bash scripts/test-installed-zupt.sh /path/to/staged/bin/zupt
```

The Guix CLI recipe now runs this script with its exact `$out/bin/zupt`
after standard stripping and RUNPATH validation. It honors `#:tests? #f`;
cross-builds skip the new check by default, as the standard GNU check phase
does. A skipped check is not installed-runtime acceptance. Test the phase
wiring with Guile and the Guix modules available:

```sh
guile --no-auto-compile -q -s tests/test_guix_gui_install_plan.scm
```

The Scheme controls execute the real phase with a recording script to check
ordering, paths containing spaces and child failure propagation; they do not
run the codec. Separately, the recorded private staged profile builds the
current CLI with strict GCC, installs it with Make, runs the real Guix
postprocessing phases and passes the functional script after removing the
build-tree executable. Removing the installed binary then makes the phase
fail. This does not lower a derivation, resolve its native dependency closure,
install a user profile or qualify the recipe's withdrawn source origin.

The SHA-256 manifest stage checks hash producers as well as enumeration and
sorting. Any failed stage rejects the smoke gate, including a producer that
prints plausible output or leaves both manifests empty. Byte comparisons and
CLI status/sanitizer checks remain separate requirements.

Test the validator itself with the actual CLI:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-installed-smoke-harness
# Or use an already built executable:
bash tests/test_installed_smoke_harness.sh /path/to/staged/bin/zupt
```

On POSIX hosts this runs 65 cases: the existing 53 process-boundary controls
and 12 checksum-tool controls. Both checksum interfaces have a successful
control, empty/plausible failed hash output, and failed enumeration/sorting.
Private tool adapters forward to the available real SHA-256 engine; the
`shasum` branch does not require Perl for these controls. They validate the
script's failure handling, not native Perl, macOS/BSD/Windows packages,
sanitizer coverage or production readiness. Windows skips the POSIX signal
fixtures explicitly.

This exercises synthetic archive round trips and failure handling; it does
not install anything into a user profile or replace the formal gates.
In the recorded 2026-10-09 GNU Guix CLI experiment, the real derivation's
build, enabled `check` and installation phases passed in a disposable VM.
The earlier complete volatile run of the same source and derivation records
ten explicit skips. Exporting its output
for durable retention then failed the bounded compressed-file limit.
In a subsequent bounded binary-transfer experiment, the exact output was
captured, restored in private temporary storage and reserialized byte-for-byte.
The command above passed all eight checks against the actual CLI candidate.
The complete VM classifier still rejected that run: final console receipts
were truncated at poweroff, and the quiet client omitted phase/test logs.
This does not override the failed acceptance gate
or establish sanitizer coverage, GUI validation or production approval.
Another run of the same frozen source and derivation restored full phase
logs and used a bounded console drain before poweroff. Its complete native
and volatile classifiers passed, with the ten explicit skips and identical
output size/hash. That run transferred no package; it does not make the
earlier binary-transfer run an accepted package.
A separate run on 2026-10-10 completed the full native and volatile
classifiers and compared its fresh UART stream byte-for-byte with the
preserved candidate through EOF. Producer, collector, compressor and
comparison statuses were all zero; ten explicit skips remain. This verifies
the transfer in that run without creating another durable artifact.
A subsequent private retention check stored a 277,792-byte XZ copy of the
exact output. It passed single-stream CRC32 validation, full decoding and
comparison through EOF, checked file/directory synchronization and complete
readback. Restoration from that compressed copy, NAR reserialization and
all eight actual CLI smoke checks passed against the preserved raw reference.
Thirteen synthetic retention controls passed separately; those controls do
not audit the product or prove physical durability. This closes only the
private retained-copy gate, not power-loss durability or release approval.
Public software packages still require `.zupt`; XZ here is private evidence.
Earlier failed runs remain failed. The later documentation changes were not
part of the frozen build. That installation phase is inside the VM, not a
host installation: native GUI packaging, immutable reviewed source,
formal/constant-time closure, signatures and final release validation remain pending.
Do not substitute an older recipe pin or skip tests to promote 5.2.10.

For packaging metadata and the Guix CLI/GUI phase tests, run from the source
root with Guile, Guix's Scheme modules, `sh`, `bash`, `python3` and `make`
on `PATH`. Keep an external deadline for subprocess failures:

```sh
timeout --kill-after=2s 30s guile --no-auto-compile -q -s tests/test_guix_gui_install_plan.scm
NIX_REMOTE=dummy:// timeout --kill-after=2s 30s bash tests/test_packaging_syntax.sh
```

The focused test evaluates the actual recipe and executes Guix's copy install
phase in temporary storage. It checks the installed GUI manpage, project and
GUI license files, asset provenance, module-relative icon, both user guides and
the security/distribution policies byte-for-byte: ten GUI file checks in total.
It also executes the actual CLI documentation phase and compares both installed
guides plus `SECURITY.md` and `DISTRIBUTION.md`, for four CLI file checks.
On 2026-10-17, the extended regression first fails on missing CLI
`DISTRIBUTION.md`; after that entry is fixed, it detects missing GUI
`SECURITY.md`. The corrected recipe passes both sets of real installed-file
checks. A fresh strict GCC run also passes all 17 stages, CLI functional tests
and 56 actual offscreen GUI tests with 11 ordinary skips, on the corrected
282-file snapshot before this results-only documentation update. The source
origin is deliberately unchanged; these phases do not establish a native Guix
derivation, complete dependency closure, package-manager installation or release.
The fixture-interpreter regression executes the actual standard
`patch-source-shebangs` phase before the recipe's generated-fixture patch phase,
then runs nine shell-only control groups. The reader, logarithm and
exact-size wrappers start as non-executable source files and copy themselves
into executable tools; this catches missing source-shebang preparation without
requiring a real compiler or Frama-C run. It does not build or run the codec.
The DEB/RPM groups additionally run the actual packaging helpers with tool
doubles: all 20 DEB and 55 RPM cases must pass. The recipe patches their
generated interpreters too; entry-shebang patching alone is insufficient.
This regression detects those omissions in a Guix-style environment without
`/usr/bin/env`; a conventional host can conceal that dependency.
A recorded networkless namespace run omits `/bin/sh` and `/usr/bin/env`, checking
that generated fixtures use the selected store interpreters. The recipe's
withdrawn source pin, native build and real Qt closure remain separate gates.
A separate host run applies those actual source phases to the complete
281-file snapshot, then passes strict GCC 14.3.0 `make check` and the real CLI
functional suite. It executes 29,413 codec boundary checks; SDK/PQBOX/Jasmin
are disabled for that build. The 11 explicit skips cover native Windows,
the Clang-only bionic header model, five SDK sweeps, privileged loop devices,
zsh, fish and manpage renderers. Source hashes and modes are checked before
and after testing. This is host validation, not a Guix derivation or GUI run.
The theme icon remains installed
separately; the relative copy lets the Python module find its own image.
The test also executes the actual `make-launcher` and `install-desktop-file`
phases with controlled default-output package paths. A recording Guile
executable stands in for Python: it checks exact argument boundaries, including
empty strings, spaces, quotes, a matching glob and a newline; unset, empty and
inherited path variables; the pinned CLI, complete 48-leaf library prefix,
exit status 37 and executable mode. Required desktop fields include the
generated `Exec` path with `%F` and `Icon=zupt-gui`. This probe does not run Qt.
The parent environment is restored and the subprocess pipe is closed/reaped,
including on read errors. Eight deliberate mutations in private recipe copies
were rejected by the corresponding checks; these controls are not product bugs.
The 2026-10-10 isolated metadata run recorded 55 passes, zero failures and
two skips (Make and `dpkg-parsechangelog` unavailable); Nix parsing used its
`dummy://` store without persistent storage. These checks do not build
dependencies, perform full Gexp/store lowering, verify the pinned remote archive
or validate a complete native GUI package or real desktop launch. Missing Guile
is a skip in the metadata suite, not a pass for the focused test.

A separate isolated probe used the same recipe phases with existing installed
dependencies and the privately restored CLI. With inherited Python/plugin/library
paths removed and a conflicting `ZUPT_BIN`, the generated launcher returned
`zupt-gui 5.2.10` and passed the real offscreen six-tab selftest, selecting
`/tmp/package/bin/zupt`. It used Python 3.12.12 and PySide6 6.9.2/Qt 6.9.2 under
the limits below. Some installed leaf versions are older than the recipe's
current snapshot; this is runtime evidence for those specific inputs, not
validation of the target Guix dependency closure or a native GUI build.

For direct Python testing of a prepared GUI, use an environment with PySide6
and its Qt dependencies. Select the matching staged CLI and module explicitly:

```sh
env ZUPT_BIN=/path/to/staged/bin/zupt \
    ZUPT_GUI_MODULE=/path/to/staged/lib/zupt-gui/zupt_gui.py \
    QT_QPA_PLATFORM=offscreen python3 -B tests/test_gui_workflows.py \
    BootstrapGuardTests CapabilityLabelTests WorkerLogTests SupervisorTests \
    GuiWorkflowTests.test_plain_vaptvupt_archive_actions \
    GuiWorkflowTests.test_password_vaptvupt_archive_actions \
    GuiWorkflowTests.test_cancel_before_worker_start
```

This selects 38 tests, not the complete suite. On 2026-10-10 they passed with
Python 3.12.12, PySide6 6.9.2/Qt 6.9.2 and the privately restored native Guix
CLI 5.2.10. A separate probe verified the exact CLI path/version, discovered
the installed relative icon and ran the six-tab offscreen selftest. The checkout
and installed tool store were mounted read-only in an unprivileged, networkless
sandbox: CPUs 0/1,
1-GiB per-process address space, 32-MiB temporary storage, 1-MiB file limit
and a 30-second outer timeout. The full suite's close/cancel test creates a
32-MiB file and was not run in this profile; its fixture and criteria remain
unchanged. Run the full `check-gui` command above in a suitably provisioned
disposable environment. The selected workflow run used direct Python execution,
not the generated launcher. The separate launcher probe above does not establish
full workflow coverage, real X11/Wayland desktop activation or a complete native
GUI derivation. The CLI build remains tied to its earlier frozen source.

A subsequent, separate RAM-only profile ran all 39 unchanged tests on
2026-10-10: zero failures or skips, including closing the window while the CLI
was running, cancelling the child and joining the worker. For the full suite,
omit test selectors and inherit bytecode suppression into its child process:

```sh
env PYTHONDONTWRITEBYTECODE=1 \
    ZUPT_BIN=/path/to/staged/bin/zupt \
    ZUPT_GUI_MODULE=/path/to/staged/lib/zupt-gui/zupt_gui.py \
    QT_QPA_PLATFORM=offscreen \
    timeout --kill-after=2s 135s python3 -B tests/test_gui_workflows.py
```

Use a disposable environment with PySide6 and its Qt dependencies configured.
Its teardown must terminate and reap all descendants, including separate
sessions; the example timeout command alone does not provide that isolation.
The complete run used 128-MiB temporary storage, a 32-MiB file limit and a
135-second outer deadline; the unchanged suite supervisor has a 120-second
deadline. The existing close/cancel fixture writes exactly 33,554,432 bytes,
so it cannot fit the earlier 1-MiB file limit or 32-MiB temporary-storage
profile. The new profile retained CPUs 0/1, a 25-second per-process CPU limit,
1-GiB per-process address space, 64 file descriptors, disabled core dumps,
synthetic UID/GID 65534, read-only source/tools and no network, home, Guix
daemon or host display. These are not aggregate RAM limits or a VM test.
The earlier profile and its recorded partial result were not changed.

The full workflows used direct Python execution of the current installed GUI
module and the privately restored CLI from the earlier frozen source, with
existing Python 3.12.12 and PySide6/Qt 6.9.2. Before this run, the actual
recipe-generated launcher again passed its version and six-tab offscreen
selftest checks. This does not establish real desktop activation or validate
the current recipe's dependency closure. At that snapshot, Guix's
`copy-build-system` removed the standard `check` phase and the GUI recipe
did not add it back: those external workflow results must not be attributed
to a native GUI build.
A complete native GUI derivation and the remaining release gates are still
pending.

The 39-test result above predates the completed-job lifetime fix. A separate
real-CLI probe then reproduced one, two and three finished job objects
remaining parented to the live tab. The added regression failed before the fix
and passed afterward: three operations, no remaining job children and exactly
one destruction notification for each job, thread and worker while the window
remained open. The worker is deleted when its thread finishes; the controller
schedules its own deletion only after the existing native join and active-list
removal. Archive and cancellation tests now observe thread destruction instead
of calling methods on disposed Qt objects, retaining their real child-status,
widget-state and GUI-thread assertions.

All 40 tests subsequently passed without failures or skips using the same
separate full-suite profile and prepared inputs. The full command above now
includes the new regression; to select it alone, append
`GuiWorkflowTests.test_completed_jobs_release_qobjects_before_window_close`.
This checks the observed Qt object lifetime, not aggregate RSS leakage,
arbitrary concurrency, PyQt6 compatibility or the pending native GUI package.

The close-confirmation dialog runs a modal event loop: a job in the initial
snapshot may finish and be destroyed before the user confirms cancellation.
The new regression reproduced a deleted-QThread error with a real CLI job.
The close handler now takes a fresh active-job snapshot after confirmation;
it does not retain a disposed thread across that event loop. The focused
regression and then all 41 tests passed; the full suite also passed again
after the final test-source correction, without failures or skips. To select
the new case alone, append
`GuiWorkflowTests.test_job_finishing_during_close_confirmation_does_not_use_deleted_thread`
to the command above. The staged-input and isolation limits above still apply;
these runs do not approve a native GUI package or production publication.

Python syntax checks passed for the two modified Python files. Ruff 0.16.10
reported the same 29 diagnostics and two unformatted files before and after
these changes; no new diagnostics remain, but these lint and format checks
did not pass. Pyright did not reach analysis: V8 could not
reserve its code range under the unchanged 1-GiB per-process address-space
limit. That type check remains blocked, not passed.

### Guix GUI build-time checks

The updated GUI recipe adds `check` after `install-desktop-file`; checks are
enabled by default. It runs the installed `zupt-gui --version` and
`zupt-gui --selftest`, then invokes Python with `-B` to execute
`tests/test_gui_workflows.py` without test selectors. `ZUPT_BIN` selects the
matching input CLI and `ZUPT_GUI_MODULE` selects the installed module. Qt runs
offscreen, and child processes inherit bytecode suppression. Setting
`#:tests? #f` deliberately skips this gate; such a build does not establish
GUI test coverage.

Launcher generation and the workflow check share the same Python, Qt plugin
and library path calculation. The check removes inherited path values before
running the launcher, then sets the exact package paths for the direct Python
workflow run. It restores the complete parent environment on success or child
failure. A failed version check, selftest or workflow invocation stops the
phase instead of accepting earlier successful output.

The focused Scheme command above also checks phase ordering, default and
explicitly enabled testing, disabled testing without child execution, the
three exact child invocations, clean paths and environment restoration.
Each child position is tested with exit status 37 and Guix's real invocation
error. Its recording executable validates wiring, not Qt behavior.

Separately, the actual new recipe phase ran the real installed launcher,
six-tab selftest and all 41 workflows twice on 2026-10-10, including after
the final recipe formatting change: no failures or skips, exact completion
marker and restored environment. This used the separate RAM-only profile
above, existing Python 3.12.12 and PySide6/Qt 6.9.2, the current installed GUI
and the CLI restored from the earlier frozen source. It did not run a native
GUI derivation or validate the recipe's current dependency closure. Pure
package metadata and similarly named store directories are not authenticated
derivation outputs or proof that the required closure is available.

On 2026-10-16, a separate run used a freshly built matching CLI and the
current GUI from the recorded 281-file snapshot. The actual install, launcher,
desktop and check phases passed with existing Python 3.12.12 and PySide6/Qt
6.9.2: 13 installed-file byte comparisons, six-tab selftest and all 41 workflows.
All 17 recorded stages passed, including strict GCC checks and real CLI smoke
tests; their 11 unavailable platform/provider/tool checks remain explicit.
This was a networkless offscreen host run, not a native Guix derivation or
dependency-closure test. It manually mapped existing library outputs as data.
The unchanged cancellation test needs a 32-MiB fixture: only the GUI stage and
its CLI children received that per-file cap, while ordinary stages retained
16 MiB, inside the same 128-MiB temporary RAM filesystem. The earlier driver
error and 16-MiB fixture-capacity failure remain failures; neither test nor
oracle was weakened. Later documentation and test-supervisor edits are not
part of that snapshot. Qt's C-locale fallback and Guile's imported-binding
notice are retained in the raw log.

The recipe's source origin still selects the earlier release-tag archive;
it does not yet select these edited sources. A native acceptance run must
use the reviewed final source pin, the actual target inputs and a separately
admitted disposable build profile. Current retention limits do not admit
the existing native GUI experiment. No package installation or release
approval follows from the staged phase result.

On 2026-10-17, three new literal-rendering regressions failed against the
unchanged rich-text log. The plain-text log then passed all 50 tests through
the actual installed GUI recipe phase: the previous 41 tests, eight widget
controls and one real POSIX archive-path round trip. Checks cover markup,
entities/Unicode, repeated and empty/multiline appends, read-only height,
effective stylesheet, selection and scrolling. Run `make check-gui` as shown
above to include them; the POSIX filename case is explicitly skipped on
platforms that cannot represent that fixture.

The recorded host run used fresh GCC 14.3.0 CLI sources and existing Python
3.12.12/PySide6/Qt 6.9.2, with the same networkless 128-MiB RAM filesystem,
2-CPU/1-GiB process limits and separate 32-MiB GUI fixture cap described above.
All 17 stages passed, including strict CLI checks and functional tests; their
11 ordinary skips remain explicit. The selected source contained 282 files
before this documentation update. Neither PyQt6 nor a native Guix dependency
closure or real desktop session was tested. This does not approve the release.

Separate Python quality checks remain non-clean: Ruff reports the same 29
diagnostics on the saved baseline and modified sources, and both fail its
formatting check. Earlier Pyright attempts exited 133 during code-range
reservation and 134 during heap allocation under the 1-GiB address-space cap;
those failures remain recorded. Archive format, cryptography and CLI arguments
are unchanged by the display correction.

A later 2026-10-17 run reproduces 22 failing stream assertions before fixing
per-chunk UTF-8 decoding. Five additional test methods exercise 31 real-worker
scenarios: every split in 2/3/4-byte characters, bytewise input, LF/EOF,
interleaved progress, malformed/truncated sequences, empty EOF and worker
reuse. Deterministic `read1` boundaries wrap a real child process; completion
must follow reaping and pipe closure. All 55 tests then pass in the installed
GUI phase, together with fresh strict GCC checks, CLI functional tests and
17 recorded stages; 11 ordinary skips remain explicit. The same provider and
resource profile above applies. Only this later 282-file snapshot contains
the UTF-8 fix, before the subsequent documentation update. No native-package,
PyQt6, whole-suite sanitizer or production approval follows. Total output
retention remains a separate resource-review concern; this fix adds no cap.

For Python type analysis, a paired isolated Linux experiment kept the same
2 CPUs, 1-GiB address-space cap and V8 interpreter/heap options. Default glibc
arenas aborted with status 134; setting `MALLOC_ARENA_MAX=1` allowed the same
baseline analysis to finish. Recorded `VmPeak` fell from 1,048,480 to 819,064
KiB; these are recorded process observations, not codec benchmarks. A separate
run with correctly scoped relative inputs then analyzed exactly the then-current
GUI and test file using real PySide6/Qt 6.9.2 declarations and Python 3.12.12.
Pyright 1.1.403/Node 24.18.0 completed configured basic analysis with status 1:
three unresolved optional PyQt6 imports and twelve invalid Qt base classes.
The default-mode command below additionally reports a possibly-unbound `obj`
in the existing lifetime fixture, for 16 errors total. Runtime import
alternatives are not a statically selected provider. No diagnostics were
suppressed; that snapshot does not pass type checking or qualify both providers.

The subsequent preferred-provider profile uses PySide6's real declarations.
`TYPE_CHECKING` prevents static merging with the optional provider; its runtime
value is false, so the existing PySide6-first/PyQt6-fallback imports remain.
Concrete types exposed ten diagnostics from the controller's `thread` storage
hiding the inherited `QObject.thread()` method. A real Qt regression reproduced
the resulting `TypeError` before private `_thread` storage fixed it. The test
checks the controller, worker and QThread-object affinities before starting the
real CLI, then waits for normal cleanup even if an assertion fails. The existing
lifetime fixture also initializes its loop reference without retaining a QObject.

All 56 real GUI tests then passed, including completion, cancellation, close-race
and object-destruction checks. Fresh strict GCC checks, CLI functional tests and
all 17 host stages passed with the same 11 ordinary skips, provider and limits
above. Pyright basic and the default command below both returned zero errors
for exactly the GUI and workflow test file under the unchanged typing limits.
A separate isolated Python run without site packages preserved the missing-Qt
diagnostic and exit 1. No fake declarations, ignored diagnostics or increased
limits were used. Ruff's 29 diagnostics and formatting failures remain.
This later 282-file snapshot predates the results-only documentation update;
it still does not qualify PyQt6 runtime, native packages, a real desktop,
whole-suite sanitizers or the production release.

The later subprocess-policy clarification adds explicit `check=False` to five
GUI helpers and the supervisor's deliberately failing child. This matches the
existing Python default: nonzero return codes remain available for inspection.
With the same effective Ruff settings and working directory, the focused rule
changes from six diagnostics to zero; full lint falls from 29 to 23 with the
remaining diagnostics unchanged. Both files still fail formatting. Fresh
strict GCC checks, CLI functional tests, all 56 Qt tests and 17 host stages
pass with 11 ordinary skips; both preferred-provider typing profiles remain
at zero errors. Reproduce the separate quality checks with:

```sh
ruff check --no-cache --select PLW1510 gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff check --no-cache --select F401,RUF059 gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff check --no-cache --select I gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff check --no-cache gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff format --check --no-cache gui/src/zupt_gui.py tests/test_gui_workflows.py
```

The first command checks only the explicit exit-policy rule, not all lint.
Record effective rules with
`ruff check --no-cache --show-settings gui/src/zupt_gui.py`;
full-lint results depend on the selected configuration.
The earlier full-lint and formatting failures remain recorded; the current
results after import organization and formatting are described below.

On GNU/Linux, with Pyright installed and genuine PySide6 declarations visible to
the selected Python, the bounded typing command is:

```sh
env MALLOC_ARENA_MAX=1 NODE_OPTIONS='--jitless --max-old-space-size=256 --max-semi-space-size=8' \
  timeout --kill-after=5 120 prlimit --as=1073741824 --cpu=120 \
  --nofile=128 --fsize=1048576 --core=0 taskset -c 0,1 \
  pyright --pythonpath "$(command -v python3)" --pythonversion 3.12 \
  gui/src/zupt_gui.py tests/test_gui_workflows.py
```

This requires GNU `timeout`, `prlimit`, and an allowed CPU set containing
0 and 1; tool failure is not success. The recorded run additionally used a
networkless namespace, read-only source/tools and private 64-MiB RAM storage;
the command above alone does not provide that filesystem/network isolation.

The subsequent probe-contract run adds six methods without changing the
production GUI: the suite now has 62 methods, comprising the previous 56 and
six POSIX tests that launch owned executable Python fixtures. They check
missing/non-executable paths, exit diagnostics, successful-only version
banners, help output on either stream after success or failure, cached
capabilities without another child, archive-info streams and command results.
Fixture executable paths and arguments include spaces; expected results are
literal, not computed by the GUI under test.

Fresh strict GCC/CLI checks and all 62 methods pass in the recorded 18-stage
host run with 11 ordinary skips. A separate six-test positive control passes;
five private GUI mutations fail in the expected methods. Four change subprocess
exit handling and one incorrectly accepts a failed version command. Those
copies are sensitivity controls, not five discovered product defects or a
security proof. Both actual preferred-provider typing profiles return zero
errors after an explicit stream-argument correction in the test fixture. The
initial type failure, 23 remaining Ruff diagnostics and both formatting
failures remain recorded.

The later unused-binding cleanup removes `Qt` and `QPixmap` from both provider
imports and names the ignored Info status `_code`. Provider selection,
subprocess calls, stdout-first/stderr-fallback display and test bytes are
unchanged. The focused F401/RUF059 check falls from three findings to zero;
that snapshot has 20 full Ruff findings, with the other diagnostics and settings
unchanged. Both files still failed formatting. Fresh strict GCC/CLI checks, the
same 62 methods, 18 host stages, positive probe control and five rejected
mutations pass again with 11 ordinary skips. Both actual preferred-provider
typing profiles return zero errors; recorded content fingerprints of the
installed Pyright package match before and after analysis. This is not clean
lint, a complete toolchain/dependency audit or PyQt6 runtime validation.

The subsequent mechanical cleanup organizes imports and formats both Python
files with Ruff 0.16.10. The import and formatting checks pass; full lint falls
from 20 to 16 findings with the other diagnostics and effective settings
unchanged. The remaining findings are 12 BLE001, two S110 and two EXE001;
no exception policy, suppression, rule or file mode was changed. A constrained
AST comparison preserves all non-import fields, import records and multiplicity
within each consecutive group, comment text/order, license headers and all
62 ordered test methods. That check does not establish import initialization
effects or comment attachment. Fresh strict GCC/CLI checks, 18 host stages,
all 62 methods, the six-test positive probe control and five rejected private
mutations pass with 11 ordinary CLI skips. Both genuine PySide6 typing profiles
report zero errors, with matching installed Pyright package fingerprints before
and after analysis. Full lint and the remaining production gates are not passed.

### PyQt6 fallback and native object lifetime

The later fallback run reproduced a missing anonymous destruction callback in
PyQt6. Native deletion measurements confirmed that job, thread and worker had
all been destroyed. The existing regression now uses independent GUI-thread
QObject receivers with decorated, zero-argument slots and retains the worker
wrapper until its assertions finish. This prevents garbage collection from
masking missing native cleanup; no production lifetime code changed.

All 62 methods pass with real PySide6 6.9.2 and PyQt6 6.9.1/Qt 6.9.2. Both
providers pass positive controls and reject five probe mutations plus removal
of `finished -> worker.deleteLater`. Final strict GCC `all`, CLI functional
tests and GUI checks pass in 18 PySide/19 PyQt stages. Full strict GCC `check`
also passed before the final one-line fixture capture clarification, with
identical C/GUI inputs and 11 ordinary CLI skips. Both final preferred-provider
typing profiles pass. Imports/format pass; full lint retains 16 findings.
These are host offscreen results, not native-package, VM or sanitizer approval.

To reproduce the fallback suite, use a matching tested CLI and a Python
environment containing genuine PyQt6 but not PySide6/shiboken6. Run these
POSIX-shell commands from the source root, replacing the example paths:

```sh
PYQT_PYTHON=/absolute/path/to/python-with-PyQt6
export ZUPT_BIN=/absolute/path/to/tested/zupt
export ZUPT_GUI_MODULE="$PWD/gui/src/zupt_gui.py"
export QT_QPA_PLATFORM=offscreen
"$PYQT_PYTHON" -B - <<'PY'
import sys
from importlib import metadata, util
assert all(util.find_spec(name) is None for name in ("PySide6", "shiboken6"))
from PyQt6 import QtCore, QtGui, QtWidgets, sip
print("Python:", sys.executable)
print("PyQt6:", QtCore.PYQT_VERSION_STR, "Qt:", QtCore.qVersion())
print("PyQt6-sip:", metadata.version("PyQt6-sip"), "SIP:", sip.SIP_VERSION_STR)
for module in (QtCore, QtGui, QtWidgets, sip):
    print(module.__name__, module.__file__)
PY
"$PYQT_PYTHON" -B tests/test_gui_workflows.py
"$PYQT_PYTHON" -B tests/test_gui_workflows.py GuiWorkflowTests.test_completed_jobs_release_qobjects_before_window_close
```

Keep the reported module paths, `GUI binding: PyQt6`, exit status and normal
completion marker. Distribution and SIP generator version numbers differ;
the recorded run used PyQt6-sip 13.10.2 and SIP 6.11.1. These commands do not
create the recorded networkless namespace/resource caps or run its private
mutation controls. Failed tests, missing completion and skips are not approval.

From the source root, after configuring the selected Python's real PySide6/Qt
runtime and building or staging a matching CLI and GUI, run only these probes:

```sh
env PYTHONDONTWRITEBYTECODE=1 \
  ZUPT_BIN=/path/to/staged/bin/zupt \
  ZUPT_GUI_MODULE=/path/to/staged/lib/zupt-gui/zupt_gui.py \
  QT_QPA_PLATFORM=offscreen \
  python3 -B tests/test_gui_workflows.py CliProbeTests
```

Replace the example paths with actual staged files. Import/bootstrap still
requires the runnable matching-version CLI. The six fixtures require POSIX and
an interpreter path usable in a portable shebang; unsupported systems report
explicit skips, not coverage. This selector does not run the remaining methods;
the recipe runs the complete suite without selectors. Neither the probe
fixtures nor the host recipe run qualifies native packages, whole-suite
sanitizers, PyQt6 runtime or production release readiness.

### GUI query failures

On 2026-10-18, the three synchronous version, capability and archive-info
queries retain their existing fallbacks for `OSError`,
`subprocess.SubprocessError` and `UnicodeError`. Unexpected programming errors
now propagate rather than silently becoming missing metadata. No exception
payload is printed by the expected-failure paths. Nonzero help/info output,
cached capabilities and Worker cleanup retain their earlier contracts.

Two regression methods cover 18 expected failures and nine unexpected errors.
The nine unexpected-error cases first fail against the old GUI. With the
correction, the full suite has 64 methods; earlier 62-method entries above
describe the preceding snapshots. All 64 pass under genuine PySide6 6.9.2
and separately under PyQt6 6.9.1/Qt 6.9.2, with installed-source byte checks,
version/selftest checks and the existing probe mutation controls. A fresh
strict GCC 14.3.0 `check` and CLI functional run pass with 11 ordinary skips.

Using the real Qt/Python environment and matching staged paths described
above, select just the two new methods with:

```sh
env PYTHONDONTWRITEBYTECODE=1 \
  ZUPT_BIN=/path/to/staged/bin/zupt \
  ZUPT_GUI_MODULE=/path/to/staged/lib/zupt-gui/zupt_gui.py \
  QT_QPA_PLATFORM=offscreen \
  python3 -B tests/test_gui_workflows.py CliQueryFailureTests
```

This selector does not replace the full `check-gui` run. The recorded runs
preserve an initial regression-harness error and an earlier private supervisor
directory collision; neither is counted as a successful test. Formatting and
both real preferred-provider typing profiles pass. Full Ruff still exits 1:
its 16 diagnostics decrease to 11, comprising nine Worker boundary/cleanup
handlers and two shebang/mode findings. Those handlers and intentional 0644
source modes are unchanged; no rules were suppressed. These host offscreen
results do not qualify a native Guix closure, real desktop, current VM
sanitizer campaign or production release. The C/Jasmin formal inputs are
unchanged from the separately recorded selected analyses, not newly proved
by these Python tests.

### Fuzz harness build and seed validation

Run the real harness regression and its shell controls from a fresh source
copy, then repeat with `CC=clang`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O2 -Werror -Wpedantic -Wshadow -Wcast-align -Wformat=2' \
  test-fuzz-harness test-fuzz-build test-fuzz-build-wrapper
```

The child-execution regression `test-fuzz-harness` compiles its fixtures with
the caller's flags before selecting the mutation directory containing spaces.
Compiler scratch remains separate from runtime scratch, including with GCC
LTO. The runtime cases still check spaced private-input paths, cleanup,
retention, real UBSan failures and synthetic sanitizer-diagnostic classification.

The `test-fuzz-build` target first builds the matching CLI and supplies its absolute path
through `FUZZ_TEST_CLI`. That CLI only creates and tests the unencrypted STORE
seed. Both fuzz executables still compile their own UBSan core; separate
non-LTO objects retain the real short/interrupted I/O, setup-failure,
extraction/test/list and cleanup checks. A supplied empty, missing,
non-executable or directory path fails before compiler discovery. Relative
paths resolve against the working directory, not `PATH`; spaces remain part
of the filename. Build, seed-creation and seed-test errors stop the test.

Without `FUZZ_TEST_CLI`, direct execution still builds its private CLI:

```sh
env -u FUZZ_TEST_CLI CC=gcc \
  CFLAGS='-O2 -Werror -Wpedantic -Wshadow -Wcast-align -Wformat=2' \
  sh tests/test_fuzz_build.sh
```

The ten synthetic controls check selection, arguments, order and error
propagation, not C correctness or fuzz coverage. Their override regression
failed before the change and passed afterwards. An isolated GCC 14.3.0 probe
measured 5.17 seconds for the duplicated ordinary CLI build; this is one
build-cost observation, not a compression benchmark. Default Make execution
uses the ordinary CLI warning flags instead of recompiling it with the
test's extra `-Wcast-align -Werror`; the strict profile above and CI retain
both flags for the full CLI. No fuzz compiler flags or resource limits change.

### Optional Rust varint checks

The gradual migration starts with `rust/varint`, a separate `no_std` library
matching the canonical unsigned base-128 integers in `src/zupt_format.c`.
It has no external crates, build scripts, allocation, FFI or unsafe code.
It is not an archive verifier and is not linked into the C11 CLI or installed
packages. Normal `make`, `make check`, installation and distro recipes do
not invoke Rust; this first component does not make production parsing Rust.

For this developer-only profile, install/provide Rust and Cargo **1.93 or
newer**, rustfmt, Clippy, Bash and a C compiler/linker with function/data
section garbage collection. No tool or dependency is downloaded by the targets:

```sh
make test-rust-varint
make audit-rust-varint
```

`CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS` and `CARGO` remain selectable.
The runner uses a private `TMPDIR` child, a two-job Cargo budget, offline/locked
resolution and temporary build outputs. Keep the temporary parent trusted.
Missing tools, a failed compiler, oracle failures and test failures are errors,
not skips. The oracle links the actual `src/zupt_format.c` translation unit;
dead-section removal avoids substituting a copied C parser or importing the
rest of the application into the Rust core. This profile has been executed
on x86_64 GNU/Linux with GCC 14.3.0 and Rust/Cargo 1.93.0, not all platforms.

Nine focused tests cover known bytes, truncation, overlong encodings, invalid
tenth bytes, trailing input, offset slices, unchanged undersized destinations,
bit-boundary/deterministic round trips and a large input. Two integration tests
check malformed helper-protocol rejection and **114,721** real C/Rust cases
per debug/release profile, including all 65,536 two-byte inputs. The fixed
synthetic seed is `0x5a55505452555354`; this is not coverage-guided fuzzing.
Successful C buffer/FILE encodings, decoded values and consumed lengths match.
On errors only acceptance/rejection is compared: C partial output and stream
error-position state are not part of the Rust `Result` API. Rust encoding
checks capacity before changing output; the C encoder requires enough storage.

The recorded focused and differential runs, formatting and Clippy pass.
Miri, a Rust formal verifier, RustSec advisory scanning and coverage-guided
Rust fuzzing have **not** run in this profile. Miri is not a general native-FFI
checker; qualify its applicable Rust-only tests separately. Frama-C still
applies to C slices, Jasmin to its own modules; neither proves this Rust code.
These developer results do not replace the existing release/security gates.
Keep 5.2.10 unpublished until its complete production qualification is accepted.

A fresh strict GCC 14.3.0 `make check` and actual CLI functional suite also
pass with `CARGO` set to a failing executable, confirming the production test
path does not require Cargo. Eleven skips remain: native Windows, the modeled
bionic-header/Clang case, five external-SDK cases, a privileged loop device,
zsh, fish and man-page renderers. This networkless, home-isolated Linux profile
uses only installed tools and read-only pinned `sh`/`env` mappings; it is not
a native Guix derivation or openSUSE package build. Earlier missing headers,
interpreters and tools, and a private launcher failure, remain recorded rather
than being counted as passes. No production C or existing test source changed.

### Codec and cryptographic checks

Run the existing extended CLI scripts separately from the basic `check` target:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 all
bash tests/regression.sh ./zupt
sh tests/test_pq.sh ./zupt
bash tests/test_dedup_props.sh ./zupt
```

On 2026-10-18, a fresh strict GCC 14.3.0 build and the CLI functional script
passed, followed by 22 regression, 10 built-in PQ and 14 dedup-property checks,
with zero failures in each suite. The last suite includes encrypted-reference
tamper rejection. Tests used synthetic data and keys inside a networkless
namespace, read-only source/tools, two-CPU affinity, AS 1 GiB, NPROC 64 and
128 MiB of private RAM scratch. Affinity does not limit worker count: default
and explicit thread settings still apply. The full threaded suite was not run
in this profile because its worst-case scratch footprint can exceed that cap.
`test-all` also invokes the separate timing and ASan exact-size gates; these
were not executed here. Informational size/throughput output from older scripts
is not a representative performance comparison. The scratch cap is a test
environment limit, not an archive-size limit or a package qualification.

For ML-KEM-768 interoperability, use OpenSSL 3.5 or newer with ML-KEM enabled:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-crypto-test-wrappers
CC=gcc bash tests/test_mlkem_fips203.sh
CC=clang bash tests/test_mlkem_fips203.sh
```

The first command runs 27 shell-supervisor controls, not cryptographic
verification. Its 15 ML-KEM cases include successful flows, legacy/provider
skips and ten producers that return an error after writing plausible output. They
exercise the real interoperability script with synthetic compiler/OpenSSL
boundaries; a clean-looking comparison must not override a process failure.
The two direct commands compile the real portable C harness separately with
the selected compiler. Each compares deterministic public-key generation
and shared secrets in both encapsulation directions against real OpenSSL.
Require `Conformance: 3 passed, 0 failed` and exit zero. Missing tools or an
OpenSSL without ML-KEM or another reference provider produce an explicit
`SKIP`, not interoperability evidence; a failed capability query or later
subprocess is a failure.
Record actual compiler/OpenSSL versions and the complete output. These finite
checks are not algorithm certification or a constant-time proof.
The earlier 2026-10-16 post-fix run passes all 27 controls, fresh strict GCC `make check`
and the real CLI functional suite. GCC 14.3.0 and Clang 22.1.8 each pass all
three real interoperability comparisons against OpenSSL 3.5.7, with no skips
in those two stages. The ordinary suite retains its 11 unrelated skips.

A fresh 2026-10-18 GCC 14.3.0 run repeats the three genuine comparisons against
OpenSSL 3.5.7, with zero failures and no skips. No fresh Clang or sanitizer run
is implied. `CC` selects the driver, but this script uses its own `-O2` command,
not Makefile `CFLAGS`. Put the intended OpenSSL on `PATH`; a Guix compiler also
needs its configured include/library environment. This run used the existing
pinned profile only inside the private namespace, without changing a user
profile or installing tools.

Strict Clang 22.1.8 `check` and the actual CLI functional script were rerun on
the current sources on 2026-10-18. Both pass with SDK/PQBOX/Jasmin disabled
and 10 explicit skips: Windows, five external-SDK cases, a privileged loop
device, zsh, fish and the man-page renderers. Unlike GCC, this run exercises
the modeled bionic-header case. Use a fresh source copy for each compiler;
changing `CC` over existing objects does not rebuild every cached object.
From the configured Clang development environment, run:

```sh
make -j2 CC=clang CFLAGS='-O2 -g -Werror -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2' WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
bash scripts/test-installed-zupt.sh ./zupt
```

The first isolated attempt could not load `libgcc_s.so.1` for a UBSan helper
and failed; the CLI script was correctly not run afterward. A fresh attempt
made the installed Clang toolchain's configured GCC support-library directory
available only in its child environment. No source, warning flag, criterion
or limit changed. Configure the intended toolchain and its runtime together;
do not suppress a loader error or change global library paths to call a test
passed. This result includes the existing UBSan helper checks, not full
`test-all`, an ASan/LSan VM campaign or native-package qualification.

The existing `test-ans-allocation` target now also checks seven hand-derived
reader states from a 16-byte fixture. It verifies that reading zero bits does
not prefetch input, then checks the accumulator, buffered count, source
position and source span across masked refill, a short tail and EOF. These
ordinary failure checks remain active with `NDEBUG`. All previous tests,
including the 2,312 bit-reference and 520 exhausted-counter cases, remain.
The target is already part of `check`; no extra test framework is needed.

The extended target passed with non-recovering UBSan and `NDEBUG` on GCC
14.3.0 and Clang 22.1.8 on 2026-10-18. Separate fresh strict `check` and CLI
runs passed with 11 GCC and 10 Clang skips. A private eager-refill mutation
passed the old suite but the extended test rejected it at the first
zero-width read after successful compilation. That control validates the
new state oracle; it does not establish an existing decoder vulnerability.
For a targeted run in a fresh source copy and configured compiler runtime:

```sh
make -j2 CC=clang CFLAGS='-O1 -g -DNDEBUG -Werror -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -fsanitize=undefined -fno-sanitize-recover=undefined' LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
```

Use `CC=gcc` for GCC. These are bounded native regressions, not a general
reader proof, big-endian qualification, current VM ASan/LSan campaign or
release approval. The implementation and existing formal criteria are
unchanged; the private mutant is not shipped.

#### Direct refill boundaries

On 2026-10-22 UTC, `test-ans-allocation` adds 79,560 initial refill states:
four source alignments, prefixes 0/1/7, 0..16 remaining bytes, buffered counts
0..64 and six accumulator patterns. A separate byte-at-a-time loop supplies
the expected accumulator, count and position. Both fills check all five
reader fields and unchanged source bytes; the second must be a no-op.
Nonempty spans end exactly at the allocation boundary. Zero-sized allocations
use one byte instead; the existing exhausted-NULL tests remain separate.
The synthetic accumulator patterns also check preservation of bits above
the buffered count; not every state is an encoder-produced state.

In fresh source copies with the selected compiler runtime configured, run:

```sh
make -B -j2 CC=gcc CPPFLAGS='-DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE' \
  CFLAGS='-O2 -g -Werror' LDFLAGS= \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
make -B -j2 CC=gcc CPPFLAGS='-DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE' \
  CFLAGS='-O1 -g -Werror -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
```

Repeat with `CC=clang`. GCC 14.3.0 and Clang 22.1.8 pass both scalar profiles.
`-B` rebuilds the Huffman object using its existing local alignment handling.
Two private non-UB mutations pass the old suite, but the new suite rejects
skipping refill at count 56 and clearing a pending-input no-op at count 57
(actual Make/program exits 2/1, not crashes). Strict `check` plus functional
CLI smoke also pass with 11 GCC and 10 Clang skips. Native runs retain the
two-CPU, 1-GiB per-process, 128-MiB scratch and 600+5-second wall envelope.

A separate private finite fixture extends the seven-step characterization
with one literal count-56 case and all eight pending-input counts 57..64.
Frama-C 29.0/GCC 14.3.0 Eva reaches 159/197 statements, validates all 33
preconditions, reports zero unknowns/invalids/alarms and returns `main == 0`.
Completion counters establish all eight iterations and the adjacent boundary.
The old fixture accepts the preservation mutation; the extended fixture has
one invalid assertion precondition and is rejected, despite analyzer exit 0.
The maintained reader WP target separately passes its 30 exact JSON goals
with recognized Z3 4.12.2. The raw logs retain the Why3 bootstrap warning and
an informational unsupported-libc-`memcmp` note; this is not a libc proof.

These finite checks do not close the 14 broader caller obligations or prove
general refill safety. Fresh VM ASan/LSan is blocked because its pinned
kernel is unavailable; no alternate kernel or historical result substitutes
for that run. No new full `test-all`, Jasmin analysis, benchmark or package
qualification is implied. Final documentation edits are outside the runtime
snapshot. The codec implementation, public API and wire format are unchanged.

A later 2026-10-22 UTC prerequisite run uses a separately pinned installed
kernel because the old image could not be recovered from the inspected local
artifacts. Seven generic and nine native isolation/limit/supervision controls
pass with the exact 17-record completion protocol; 13 synthetic parser cases
also pass. The guest has two CPUs/2 GiB and no NIC, host disks or home. The
execution-envelope controls retain 768 MiB, swap zero, 16 tasks, 512-MiB
scratch and 64-MiB files, including real limit, cleanup, timeout and excessive
output negatives. Source-state and named-input/tool checks pass before/after.
This minimal private image contains only a trusted static controller and
synthetic sentinels, not Zupt, a guest compiler or sanitizer payload.

An initial namespace failure is preserved: the same 16-process limit must
apply inside the new namespace, not to the already populated host UID before
namespace creation. A linker-wrapper GC warning is also retained. Restoring
the previous real-binutils-first tool route removes that warning and produces
identical controller bytes; no cap, warning filter or GC setting changes.
This qualifies the measured isolation slice only. Qualify the selected guest
toolchain and real ASan-OOB/LSan-leak/UBSan-overflow negatives again before
running the actual software tests; historical sanitizer passes do not transfer
to this new kernel/input set. Broader formal and final-package gates stay open.

A subsequent run on the frozen 294-file source qualifies the selected GCC
14.3.0 guest toolchain and executes the real profile. The ASan redzone/clean
controls and heap-overflow, leak and signed-overflow negatives produce the
expected diagnostics and exits 134/134/1. Only then does the profile build
the current CLI and run `make test-asan-run` plus
`bash scripts/test-installed-zupt.sh ./zupt_asan`, with leak detection enabled.
Archive and regular-file disk round trips, wrong passwords, corrupt input and
destination-symlink rejection pass without sanitizer findings. No host disk
device is used. Separate ordinary `audit-licenses`, `sdk-test` and
`sdk-verify-symbols` targets pass; three ML-KEM comparisons against OpenSSL
3.5.7 also pass. Those SDK and interop results are not sanitizer coverage.

The full protocol has 25 ordered records, including the same 16 isolation
controls; process, collector, protocol and before/after source/input checks
all return zero. The target retains 768 MiB, 16 tasks and 512-MiB scratch
inside the two-CPU/2-GiB disposable VM. Private verifier tests cover 12 input
inventory methods and eight synthetic diagnostic-gate methods; they are
not product tests. This run does not include a fresh full `test-all`, the
direct 79,560-state ANS-refill test under ASan, Qt or final packages. It also
does not discharge the 14 broader formal obligations. Final documentation
edits are outside this runtime snapshot; implementation/API/format are unchanged.

The five existing formal gates were also rerun on the current selected sources
on 2026-10-18, with Frama-C 29.0, Why3 1.7.2, Z3 4.12.2, Jasmin 2026.09.0 and
GCC 14.3.0. All pass: logarithm Eva, fixed-vector AES Eva, reader WP, the current
three-metadata-fixture Eva profile and the five-source Jasmin gate. Reader WP
reports 30 valid exact JSON goals, with 16 Qed and 14 Z3 results (34/34 console
obligations). Metadata Eva reaches 138/358 statements with zero alarms and
20 valid preconditions. Jasmin includes 1,026 AES blocks and 1,539 CTR4 cases.
The commands and individual proof limits follow below. Earlier `cmp` and
`libcrypto.so.3` resolution failures remain recorded; only the private tool
environment was corrected. Ensure `cmp`, binutils, `pkg-config`, the selected
libcrypto runtime and the compiler runtime are available before running the
Jasmin fixtures. These conditional results do not establish whole-program
security, full valid-stream decoder coverage or production-release approval.

For the current [ANS bounds regression](#ans-exact-output-bounds), run:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-decode-bounds
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds-wrapper
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds
```

The native regression is included in `check`. The Frama-C target requires
Frama-C 29.0 on `PATH`, or `FRAMA_C` set to its executable path, and invokes
`tests/test_frama_ans_decode_bounds.sh`. It is separate from the basic
`check` target and mandatory before a release. Missing tools, execution
errors, analysis warnings, alarms or unproved preconditions fail the gate;
they are not skips. The result parser requires six exact fixture witnesses
and the recorded 63-precondition, zero-alarm summary, rejecting missing,
duplicate, conflicting or pruned results. GNU awk and grep must be on `PATH`.

`test-frama-ans-decode-bounds-wrapper` is included in `check`; its current
82 controls are described in the [current profile](#ans-exact-output-bounds).
The earlier 57-control wrapper retained its previous 56 cases and rejected
the stale two-fixture, 121/343-statement, 14-precondition report. Eight earlier
complete-profile warning,
error, failure and timeout fixtures reproduced false passes before the
case-insensitive scanner fix. A positive control preserves the informational
unsupported-ACSL `memset` note. Scanner errors 2/127 must fail both diagnostic
detection and PASS-marker checking; they are not equivalent to no match.
These controls do not analyze the codec. That earlier metadata extension
preserved its analysis settings when adding the third fixture. Record the
preprocessor version alongside Frama-C; the retained warning-free run used
GCC 14.3.0. With GNU Guix, an ephemeral pinned environment can run the current
targets:

```sh
guix shell --pure frama-c@29.0 gcc-toolchain@14 make bash-minimal coreutils gawk grep -- \
  bash -c 'make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds-wrapper test-frama-ans-decode-bounds'
```

Use a known Guix channel revision and retain its commit in the audit record.
This command does not install Frama-C into the user profile. GCC 16's
preprocessor emits macro-redefinition warnings with this Frama-C version;
the gate rejects that run rather than treating its zero-alarm summary as a
complete pass.

The metadata-only figures below describe earlier snapshots. The commands
above now run the [current exact-output profile](#ans-exact-output-bounds).

The earlier two-fixture Eva run passed with zero alarms and 14/14
preconditions at 121/343 reached statements. The later three-fixture run added
a 33-byte fixture with lane sizes `{1,0,0,1}` and only one payload byte. The
fourth lane
must reject after the first consumes that byte, retaining `SIZE_MAX` consumption
and four output bytes initialized to `0xa5`. At that snapshot, the unchanged
decoder reached 138/358 statements in 5/76 functions with zero alarms and
20/20 valid preconditions under the same `slevel=16`, `plevel=512` settings.
The decoder body
returns `VVA_ERR_CORRUPT` and `main` returns 0. Frama-C's libc models C `assert`
checks through `__FC_assert` preconditions; the ACSL Assertions count is zero.
This result covers those fixtures under the script's `gcc_x86_64` machine
model; it does not verify the allocated decode table, four-lane hot path or
every decoder input. The script maps `_Alignof` to the equivalent GCC
`__alignof__` operator because
Frama-C 29.0 does not parse the C11 spelling. Retain the complete analysis
output when reproducing the check.

The earlier three-fixture native test passed scalar UBSan with GCC 14.3.0
and Clang 22.1.8 through the real Makefile. Its historical standalone recipe
below excludes the production match-copy path. Use the
[current sanitizer recipe](#ans-exact-output-bounds) for today's expanded
fixtures, with a fresh source copy for each compiler and configuration:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  CPPFLAGS='-DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE' \
  CFLAGS='-O1 -g -Werror -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -DNDEBUG -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' test-ans-decode-bounds
```

Repeat with `CC=clang` in the other tree. The target restores assertions with
`-UNDEBUG`. Clang uses the existing object-local cast-alignment exception for
the ANS arena; no new or global suppression was added. A separate direct
strict-Clang attempt fails with 16 existing cast-alignment diagnostics and is
not a passing profile. The isolated Clang UBSan runtime required the pinned
GCC runtime library; its initial loader failure is retained separately.

Private linker-allocation controls verify zero table-allocation attempts for
all three fixtures. Changing only the lane guard to compare against the
original payload budget leaves the old two fixtures passing, but the new
case reaches one allocation attempt and returns `NOMEM`. The control returns
NULL there to prevent invalid lane reads; it does not execute an unsafe decode
or establish a full-decoder proof. Fresh strict GCC `check` and actual CLI
functional tests pass on the recorded 283-file snapshot before documentation
updates, retaining 11 ordinary skips. Production C, API and format are unchanged.

A separate private valid-stream experiment
reached those later paths but retained 15 alarms and five unknown
preconditions; a 120-second higher-precision run did not complete. That
experiment is not part of the included gate and does not approve production.

On 2026-10-10, a fresh Frama-C 29.0 executable and the unchanged synthetic
fixture again produced the complete 15-alarm, five-unknown-precondition
result at `slevel=16`, `plevel=512`. A separate run varied only `plevel` to
4096, without the earlier global loop-unroll override. Under a smaller
RAM-only diagnostic profile (25-second analyzer deadline, 30-second outer
deadline, 768-MiB analyzer address space and 1-MiB log-file limit), it stopped
with status 153 at the log limit, before a final summary. Exact captured log
bytes and hashes were verified; this incomplete result is a failure, not
evidence of fewer alarms. Neither run changes the decoder, assertions or
allocation-failure model, or substitutes for the earlier VM experiment.

#### ANS reader consumption and conditional WP check

The shared reader counts only buffered bits after exhaustion, retaining the
format's implicit zero extension. The old counter became negative on the
first exhausted positive-width read. A direct bounded regression reproduced
that state; no huge-input CLI exploit is claimed. Single-stream source
consumption and the encoding grammar remain unchanged.

Select an isolated environment and any private `WHY3CONFIG` path before
running either the solver detection or Make commands below.

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-reader-wrapper
why3 config detect
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-reader
```

Use Frama-C 29.0, Python 3, GCC 14's preprocessor and recognized Z3 4.12.2
with Why3. Configure the solver in an isolated environment, not by replacing
host libraries. If using a private configuration, set `WHY3CONFIG` to its
path before running detection or Make. `FRAMA_C` and `PYTHON` can select the executables.
The existing gate also accepts Z3 4.13.0. A later actual gate pass used that
version, but Why3 1.7.2 reported it as unrecognized during detection. Preserve
that warning; gate acceptance is not recognized-solver qualification. If
`WHY3CONFIG` is set, create and inspect that configuration before **any**
Frama-C invocation, including Eva-only runs: WP initialization can still read it.
The subsequent repeat documented below uses recognized Z3 4.12.2 again; the
4.13.0 detection warning remains part of the earlier run, not the new profile.
The script uses `gcc_x86_64`, the same standalone/scalar preprocessing as the
metadata check, `-wp -wp-rte -wp-fct ans_br_init,ans_br_take -wp-prover z3 -wp-par 1
-wp-timeout 2` and a raw WP report. Unknown goals, warnings, missing tools,
timeouts and mismatched/duplicated results fail, even with analyzer exit 0.

The real run proves 30 exact non-smoke JSON obligations: 12 for initialization
and 18 for extraction. The console's 34/34 also includes termination and
unreachable results for both functions. Initialization requires a writable
context and resets the accumulator, count and position while retaining the
supplied source pointer and length; it does not read the source. Extraction
checks count saturation, writes limited to `a`/`n`, shifts and selected
runtime-error conditions, assuming valid initialized `a`/`n`, a buffered count
in 0..64 and a read width in 0..32. This does not prove refill, all callers,
table initialization, format validation or the entire decoder. The 40 mock
controls test report handling only. Frama-C 29 emits zero prover times as
`0.`; the parser adapts only that numeric spelling outside strings, rejects
duplicate keys/nonfinite values and prints the unchanged report with its hash.
Retain the complete stdout/stderr, tool hashes and exit code when reproducing.

Native GCC 14.3.0 and Clang 22.1.8 pass 2,312 reader configurations (four
alignments, lengths 0..16, widths 0..32 and mixed widths), 160 reads each,
including reset from a poisoned context,
single-stream consumed lengths 10/12 and ANS4 requested lengths 1..4096.
Output suffixes, return values and allocation cleanup are checked. Focused
scalar UBSan runs also pass with both compilers at `-O1 -fsanitize=undefined
-fno-sanitize-recover=undefined`. ASan/leak repetition in a disposable VM on
this edited source now passes with Clang 22.1.8 in scalar and AVX2 modes.
The focused follow-up below is not complete CLI or fuzz validation.

#### Reproduce the focused ANS sanitizer tests

The 2026-10-10 private run froze 255 source files and freshly compiled the
actual ANS implementation included by `tests/test_ans_allocation.c`, plus
an instrumented Huffman object. Both executions passed the allocation,
reader/reset, exhausted-counter, 1..4096 output-length and logarithm checks.
ASan, LSan and UBSan negative controls were separately required to fail with
their expected diagnostics. Exact-size codec tests passed 81/0 and 1,024
BCJ bijection cases; L5/L9 archive roundtrips used the ordinary CLI.

For a focused reproduction, use a disposable Linux x86_64 VM and run this
Bash block from the source root. If using fish, enter `bash` first. `CC`
names one compiler executable with working sanitizer runtimes; Guix compiler
resource directories and runtime search paths must be configured separately.
The AVX2 pass requires the VM to expose AVX2 and fails if it does not; do not
interpret a missing instruction set as passed coverage. Temporary objects
avoid mixing sanitized and cached project objects.

```bash
(
set -eu
audit_tmp=$(mktemp -d)
trap 'rm -f -- "$audit_tmp/huffman.o" "$audit_tmp/ans-test"; rmdir -- "$audit_tmp"' EXIT
audit_cc=${CC:-cc}
audit_flags=(-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror '-fsanitize=address,undefined' -fno-sanitize-recover=all -fno-omit-frame-pointer)
audit_cast=()
case "$("$audit_cc" --version)" in *clang*) audit_cast=(-Wno-cast-align) ;; esac
for audit_mode in scalar avx2; do
    audit_simd=(-DVV_DISABLE_SIMD=1)
    if test "$audit_mode" = avx2; then
        grep -qiw avx2 /proc/cpuinfo
        audit_simd=(-mavx2)
    fi
    "$audit_cc" "${audit_flags[@]}" "${audit_simd[@]}" -D_DEFAULT_SOURCE -Iinclude -Isrc -c src/vv_huffman.c -o "$audit_tmp/huffman.o"
    "$audit_cc" "${audit_flags[@]}" "${audit_simd[@]}" "${audit_cast[@]}" -D_DEFAULT_SOURCE -Iinclude -Isrc tests/test_ans_allocation.c "$audit_tmp/huffman.o" -o "$audit_tmp/ans-test"
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$audit_tmp/ans-test"
done
)
```

The measured VM retained 2 CPUs/2 GiB, a 768-MiB/16-task target cgroup and
512-MiB scratch, with no NIC, host home, host disks or host sockets. The
final focused target peaked at 235,048,960 bytes, with no unexpected resource
events or surviving descendants. The commands above do not themselves
configure those VM controls or run the separate negative-control/exact-size
harnesses. They do not prove decoder correctness, absence of vulnerabilities
or release readiness; the formal caller/table/refill and final-package gates
remain unresolved. Later documentation changes were outside the VM snapshot.

The refill now tests `l - p >= 8` under its existing `p <= l` invariant,
instead of adding eight to `p`. Another 520 cases start with `p == l`, a NULL
source, eight ordinary/near-`SIZE_MAX` positions and every count in 0..64.
They check that refill touches no source and preserves all fields, then
check zero-extension and exact counts across widths 0..32. These are
synthetic counters, not allocated giant buffers. The old predicate fails
with a non-recovering UBSan NULL-pointer-offset diagnostic; both compilers
pass the corrected test. The ANS4 metadata prefix already bounds real lane
sizes away from this overflow, so this does not establish a reachable
archive vulnerability or change the format. Full strict native `make check`
also passes with GCC 14.3.0 and Clang 22.1.8 after this change, with
SDK/PQBOX/Jasmin disabled and unavailable-platform/tool skips retained.
Both initial parallel runs reached the 125-second deadline (124); sequential
runs pass without increasing deadlines or CPU/memory limits. The complete
raw logs preserve those failures as well as the later successful runs.

The private 4096-byte valid-stream Eva diagnostic now uses a local 256-symbol
loop-unroll annotation and `-eva-domains-function gauges:vva_decode4_impl`,
with the same slevel 16, plevel 512, byte oracle and nullable-allocation model.
After the refill-guard change, it reaches 349/496 statements and has zero
memory alarms, but 14 of 51 preconditions remain unknown (37 valid): four
bit-width bounds and four reader-count bounds at the four `ans_br_take`
calls, one `memcpy` source-span condition, and five fixture assertions about
allocation-failure behavior, consumption and decoded bytes. The
earlier annotation-only snapshot had 38 valid/13 unknown. This conditional
diagnostic is not a passing release gate. Only the annotations leave the
preprocessed executable C unchanged; the guard is an executable change. A broader
refill WP trial timed out and reported incompatible-pointer memory-model
warnings; its draft contracts were not retained as proved guarantees.

A separate Eva entry at `check_reader_exhausted_positions` is also unresolved.
At slevel 16/plevel 512 with gauges scoped to refill, it merges distinct
counter states and reports one sure memory alarm and one invalid precondition
(nine valid). Raising only that entry's slevel to 20000 reaches the 25-second
deadline before a summary. Neither run is a passing check; native regressions
and manual invariant reasoning are not substitutes for a generic refill proof.

A separate WP diagnostic on 2026-10-13 analyzed the unchanged executable C
with an exhausted-state contract (`p == l`), allowing a null or unreadable
source pointer and imposing no extra length cap. Qed proved 44/78 goals;
selecting the already admitted Z3 4.12.2 proved the same 78/78 goals. Three
warnings remain: missing explicit `memcpy` termination/exit clauses and two
incompatible Typed-model pointer casts. Strict admission therefore exits 1.
This establishes progress for the exhausted slice only; warning-free
admission, general refill and caller obligations remain open.

On 2026-10-19, a new private contract admitted a read-only reader with all
fields initialized, `0 <= n <= 64` and `p == l`, without input validity,
separation or a length ceiling. A loop invariant `p == l`, `loop assigns
\nothing` and constant variant describe the unreachable loop body. WP+RTE
improved this new diagnostic from 40/54 to 62/62 goals with the recognized
Z3 4.12.2, retaining all three `memcpy`/Typed warnings. Strict admission
still fails. Adding only the false postcondition `a == 0` leaves precisely
that extra goal unproved (62/63). Restoring the old `p + 8 <= l` guard in
another private control leaves 25/54 goals unproved, including source
validity. All raw reports and exact goal identities are retained privately;
these counts are not the historical 78-goal inventory. Neither the contract
nor its loop annotations are shipped as established guarantees.

The maintained native target now adds 9,360 synthetic preservation states:
eight positions, 65 bit counts, six accumulator patterns and three source
pointers (NULL, one local byte and an alias into the reader). It compares all
five fields after refill. Two private mutations clear either a nonzero
accumulator at `SIZE_MAX` with NULL input or one whose source aliases the
reader. Both pass the old test and fail this new check; these controls use
GCC without sanitizers. Strict GCC 14.3.0 and Clang 22.1.8 pass the unmodified
codec at `-O2`, including separate non-recovering UBSan runs whose actual
overflow controls fail as required. This is field-preservation coverage,
not proof of every possible memory access or a new ASan/LSan VM result.
The executable codec, API and format are unchanged. Reproduce the new
ordinary profile in a fresh source-only checkout:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O2 -g -Werror' test-ans-allocation
```

Repeat with `CC=clang` in another fresh checkout. For the measured UBSan
profile, append `-fsanitize=undefined -fno-sanitize-recover=undefined` to
`CFLAGS` and pass those same two flags in `LDFLAGS`. Use a complete compiler
and sanitizer runtime environment, not a dangling compiler path.

The subsequent GCC 14.3.0 sanitizer follow-up on 2026-10-19 used a frozen
291-file source snapshot in a disposable VM. Independent fresh copies built
the actual `test-ans-allocation` target at `-O2` with ASan and UBSan, fatal
diagnostics and leak detection. The project-SIMD-disabled profile verifies all
three feature macros are zero; the AVX2 profile requires guest AVX2 and verifies
both compiler and project AVX2 macros. Each passes the 9,360 preservation states
and all retained checks. This is not a claim about libc/compiler vectorization
or coverage of every SIMD instruction.

The original resource/isolation probes and three real sanitizer fault controls
pass before the product runs. All 23 ordered completion records and separate
VM/collector/integrity/protocol statuses pass. The scalar/AVX2 stages peak at
236,113,920/235,483,136 bytes, with no OOM/PID-limit events or remaining children.
The VM retains 2 CPUs/2 GiB and the target 768 MiB/16 tasks/512 MiB scratch,
without network, home, host disks or sockets. A new private profile's 22 runner
regression methods reject missing/reordered/duplicate stages and failed external
statuses. These supervisor tests are not codec tests. This follow-up does not
repeat Clang ASan, complete CLI/SDK/fuzz suites, Frama-C/Jasmin or final packages.
It does not resolve the three formal warnings above or approve production.

An additional Frama-C 29 diagnostic isolated the missing libc clauses. A private
copy of its original `string.h` adds only `terminates \true;` and `exits \false;`
to the existing `memcpy` contract, retaining validity, separation, frame,
copied-content and return-value clauses. These are explicit external-library
assumptions, not a proof of the libc implementation. The analysis C, target,
Typed model, recognized Z3 4.12.2, solver limits and strict warning policy stay
unchanged. The missing-spec warning disappears; all 62 original positive goal
identities still pass. A matched false postcondition adds exactly one unproved
goal (62/63). Two Typed pointer-cast warnings remain, so strict admission still
fails. The original-header result retains its three warnings. Neither the
private header nor the diagnostic annotations are shipped as a proved contract.
No unsafe cast mode, warning suppression or codec rewrite was used.

The next private experiment replaces only the eight-byte `memcpy` load with
eight scalar byte reads and explicit unsigned 64-bit shifts. On the pinned
little-endian target, Frama-C 29 validates 63 exact JSON goals, with 65/65
console results and no analysis warnings, using either the explicit header
or the original libc header. Exhausted-reader preconditions are unchanged:
there is no new readable-source, separation or length assumption. The matched
false postcondition leaves only its extra goal unproved; the overflow-prone
guard leaves 18 goals unproved. Timeouts are not solver counterexamples.

A separate live-bulk contract requires an initialized writable reader,
`0 <= n <= 56`, `p <= l`, eight remaining readable initialized bytes and
separation between those bytes and the reader. Across strategy experiments,
the private candidate C and its contract remain unchanged;
Frama-C 29/recognized Z3 4.12.2 validate all 64 original root obligations.
Existing shift tactics and an explicit three-case split at zero close the
remaining mask-shift bound; all three children are Qed Valid. The matched
negative leaves only its added false postcondition unproved (64/65). Earlier
failed prover alternatives remain recorded; process exit zero alone is not
proof admission. Postconditions cover exact `p`/`n` advances and bounds and
unchanged `s`/`l`, not accumulator functional equality. These bulk preconditions
exclude the fallback and do not establish the general reader or its callers.

Eight actual GCC 14.3.0/Clang 22.1.8 reference/alternative ordinary/UBSan runs
pass the maintained `test-ans-allocation` target above, including the 2,312
reader configurations, 9,360 preservation states and 288 mixed-lane calls.
Clang emits identical stripped objects; GCC keeps a 30,168-byte text section
but changes instructions and some function sizes. A later private in-process
ANS benchmark uses those retained GCC objects, seven accepted synthetic
datasets and 31 alternating paired batches per dataset and API. Five
encoder-declined inputs are not assigned timings. For multisymbol inputs,
table construction/reset is inside each decode; input encoding and reusable-
workspace allocation are outside. Constant inputs bypass tables and refill.
Both timing gains and losses occur, with no consistent
benefit; batch averages are not per-call latency distributions or a comparison
against Zstd. These diagnostic inputs, tactics and benchmarks remain private,
not new shipped audit targets. Use the maintained test commands above for the
product; those commands do not reproduce this private contract experiment.
The alternative is not part of the product: the original decoder
and its two Typed warnings remain unchanged. It is not general refill proof,
other-endian qualification, final-package acceptance or production approval.

The next maintained regression adds 288 mixed-lane ANS4 calls to the same
`test-ans-allocation` target, already included in `make check`. Its synthetic
accepted input has lane lengths 0/1/8/9, not an encoder-produced archive.
A fixed, independently derived 36-byte expectation checks every output length
1..36, four source/output alignments and both ordinary/workspace APIs. Source
and destination end at their actual allocation boundaries; prefix canaries,
consumed length 50 and decoder allocation counts 1/0 are checked. One aligned
workspace is initialized once and reused across 144 calls. Long zero-valued
lanes exercise EOF transitions, not every possible bulk-bit pattern or reuse
across different frequency tables. Two private lane-span/partial-bit mutations
pass the old target and fail the new checks at the predicted output bytes.

Use the preceding `make ... test-ans-allocation` command in fresh ordinary
GCC/Clang and separate UBSan checkouts. All four strict native profiles pass.
Fresh scalar and AVX2 GCC ASan/LSan/UBSan VM profiles also pass the new cases
and retained 9,360 states, after rejecting actual sanitizer fault controls.
The original 2-CPU/2-GiB VM and 768-MiB/16-task target limits remain unchanged.

The same fixed source then passes actual strict `test-all` and separate
`audit-licenses sdk-test sdk-verify-symbols` targets with GCC 14.3.0 and Clang
22.1.8. Each has 24 ordered completion records and zero process, collector,
integrity and protocol statuses; 15/14 explicit skips remain respectively.
External system SDK/PQ integrations, native Windows, privileged loop devices
and unavailable shells/renderers are not covered. The Clang bionic-header
check is syntax modeling, not Android qualification. These suites use
`WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0`; in-tree SDK checks run separately.
They include focused sanitizer checks but are not globally instrumented.
The old Clang tool artifacts are missing; a new explicitly pinned installed
provider passes its own smoke, controls and complete suite without downloads
or larger resource limits. Later documentation edits are excluded from the
product snapshot. Neither these results nor the new regression resolve the
two Typed warnings, broader formal obligations or final-package release gates.

Inside a disposable VM with a complete GCC 14.3.0 sanitizer toolchain, use a
fresh copy of the reviewed source for each build. Reproduce the scalar target:

```sh
env ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CPPFLAGS='-DVV_DISABLE_SIMD=1' \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all' \
  test-ans-allocation
```

For AVX2, use another fresh source copy, omit `CPPFLAGS` and append `-mavx2`
to `CFLAGS`; require an AVX2-capable guest rather than accepting a skip.
Reusing the first tree can retain an object compiled with different flags.
These commands run the target, not the private VM envelope or its admission
controls. Do not remove host sanitizer limits or use active swap as a fixture.

In a fresh source-only checkout, reproduce the earlier focused UBSan profile with
GCC and repeat in another fresh checkout with `CC=clang`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O1 -Werror -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined' test-ans-allocation
```

The earlier valid-stream Eva run after count saturation had three alarms
(two table initialization, one output bounds), 37 valid and 13 unknown
preconditions, with 349/496 statements reached. Helper contracts make this
analysis conditional on unresolved caller obligations. The newer precision
profile above resolves those alarms, not the unknown preconditions. A separate
table-specific precision attempt timed out at 25 seconds. Both retain the
original fixture, oracle, malloc model and resource bounds; earlier failed
analyses remain recorded. No complete decoder proof or release approval follows.

A separate private table-width diagnostic parsed the actual two-symbol
header with frequencies 1/4095, validated it and called `build_dec_direct`.
At slevel 16, helper slevel 64 and plevel 512, it proved two of four
assertions and all eight preconditions, but reported two arithmetic alarms
and left successful table construction and width unknown (139/228 reached
statements in 5/75 functions). A table-only slevel 8500 retry reached the
unchanged 25-second deadline without a complete summary. Neither is a passing
gate or a confirmed runtime bug; no table specification or desired bound was
assumed. These results do not close the four caller-width obligations.

#### ANS logarithm ranges

`tests/test_ans_log_bounds.c` includes the real scalar core and calls its
unchanged `ilog2` twice through Frama-C's unsigned interval model: all
`uint32_t` values, then independently every value in 0..4096. A preprocessor
check requires 32-bit `unsigned int`; desired result bounds are assertions,
not assumptions or a substitute helper specification. With Frama-C 29.0,
GCC 14.3.0, GNU awk and the `gcc_x86_64` machine model, run:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-log-bounds-wrapper
FRAMA_C=frama-c make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-log-bounds
```

The gate selects scalar/standalone preprocessing, slevel 16, helper-specific
slevel 64 and plevel 512, with signed/unsigned overflow warnings enabled.
It requires both reached returning bodies, the full input domain, exact
result ranges 0..31 and 0..12, 2/2 assertions and 2/2 interval preconditions
valid, zero warnings/alarms and 15/15 reached statements in 2/75 functions.
Unexpected, duplicate or incomplete profiles and tool failures are errors;
keep raw output and exit status. The real run passed under a 25-second,
768-MiB analyzer limit with two-CPU affinity and no network or home access.
The separate 60 mocked controls check result handling, not C correctness.
They reject uppercase and mixed-case warning/error diagnostics even when the
rest of the report contains the expected complete profile.

A fresh 2026-10-16 run with pinned Frama-C 29.0 and GCC 14.3.0 x86_64 passed
this real Eva gate and the separate malformed-metadata gate: respectively
2/2 assertions plus 2/2 preconditions at 15/15 reached statements, and 14/14
preconditions at 121/343 statements. Both retained zero reported warnings/alarms
and the existing exact-result checks. The metadata log also retains an
informational note about an unsupported ACSL `memset` term. This does not close valid-stream caller,
refill, table or full-decoder obligations.

The native allocation regression adds 4,195 expected-value checks: zero,
`UINT32_MAX`, all 32 powers of two and their neighbors, and every value in
0..4096. GCC 14.3.0 and Clang 22.1.8 pass with non-recovering scalar UBSan.
A private mutation returning zero fails the new boundary check. No runtime
algorithm changed. This range analysis is not an exact floor-log functional
proof, table equivalence, caller frequency bounds or complete decoder proof;
the valid-stream profile's 14 unknown preconditions remain unresolved.

#### Portable AES known-answer and Eva checks

The native fixture links `src/zupt_aes256.c` directly, even when the surrounding
build enables `WITH_JASMIN=1`. It checks all 64 ciphertext bytes from the four
fixed AES-256 ECB vectors in
[NIST SP 800-38A F.1.5, printed page 26](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf),
using one fixed key and valid disjoint buffers. It does not exercise the
runtime assembly dispatcher. Native and supervisor-control targets are in
`check`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-aes-nist test-frama-aes-nist-wrapper
```

For the strict UBSan profile, run this with GCC and repeat with `CC=clang`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O1 -g -Werror -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -DNDEBUG -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined' test-aes-nist
```

The recorded GCC 14/Clang 22 runs passed with caller `-DNDEBUG`; the Make target
places `-UNDEBUG` after caller compiler flags, keeping all assertions active.
The fixture also rejects a direct build that leaves `NDEBUG` defined.
This target recompiles the portable C source rather than reusing existing
objects. The compile-only disabled-assert control returned 0 before that
fixture guard and 1 afterward; it is a test-quality control, not a product fix.

The separate Eva gate is mandatory in `release-check`, not in basic `check`.
Reproduce its pinned `gcc_x86_64` profile with Frama-C **29.0**, GCC **14.3.0**,
GNU awk (`awk` on `PATH`) and a GNU-compatible deadline executable:

```sh
FRAMA_C=frama-c FRAMA_CPP_CC=gcc FRAMA_TIMEOUT=timeout \
  make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-aes-nist
```

Set `FRAMA_C` and `FRAMA_CPP_CC` to alternate executable paths when necessary;
versions are checked, not inferred from filenames. Set `FRAMA_TIMEOUT=gtimeout`
where GNU coreutils installs that name. The real analysis has a 120-second
deadline and a five-second kill grace. Missing tools, nonzero execution status,
warnings, alarms, unknown/invalid properties or incomplete output fail without
a skip. Keep the complete raw log and exit status.

An ephemeral Guix environment can supply the tools without installing them
into the user profile. Pin and record the channel commit; `gcc-toolchain@14`
must resolve to the required 14.3.0 rather than another 14.x release:

```sh
guix shell --pure frama-c@29.0 gcc-toolchain@14 make bash-minimal coreutils gawk grep -- \
  bash -c 'FRAMA_C=frama-c FRAMA_CPP_CC=gcc FRAMA_TIMEOUT=timeout make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-aes-nist test-frama-aes-nist-wrapper test-frama-aes-nist'
```

The current Eva run passed with no warnings and zero alarms, 21 valid
properties, seven valid preconditions and a returning `main`. It reached all
162 statements in five analyzed functions out of 27, including the actual
initializer, block encryptor, `gmul` and `xtime` bodies. Automatic builtin
substitution is disabled for these C functions. The gate requires 64 reached
`__FC_assert` calls and its valid `nonnull_c` precondition; Eva's 21 summary
Assertions are four initialization-loop properties, two internal initialization
checks, one `gmul` loop invariant and fourteen block-loop invariants,
**not 64 separately quantified proof goals**. The earlier 248-file snapshot
had four properties and 160 statements, before the internal assertions.
The intervening initialization-only snapshot had six properties and 162
statements; the subsequent helper-only snapshot had seven properties.
The new block-loop invariants add no executable statement.
An intentionally wrong expected byte produced zero process status and zero
alarms but an invalid assertion precondition and a pruned `main`; the gate
correctly rejected it.

The wrapper's 32 synthetic controls test diagnostics, tool/status handling,
body coverage, byte counts and incomplete/pruned analysis, including rejection
of the old four-property/160-statement, six-property and seven-property
summaries. The 28 earlier cases are retained; four additional cases cover
uppercase and mixed-case `warning:`/`error:` prefixes. A regression against the
old gate exposed the uppercase warning being accepted with status zero. The
wrapper stops at its first failure, so this does not represent four separately
observed false approvals. The gate now uses POSIX awk `tolower` only for that
predicate, preserving raw output and the other profile checks. Its mock supervisor
checks deadline arguments but enforces no deadline. It does not analyze AES
and needs neither Frama-C nor a real GNU `timeout`, so these optional tools
are not dependencies of default `check`.

On the fixed 294-file snapshot tested on 2026-10-22 UTC, all 32 controls and
the real Eva profile above pass: 162/162 statements, 21 valid assertions,
seven valid preconditions and zero alarms in this fixed-vector scope. Fresh
strict GCC 14.3.0 and Clang 22.1.8 `check` and functional CLI smoke also pass,
with 11 and ten explicit skips respectively. Clang executes the modeled bionic
header fixture that GCC skips; Windows, five external-SDK cases, the privileged
loop-device check and unavailable shell/manual tools remain untested.
The installed Clang executable was pinned separately from the unavailable
historical provider, not treated as byte-identical. These are native namespace
runs, not a new VM, full `test-all`, globally instrumented sanitizer campaign
or final native-package acceptance. Final documentation edits are outside the
runtime snapshot; no C, assembly, cryptographic or archive-format code changed.

Run the focused supervisor without the optional formal toolchain:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-aes-nist-wrapper
```

Repeat the ordinary regression in a fresh disposable source checkout for each
compiler; Make does not track every compiler/flag change. For Clang, replace
`CC=gcc` with the selected Clang executable. Run the real Frama-C command above
with its pinned GCC preprocessing profile, independently of this choice:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
bash scripts/test-installed-zupt.sh ./zupt
```

These results cover one fixed key and four valid vectors in portable C only.
They do not prove arbitrary-key AES/FIPS equivalence, side-channel resistance,
assembly caller correctness or the whole program. The historical Qed-only WP
result below remains partial. GCC 14 `test-all` with `WITH_JASMIN=1` passed in
an isolated VM on a frozen 247-file snapshot, with 14 explicit skips; later warning-scan
wrapper, Makefile and documentation changes were excluded. Clang 22 passed
on the frozen 248-file snapshot with 15 explicit skips, including OpenSSL
interoperability because its guest had no `openssl` executable. Three
interoperability checks passed separately in GCC247, not Clang248. Both
ordinary suites use `WITH_SDK=0 WITH_PQBOX=0` and are not globally rebuilt
with ASan/UBSan. Later documentation edits still require a final source audit;
neither result approves production publication.

After the AES initialization changes, fresh GCC 14.3.0 and Clang 22.1.8
`test-all` runs passed on the frozen 248-file source in a 2-CPU/2-GiB VM with
`WITH_JASMIN=0 WITH_SDK=0 WITH_PQBOX=0` (14 and 15 explicit skips respectively).
Clang also passed the complete `WITH_JASMIN=1` suite, requiring actual
Jasmin AES-NI vector dispatch with OS-enabled AVX; 15 skips remain untested.
Separately, GCC `test-asan-run` and installed-smoke checks passed with the CLI
instrumented by ASan/UBSan and leak detection enabled. The ordinary full
suites are not globally instrumented. These checks do not establish native
package installation or compiler regeneration, and exclude later documentation
edits. Preserve the raw logs and all skips; see the README validation table
for the separate integration results and remaining release requirements.

#### Reproduce the CLI sanitizer smoke checks

Use a disposable source checkout and a configured GCC or Clang sanitizer
runtime. Do not reuse objects built with another compiler or feature profile;
Make does not track all flag changes. The Guix Clang environment also needs
its resource-directory and runtime paths configured. Run these commands in
Bash, not directly in fish. Use an ordinary user: root execution skips the
unprivileged permission check. The subshell stops after any failed command:

```sh
(
set -eu
make -j1 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC="${CC:-cc}" \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror' \
  ASAN_CFLAGS='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined' \
  ASAN_LDFLAGS='-fsanitize=address,undefined' \
  test-asan-run
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  bash scripts/test-installed-zupt.sh ./zupt_asan
)
```

The command pins the default sanitizer flags rather than accepting environment
overrides. The Makefile appends `ASAN_CFLAGS`, whose `-O1` overrides the earlier
`-O2`. It instruments every C source in this CLI profile; `WITH_JASMIN=0`
excludes uninstrumented assembly. Clang's existing cast-alignment exceptions
remain local to the designated translation units. The first target checks
archive roundtrips, a fictitious encrypted/deduplicated disk image and
help/version. The installed-smoke script adds nested, empty, random, spaced
and UTF-8 paths, wrong-password and corruption rejection, and symlink-escape
rejection. Sanitizer diagnostics must fail even expected-rejection cases.

Do not impose a small virtual-address-space limit on ASan: its shadow mapping
needs a large address range. Bound actual memory and execution time in a
disposable VM instead. These commands do not configure that isolation or run
`test-all`, fuzz campaigns, exact-size codec tests, SDK/interoperability checks
or Frama-C/Jasmin analysis. Record the complete logs, compiler/flags, source
commit and dirty-source hashes; a successful smoke check is not release approval.

A fresh 2026-10-17 attempt pinned the corrected 282-file source, historical
243-file baseline and existing CLI runtime/tool selection. Admission returned
78 with 4,754,292 KiB available, below the unchanged 5-GiB host-memory floor.
No image, guest control or product test ran; VM limits remain 2 CPUs/2 GiB.
Separately, a private wrapper regression reproduced six false approvals when
QEMU exited zero despite an incomplete or blocked guest transcript. Its
11 fixture tests now pass by requiring every expected control, sanitizer
negative control and product-stage marker once in order, plus final completion.
Producer, collector and integrity failures still propagate. These controlled
fixtures test the wrapper, not sanitizer runtime or codec correctness. That
attempt did not execute the current-source VM; later runtime evidence follows.

On 2026-10-18, a freshly pinned 284-file snapshot passes the bounded GCC
ASan/LSan/UBSan CLI profile in the actual disposable VM. Host headroom exceeds
the unchanged 5-GiB floor at preflight, image compression and launch. The
2-CPU/2-GiB guest verifies isolation, cgroup enforcement, cleanup, timeout and
output limits before running sanitizer negative controls and product stages.
The target retains 768 MiB/16 tasks, 512-MiB scratch and 64-MiB files; each
stage is limited to 4 MiB of output. Heap overflow, leak and signed-overflow
negative controls are rejected with the expected diagnostics. The instrumented
CLI then passes `test-asan-run` and the installed functional smoke suite with
leak detection enabled. Separate, uninstrumented in-tree SDK/license/export
tests and three ML-KEM/OpenSSL interoperability cases pass. All 25 required
protocol records appear once in order; VM, collector, preservation and protocol
statuses are zero. Raw transcript SHA-256:
`4b6fbfaf54090103f6dd536208ac94f71c800b8e769bcce097964162d783c156`.
Later changes only document results. This does not qualify full `test-all`,
exact-size, fuzzing, external SDK/PQBOX, GUI, native packages or the release;
SDK/interoperability success is not sanitizer coverage of those stages.

A subsequent formal repeat initially could not start: the pinned validation
profile, Frama-C 29.0 and Why3 1.7.2 paths were unavailable. The first ANS gate
stopped before analysis, so the later selected checks did not run. That failed
attempt remains recorded; it provided no fresh formal result.

On 2026-10-19 UTC, normal authenticated Guix substitution and grafting restored
the private Frama-C 29.0/Why3 1.7.2 closure. Recursive NAR hashes were checked;
the user profile and trust configuration did not change. The four unchanged
actual Frama-C gates then passed with GCC 14.3.0:

This table retains those 2026-10-19 results. See the
[current ANS bounds profile](#ans-exact-output-bounds) for the expanded scope.

| Gate | Observed result | Limit |
| --- | --- | --- |
| ANS malformed metadata | 138/358 statements, zero alarms, 20 valid preconditions | Three fixtures, not the complete decoder |
| ANS logarithm | 15/15 statements, two valid assertions and two valid preconditions | The modeled unsigned ranges |
| ANS reader WP | 30 exact JSON goals, 16 Qed and 14 Z3; console 34/34 | Initialization/extraction under caller preconditions, not refill |
| Portable AES Eva | 162/162 statements, 21 valid assertions, seven valid preconditions, 64 byte checks | Four fixed NIST blocks, not all keys or modes |

Three initial Eva stages exited 125 after their summaries because the private
controller selected an absent `WHY3CONFIG` file. Creating and recording the
same configuration before every invocation fixed those runs; the original
failures remain failed evidence, not passes. No product source, public test,
analyzer option, acceptance criterion or resource limit changed.

The reader used Z3 4.13.0, which its existing parser accepts. Why3 1.7.2 warned
that the solver version was unrecognized during private detection. Record that
warning separately from the successful analyzer/report gate; this does not
qualify a recognized-solver environment or the complete program. The later
Jasmin repeat below does not discharge C caller obligations or validate final
packages. Final release acceptance remains pending.

The subsequent repeat on 2026-10-19 UTC uses the already retained official
Z3 4.12.2 executable with its pinned glibc/GCC runtime. Fresh checks match the
historical ZIP, executable, MIT license, runtime and Why3 detection-data hashes.
The executable SHA-256 is
`4f490bb1b8f4d71dea98cbd4a7b56a3fdf261ba8ca30a65f22a359d51e70ebd8`.
The original release API provided no digest; these hashes establish retained-byte
identity, not upstream signature verification or independent tool qualification.
No download, rebuild, global configuration or product dependency change is needed.

Inside the same networkless limits, the actual binary reports 4.12.2, Why3 1.7.2
reports it recognized, and real SMT inputs return the required `unsat` and `sat`
before analysis. All four unchanged gates in the table above pass again. Reader
WP reports exactly 30 valid JSON goals, 16 Qed and 14 Z3 4.12.2, with console
34/34. The private supervisor's recognition guard also passes seven execution
controls after four false approvals are reproduced and corrected; those
synthetic controls are not analyzer results. The affected real gates are rerun
after that correction. The first-use missing-config warning is retained before
successful configuration creation; no unrecognized-version warning occurs.
The previous 4.13.0 run is not relabeled or discarded. Broader proof obligations,
final packages and production acceptance remain separate and pending.

On 2026-10-20, the same four maintained Frama-C gates passed again on the
frozen 291-file tree, without changing options, acceptance criteria or resource
limits. The selected Jasmin 2026.09.0 source gate also passed in separate
ordinary and non-recovering UBSan C-fixture profiles: five source-analysis
groups, 1,026 AES blocks and 1,539 AES4 cases per profile. UBSan instruments
the C fixtures, not assembly or analyzer executables. These repeats do not
qualify final packages or establish a whole-program proof.

A fresh strict GCC 14.3.0 `check` and the actual CLI functional smoke suite
also pass on the unchanged C source with SDK/PQBOX/Jasmin and Cargo disabled.
Eleven skips retain the native Windows/Clang-specific ABI, external SDK,
privileged loop-device, optional-shell and man-renderer limitations. The
existing C profile uses 600-second per-process CPU and outer wall limits
plus five-second kill grace; this is separate from the unchanged formal
125-second wall/120-second CPU profile. Both retain two-CPU affinity,
1-GiB per-process address space, private 128-MiB scratch and 1-MiB logs,
not aggregate RAM/CPU quotas. This is not full `test-all`, fresh VM sanitizer,
native-package, GUI, platform or final release acceptance.

#### Optional integration and assembly profiles

`test-all` includes `tests/test_audit.sh`, which exercises the authenticated
SDK paths only when ZUPT is built with a compatible system SDK
(`WITH_SDK=1`); otherwise it reports an explicit
skip. In a clean checkout with the optional integration installed, repeat the
suite with `WITH_SDK=1` and the required SDK linker flags. Run `make clean`
before changing the compiler or feature flags: Make does not track those
values as object-file dependencies. Keep the complete output, including
skipped checks, in the audit record.

On x86_64, the checked-in assembly integration is an additional, explicitly
opt-in check:

```sh
make clean
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
```

Test the Jasmin supervisor's warning-scan status handling separately:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-source-wrapper
```

This default-`check` regression runs the actual source-gate script with mock
tools. Its four controls check no-warning continuation, warning rejection,
scanner error `2` and simulated scanner-unavailable status `127`. Scanner
failures must stop before downstream work, preserve their status and emit a
diagnostic. A passing control prints an explicitly synthetic result, not the
mock tools' expected failure messages. No actual Jasmin analysis is run;
these controls do not need the optional Jasmin compiler or analysis tools.

On x86_64 Linux, analyze and regenerate all five current Jasmin sources:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-source
```

This explicit target requires Jasmin 2026.09.0 (`jasminc`, `jasmin-ct` and
`jasmin-checksafety`), a C compiler, GNU binutils `objcopy` and `readelf`, `cmp`, `awk`,
`pkg-config` and OpenSSL `libcrypto` development files. Override tool paths
with `JASMINC`, `JASMIN_CT`, `JASMIN_SAFETY`, `OBJCOPY` and `READELF` when
needed. In Guix, keep the compiler toolchain's wrapped linker on `PATH`; select
`objcopy`/`readelf` with their explicit overrides instead of prepending a bare
binutils directory that shadows the linker. Missing library search metadata
can otherwise prevent the test executable from loading `libcrypto`.
The generated AES tests require a CPU with AES-NI and OS-enabled AVX; missing
dependencies and unavailable CPU features fail the target, not skip it.

The ordinary repeat on 2026-10-23 UTC passes all five source analyses and
instruction comparisons, 1,026 AES blocks and 1,539 AES4 cases. It also
passes seven package-member comparisons, two exact environment rejection
controls, four synthetic warning-screen controls and seventeen wipe controls.
To run the distributed controls together with the actual source gate:

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-jasmin-source-wrapper test-jasmin-wipe-checker test-jasmin-source
```

Use a disposable, networkless environment with the dependencies and limits
described here. The recorded run uses the pinned runtime and GCC 14.3.0;
this command alone does not enforce isolation or resource limits. Its
294-file runtime snapshot precedes final documentation edits. No fresh
UBSan run, application caller proof, register-erasure proof or final-package
approval follows from this ordinary repeat. A separate ANS floor-log
experiment was not adopted: the private division variant proved its bounded
contract but failed the required whole-object comparison, while the stronger
proof of the original shift implementation was incomplete at that checkpoint.
The subsequent bounded logarithm proof above closes only its stated helper
contract. The maintained codec behavior remains unchanged.

The earlier independent repeat recorded on 2026-10-19 UTC used the existing
hash-checked Jasmin 2026.09.0 runtime without the then-unavailable Frama-C profile.
The three tool executables and four APRON libraries are compared byte-for-byte
with their hash-pinned package members. The package hash chain and historical
signature record are retained; this is not a new independent signature audit.
No tool installation, profile change or analyzer substitution is needed for
this Jasmin repeat. Ordinary GCC 14.3.0 fixtures and a separate non-recovering
UBSan profile each pass the five-source gate, 1,026 block cases and 1,539 AES4
cases. The qualified UBSan repeat first rejects an actual signed-overflow
control with status 1. To repeat that fixture profile after supplying the
dependencies above, use a clean source copy:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  CFLAGS='-O1 -g -Werror -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -DNDEBUG -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' \
  test-jasmin-source
```

The recorded runs have CPUs 0/1 affinity, inherited per-process 1-GiB
address-space and 120-second CPU limits, a 125-second outer deadline with
five-second kill grace, and 128 MiB of private temporary storage. These are
not aggregate cgroup RAM/CPU quotas. Only named read-only tool paths are
exposed; the host home, credentials, network, daemon and KVM are unavailable.
UBSan instruments the C fixtures, not the assembly. Safety remains
conditional on caller preconditions. The reader attempt associated with that
earlier snapshot stopped before analysis because its pinned executable was
missing; see the subsequent restoration result above. After restoration, a
fresh package-member comparison and the same qualified UBSan fixture profile
also pass, again with 1,026 blocks and 1,539 AES4 cases. Neither Jasmin repeat
replaces the Frama-C gates or qualifies final packages.

#### Jasmin-enabled runtime and current-source suite

The latest repeat, on 2026-10-21 UTC, uses the corrected 294-file source with
GCC 14.3.0 and `WITH_JASMIN=1`. The run passes strict `check`, 16 cryptographic
vectors, the CLI functional smoke and 14 threaded checks.
F-06 reports the actual Jasmin AES-NI path, 2,000 honest round trips and zero
encryption failures, mismatches or accepted one-bit HMAC tampers. Eleven
explicit skips remain: native Windows, the selected-Clang bionic fixture,
five external SDK cases, privileged loop device and zsh/fish/manual tools.

The same just-tested CLI also passes all 12 portable-helper test methods and
their subcases. Reproduce the runtime commands and extra helper gate in one
clean build copy with:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
bash scripts/test-installed-zupt.sh ./zupt
sh tests/test_threaded.sh ./zupt
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 test-portable-gui
```

This target is separate from `test-all` and needs no Qt binding. It exercises
the actual helper with genuine unencrypted level-9 `.zupt` containers,
the exact 17-file inventory, checksums and byte-matching extraction. Negative
cases cover CLI failures, altered/missing/unsafe members, policy sources,
existing outputs and directory replacement/collision. Temporary outputs are
not published assets. It does not exercise a Qt window or native GUI install.

The native profile keeps CPUs 0/1, per-process 1-GiB address space, 600-second
CPU and outer deadlines with five-second kill grace, 128-MiB scratch and
1-MiB raw output. Process/collector statuses are 0/0; source and input/tool
postchecks pass. Named host-helper identities are checked at both ends, not
a complete dependency closure. No new ASan/UBSan, full optional-profile
`test-all`, formal proof or final-package approval follows from this run.
The threaded timing printout is informational: N=1 took 10 ms and N=4 took
13 ms (0.8x). It is not a codec benchmark or evidence of a speed improvement.
Final documentation edits are outside the measured snapshot; source/package/
platform/signature and required formal-review gates still govern publication.
Complete raw transcript SHA-256:
`978a5250920ee8712cb1c9ae7eca297b46f8d094b92a31f9440bd85c5c30cf57`.

On 2026-10-19 UTC, the frozen 291-file source also passes the actual
Jasmin-enabled CLI checks, not just generated fixtures. In a clean copy on
x86_64 with AES-NI and OS-enabled AVX, reproduce the product commands with:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
bash scripts/test-installed-zupt.sh ./zupt
sh tests/test_threaded.sh ./zupt
```

GCC 14.3.0 reaches the Jasmin AES-NI F-06 path: 2,000 honest round trips,
zero encryption errors, mismatches or silent accepted one-bit HMAC tampers.
All 14 threaded checks pass; 11 explicit platform/provider/tool skips remain.
The recorded native envelope is CPUs 0/1, per-process 1-GiB virtual space,
600-second CPU and outer limits, five-second kill grace, 128-MiB temporary
storage and a 1-MiB raw-log cap. It has no network or host home access;
these are not aggregate cgroup quotas or assembly sanitizer coverage.

A separate disposable VM passes the unchanged `test-all` with Jasmin disabled,
then the in-tree SDK checks. Reproduce those product commands in a clean copy
inside a suitably isolated VM, using the selected GCC toolchain:

```sh
strict_cflags='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror'
make -j1 CC=gcc CFLAGS="$strict_cflags" \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make -j1 CC=gcc CFLAGS="$strict_cflags" \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses sdk-test sdk-verify-symbols
```

The recorded VM has 2 CPUs/2 GiB, a 768-MiB/16-task target cgroup, 512-MiB
scratch, 64-MiB files, 4-MiB stage output and unchanged 300-second stage
deadlines. ASan virtual space is not artificially capped. All 16 enforcement
controls and three real sanitizer negatives pass before product execution;
all 24 ordered completion records and independent status checks pass.
`test-all` includes 22 general, 14 threaded, 10 PQ and 14 dedup checks,
the timing regression gate, 81 ASan exact-size cases, 1,024 BCJ bijections,
two real-binary BCJ round trips and three ML-KEM/OpenSSL interoperability cases.
The SDK round-trip suite passes 15 cases and its symbol check passes. Its
corrupted-archive negative deliberately emits a failed archive verification;
the surrounding test requires rejection. The run retains 15 skip occurrences,
including disabled external SDK/PQBOX, unavailable platform/tool checks and
the privileged loop-device case. SDK success is not SDK sanitizer coverage.
The suite/SDK cgroup peaks are 245,923,840/95,727,616 bytes, with no unexpected
OOM/PID event or surviving descendant. Raw transcript SHA-256:
`5192b640065e80f4420ee4b862735ad7c5912f5aa1be76a217f0ea16c94e6074`.

A separate Clang 22.1.8 run passes the same product targets on the current
291-file snapshot. Use `CC=clang` in the two commands above with a working
Clang installation and matching ASan runtime; the recorded Guix guest uses
private resource-directory aliases to the pinned installed runtime, not a
different compiler. All 24 ordered records and independent statuses pass,
including timing regression, 81 ASan exact-size cases, BCJ checks and 15 cases
in the SDK round-trip suite. Its 15 skip occurrences include unavailable guest
OpenSSL, so
the three GCC interoperability cases are not counted as Clang coverage.
Suite/SDK cgroup peaks are 239,464,448/33,640,448 bytes, with no unexpected
OOM/PID event or surviving descendant. Raw transcript SHA-256:
`100c3c234487384b76361a33950c46e6f839ced6940acff1382be0b4cb92b592`.

The subsequent run includes the two missing OpenSSL `bin` entries, already
covered by the existing tool pin, without removing inputs or changing tests.
With the same product-code bytes and updated result-only docs, it passes the
full suite, SDK and 24-record protocol again. All three real ML-KEM/OpenSSL
comparisons now pass; 14 other skips remain. Suite/SDK cgroup peaks are
242,233,344/33,619,968 bytes, with no unexpected OOM/PID event or surviving
descendant. Its image is 132,982,776 bytes under the same 128-MiB ceiling.
Raw transcript SHA-256:
`c72055db573ba7d556395403f59f480e6bc4fdfbb97559c358639457e2ef0f6e`.

The initial Clang image attempt exceeded the unchanged 128-MiB image-file
cap before boot; no product tests ran in that attempt. The follow-up retains
every selected source/tool byte and uses CRC32, one XZ thread, x86 BCJ and
LZMA2 preset 9 for transport. The image is 132,702,328 bytes, below the
134,217,728-byte ceiling; this small margin is not a promise for later inputs.
Six real compressor transport checks and 12 wrapper controls pass before the
VM run. These private-image checks are not product, fuzz or formal proofs.

An earlier profile stopped before `test-all` because decoder `.text` differed
from a historical cast-only reference. Four later literal-count allocation
guards intentionally change that code. Preserve this failed identity check;
do not change its expected hash or claim it passed. The explicit current-source
profile runs the actual suite separately with the same tests and limits.
These results do not prove constant-time behavior, qualify all optional
profiles or close broader formal, native-platform and final-package gates.

The separate `test-jasmin-wipe-checker` fixture also requires `sed`, Bash and
`awk`. The recorded combined validation used GNU sed 4.9; ensure it is on
`PATH` when running that fixture or `release-check`.

The target checks compilation, safety under emitted caller preconditions,
explicit constant-time contracts, DOIT, and CT/DOIT after instruction lowering.
For AES4, the safety command declares the pointer/count roles explicitly:

```sh
jasmin-checksafety --arch=x86-64 \
  --param 'zupt_aes256_ctr4>out_ptr,in_ptr,key_ptr,ctr_ptr;nblocks' \
  jasmin/zupt_aes_ctr4.jazz
```

The two AES4 loops carry termination annotations. The result remains
conditional on caller allocation ranges and alias rules in
[`include/zupt_jasmin.h`](../include/zupt_jasmin.h): live, nonwrapping spans,
`nblocks <= SIZE_MAX/16`, identical or disjoint input/output, and the stated
key/counter separation. The earlier unparameterized safety run reached its
120-second limit and remains a historical `BLOCKED` result, separate from the
parameterized check.

Before comparing `.text`, the gate requires each generated/runtime object to
export the exact global function at the section start and contain no
relocations. Instruction bytes alone cannot validate external-symbol references.
It checks fifteen single-block and sixteen AES4 stack-wipe stores. AES4 uses
a 256-byte frame (240 round-key bytes and 16 counter bytes); its maximum RSP
descent from function entry is 264 bytes under x86_64 SysV ABI alignment.
This does not prove register erasure or wiping of alignment padding.

On the frozen 248-file source, GCC 14 and Clang 22 gates each passed 1,026
single-block cases (two NIST vectors and 1,024 OpenSSL differential blocks)
and 1,539 AES4 cases.
The AES4 fixture covers separate/in-place and misaligned buffers, split calls,
low-64-bit counter wrap and zero block counts. Canary checks cover writes,
not assembly read bounds. These correctness checks establish no throughput
advantage, complete FIPS equivalence, every C caller or final packaged binary.
The safety check's pointer-array summaries are not a proof that no array
memory was read.

The same frozen source passed native AES with strict UBSan in both compilers,
its separate mock-control targets, the actual fixed-vector Frama-C Eva gate,
and the license inventory gate. These host checks are separate from the full
VM suites and do not resolve the broader WP obligations or final package and
signature checks.

For the actual C/assembly MAC caller, use another clean source copy:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 \
  CFLAGS='-O1 -g -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=undefined' \
  test-f06 test-vectors
./test_vectors
```

Repeat with `CC=clang` in a separate clean tree. `test-f06` executes 2,000
round trips and single-bit MAC changes across all 256 tag bits. `test-vectors`
only builds its executable; the explicit final command runs its 16 vector
checks. The unsigned MAC reduction avoids signed overflow when the assembly
accumulator has only its high bit set. This preserves both legacy MAC
candidates and does not change the archive format.

Both executables initialize the real CPU detector before testing and print
their selected AES path. An assembly-enabled build still uses portable C when
AES-NI or OS-enabled AVX is unavailable; that is not an assembly-test result.
Repeat this recipe with `WITH_JASMIN=0` in another clean tree to test the
portable path explicitly. The current canonical source passed all four
compiler/feature profiles with 16 vectors and 2,000 F-06 round trips each,
with no accepted altered MACs. Earlier GCC 14 and Clang 22 checks also used
private link instrumentation to confirm calls to the real C, single-block and four-block
implementations and the disabled-feature fallback. That instrumentation is
coverage evidence, not a proof of the complete C dispatch contract.

For formal review, run Frama-C Eva and WP in a pinned environment and retain
the raw logs. The bounded Eva harness, the unconstrained decoder entry point,
and every unresolved WP obligation must be reported separately. A successful
assembly build does not regenerate or formally verify `.jazz` sources; that
requires the matching Jasmin compiler and its reproducible toolchain.

#### Scoped AES key-schedule WP analysis

In the historical Qed-only run, the loop annotations in `src/zupt_aes256.c`
improved the `zupt_aes256_init` analysis without changing its public contract or runtime
instructions. With Frama-C 29.0, GCC 14.3.0, `gcc_x86_64`, `Typed+int` and
built-in Qed, the result improves from 16/39 to 39/58 discharged goals
(37 Qed, one termination, one unreachable). Nineteen goals remain unknown:
eight memory accesses, four index bounds, three signed-arithmetic checks,
three initialized-prefix obligations and the initialization postcondition.
Typed-model separation hypotheses also remain unresolved. This is a partial
source-contract analysis, not a proof of AES/FIPS functional equivalence.
The annotations introduce additional obligations, so the baseline and current
goal totals differ.

To run the historical Qed-only options, use the following in Bash from
the repository root with the pinned tools on `PATH`, GNU coreutils `timeout`
and util-linux `taskset`. Reproducing the old 39/58 totals requires the old
source snapshot, before the masks and internal assertions; current source
generates a different goal set. The recorded run used
CPUs 0 and 1; choose two CPU IDs permitted by your environment. A pinned
ephemeral Guix shell can provide `frama-c@29.0 gcc-toolchain@14 bash-minimal
coreutils util-linux`; record the channel commit and exact tool versions.

```sh
wp_dir=$(mktemp -d) || exit
gcc_path=$(command -v gcc) || exit
audit_cpus=0,1
analysis_status=0
(
  ulimit -v 1048576 || exit
  LC_ALL=C WHY3CONFIG=/dev/null taskset -c "$audit_cpus" \
    timeout --signal=TERM --kill-after=5s 120s \
    frama-c -machdep gcc_x86_64 \
      -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
      -cpp-extra-args="-I$PWD/include" \
      -wp -wp-rte -wp-model Typed+int \
      -wp-fct zupt_aes256_init -wp-prover qed -wp-timeout 2 \
      -wp-par 2 -wp-memlimit 256 -wp-out "$wp_dir/wp-out" \
      -wp-report-json "$wp_dir/results.json" src/zupt_aes256.c
) >"$wp_dir/analysis.log" 2>&1 || analysis_status=$?
printf '%s\n' "$analysis_status" >"$wp_dir/analysis.exit"
cat "$wp_dir/analysis.log"
printf 'Analysis exit: %s; evidence: %s\n' "$analysis_status" "$wp_dir"
```

This selects every obligation for that function, including RTE, frame,
termination and initialization obligations, without selecting only proved
goals. `-wp-prover qed` runs the internal prover; `-wp-prover none` only
generates obligations and is not a Qed proof run. The 1 GiB virtual-memory
limit is per process, not an aggregate limit. Keep the log and JSON report;
**process exit 0 is not proof PASS**. Warnings, unknown/unproved goals,
timeouts, missing tools or failed execution block a strict proof gate. The
recorded process exited 0 but its strict gate exited 1.

A separate, sealed run on 2026-10-07 passed the strict AES-init WP gate:
60/60 console obligations and 58/58 unique, non-smoke JSON goals, all valid.
It retains all 56 baseline IDs and proves both `old_prefix_initialized` and
`new_word_initialized` before using them as internal proof cuts. No public
precondition, invariant, frame condition or postcondition was removed or
weakened. Two redundant top-byte masks make SBOX indices explicit; GCC 14 and
Clang 22 emitted identical `.text` before and after this change.

This run used Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 and recognized Z3 4.12.2.
The source SHA-256 is
`35562ca8e0861db3fbd185cf9ba61c1d6e43c097f34a6d38fb254c83352a4e1b`;
the complete raw VM transcript SHA-256 is
`4efe9b76ae541c9e8c594f92a9542d46e611914cb7c6ef052339160b6b4ae19b`.
The VM had two CPUs and 2 GiB RAM; the target cgroup had 768 MiB, 16 tasks,
512 MiB scratch and a 4 MiB output limit. Provers retained two seconds and
256 MiB each, with two jobs and a 120-second analysis deadline. NIST's four
fixed blocks and the deliberately wrong-byte control also passed their gates.

For the Z3 analysis invocation below, first prepare a private Why3 configuration
whose `why3 config detect` and `why3 config show` recognize Z3 **4.12.2**.
Record the configuration, driver, solver binary and tool hashes. Do not reuse
the Qed-only `WHY3CONFIG=/dev/null` setting. With the preceding Bash variables:

```sh
WHY3CONFIG="$wp_dir/why3.conf" LC_ALL=C taskset -c "$audit_cpus" \
  timeout --signal=TERM --kill-after=5s 120s \
  frama-c -machdep gcc_x86_64 \
    -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
    -cpp-extra-args="-I$PWD/include" \
    -wp -wp-rte -wp-model Typed+int \
    -wp-alias-vars SBOX,RCON -wp-msg-key=prover -wp-no-init-const \
    -wp-fct zupt_aes256_init -wp-prover z3 \
    -wp-timeout 2 -wp-par 2 -wp-memlimit 256 \
    -wp-out "$wp_dir/wp-z3-out" \
    -wp-report-json "$wp_dir/results-z3.raw.json" src/zupt_aes256.c
```

This command is the analysis invocation, not the complete VM/resource/checker
envelope. Preserve its exit status, full log and original report. Frama-C 29.0
can emit numeric literals such as `0.`; retain the raw bytes when normalizing
with jq and verify parsed-array identity before strict JSON checks. Require
all expected goal IDs, including both assertions, all valid/passed verdicts,
recognized prover identities and no warnings or incomplete goals. Counts or
exit 0 alone are insufficient. There is no public standalone WP Make target;
`test-frama-aes-nist` is the separate executable Eva fixture gate.

`-wp-alias-vars SBOX,RCON` models those addressable globals explicitly.
`-wp-no-init-const` omits their literal initializer values, not their validity
or initialization. The result covers the selected bounds/RTE, frame,
initialization and termination obligations under the model and preconditions.
It does not prove AES/FIPS functional equivalence, side-channel resistance,
the whole program, native Guix packaging or production readiness.

The arithmetic helpers now have function frames and an explicit `gmul` loop
frame, invariant and variant. Six added ACSL lines change no executable C or
public precondition. On the same pinned tool/model/resource profile, a separate
`xtime,gmul` WP run passed 19/19 console and 17/17 exact JSON obligations.
It retains six baseline IDs; the two old split termination goals are replaced
by the function termination goal and separately required variant positivity
and decrease checks. The original unannotated termination timeout is preserved.
No `-wp-variant-with-terminates` hypothesis or new axiom was used.

Reproduce the helper analysis with the prepared Why3 configuration:

```sh
WHY3CONFIG="$wp_dir/why3.conf" LC_ALL=C taskset -c "$audit_cpus" \
  timeout --signal=TERM --kill-after=5s 120s \
  frama-c -machdep gcc_x86_64 \
    -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
    -cpp-extra-args="-I$PWD/include" \
    -wp -wp-rte -wp-model Typed+int \
    -wp-alias-vars SBOX,RCON -wp-msg-key=prover -wp-no-init-const \
    -wp-fct xtime,gmul -wp-prover z3 \
    -wp-timeout 2 -wp-par 2 -wp-memlimit 256 \
    -wp-out "$wp_dir/wp-helpers-out" \
    -wp-report-json "$wp_dir/results-helpers.raw.json" src/zupt_aes256.c
```

The earlier helper-only source SHA-256 is
`f88d4c5ac413b63382fa1b3da27833b9d83c956429a1d4d1b7274df8b2503ce1`;
its strict VM transcript SHA-256 is
`3d1913df8ee03e2633bbb39349626c24c02f7e21600b133b34df0e4fb9e407be`.
A separate combined run on the same source rechecked all 58 initialization
JSON goals, actual seven-property Eva result and 27 supervisor controls:
raw transcript SHA-256
`222aa0eeb158d335a4bac10ace69a36bd672df9c79d8a6e7cd09da494b9b89ce`.
Both complete GCC NIST executables remained byte-identical after the annotations.
Keep exact goal IDs, valid verdicts, original reports and resource/diagnostic
checks; totals alone are not acceptance. This proves selected frames, bounds
and termination under the model, not functional GF multiplication, AES
equivalence, block-encryptor correctness or whole-program security.

#### Portable AES block-loop WP checks

The block encryptor now has bounds and initialization invariants, frame clauses
and decreasing variants for all seven loops. These 35 ACSL comment lines change
no executable C, public precondition, API or archive format. The original
unannotated run discharged 113/144 goals with 31 timeouts and seven missing-loop-
frame warnings; that result remains separate. With the annotations, all 214
distinct JSON goals passed: 28 invariant establishment/preservation obligations,
14 variant positivity/decrease obligations, output initialization, termination
and the remaining selected frame/bounds/RTE obligations. Initialization and
helper proofs passed separately on the same source, 58/58 and 17/17 JSON goals.

Reproduce the scoped invocation using the prepared Why3 configuration and the
preceding Bash variables:

```sh
WHY3CONFIG="$wp_dir/why3.conf" LC_ALL=C taskset -c "$audit_cpus" \
  timeout --signal=TERM --kill-after=5s 120s \
  frama-c -machdep gcc_x86_64 \
    -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
    -cpp-extra-args="-I$PWD/include" \
    -wp -wp-rte -wp-model Typed+int \
    -wp-alias-vars SBOX,RCON -wp-msg-key=prover -wp-no-init-const \
    -wp-fct zupt_aes256_encrypt_block -wp-prover z3 \
    -wp-timeout 2 -wp-par 2 -wp-memlimit 256 \
    -wp-out "$wp_dir/wp-block-out" \
    -wp-report-json "$wp_dir/results-block.raw.json" src/zupt_aes256.c
```

Require all exact goal identities, valid/passed verdicts, recognized solver
results and no diagnostics, unknowns, timeouts or failures. The command alone
does not enforce the complete VM/checker envelope. The recorded run uses a
2-CPU/2-GiB VM, 768-MiB/16-task stage, 512-MiB scratch, 4-MiB output cap and
the same two-second/two-job/256-MiB-per-prover limits. No model hypothesis or
new axiom was introduced. GCC preprocessed the original and modified source
identically. This is not AES/FIPS functional equivalence, a constant-time proof,
a proof of all callers or a whole-program security audit.

Source SHA-256:
`972f426d977df29cd193eb2a6f52a2c0775a480683d5d65f134c48046884d93e`.
Integrated VM transcript SHA-256:
`d0d7f3f8e2d3fc30f068ca20fda4c2b19dca323d2d280eaa4b6b448959d6c597`.
It also passes the real Eva gate, 21 valid properties, seven valid preconditions,
162/162 statements, 64 reached byte-oracle calls and returning `main`, plus
all 28 supervisor controls. Older exact store paths had become unavailable;
new installed Frama-C 29.0/Why3 1.7.2 and the disposable VM kernel were explicitly
repinned with different hashes, not treated as byte-equivalent replacements.
The missing-awk and missing-plugin setup failures are retained. A complete
Frama-C runtime needs its Eva core dependencies, including inout and scope;
do not suppress their warnings. The missing exact PPL 1.2 Jasmin dependency
was subsequently restored in a private runtime after authenticating the complete
official Guix NAR. No host store/profile or product dependency was changed.
Fresh GCC 14.3.0 and Clang 22.1.8 runs of `test-jasmin-source` and
`test-jasmin-source-wrapper` both exit zero: all five sources, matching runtime
instructions, 1,026 AES blocks, 1,539 CTR cases and four supervisor controls per
compiler. Caller preconditions and original resource limits remain unchanged.
These are source/fixture checks, not final-package or whole-program approval.
Raw log SHA-256, GCC:
`4a990a39e123c650f331576251b38c6a40bc073fc758e51627b301292d25a5c6`;
Clang: `86df7db5a0a40e29ef4a667e66add827679164e3ddcd28b3c3fa99bbffbce372`.

The historical broader WP runs remain separate: Qed discharged 285/653 goals;
the Z3 4.13.0 diagnostic run discharged 346/653 with 305 timeouts and two
unknowns, using a solver version not recognized by the cached Why3 detection
data. Those warning-rich runs do not close the broader formal release gate.
Their totals are historical, not a current unresolved-goal inventory. Later
function-specific proofs use different obligation sets; no goal-by-goal
reconciliation has been demonstrated. Do not subtract later pass counts from
653 or treat the selected proofs as complete cryptographic validation.

### Earlier continuous fuzz resource failure

The earlier disposable-VM campaign remains recorded as a failed gate. It used the
257-file source snapshot, Clang 22.1.8, scalar codec objects, seven validated
seeds, three sanitizer controls, a 4 KiB input limit, a 65,536-byte output
buffer and one continuous libFuzzer process with a 30-second budget and an
unchanged 512-MiB RSS limit. It stopped after about 8.04 seconds.
The exact executable SHA-256 is
27ffda8eecf2108b5481f47f8efd5bff23d3084564f925ed37ad4e143dae19a3.
It exited 71 after 2,360,279 executions and 2,040 new units at 598 MiB. The
target cgroup peak was 660,992,000 bytes; no cgroup OOM or PID-limit event
occurred, and no descendant remained. The saved 127-byte input is
d378fd4c77b7c57cc96bc62e04a69ad8fc3f95b849c76791c256e1ab38eba534.

Rebuilding that executable at the same logical paths reproduced its hash.
Symbolization of the displayed live-heap context returned
`___interceptor_malloc`, `operator new(unsigned long)` and `main`. That
context covers 24,383,368 of 24,791,125 live bytes; the log separately records
244,292,744 quarantined bytes. The context does not explain the full RSS or
exclude contributions from codec allocations. This is neither a pass nor a
confirmed codec leak, and does not justify raising the RSS limit.
An exact-binary VM replay executed this 127-byte input once in 1 ms with
status zero, a 47-MiB peak and no artifacts. Its target cgroup peaked at
63,795,200 bytes, without an OOM or PID-limit event or surviving descendant.
The successful 1,549-byte replay belongs to an earlier campaign. These
single-input checks do not replace a successful continuous campaign. The
outer VM exit status of zero records VM completion; assess each target's
status and retained diagnostics separately.

Later bounded continuous VM campaigns passed on their recorded snapshots,
including the 2026-10-14 campaign after sequence-allocation changes documented
in [README.md](../README.md). Those results do not reclassify this earlier
failure or establish acceptance of subsequent source changes or native packages.

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
