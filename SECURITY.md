# Security Policy — ZUPT 5.2.5

## Reporting vulnerabilities

Report suspected vulnerabilities privately to **zupt@riseup.net** with
`[security]` in the subject. Do not open a public issue before coordinated
disclosure.

Include the output of `zupt --version`, operating system and architecture,
impact, and the smallest safe reproducer. Remove passwords, keys, tokens,
personal data, and confidential archive contents.

The project aims to acknowledge reports within five business days and to target
high-severity fixes within 30 days, with the disclosure timeline agreed case by
case. These are targets, not a warranty.

ZUPT has not had an independent third-party security audit or certification.
Treat the in-repository review and tests as reproducible project evidence, not
as external assurance.

## Supported security modes

| Mode | CLI | Key establishment / derivation | Payload protection |
|---|---|---|---|
| Plain | no encryption option | none | compression checksums only |
| Password | `-p/--password`, `--password-prompt`, `--pass-file`, or `--pass-fd` | PBKDF2-SHA256, 600,000 iterations | AES-256-CTR + HMAC-SHA256 |
| Native hybrid PQ | `--pq` | ML-KEM-768 + X25519, SHA3-512 combiner | AES-256-CTR + HMAC-SHA256 |
| Native PQ only | `--pq-only` | ML-KEM-768, SHA3-512 derivation | AES-256-CTR + HMAC-SHA256 |

The native hybrid mode is the recommended post-quantum mode unless a policy
forbids a classical component. `--pq-only` removes the X25519 fallback: a break
of ML-KEM-768 alone would then compromise key establishment. Password security
is bounded by password entropy; PBKDF2 cannot make a short or reused password
safe against offline guessing.

The `-p/--password PASSWORD` argument form can be visible to process-list users
and shell history. Prefer `--password-prompt`, `--pass-file` with restrictive
permissions, or `--pass-fd` with a descriptor inherited from a trusted caller.
The file/descriptor forms read one line, remove LF and an optional preceding CR,
and reject empty, NUL-containing, or overlong input. ZUPT does not enforce
password-file ownership or mode; the caller remains responsible for creating,
protecting, and deleting that file. The descriptor form duplicates the supplied
descriptor and does not close the caller's original descriptor.
The duplicate shares the same underlying stream and offset, and buffered input
may consume beyond the password line. Pass a descriptor dedicated to this one
password read; do not reuse it as a multi-record protocol channel.

On POSIX terminals, the explicit prompt saves terminal state and installs
signal-aware cleanup so a handled interruption restores echo and other changed
settings before termination. This behavior is covered by a PTY regression and
passed in the full local Linux gate for commit `ff99770`.

## Native key files

Native private keys use no-replace creation: POSIX files are mode `0600` and
Windows files receive a current-user-only DACL. An existing destination is
never truncated. If write, flush/fsync, or close fails, ZUPT deliberately leaves
the exclusively created incomplete or durability-uncertain file at that path
for the user to inspect and remove. It does not unlink by pathname after close,
which avoids deleting a replacement installed during a race. Public keys may be
shared deliberately and are not treated as secret. ZKEY and ZPQK readers
validate the checksum, format version, flags, reserved bytes, exact encoded
size, and public/private role before using any key material. A truncated,
extended, structurally invalid, or role-confused key is rejected rather than
partially accepted.

### Optional integrations

The 5.2.5 default is `WITH_SDK=0 WITH_PQBOX=0`:

- `WITH_SDK=1` enables libvuptsdk-backed features, including the SDK PQ mode
  and Argon2id support, using a separately installed system development package.
- `WITH_PQBOX=1` independently enables the libpqvaptvupt sealed-box mode using
  its separately installed system development package.

Neither library is committed as a precompiled artifact, and no build path
downloads it. A missing requested dependency is a build error. Security
properties of these optional libraries are outside the source-only CLI audit
unless their exact source package and version are reviewed separately.

## Cryptographic construction

Encrypted blocks use a fresh 128-bit nonce, AES-256-CTR, and HMAC-SHA256. The
MAC binds the encrypted payload, canonical block metadata, and the frame's
logical position, and is checked before restored data is accepted. In 5.2.2,
this positional AAD applies to DATA and DEDUP_REF frames. An authenticated
reference is bound to its own position and carries the authenticated source
position needed to verify the referenced DATA frame.

An archive-integrity trailer (AIT) covers global metadata. The 5.2.2
`extract`, `list`, `test`, and `disk restore` paths refuse a no-AIT layout by
default, without trusting the archive's unauthenticated `ENCRYPTED` bit to
decide whether that check matters. `--allow-legacy-no-ait` is accepted only by
those commands; it is a recovery-only opt-in for a known, trusted pre-AIT
archive and emits a downgrade warning. Never use it for an archive from
untrusted or attacker-writable storage. `info` only reports unauthenticated
framing and apparent AIT presence; it does not validate the trailer or archive
contents. Plain archives use non-cryptographic checksums and do not provide
protection against an attacker who can rewrite the archive.

Archive comments are authenticated according to the archive mode, but they are
still untrusted display data. ZUPT renders control bytes safely when showing a
comment and does not emit raw terminal-control sequences. This prevents a valid
or attacker-supplied comment from rewriting terminal output; it does not make a
plain archive cryptographically authentic.

In new 5.2.2 encrypted+dedup archives, each reference offset is included in
the authenticated reference payload. New encrypted disk archives also
authenticate their index; the index binds the image size, block count, and a
chained XXH64 hash of the complete restored byte stream. The writer
additionally requires an XXH64 and SHA-256/128 match before emitting a dedup
reference, but that SHA-256/128 digest is an in-memory collision guard and is
not stored as an on-disk integrity claim. XXH64 is non-cryptographic: in a
plain archive it
detects accidental corruption but can be recomputed by an attacker.

The native hybrid derivation implemented by 5.2.2 is:

```text
ml_ss       = ML-KEM-768 shared secret
x25519_ss   = X25519 shared secret
hybrid_ikm  = ml_ss XOR x25519_ss
archive_key = SHA3-512(hybrid_ikm || ml_ct || ephemeral_pk ||
                       "ZUPT-HYBRID-v1")
```

`--pq-only` derives the archive key as
`SHA3-512(ml_ss || ml_ct || "ZUPT-PQ-ONLY-v1")`.

The native modes are at-rest archive encryption. They do not provide protocol
session forward secrecy: later compromise of the relevant long-term private key
can compromise archives encrypted to it.

## Constant-time and side-channel scope

Portable C is the 5.2.5 default. Sensitive comparisons and selections use
branchless helpers, but generated machine-code behavior remains dependent on
the compiler and platform. This is not a formal whole-program constant-time
claim. The C AES implementation uses table lookups and is unsuitable for a
claim of cache-timing resistance on hostile shared hardware.

Textual assembly under `jasmin/` can be enabled explicitly with
`WITH_JASMIN=1` on a supported x86_64 compiler target. The directory contains
Jasmin-generated output and separately identified hand-written assembly; all of
it is disabled by default and its inclusion must be confirmed in the exact
binary being assessed. Its availability does not imply formal verification of
the archive parser, compression codec, or the whole program.

## Security boundary and limitations

ZUPT is designed for backups created and restored on trusted endpoints. It
does not protect against:

- malware, keyloggers, memory inspection, or a compromised user account on the
  machine handling plaintext or keys;
- disclosure of a password or private key;
- denial of service from arbitrarily large or adversarial input;
- traffic analysis from archive size and visible framing metadata;
- hiding that a file is a ZUPT archive;
- compression-length side channels when attacker-controlled and secret data are
  compressed together and an attacker can observe output length;
- network transport attacks, multi-party access control, threshold recovery, or
  key rotation;
- every compiler-, microarchitecture-, power-, or speculative-execution side
  channel.

Archive entry paths reject traversal, absolute paths, control characters,
Windows alternate streams/device names, and ambiguous trailing dot/space
components. POSIX extraction resolves each parent relative to a pinned file
descriptor with no-follow semantics after canonicalizing the user-selected
output root once; symlinks below that root remain forbidden. Windows resolves
each parent and temporary
file relative to a directory handle and performs the final no-replace rename by
handle, so a checked path is not looked up again through a mutable junction or
reparse point. An existing destination leaf is never overwritten.

Decoded bytes first go to a private, exclusively created temporary file. The
final name is published only after the expected decoded size and chained
checksum match and the stream closes successfully; failures remove the
temporary by descriptor/handle. These controls reduce traversal, link, race,
and partial-output risks, but they do not make privileged extraction
appropriate. Extract untrusted archives as a dedicated unprivileged user into
a new empty directory, inspect the result before moving it, and apply OS
sandboxing where available.

Disk restore has a separate destructive-device boundary. It measures and
copies the compacted archive to an exclusively created, auto-deleted private
scratch file before opening the target, then performs both validation and
restoration from that same snapshot. `ZUPT_TMPDIR` is an explicit existing
scratch-directory override; an invalid override fails without fallback. Raw
block devices are opened only after their capacity has been determined and
shown sufficient on supported Linux, macOS, or FreeBSD interfaces. Unknown
device capacity, an undersized device, a source/destination identity match, or
a snapshot failure stops before the first target write. These checks do not
make raw-device restore non-destructive: verify both operands and keep recovery
media before proceeding.

The Windows handle-relative implementation is scoped to normal local Win32
paths. Win32 extended-length and device-namespace paths, raw UNC output roots,
and mapped/network-drive output are not supported in 5.2.5. Cross-build and
Wine results are not native-Windows evidence; the `windows-latest` package gate
must pass its Unicode round trip before Windows assets are published. Restore
to a normal local directory first and move verified output to network storage
afterward.

## Historical compatibility and fixes

These statements are historical release records, not claims that every current
gate was rerun on every platform:

- In 4.2.0, encrypted deduplication changed from a repeated derived nonce to a
  fresh random per-block nonce. Re-encrypt encrypted `--dedup` archives written
  by releases through 4.1.0.
- In 5.0.0, native ML-KEM was corrected from round-3 CRYSTALS-Kyber semantics
  to FIPS 203 ML-KEM-768. Native `--pq` and `--pq-only` keys and archives from
  releases through 4.2.1 are not compatible with the corrected mode. Password
  and plain archive paths were not affected by that KEM change.
- Releases predating the archive-integrity trailer may have a structurally
  valid no-AIT layout. Such an archive now fails closed unless the caller uses
  `--allow-legacy-no-ait` on a supported read command. This option permits
  recovery of trusted old media; it is not a general compatibility mode and
  does not make unauthenticated header/footer metadata safe.
- Readers since 5.2.2 accept the fixed-width disk index and encrypted-dedup linear
  AAD sequence published through 5.2.1 and warns that the legacy index has no
  whole-image content hash. Its regression fixture is an actual v5.2.1
  password-encrypted DATA/DATA/REF/DATA disk archive stored as hexadecimal text with
  source and hash provenance. The candidate lists, tests, extracts, and restores it
  byte-exact; the full local Linux gate passed on commit `ff99770`. This does not
  claim that 5.2.1 readers accept the new flag-gated 5.2.2 records or that every
  historical encrypted+dedup combination was validated.

The repository contains NIST/RFC vector tests and an OpenSSL 3.5 ML-KEM
interoperability test. The OpenSSL test can only execute when the environment
provides an ML-KEM-capable OpenSSL; otherwise it must be reported as skipped.

## Source and release integrity

Git and upstream source archives contain no compiled executable, object,
shared/static library, or distribution package. Audit them with:

```sh
scripts/check-source-only.sh
scripts/check-source-only.sh --archive /path/to/zupt-5.2.5.tar.gz
```

Nested archive inspection is required to enforce bounded recursion, member
count, per-entry expanded size, and total expanded size, and to fail closed on
limit violations. On commit `ff99770`, the source-only scanner suite passed
39/39, including GNU thin archives, resource-limit cases, and safe diagnostics.

DEB, binary RPM, SRPM, notice-bearing Linux tar.xz, source-only portable GUI
ZIP, Windows ZIP, and macOS DMG release assets are separate outputs. An
AppImage is not promoted for 5.2.5. A bare Linux or Windows executable is also
excluded; executables are distributed only inside their notice-bearing
archives. Trust an artifact only when its exact format has a recorded build,
content/metadata inspection, extracted or installed smoke test, and applicable
archive round trip. Never treat an unexecuted platform as passing.

The gated 5.2.5 set is the CLI package/archive set plus the exact GUI DEB,
noarch/source RPM, and source-only portable ZIP documented in the README. The
portable GUI ZIP contains no compiled runtime and is scanned as source before
and after extraction. Other GUI packages, AppImage, AppDir and Flatpak bundles,
and GUI platform installers are excluded. Windows ZIP and macOS DMG artifacts
remain CLI-only.

## Reproducing project checks

Start with the baseline source-only build:

```sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)" \
  WITH_SDK=0 WITH_PQBOX=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 check
make WITH_SDK=0 WITH_PQBOX=0 test-all
```

Where the compiler supports them, run the sanitizer target separately:

```sh
make test-asan
make test-asan-run
```

The first command builds the sanitizer configuration; the second executes its
test suite. Neither substitutes for the normal optimized build and tests.

The full local Linux `make release-check` passed on the immutable, non-promoted
5.2.2 candidate at `ff99770`. Its recorded evidence includes packaging
`PASS=49 FAIL=0 SKIP=0`,
the 39/39 source-only scanner suite, strict GCC and Clang builds, GCC
`-fanalyzer`, 9/9 static analysis in a tool-enabled run, ASan/UBSan/LSan, and
1,000 mutation-fuzz iterations without a sanitizer-detected crash. An earlier
off-screen GUI smoke run is supporting evidence, not an exact-candidate package
result.

Post-tag CI integration failures prevented 5.2.2 promotion. Those upstream
self-audit results are not independent certification and do not transfer to
5.2.5. The immutable 5.2.3 candidate was not promoted because its source-policy
test assumed LF for a Windows `.bat` file checked out as CRLF. The immutable
v5.2.4 candidate was not promoted after exact-tag GitHub Actions run
`33431386002`: 12 jobs succeeded, the sole openSUSE job failed in its
standalone source-service harness because it did not enter the service
directory, and dependent Windows and macOS jobs were skipped. A local
Tumbleweed reproduction confirmed that `refs/tags/v5.2.4` is valid and that
`os.chdir(service_dir)` lets `obs_scm`, `tar`, and `recompress` complete with a
source-scanned archive. This was a release/test integration defect, not a
product, archive, cryptographic, codec, or SDK ABI change, and its evidence does
not transfer automatically to 5.2.5. The exact 5.2.5 candidate must repeat the
required suite. Native Windows and macOS, hosted GitHub CI/release promotion,
authenticated OBS, and the openSUSE automatic `debugsource` rpmlint `no-binary`
finding remain pending until recorded otherwise. An unavailable or unexecuted
environment remains `SKIP`, never `PASS`.

Run target-native static analyzers and package checks as additional evidence.
Do not infer x86_64, aarch64, ppc64le, s390x, riscv64, macOS, Windows, Leap, or
SLE success from these commands unless that exact environment produced a
successful recorded result.

ZUPT application code is distributed under AGPL-3.0-or-later. The bundled
VaptVupt codec source is GPL-3.0-or-later. The two xxHash-derived XXH64 units
also carry BSD-2-Clause. The pq-crystals/kyber-derived portions of native
ML-KEM carry CC0-1.0 in addition to the application license, and the x86 BCJ
state machine is adapted from public-domain LZMA SDK source. Native X25519
portions adapted from curve25519-donna conservatively retain BSD-3-Clause. See
`LICENSE`, `LICENSE-GPL-3.0`, `LICENSE-BSD-2-Clause`, `LICENSE-BSD-3-Clause`,
`LICENSE-CC0-1.0`, `NOTICE`, and `THIRD-PARTY-NOTICES.md`. Historical license
grants for exact earlier material are recorded in the 5.2.2 licensing erratum;
the current notices do not revoke them.
