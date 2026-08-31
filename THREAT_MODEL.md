# ZUPT 5.2.2 threat model

This document defines the security boundary of the ZUPT archive tool. It is
not a certification, a guarantee against every hostile input, or a substitute
for reviewing the exact source and binary used for important data.

## Intended use

ZUPT is intended for at-rest backup archives created and restored on
machines controlled by the user. It can be used when the storage provider or
physical medium is not trusted, provided encryption is enabled and credentials
remain secret.

It is not a network protocol, a full-disk encryption system, a multi-party or
threshold scheme, a password manager, or a way to make an archive's existence
plausibly deniable.

## Baseline considered here

The upstream baseline is built from the 5.2.2 source with:

```sh
make WITH_SDK=0 WITH_PQBOX=0
```

It contains the native password, ML-KEM-768 + X25519 hybrid `--pq`, and
ML-KEM-768-only `--pq-only` modes. It does not load a precompiled library from
the repository and does not download a dependency while building.

`WITH_SDK=1` and `WITH_PQBOX=1` add separately installed system libraries and
change the assessed code boundary. The SDK and PQBOX integrations must be
reviewed with their exact packaged source and version; success of the baseline
tests is not evidence for them.

Textual assembly under `jasmin/` is a separate `WITH_JASMIN=1` option for
supported x86_64 compiler targets. The directory contains both generated and
separately identified hand-written assembly. Portable C is the default.
Architecture portability is a source property, not evidence that an unexecuted
architecture passed.

## Assets

The assets ZUPT tries to protect are:

- archived file contents and encrypted index data;
- the integrity and ordering of encrypted archive blocks and current global
  metadata covered by the archive integrity trailer;
- private keys, passwords, and derived encryption/MAC keys while held by the
  trusted caller;
- safe placement of extracted entries within the requested destination.

The archive's existence, total byte length, magic, encryption/framing flags, and
some size/structure information are observable. Plain archives provide
corruption detection, not cryptographic protection against an active attacker.

## Adversaries considered

The design considers an adversary who can read, copy, truncate, reorder, or
modify stored archive bytes but cannot read the encryption endpoint's memory or
credentials. It also considers accidental corruption and malicious archive
entry paths during extraction.

The following adversaries are outside the protection boundary:

- malware, a keylogger, or an administrator on the source or restore endpoint;
- an attacker who obtains the password or matching private key;
- a malicious compiler, kernel, CPU, firmware, or random-number generator;
- an attacker with unrestricted side-channel observation of a shared machine;
- an attacker allowed unbounded CPU, memory, or storage denial of service.

## Security properties

### Encrypted archive confidentiality

Password and native PQ modes encrypt blocks with AES-256-CTR and authenticate
them with HMAC-SHA256. Confidentiality depends on unique nonces, correct
implementations, OS randomness, and credential secrecy. In password mode it
also depends on password entropy; PBKDF2-SHA256 slows but cannot prevent offline
guessing of a weak password.

Prefer `--password-prompt`, `--pass-file`, or `--pass-fd`. A password supplied
through `-p/--password` can be visible through process inspection or shell
history. A password file is protected only by the caller's filesystem choices;
ZUPT does not validate its ownership or permission bits. A descriptor is
trusted input inherited from the caller. Both non-interactive forms read one
line and reject empty, NUL-containing, or overlong values. The descriptor form
duplicates but shares the underlying stream/offset and may buffer beyond the
line, so callers should provide a descriptor dedicated to that password read.
On POSIX, handled prompt interruptions restore the saved terminal state before
termination; an exact-candidate PTY regression is required before release.

Native private-key generation uses no-replace creation with POSIX mode `0600`
or a Windows current-user-only DACL. A failed write, flush/fsync, or close leaves
the incomplete or durability-uncertain exclusive file for manual review and
removal instead of risking an unlink-after-close race against a replacement
pathname. ZKEY and ZPQK inputs
are accepted only after checksum, version, flags, reserved bytes, exact size,
and public/private role validation. This prevents role confusion and
partial/trailing-key acceptance; it does not protect a key after endpoint or
account compromise.

### Encrypted archive integrity

Current encrypted archives authenticate ciphertext, canonical block metadata,
and each frame's logical position. DATA and DEDUP_REF frames both receive this
positional AAD. A reference is authenticated at its own position and carries
the authenticated source position needed to verify the referenced DATA frame,
so exchanging otherwise equivalent frames is not accepted.

Current archives carry an archive-integrity trailer for global metadata. The
`extract`, `list`, `test`, and `disk restore` paths refuse any no-AIT layout by
default without relying on an unauthenticated header flag.
`--allow-legacy-no-ait` is a narrowly scoped, warning-producing recovery option
for those commands when the caller already trusts a pre-AIT archive. Selecting
it for attacker-controlled storage removes the header/footer authentication
assumption and is outside this threat model. `info` is an unauthenticated
framing inspection that reports apparent AIT presence but validates neither the
trailer nor archive contents. These checks do not prevent deletion of the
entire archive, rollback to an older valid archive, or storage-layer replay.

Archive comments remain untrusted presentation data even when they are
authenticated. Display paths render control bytes without emitting raw terminal
control sequences, limiting terminal-output injection while leaving the stored
and authenticated comment bytes unchanged.

New 5.2.2 encrypted+dedup archives authenticate each reference offset. New
encrypted disk archives also authenticate an index that binds image size,
block count, and a chained XXH64 hash of the complete restored stream. The
writer's additional SHA-256/128 comparison is only an in-memory collision guard
before deduplication; it is not an on-disk cryptographic hash. XXH64 is not
cryptographic, so a writer who controls a plain archive can recompute it.

Plain archives use non-cryptographic checksums. A writer who controls a plain
archive can recompute them.

### Native hybrid post-quantum mode

The `--pq` mode combines an ML-KEM-768 shared secret and an X25519 shared secret
as implemented in 5.2.2:

```text
hybrid_ikm  = ml_ss XOR x25519_ss
archive_key = SHA3-512(hybrid_ikm || ml_ct || ephemeral_pk ||
                       "ZUPT-HYBRID-v1")
```

Its goal is harvest-now/decrypt-later resistance if ML-KEM-768 remains secure,
with X25519 as a classical hedge under the combiner assumptions. This is not
session forward secrecy: compromise of the recipient's long-term private key
can compromise previously captured archives encrypted to it.

The native `--pq-only` mode removes X25519 and derives a key from ML-KEM-768
alone. Use it only when a policy specifically excludes the classical component;
it loses the hybrid hedge.

The in-tree ML-KEM code has project tests, including known-answer vectors and a
conditional OpenSSL 3.5 interoperability test. It has not been independently
audited or formally verified as a whole implementation.

### Extraction containment

The reader rejects absolute paths, traversal components, control characters,
ambiguous trailing dot/space components, NTFS alternate-stream syntax, and
reserved Windows device names. POSIX extraction resolves every parent below a
pinned destination descriptor with no-follow operations after canonicalizing
the user-selected root once. Windows extraction
uses handle-relative traversal, rejects reparse-point parents, and publishes the
final name by handle without replacing an existing leaf. A checked path is not
re-resolved through a mutable parent.

Decoded bytes are first written to a private, exclusively created temporary
file. The final name is published only after the expected decoded size and
chained checksum match and the stream closes successfully; failures remove the
temporary through its descriptor or handle. These controls reduce traversal,
link, race, and partial-output risks, but do not establish that no parser or
filesystem bug can exist.

The Windows handle-relative boundary in 5.2.2 covers normal local Win32 paths.
Win32 extended-length and device-namespace paths, raw UNC output roots, and
mapped/network-drive output are not supported. Cross-build and Wine results are
not a substitute for the required native `windows-latest` Unicode package
gate. Restore locally before moving verified output to network storage.

Disk restore copies the measured compacted archive into one exclusively
created, auto-deleted scratch file before it opens a destructive destination.
Preflight and restoration consume that same open snapshot. An explicit
`ZUPT_TMPDIR` selects an existing scratch directory; failure there does not
fall back to consuming the mutable source pathname. On supported Linux, macOS,
and FreeBSD interfaces, a raw block-device target is rejected before writing if
its capacity is unknown or smaller than the image. These controls reduce source
exchange and immediate overrun risk but do not protect against a compromised
kernel/device, a wrongly selected sufficiently large device, power loss, or
hardware failure.

For an untrusted archive:

1. use a new empty destination outside sensitive trees;
2. run as a dedicated unprivileged user, never root;
3. apply a container, sandbox, resource limits, and a storage quota when
   available;
4. inspect extracted paths, types, permissions, and content before moving them;
5. never restore a disk image to a device without independently confirming both
   source and destination.

## Non-goals and residual risks

ZUPT does not claim to provide:

- resistance to cache, power, EM, acoustic, speculative-execution, or all
  compiler-introduced timing side channels;
- bounded resource consumption for every malformed archive;
- confidentiality of archive size or complete framing metadata;
- protection against compression-length oracles when secret and
  attacker-controlled data are compressed together;
- rollback detection across multiple valid versions of a backup;
- forward-secure sessions, remote authentication, replay protection, or secure
  transport;
- automatic key rotation, recovery, escrow, threshold access, or secure
  deletion;
- preservation of every operating-system ACL, ownership attribute, extended
  attribute, or special-file semantic;
- safe operation on a compromised host.

## Credential handling

- Generate PQ keys on a trusted system using the OS CSPRNG.
- Keep private keys separate from the archive and from release/package inputs.
- Store an offline recovery copy and test recovery before relying on a backup.
- Use a distinct high-entropy credential where compromise isolation matters.
- Re-encrypt under a new credential after suspected disclosure; there is no
  in-place key rotation.
- Never include credentials or sensitive archives in bug reports or CI logs.

## Supply-chain boundary

Git and upstream source archives are source-only. They must pass
`scripts/check-source-only.sh` and must not contain executable code artifacts,
objects, shared/static libraries, distribution packages, unsafe symlinks, or Git
LFS pointers.

Nested inspection is itself an untrusted-input boundary. The release scanner
must cap recursion depth, archive members, per-entry expansion, and total
expanded bytes and fail closed when a cap is reached. Scanner bomb regressions
and all other late self-audit fixes are pending until rerun on the exact
candidate.

DEB, binary RPM, SRPM, notice-bearing Linux tar.xz, source-only portable GUI
ZIP, Windows ZIP, and macOS DMG files can be published separately from the
tagged source. Each artifact extends the trust boundary to its builder,
toolchain, runner image, and packaging scripts. Treat it as validated only when
the exact target has a recorded build, content/package inspection, extracted or
installed smoke test, and applicable archive round trip. An AppImage is not
promoted for 5.2.2; bare Linux and Windows executables are also excluded.

For 5.2.2, that gated artifact scope covers the CLI files plus the exact GUI
DEB, noarch/source RPM, and source-only portable ZIP named in the README. The
portable ZIP contains no compiled runtime and crosses the release boundary only
after source scans and an exact safe-member check. AppDir and Flatpak bundles
and GUI platform installers remain excluded; Windows ZIP and macOS DMG outputs
remain CLI-only.

## Historical compatibility notes

These are historical facts about earlier releases, retained to support recovery:

- Releases through 4.1.0 could reuse an AES-CTR nonce in encrypted `--dedup`
  archives. Release 4.2.0 changed to fresh random per-block nonces. Re-encrypt
  affected older archives.
- Releases through 4.2.1 used round-3 CRYSTALS-Kyber semantics in the native PQ
  path. Release 5.0.0 corrected the implementation to FIPS 203 ML-KEM-768,
  changing native PQ key/archive compatibility. See `CHANGELOG.md` before
  planning cross-version restoration.
- Pre-AIT archive layouts now fail closed by default. The explicit
  `--allow-legacy-no-ait` read option is only for recovery from a known, trusted
  historical archive and leaves its header/footer metadata outside the current
  authenticated boundary.
- The 5.2.2 reader retains compatibility parsers for the fixed-width disk index
  and encrypted-dedup linear AAD sequence published through 5.2.1. An actual
  v5.2.1 password-encrypted DATA/DATA/REF/DATA disk fixture is stored as hexadecimal
  text with source and hash provenance. The candidate lists, tests, extracts, and restores
  it byte-exact, with a warning that the legacy index has no whole-image hash;
  the exact final candidate must repeat that gate. Older readers are not
  claimed to accept new flag-gated 5.2.2 records, and untested historical mode
  combinations remain unclaimed.

Historical test counts in the changelog describe those releases. They do not
automatically become 5.2.2 results; current outcomes belong in the release
validation record, with unavailable environments marked `SKIP`. In particular,
runs made before the final positional-AAD and mandatory-AIT changes are not
final release gates for the resulting candidate.

## Reporting security issues

Email **zupt@riseup.net** with `[security]` in the subject. Include the version,
platform, impact, and a minimal non-sensitive reproducer. Do not disclose the
issue publicly until a coordinated timeline has been agreed.

Document version: 5.2.2, 2026-08-31.
