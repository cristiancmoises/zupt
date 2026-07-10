# VaptVupt threat model

Plain-English description of what VaptVupt protects against, what it
doesn't, and what assumptions you're making when you use it.

This document is for users and downstream packagers. Read it before
trusting VaptVupt with anything you can't afford to lose.

---

## TL;DR

VaptVupt is designed for at-rest backup encryption by someone who
controls the machine doing the encryption and the machine doing the
extraction. It is not a network protocol, a multi-party scheme, or
a substitute for full-disk encryption.

| Use case | VaptVupt is appropriate? |
|---|---|
| Backing up files to an untrusted cloud (S3, Backblaze, Google Drive) | Yes |
| Backing up a disk image to external media you might lose | Yes |
| Long-term archival of personal/business data | Yes |
| Sharing an encrypted archive with someone you trust to handle the key | Yes, with care (see "Key distribution" below) |
| Real-time encrypted communication | No (use Signal, age, or TLS) |
| Multi-party access (n-of-m) | No (no threshold scheme) |
| Hiding the existence of an archive (steganography) | No (archive header has fixed magic bytes) |
| Protecting against a hostile machine you're encrypting on | No (a compromised host can read plaintext before encryption) |

---

## Modes referenced in this document

- `-p` / password mode: symmetric encryption with a key derived from a
  password. The default build derives the key with PBKDF2-SHA256
  (600k iterations). Argon2id is available only in an upstream
  `make WITH_SDK=1` build against the separately distributed
  libraries.
- `--pq`: native post-quantum **hybrid** mode (ML-KEM-768 + X25519), the
  recommended PQ mode in the default build. The ML-KEM-768 implementation
  is in-tree.
- `--pq-only`: native **full/pure** post-quantum mode (ML-KEM-768 only, no
  X25519), also in the default build. For compliance postures that mandate a
  single NIST-standardised PQ primitive with no classical KEM in the envelope.
  Its threat profile differs from `--pq` in exactly one axis: it has no
  classical fallback, so a break of ML-KEM-768 alone breaks the archive
  (see §5 and "Cryptographic assumptions").
- `--pq-sdk` / `--pq-box`: optional post-quantum modes backed by the
  separately distributed `libzuptsdk` / `libpqvaptvupt` libraries.
  Available only in a `make WITH_SDK=1` build. Key files for these
  modes are produced by `vaptvupt keygen --sdk`, also SDK-only.

---

## What VaptVupt protects against

### 1. Confidentiality of archive contents (encrypted mode)

An attacker with read access to the archive bytes cannot recover
plaintext file contents, file names, file sizes, file modes, or
embedded comments without the key/password, assuming:

- The chosen mode is one of the encrypted modes (`-p`, `--pq`, or the
  optional `--pq-sdk` / `--pq-box`)
- The password is strong enough to resist offline brute-force
  (see "Password strength" below)
- The key file (for `--pq-sdk` / `--pq-box`) was not compromised at
  generation time

### 2. Integrity of every byte of an encrypted archive

If any single bit of the on-disk archive bytes is flipped, the
extraction fails with an authentication error. Coverage layers:

- Per-block HMAC-SHA256 with frame-preface AAD (F-09): every data
  block carries an HMAC over its ciphertext and over the canonical
  29-byte preface (block_type, codec_id, block_flags, sizes,
  plaintext-XXH64)
- Archive Integrity Trailer (F-08): HMAC-SHA256 over the 64-byte
  header and 24 bytes of footer, appended after the footer
- Strict structural validation of the encryption-header block (F-09):
  codec must be `STORE`, flags must be 0, csz must equal usz, the
  plaintext XXH64 must match

### 3. Tamper detection on plaintext archives (best-effort)

Plaintext archives (no `-p`, no `--pq*`) are protected by XXH64
plaintext checksums per block plus structural validation. This is
not cryptographic integrity — a determined attacker with write access
can produce a tampered plaintext archive that passes the checksum
(XXH64 is not collision-resistant). It does catch accidental
corruption and naive tampering.

Use an encrypted mode if you need cryptographic integrity.

### 4. Authentication failure indistinguishability (F-11)

The default error message for "wrong password", "wrong PQ key",
and "actual header tamper" is the same single line:

> `Error: Authentication failed (wrong key, wrong password, or tampered archive).`

This prevents an attacker who can issue extraction attempts from
learning which check failed first via the stderr output. Timing is
also constant (HMAC is always run, branchless return).

The detailed cause is available via `--verbose` for debugging on
machines under the user's own control.

### 5. Post-quantum forward secrecy (`--pq`, `--pq-only`, and optional `--pq-sdk`)

The native `--pq` mode uses ML-KEM-768 (FIPS 203) hybridized with
X25519 via an HKDF combiner. Archives encrypted today cannot be
decrypted by a future quantum adversary holding only the ciphertext,
assuming:

- ML-KEM-768 retains its claimed security level (NIST Category 3,
  192-bit classical / 96-bit quantum strength)
- X25519 hybridization protects against an unforeseen ML-KEM break
- The recipient's private key is not later compromised

The native `--pq-only` mode (envelope type `0x06`) provides the same
harvest-now-decrypt-later protection using ML-KEM-768 as the *sole* key
mechanism. It exists for compliance postures that mandate a single
NIST-standardised PQ primitive with no classical KEM in the envelope
(CNSA 2.0-style "PQ-only"). **The trade-off is a loss of the second
assumption above:** there is no X25519 hybridization, so an unforeseen
break of ML-KEM-768 alone is sufficient to recover the archive key. For
that reason `--pq` (hybrid) is the recommended default, and `--pq-only`
should be used only when a policy forbids the classical component.

The optional `--pq-sdk` mode provides the same hybrid guarantee as
`--pq` via the separately distributed SDK libraries.

### 6. Side-channel resistance for cryptographic primitives

The hot crypto paths (AES-256-CTR, HMAC-SHA256 comparison, X25519
field operations, ML-KEM polynomial arithmetic) are implemented in
Jasmin and proved constant-time at the assembly level on x86_64.
Non-Jasmin platforms (aarch64, fallback x86_64) use C implementations
that avoid secret-dependent branches and memory accesses where
feasible — but without formal proof.

---

## What VaptVupt does NOT protect against

### 1. Compromised endpoints

VaptVupt cannot protect against:

- Malware on the machine doing the encryption (it sees plaintext
  before any crypto is applied)
- Malware on the machine doing the extraction (it sees plaintext
  after decryption)
- A hardware keylogger capturing the password
- A compromised user account that can read your files or
  `~/.zupt-key` directly
- Cold-boot attacks on running machines

If you don't trust the machine, VaptVupt cannot help.

### 2. Key compromise

If the password or `~/.zupt-key` is leaked:

- All archives encrypted with that key are decryptable
- VaptVupt has no forward secrecy across archives — each archive
  is encrypted under a single static key derived from the password
  or stored in the key file
- There is no key-rotation feature; rotate by re-encrypting
  archives under a new password/key and securely deleting the old
  password/key

For high-value, long-term archives, treat the key file as you
would a master password: store it offline, encrypt it under
another layer (e.g. on an encrypted USB), and rotate periodically.

### 3. Password strength

Password mode derives the key with PBKDF2-SHA256 (600k iterations)
in the default build, or Argon2id in a `make WITH_SDK=1` build. A
key derivation function slows offline guessing but does not make a
short, common password safe: a determined attacker with GPU clusters
or cloud compute can still exhaust a weak password.

Use a long, high-entropy password — a multi-word diceware passphrase
or a random 16+ character string with a full alphabet. For critical
data, use a key-file mode (native `--pq`, or the optional `--pq-sdk`
with a random key file from `vaptvupt keygen --sdk`) so the key is
CSPRNG output, not derived from human-typed text.

### 4. Metadata leakage from archive structure

Even with encryption, an attacker who can see the archive bytes
can infer:

- Approximate file count (from `total_blocks` in the footer)
- Total archive size (file size on disk)
- Whether the archive is encrypted at all (`ZUPT_FLAG_ENCRYPTED`
  in the global flags is visible)
- Whether the archive is solid or per-file mode (visible flag)
- Whether post-quantum mode is in use (visible flag)
- Approximate file size distribution (block sizes are visible
  even when block payloads are encrypted)
- Archive creation time (a 64-bit timestamp in the header)
- A random 16-byte UUID per archive (no information leak, but
  globally identifies the archive across copies)

If metadata privacy matters, layer VaptVupt under another tool that
hides bulk metadata (e.g., put the `.zupt` file inside a fixed-size
encrypted container).

### 5. Network attacks

VaptVupt is not a network protocol. There is no:

- Forward-secure session establishment (use TLS or Noise)
- Mutual authentication of remote parties (use signed messages or
  TLS client certs)
- Replay protection across sessions (archives can be replayed by
  an attacker who can write to the destination)
- Network-layer encryption (use TLS to transport `.zupt` files)

### 6. Multi-party schemes

There is no threshold cryptography, no n-of-m sharing, no
multi-party computation, no proxy re-encryption. Each archive
has exactly one decryption credential (one password OR one
recipient key). To give two people access to the same archive,
they must share the password or the key file.

### 7. Plausible deniability / hidden volumes

VaptVupt archives have a fixed 6-byte magic `\x90\x5a\x55\x50\x54\x01`
at offset 0. Anyone scanning the bytes can see it's a VaptVupt
archive. VaptVupt has no hidden-volume or duress-password feature.

### 8. Side channels we don't claim to address

- Power analysis (relevant for embedded targets, not commodity desktops)
- Electromagnetic emanation
- Acoustic side channels
- Network timing of upload patterns
- Filesystem-level metadata (mtime/atime of the `.zupt` file)

### 9. Trusted setup of post-quantum primitives

The in-tree ML-KEM-768 implementation was not independently audited
at the time of writing. We use NIST KAT vectors for correctness
verification but have not formally proven constant-time properties
for every PQ code path.

For maximum assurance, treat the post-quantum layer as a hedge — it
does not replace the X25519 layer; both must be broken for an
attacker to recover plaintext.

### 10. Format extension attacks

The format is versioned (v1.6). Older readers may accept newer
archives in unexpected ways. We try to maintain forward
compatibility, but a careful attacker who can produce
malformed-but-just-valid archives may find parser-state issues that
don't rise to the level of a CVE. The fuzzing harness
(`make fuzz-format`) is the primary mitigation; report bugs.

### 11. Compression-side-channel attacks (CRIME / BREACH style)

VaptVupt compresses before encryption. If an attacker can:

- Influence part of the plaintext (e.g. inject a known prefix)
- Observe the resulting archive size precisely

then they can use the compression ratio to learn information about
the rest of the plaintext — this is the classic CRIME/BREACH attack
against TLS compression.

VaptVupt is designed for offline backup, where attacker-controlled
plaintext injection is rare. If your threat model includes
attacker-chosen plaintext mixed with secret plaintext in the same
archive, use `--no-compress` (codec 0 = STORE) to disable the
LZ codec and eliminate this side channel.

---

## Cryptographic assumptions

VaptVupt's security rests on the following standard assumptions:

| Assumption | What breaks if it fails |
|---|---|
| AES-256-CTR is a secure stream cipher | All encrypted archives become readable |
| HMAC-SHA256 is a secure PRF / MAC | Tamper detection fails; integrity can be forged |
| PBKDF2-SHA256 (or Argon2id, WITH_SDK) is a secure password KDF | Password-mode archives become brute-forceable faster |
| ML-KEM-768 retains NIST Category 3 security | `--pq` / `--pq-sdk` reduce to the X25519 layer; **`--pq-only` has no fallback and is broken** |
| X25519 retains 128-bit security (no quantum) | Hybrid PQ modes reduce to the ML-KEM layer; `--pq-only` and classical password mode unaffected |
| HKDF-SHA256 is a secure key-derivation construction | Combined PQ + classical keys may be predictable |
| SHA3 / SHAKE retain pre-image and collision resistance | Auxiliary protocol bindings may be forged |

If you don't trust one of these primitives, VaptVupt cannot protect
you. We rely on the same primitives the broader cryptographic
community has standardized.

---

## Reporting security issues

Email `sac@securityops.co` with the subject `VaptVupt security report`.
PGP key available on request.

We will:

- Acknowledge receipt within 7 days
- Investigate and publish a CVE / advisory if warranted
- Credit you in the CHANGELOG if you wish

Please don't open public issues for security reports until we've
coordinated disclosure. For non-security bugs (parser edge cases,
documentation typos, performance issues), open a public issue
normally.

---

## Document version

This threat model covers archive format v1.6 as shipped in VaptVupt
4.2.1. It is part of the source tree (`THREAT_MODEL.md`) and
versioned with the project; this section will be updated as the
format evolves.
