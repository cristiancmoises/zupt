# VaptVupt threat model

Plain-English description of what VaptVupt protects against, what it
doesn't, and what assumptions you're making when you use it.

This document is for users and downstream packagers. Read it before
trusting VaptVupt with anything you can't afford to lose.

---

## TL;DR

VaptVupt is designed for **at-rest backup encryption** by someone who
controls the machine doing the encryption and the machine doing the
extraction. It is **not** a network protocol, a multi-party scheme, or
a substitute for full-disk encryption.

| Use case | VaptVupt is appropriate? |
|---|---|
| Backing up files to an untrusted cloud (S3, Backblaze, Google Drive) | **Yes** |
| Backing up a disk image to external media you might lose | **Yes** |
| Long-term archival of personal/business data | **Yes** |
| Sharing an encrypted archive with someone you trust to handle the key | **Yes, with care** (see "Key distribution" below) |
| Real-time encrypted communication | **No** (use Signal, age, or TLS) |
| Multi-party access (n-of-m) | **No** (no threshold scheme) |
| Hiding the existence of an archive (steganography) | **No** (archive header has fixed magic bytes) |
| Protecting against a hostile machine you're encrypting on | **No** (a compromised host can read plaintext before encryption) |

---

## What VaptVupt protects against

### 1. Confidentiality of archive contents (encrypted mode)

An attacker with read access to the archive bytes cannot recover
plaintext file contents, file names, file sizes, file modes, or
embedded comments **without the key/password**, assuming:

- The chosen mode is one of the encrypted modes (`-p`, `--pq`, `--pq-sdk`, or `--pq-box`)
- The password is strong enough to resist offline brute-force
  (Argon2id default with m=64 MB, t=3, p=4 makes this very expensive
  but not infinite — see "Password strength" below)
- The key file (for `--pq-sdk` / `--pq-box`) was not compromised at generation time

### 2. Integrity of every byte of an encrypted archive

If any single bit of the on-disk archive bytes is flipped, the
extraction **must fail** with an authentication error. This has been
verified by the v1.6 exhaustive byte sweep:

- 0 silent-accept positions out of 1827 (encrypted, no comment)
- 0 silent-accept positions out of 1878 (encrypted, with comment)

Coverage layers:

- **Per-block HMAC-SHA256** with frame-preface AAD (F-09): every data
  block carries an HMAC over its ciphertext and over the canonical
  29-byte preface (block_type, codec_id, block_flags, sizes, plaintext-XXH64)
- **Archive Integrity Trailer (F-08)**: HMAC-SHA256 over the
  64-byte header and 24 bytes of footer, appended after the footer
- **Strict structural validation of the encryption-header block (F-09)**:
  codec must be `STORE`, flags must be 0, csz must equal usz, the
  plaintext XXH64 must match

### 3. Tamper detection on plaintext archives (best-effort)

Plaintext archives (no `-p`, no `--pq*`) are protected by XXH64
plaintext checksums per block plus structural validation. This is
**not cryptographic integrity** — a determined attacker with
write access can produce a tampered plaintext archive that passes
the checksum (XXH64 is not collision-resistant). It does catch
accidental corruption and naive tampering.

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

### 5. Post-quantum forward secrecy (in `--pq-sdk` mode)

`--pq-sdk` uses ML-KEM-768 (FIPS 203) hybridized with X25519 via an
HKDF combiner. Archives encrypted today cannot be decrypted by a
future quantum adversary holding only the ciphertext, **assuming**:

- ML-KEM-768 retains its claimed security level (NIST Category 3,
  192-bit classical / 96-bit quantum strength)
- X25519 hybridization protects against an unforeseen ML-KEM break
- The recipient's private key is not later compromised

### 6. Side-channel resistance for cryptographic primitives

The hot crypto paths (AES-256-CTR, HMAC-SHA256 comparison, X25519
field operations, ML-KEM polynomial arithmetic) are implemented in
Jasmin and proved constant-time at the assembly level on x86_64.
Non-Jasmin platforms (aarch64, fallback x86_64) use careful C
implementations that avoid secret-dependent branches and memory
accesses where feasible — but **without formal proof**.

---

## What VaptVupt does NOT protect against

This list is **exhaustive of the major omissions** — if you have a
concern that doesn't appear here, please file an issue.

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
- VaptVupt has **no forward secrecy across archives** — each archive
  is encrypted under a single static key derived from the password
  or stored in the key file
- There is no key-rotation feature; rotate by re-encrypting
  archives under a new password/key and securely deleting the old
  password/key

For high-value, long-term archives, treat the key file as you
would a master password: store it offline, encrypt it under
another layer (e.g. on an encrypted USB), and rotate periodically.

### 3. Password strength

Argon2id with m=64 MB, t=3, p=4 makes a single guess cost roughly
~200 ms on commodity hardware. That's **not enough** to protect a
short, common password against a determined attacker with GPU
clusters or cloud compute.

| Password type | Approximate brute-force resistance with Argon2id |
|---|---|
| 6-char common word | Hours to days |
| 10-char mixed alphanumeric | Years on a single GPU; days on a cluster |
| 6-word diceware passphrase | Centuries to millennia even with cloud-scale resources |
| Random 16-char with full alphabet | Infeasible without quantum breakthrough |

For critical data, use `--pq-sdk` mode with a random key file
generated by `vaptvupt keygen --sdk` — the key is 64 bytes of CSPRNG
output, not derived from human-typed text.

### 4. Metadata leakage from archive structure

Even with encryption, an attacker who can see the archive bytes
can infer:

- **Approximate file count** (from `total_blocks` in the footer)
- **Total archive size** (file size on disk)
- **Whether the archive is encrypted at all** (`ZUPT_FLAG_ENCRYPTED`
  in the global flags is visible)
- **Whether the archive is solid or per-file mode** (visible flag)
- **Whether post-quantum mode is in use** (visible flag)
- **Approximate file size distribution** (block sizes are visible
  even when block payloads are encrypted)
- **Archive creation time** (a 64-bit timestamp in the header)
- **A random 16-byte UUID per archive** (no information leak, but
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

There is **no threshold cryptography, no n-of-m sharing, no
multi-party computation, no proxy re-encryption**. Each archive
has exactly one decryption credential (one password OR one
recipient key). To give two people access to the same archive,
they must share the password or the key file.

### 7. Plausible deniability / hidden volumes

VaptVupt archives have a fixed 6-byte magic `\x90\x5a\x55\x50\x54\x01`
at offset 0. Anyone scanning the bytes can see it's a VaptVupt
archive. VaptVupt has **no hidden-volume or duress-password feature**.

### 8. Side channels we don't claim to address

- Power analysis (relevant for embedded targets, not commodity desktops)
- Electromagnetic emanation
- Acoustic side channels
- Network timing of upload patterns
- Filesystem-level metadata (mtime/atime of the `.zupt` file)

### 9. Trusted setup of post-quantum primitives

The ML-KEM-768 implementation lives in `libzuptsdk` and was not
independently audited at the time of writing. We use NIST KAT
vectors for correctness verification but have not formally proven
constant-time properties for every PQ code path.

For maximum assurance, treat `--pq-sdk` as the post-quantum
**hedge** — it does not replace the X25519 layer; both must be
broken for an attacker to recover plaintext.

### 10. Format extension attacks

The format is versioned (v1.6). Older readers may accept newer
archives in unexpected ways. We try to maintain forward
compatibility (v2.4.5 readers correctly handle v1.6 archives
including encrypted comments and the Argon2id KDF path), but a
careful attacker who can produce malformed-but-just-valid
archives may find parser-state issues that don't rise to the
level of a CVE. The fuzzing harness (`make fuzz-format`) is the
primary mitigation; report bugs.

### 11. Compression-side-channel attacks (CRIME / BREACH style)

VaptVupt compresses **before** encryption. If an attacker can:

- Influence part of the plaintext (e.g. inject a known prefix)
- Observe the resulting archive size precisely

then they can use the compression ratio to learn information about
the rest of the plaintext — this is the classic CRIME/BREACH attack
against TLS compression.

VaptVupt is designed for offline backup, where attacker-controlled
plaintext injection is rare. **If your threat model includes
attacker-chosen plaintext mixed with secret plaintext in the same
archive**, use `--no-compress` (codec 0 = STORE) to disable the
LZ codec and eliminate this side channel.

---

## Cryptographic assumptions

VaptVupt's security rests on the following standard assumptions:

| Assumption | What breaks if it fails |
|---|---|
| AES-256-CTR is a secure stream cipher | All encrypted archives become readable |
| HMAC-SHA256 is a secure PRF / MAC | Tamper detection fails; integrity can be forged |
| Argon2id is a secure password KDF | Password-mode archives become brute-forceable faster |
| ML-KEM-768 retains NIST Category 3 security | `--pq-sdk` mode reduces to the X25519 layer |
| X25519 retains 128-bit security (no quantum) | `--pq-sdk` mode reduces to the ML-KEM layer; legacy `--pq` mode broken |
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

- **v1.0** (sprint 2.4.6): initial threat model. Covers archive
  format v1.6.
- Document is part of the source tree (`THREAT_MODEL.md`) and
  versioned with the project; this section will be updated as
  the format evolves.
