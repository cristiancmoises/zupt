# Security Policy — VaptVupt 4.2.1

## Reporting Vulnerabilities

Report privately by email to **zupt@riseup.net** with `[security]` in the
subject. Do not open a public issue on the project's git server.

Include:

- Version (`vaptvupt --version`) and platform.
- Description, impact assessment, and a reproduction (a minimal archive or
  a code snippet).

Disclosure SLA: acknowledgement within 5 business days; target fix within
30 days for high-severity issues. Coordinated disclosure preferred; the
timeline is discussed case by case. A PGP key is on the project's
keyserver entry.

The project has not had an external independent audit. For high-stakes
deployments, treat it as "reviewed but unaudited" and do your own review.

---

## Encryption Modes

| Mode | CLI Flag | Algorithm | PQ-Safe? | Use Case |
|------|----------|-----------|----------|----------|
| Password | `-p` | PBKDF2-SHA256 → AES-256-CTR + HMAC-SHA256 | No | Short-term backups, personal use |
| PQ Hybrid | `--pq` | ML-KEM-768 + X25519 → AES-256-CTR + HMAC-SHA256 | Yes | Long-term archives, high-value data (**recommended**) |
| PQ Only | `--pq-only` | ML-KEM-768 only → AES-256-CTR + HMAC-SHA256 | Yes | "PQ-only" compliance postures (no classical KEM) |
| None | (default) | No encryption (compression only) | N/A | Non-sensitive data |

Password mode (`-p`) is not quantum-safe. For protection against "harvest
now, decrypt later" quantum attacks, use `--pq` — the recommended
post-quantum mode. `--pq` is native and in-tree; it needs no external
library.

`--pq-only` (envelope type `0x06`) uses ML-KEM-768 as the *sole* key
mechanism, with no classical X25519 component. It exists for compliance
postures that mandate a single NIST-standardised PQ primitive with no
classical KEM in the envelope (CNSA 2.0-style "PQ-only"). **This is a
deliberate reduction in defence-in-depth:** unlike `--pq`, there is no
classical fallback, so a future cryptanalytic break of ML-KEM-768 alone is
sufficient to break the archive. Under `--pq`, an attacker must break *both*
ML-KEM-768 and X25519. **Unless a policy forbids the classical component,
prefer `--pq`.** Both modes are native, in-tree, and need no external
library.

Optional SDK modes (`--pq-sdk`, `--pq-box`) are available only in an
upstream `make WITH_SDK=1` build linked against the separately distributed
libzuptsdk / libpqvaptvupt libraries. They are not part of the default
build and are not defaults.

---

## Cryptographic Algorithms

| Component | Algorithm | Standard | Key Size | Security Level |
|-----------|-----------|----------|----------|---------------|
| Symmetric encryption | AES-256-CTR | FIPS 197 | 256-bit | 128-bit post-quantum (Grover) |
| Authentication | HMAC-SHA256 | RFC 2104 | 256-bit | 128-bit post-quantum (Grover) |
| Password KDF (default) | PBKDF2-SHA256 | RFC 8018 | 600K iterations | Password-dependent |
| Password KDF (WITH_SDK=1 option) | Argon2id | RFC 9106 | OWASP minimums | Password-dependent, memory-hard |
| Post-quantum KEM | ML-KEM-768 | FIPS 203 | 1184B pk / 2400B sk | NIST Level 3 |
| Classical KEM | X25519 | RFC 7748 | 32B scalar | ~128-bit classical |
| Hybrid KDF (`--pq`) | SHA3-512 | FIPS 202 | 512-bit output | Secure if either KEM holds |
| PQ-only KDF (`--pq-only`) | SHA3-512 | FIPS 202 | 512-bit output | Secure if ML-KEM-768 holds (no classical fallback) |
| Integrity | XXH64 | xxHash spec | 64-bit checksum | Non-cryptographic |
| Hashing | SHA3-256, SHA3-512 | FIPS 202 | 256/512-bit | Standard |
| Random | OS CSPRNG | getrandom(2) / RtlGenRandom | N/A | Hard fail if unavailable |

The default build uses PBKDF2-SHA256 (600k iterations) for password mode.
Argon2id is available only in a `make WITH_SDK=1` build.

---

## Security Architecture

### Per-Block Authenticated Encryption

```
For each data block:

  nonce = CSPRNG(16)                               [16 bytes, fresh per block]
  ciphertext = AES-256-CTR(enc_key, nonce, plaintext)
  mac = HMAC-SHA256(mac_key, aad ‖ nonce ‖ ciphertext)   [32 bytes]
  stored = nonce ‖ ciphertext ‖ mac
```

The nonce is a **fresh 128-bit random value per block**, stored in the block
prefix and bound into the block MAC. The block sequence number is bound into
the MAC AAD (not into the nonce), so reordering, splicing, or replaying blocks
is still detected.

> **History (fixed in 4.2.0):** earlier releases derived the nonce as
> `base_nonce XOR pad_le(block_seq, 8)`. In `--dedup` mode every data block is
> assigned sequence 0 (the sentinel that keeps cross-file dedup references
> authenticating consistently), so the nonce collapsed to a single value across
> all dedup blocks — reusing the AES-CTR keystream across distinct plaintexts
> (a many-time-pad). Switching to a fresh random per-block nonce closes this.
> Regression test: `tests/test_dedup_nonce.sh`. Re-encrypt any `--dedup` +
> encrypted archives written by ≤ 4.1.0.

### Encrypt-then-MAC

HMAC is computed over `nonce ‖ ciphertext` and verified **before** any
decryption. This prevents:

- Chosen-ciphertext attacks
- Padding oracle attacks
- Processing of tampered data

### Hybrid Post-Quantum KEM (`--pq`)

```
Encapsulation:
  ML-KEM-768.Encaps(pk)  → ml_ct[1088], ml_ss[32]
  eph_sk ← CSPRNG(32)
  eph_pk = X25519(eph_sk, basepoint)
  x25519_ss = X25519(eph_sk, recipient_pk)
  hybrid_ikm = ml_ss XOR x25519_ss
  archive_key = SHA3-512(hybrid_ikm ‖ ml_ct ‖ eph_pk ‖ "ZUPT-HYBRID-v1")
  enc_key = archive_key[0:32]
  mac_key = archive_key[32:64]
```

Security model: secure if EITHER ML-KEM-768 (post-quantum, NIST Level 3)
OR X25519 (classical, ~128-bit) remains unbroken. Both must be compromised
simultaneously to recover the archive key. Same approach as Signal
(PQXDH), Apple iMessage (PQ3), and OpenSSH 9.0+.

The `--pq-sdk` mode (WITH_SDK=1 only) uses an HKDF-SHA3-256 combiner, a
32-byte key commitment tag, HPKE-style context binding (RFC 9180 §5),
anti-fault double decapsulation, and XChaCha20-Poly1305 AEAD.

### Full Post-Quantum KEM (`--pq-only`)

```
Encapsulation:
  ML-KEM-768.Encaps(pk)  → ml_ct[1088], ml_ss[32]
  archive_key = SHA3-512(ml_ss ‖ ml_ct ‖ "ZUPT-PQ-ONLY-v1")
  enc_key = archive_key[0:32]
  mac_key = archive_key[32:64]
```

Security model: secure if ML-KEM-768 (post-quantum, NIST Level 3) remains
unbroken. **There is no classical component**, so — unlike `--pq` — a break of
ML-KEM-768 alone is sufficient to compromise the archive key. This mode exists
only for compliance postures that mandate a single NIST-standardised PQ
primitive with no classical KEM in the envelope (CNSA 2.0-style "PQ-only").
Decapsulation uses ML-KEM Fujisaki-Okamoto implicit rejection: a wrong or
tampered `ml_ct` yields a pseudorandom shared secret, so decryption fails
closed at the HMAC check rather than leaking a decapsulation-validity oracle.
**Unless a policy forbids the classical component, prefer `--pq`.**

---

## Constant-Time Guarantees

### Jasmin-Verified (assembly linked into binary)

| Function | Purpose | Proof |
|----------|---------|-------|
| `zupt_mac_verify_ct` | HMAC comparison (32 bytes) | Jasmin type system: no branch on diff value |
| `zupt_ct_select_32` | ML-KEM FO implicit rejection | Jasmin type system: no branch on cond value |

These functions are compiled from Jasmin source to x86-64 assembly. The
Jasmin compiler enforces that no secret-typed variable flows into branch
conditions or memory addresses. This guarantee holds at the machine code
level — no C compiler optimization can introduce timing leaks.

### C Constant-Time (branchless, compiler-dependent)

| Function | Method | Risk |
|----------|--------|------|
| X25519 `fe_cswap` | Masked XOR (`mask & (a ^ b)`) | Low — branchless but compiler may optimize |
| ML-KEM NTT/basemul | Montgomery reduction (no branches) | Low |
| ML-KEM CBD sampling | Bitwise operations only | Low |
| Key wipe (`zupt_secure_wipe`) | `explicit_bzero` / volatile | Low |

### NOT Constant-Time (documented risks)

| Function | Risk | Mitigation |
|----------|------|------------|
| AES-256 block encrypt | HIGH on shared hardware — S-box table lookups leak via cache timing | Jasmin AES-NI path planned; do not use on multi-tenant VMs |
| SHA-256 | Low — table constants are public, not indexed by secret data | Accepted |

---

## Threat Model

### What VaptVupt Protects

| Asset | Protection |
|-------|-----------|
| File contents | AES-256-CTR encryption |
| File names, sizes, structure | Encrypted in central index block, HMAC-protected |
| Archive integrity (payloads + index) | Per-block HMAC-SHA256 |
| Archive integrity (header + footer metadata) | v1.5+ archives: 32-byte archive-integrity-trailer HMAC-SHA256 over `hdr ‖ ft[0..23]`. v1.4 archives: not covered, downgrade warning on extract. |
| Against stolen backups | AES-256 requires key/password to read |
| Against tampering of file contents, names, sizes, offsets | HMAC detects any modification |
| Against tampering of per-block frame preface bytes (codec_id, block_flags, varints, plaintext-XXH64) | v1.6: per-block MAC binds the canonical preface AAD; encryption-header block validated structurally |
| Against tampering of archive comment (when present) | Comment block goes through the same per-block AEAD pipeline as data (AES-256-CTR + HMAC-SHA256 + preface AAD); `hdr.comment_offset` pointer is in the AIT-signed region |
| Against block-swap (reorder) attacks | MAC binds an 8-byte position AAD; a block moved to another position fails verification and its partial output is unlinked. Dedup refs use sentinel seq=0 and rely on plaintext XXH64 for per-block integrity. |
| Against malicious archive entries (Zip Slip / path traversal) | `zupt_path_is_safe()` rejects `..`, absolute paths, Windows drive/UNC paths, embedded NULs |
| Against symlink at extract target (TOCTOU) | `zupt_safe_fopen_output()` uses `O_NOFOLLOW` on POSIX. Windows relies on directory ACLs (documented limitation). |
| Against quantum adversary | `--pq` mode: ML-KEM-768 (NIST Level 3) hybridized with X25519 |

The wire/on-disk format is v1.6. See CHANGELOG.md for the per-release
finding history behind these protections.

### What VaptVupt Does NOT Protect Against

| Threat | Reason | Mitigation Path |
|--------|--------|----------------|
| Attacker who knows the password or has the private key | Fundamental to encryption | Use strong passwords (12+ chars); protect key files |
| Endpoint compromise (keylogger, malware on the host) | Outside the archive's trust boundary | Secure the machine where you type the password or hold the key |
| Cache-timing side channels (C AES) | Table-based S-box lookups | Build with Jasmin AES-NI when available; avoid multi-tenant VMs |
| Memory forensics during operation | Keys on stack during compress/extract | `zupt_secure_wipe()` on completion; `mlock()` planned |
| Deniability | Archive header identifies format | `.zupt` magic bytes visible; ENCRYPTED flag in header |
| Weak passwords | PBKDF2-SHA256 (600k) is the default KDF; Argon2id (memory-hard) is available in a WITH_SDK=1 build | Use `--pq` mode for critical data — keys are random, not derived from a password |
| Traffic analysis / metadata | Archive size reveals data volume; file list, sizes, mtimes not padded | Outside VaptVupt's scope |
| File permission/ownership | Not stored in archive | Documented in README.md |
| Spectre-class side channels in callers | Below the constant-time primitive layer | Host OS / compiler mitigations |

### Quantum Threat Analysis

Scenario: adversary captures an encrypted archive today, stores it, and
attempts decryption when a cryptographically-relevant quantum computer is
available.

| Mode | Classical Security | Quantum Security | Verdict |
|------|-------------------|-----------------|---------|
| Password (`-p`) | Password-dependent + 256-bit AES | ~128-bit (Grover on AES), PBKDF2 accelerated | Vulnerable — use `--pq` |
| PQ Hybrid (`--pq`) | ~128-bit (X25519) | NIST Level 3 (ML-KEM-768) | Protected |

In `--pq` mode: even if Shor's algorithm breaks X25519, ML-KEM-768
protects the archive; even if a novel classical attack breaks ML-KEM,
X25519 still provides ~128-bit security. The hybrid design is secure if
either component holds.

### Extracting untrusted archives — operational guidance

The in-binary defenses are the primary control; the following are defense
in depth:

1. Extract into a dedicated empty directory (not `~/Downloads` or `/tmp`).
2. Audit symlinks in the target directory before extraction.
3. Run extraction as a low-privilege user, never root.
4. On Windows, pre-create the target directory with restrictive ACLs
   (the `O_NOFOLLOW` defense is POSIX-only).

### Out of scope

- External independent audit.
- Side-channel testing on production hardware (timing leaks).
- Formal verification beyond the Jasmin constant-time primitives.

---

## CSPRNG Policy

| Platform | Primary Source | Fallback | Failure Mode |
|----------|---------------|----------|--------------|
| Linux | `getrandom(2)` | `/dev/urandom` | Hard exit — no encryption without CSPRNG |
| macOS | `/dev/urandom` | None | Hard exit |
| Windows | `RtlGenRandom` | None | Hard exit |

There is no `rand()`, `srand()`, or any weak PRNG fallback anywhere in the
codebase. If the OS CSPRNG is unavailable, VaptVupt exits with an error.
This is a deliberate design choice — weak random keys are worse than no
encryption.

---

## Supported Platforms

| Platform | Compiler | Threading | CSPRNG | Status |
|----------|----------|-----------|--------|--------|
| Linux x86-64 | GCC 5+ / Clang 3.5+ | pthreads | `getrandom(2)` | Primary |
| Linux ARM64 | GCC 5+ | pthreads | `getrandom(2)` | Tested |
| macOS x86-64/ARM64 | Apple Clang | pthreads | `/dev/urandom` | Tested |
| Windows x86-64 | MinGW / MSVC 2015+ | Win32 threads | `RtlGenRandom` | Tested |
| FreeBSD | GCC / Clang | pthreads | `/dev/urandom` | Untested (expected to work) |

---

## Verification Commands

Anyone can verify the security claims. The default build needs only a C
compiler + make (plus libm/pthread); no external crypto library.

```bash
# Build
make

# Functional tests
make test-all

# Memory safety
make test-asan

# NIST/RFC test vectors
make test-vectors && ./test_vectors

# Verify Jasmin symbols are active
nm vaptvupt | grep "zupt_mac_verify_ct\|zupt_ct_select_32"
# Expected: T zupt_mac_verify_ct
#           T zupt_ct_select_32

# Verify Jasmin compilation (requires jasminc)
jasminc -arch x86-64 -o /dev/null jasmin/zupt_mac_verify.jazz
jasminc -arch x86-64 -o /dev/null jasmin/zupt_mlkem_select.jazz
```

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later (dual-licensed AGPL + commercial)
