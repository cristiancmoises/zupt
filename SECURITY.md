# Security Policy — Zupt

## Reporting Vulnerabilities

**Be free to report vulnerabilities. For high-risk send an email.**

Email: **zupt@riseup.net**

Include: description, reproduction steps, impact assessment.
Response within 48 hours. Fix within 30 days for critical issues.

---

## Encryption Modes

| Mode | CLI Flag | Algorithm | PQ-Safe? | Use Case |
|------|----------|-----------|----------|----------|
| Password | `-p` | PBKDF2-SHA256 → AES-256-CTR + HMAC-SHA256 | **No** | Short-term backups, personal use |
| PQ Hybrid | `--pq` | ML-KEM-768 + X25519 → AES-256-CTR + HMAC-SHA256 | **Yes** | Long-term archives, high-value data |
| None | (default) | No encryption (compression only) | N/A | Non-sensitive data |

**Password mode (`-p`) is NOT quantum-safe.** For protection against "harvest now, decrypt later" quantum attacks, use `--pq` mode.

---

## Cryptographic Algorithms

| Component | Algorithm | Standard | Key Size | Security Level |
|-----------|-----------|----------|----------|---------------|
| Symmetric encryption | AES-256-CTR | FIPS 197 | 256-bit | 128-bit post-quantum (Grover) |
| Authentication | HMAC-SHA256 | RFC 2104 | 256-bit | 128-bit post-quantum (Grover) |
| Password KDF | PBKDF2-SHA256 | RFC 8018 | 600K iterations | Password-dependent |
| Post-quantum KEM | ML-KEM-768 | FIPS 203 | 1184B pk / 2400B sk | NIST Level 3 |
| Classical KEM | X25519 | RFC 7748 | 32B scalar | ~128-bit classical |
| Hybrid KDF | SHA3-512 | FIPS 202 | 512-bit output | Secure if either KEM holds |
| Integrity | XXH64 | xxHash spec | 64-bit checksum | Non-cryptographic |
| Hashing | SHA3-256, SHA3-512 | FIPS 202 | 256/512-bit | Standard |
| Random | OS CSPRNG | getrandom(2) / RtlGenRandom | N/A | Hard fail if unavailable |

---

## Security Architecture

### Per-Block Authenticated Encryption

```
For each data block (sequence 0, 1, 2, ...):

  nonce = base_nonce XOR pad_le(block_seq, 8)    [16 bytes]
  ciphertext = AES-256-CTR(enc_key, nonce, plaintext)
  mac = HMAC-SHA256(mac_key, nonce ‖ ciphertext)   [32 bytes]
  stored = nonce ‖ ciphertext ‖ mac
```

### Encrypt-then-MAC

HMAC is computed over `nonce ‖ ciphertext` and verified **before** any decryption. This prevents:
- Chosen-ciphertext attacks
- Padding oracle attacks
- Processing of tampered data

### Hybrid Post-Quantum KEM

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

**Security model:** Secure if EITHER ML-KEM-768 (post-quantum, NIST Level 3) OR X25519 (classical, ~128-bit) remains unbroken. Both must be compromised simultaneously to recover the archive key. Same approach as Signal (PQXDH), Apple iMessage (PQ3), and OpenSSH 9.0+.

---

## Constant-Time Guarantees

### Jasmin-Verified (assembly linked into binary)

| Function | Purpose | Proof |
|----------|---------|-------|
| `zupt_mac_verify_ct` | HMAC comparison (32 bytes) | Jasmin type system: no branch on diff value |
| `zupt_ct_select_32` | ML-KEM FO implicit rejection | Jasmin type system: no branch on cond value |

These functions are compiled from Jasmin source to x86-64 assembly. The Jasmin compiler enforces that no secret-typed variable flows into branch conditions or memory addresses. This guarantee holds at the machine code level — no C compiler optimization can introduce timing leaks.

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
| AES-256 block encrypt | **HIGH** on shared hardware — S-box table lookups leak via cache timing | Jasmin AES-NI path planned; do not use on multi-tenant VMs |
| SHA-256 | Low — table constants are public, not indexed by secret data | Accepted |

---

## Threat Model

### What Zupt Protects

| Asset | Protection |
|-------|-----------|
| File contents | AES-256-CTR encryption |
| File names, sizes, structure | Encrypted in central index block |
| Archive integrity | Per-block XXH64 + HMAC-SHA256 |
| Against stolen backups | AES-256 requires key/password to read |
| Against tampering | HMAC detects any modification |
| Against quantum adversary | `--pq` mode: ML-KEM-768 (NIST Level 3) |

### What Zupt Does NOT Protect Against

| Threat | Reason | Mitigation Path |
|--------|--------|----------------|
| Attacker who knows the password or has the private key | Fundamental to encryption | Use strong passwords (12+ chars); protect key files |
| Cache-timing side channels (C AES) | Table-based S-box lookups | Build with Jasmin AES-NI when available |
| Memory forensics during operation | Keys on stack during compress/extract | `zupt_secure_wipe()` on completion; `mlock()` planned |
| Deniability | Archive header identifies format | `.zupt` magic bytes visible; ENCRYPTED flag in header |
| Weak passwords | PBKDF2 adds ~20 bits of work factor | Use `--pq` mode for critical data |
| Traffic analysis | Archive size reveals data volume | Outside Zupt's scope |
| File permission/ownership | Not stored in archive | Document in COMPAT.md |

### Quantum Threat Analysis

**Scenario:** Adversary captures encrypted archive today, stores it, and attempts decryption when a cryptographically-relevant quantum computer is available.

| Mode | Classical Security | Quantum Security | Verdict |
|------|-------------------|-----------------|---------|
| Password (`-p`) | Password-dependent + 256-bit AES | ~128-bit (Grover on AES) but PBKDF2 accelerated | **Vulnerable** — use `--pq` |
| PQ Hybrid (`--pq`) | ~128-bit (X25519) | NIST Level 3 (ML-KEM-768) | **Protected** |

In `--pq` mode: even if Shor's algorithm breaks X25519, ML-KEM-768 protects the archive. Even if a novel classical attack breaks ML-KEM, X25519 still provides ~128-bit security. The hybrid design ensures the archive is secure if **either** component holds.

---

## CSPRNG Policy

| Platform | Primary Source | Fallback | Failure Mode |
|----------|---------------|----------|--------------|
| Linux | `getrandom(2)` | `/dev/urandom` | **Hard exit** — no encryption without CSPRNG |
| macOS | `/dev/urandom` | None | **Hard exit** |
| Windows | `RtlGenRandom` | None | **Hard exit** |

There is no `rand()`, `srand()`, or any weak PRNG fallback anywhere in the codebase. If the OS CSPRNG is unavailable, Zupt exits with an error. This is a deliberate design choice — weak random keys are worse than no encryption.

---

## Supported Platforms

| Platform | Compiler | Threading | CSPRNG | Status |
|----------|----------|-----------|--------|--------|
| Linux x86-64 | GCC 5+ / Clang 3.5+ | pthreads | `getrandom(2)` | **Primary** |
| Linux ARM64 | GCC 5+ | pthreads | `getrandom(2)` | Tested |
| macOS x86-64/ARM64 | Apple Clang | pthreads | `/dev/urandom` | Tested |
| Windows x86-64 | MinGW / MSVC 2015+ | Win32 threads | `RtlGenRandom` | Tested |
| FreeBSD | GCC / Clang | pthreads | `/dev/urandom` | Untested (expected to work) |

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-01-01 | v0.1.0 — Initial release |
| 2026-03-21 | v0.5.1 — 16 security bug fixes including CSPRNG hardening |
| 2026-03-21 | v1.0.0 — 5 critical ML-KEM bugs fixed, format frozen |
| 2026-03-28 | v1.1.0 — X25519 formula bug fixed (not interoperable with RFC 7748) |
| 2026-03-28 | v1.5.0 — Jasmin assembly linked (MAC verify + ML-KEM select) |

---

## Verification Commands

Anyone can verify every security claim:

```bash
# Build
make                              # Zero warnings

# All functional tests
make test-all                     # 62/62 pass

# Memory safety
make test-asan                    # Zero ASAN/UBSAN errors

# NIST/RFC test vectors
make test-vectors && ./test_vectors   # 13/13 pass

# Verify Jasmin symbols are active
nm zupt | grep "zupt_mac_verify_ct\|zupt_ct_select_32"
# Expected: T zupt_mac_verify_ct
#           T zupt_ct_select_32

# Verify Jasmin compilation (requires jasminc)
jasminc -arch x86-64 -o /dev/null jasmin/zupt_mac_verify.jazz
jasminc -arch x86-64 -o /dev/null jasmin/zupt_mlkem_select.jazz
```

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later

## Production deployment notes (v2.2.1)

Zupt is deployed in production environments. The following supported
configurations are considered current and receive security fixes:

| Channel | Supported | Notes |
|---|---|---|
| 2.2.x (latest) | Yes | Recommended for new deployments |
| 2.1.x | Yes (security only) | Supported through 2026-Q4 |
| 2.0.x | No | End of life |
| 1.x | No | End of life |

### Recommended configuration

For new archives, use the libzuptsdk-backed mode:

```bash
zupt keygen --sdk -o key.priv
zupt c --pq-sdk key.priv.pub backup.zupt /path/to/data
zupt x --pq-sdk key.priv backup.zupt
```

This selects:

- ML-KEM-768 + X25519 hybrid KEM with HKDF-SHA3-256 combiner (RFC-style
  KDF rather than ad-hoc XOR construction)
- 32-byte HKDF-derived key commitment tag (protects against partitioning
  oracle attacks across recipients)
- HPKE-style context binding (RFC 9180 §5)
- Anti-fault double ML-KEM decapsulation
- XChaCha20-Poly1305 AEAD with 24-byte random nonces
- Argon2id (RFC 9106 OWASP minimums) when password mode is used

### Threat model

Zupt assumes:

- The recipient's private key file is kept secret and is not exfiltrated.
- The execution environment has a working `getrandom(2)` / `/dev/urandom`.
- The archive metadata (file list, sizes, mtimes) is not considered
  confidential. Padding to hide file sizes is not implemented.
- An attacker may have full write access to the archive in transit; AEAD
  + commitment + HPKE binding ensures any modification is detected.

Zupt does **not** defend against:

- Endpoint compromise (keylogger, malware on the machine where you type
  the password or hold the private key).
- Side-channel attacks against the host OS that bypass the constant-time
  Jasmin-verified primitives (e.g. Spectre v1 in callers).
- Quantum attacks against X25519 alone — but the ML-KEM-768 component
  guarantees post-quantum security via the hybrid KDF.

### Reporting findings

If you find a security issue:

1. **Do not** open a public issue on the project's git server.
2. Email `zupt@riseup.net` with subject `SECURITY: <brief>`.
3. Include the version (`zupt --version`), platform, and a
   reproduction (a minimal archive or a code snippet).
4. Expect acknowledgement within 7 days. Coordinated disclosure
   timeline will be discussed case by case.

### Disclosure history

| Date | Version | Findings | Severity |
|---|---|---|---|
| 2026-04-27 | 2.2.1 | 6 internally-found bugs (audit pass) | 2 high, 1 medium, 3 low |

---

## v2.2.1 audit findings

The 2.2.1 release fixed six bugs found by code review and added a 10-check
double-validated audit test suite. Detailed root-cause analysis for each
finding is in `CHANGELOG.md` under the 2.2.1 entry.

| # | Severity | Component | Bug |
|---|---|---|---|
| 1 | Low (correctness) | format parser | varint reader truncated values at 2^63 |
| 2 | Medium (data loss) | extract path | unchecked `fwrite` in 6 call sites — silent corruption on disk-full |
| 3 | Low (defense-in-depth) | SDK keyring | `mac_key` was a copy of `enc_key` rather than KDF-derived |
| 4 | High (memory safety) | LZ decoder | `size_t` overflow in length accumulator could enable out-of-bounds copy |
| 5 | Medium (DoS / amplification) | dedup ref blocks | unbounded forward offset + recursion accepted |
| 6 | Low (UX) | encrypt path | partial archive left on disk after encrypt-init failure |

All six fixed in 2.2.1. Regression tests added.

## Reporting vulnerabilities

Email `zupt@riseup.net` with `[security]` in the subject. PGP key on the
project's keyserver entry. Coordinated disclosure preferred; we will
acknowledge within 5 business days and aim for a fix within 30 days for
high-severity issues.

The project does not yet have an external audit. The 2.2.1 audit pass was
internal code review combined with the 169-check libzuptsdk audit suite
inherited via vendored linkage. For high-stakes deployments, treat this as
"reviewed but unaudited" and do your own review.

---

## v2.2.2 formal audit findings (2026-04-27)

A formal cryptographic audit pass was conducted using the methodology
documented in `FORMAL_AUDIT_PROMPT.md` (auditor profile: senior
cryptographic engineer with 15+ years of production crypto systems
experience). Two security-relevant bugs and two robustness bugs found
and fixed; version unchanged at 2.2.2 — same release with hardened
internals.

| # | Severity | Component | Bug |
|---|---|---|---|
| 11 | **HIGH** | extract path | Zip Slip / path traversal — `e->path` from archive used directly in `fopen` |
| 12 | **MEDIUM** | extract output | symlink-following — `fopen "wb"` followed symlinks at output target |
| 13 | LOW (32-bit only) | size cap | 4 GiB cap exceeds `size_t` on 32-bit |
| 14 | LOW (32-bit only) | calloc on parsed count | `count * sizeof(entry)` overflowed `size_t` before calloc internal check |

All four fixed and regression-tested.

### Threat model coverage (post-audit)

The following attack vectors are now explicitly defended against:

- **Malicious archive with path-traversal entries** (Zip Slip 2018 pattern):
  rejected by `zupt_path_is_safe()` — blocks `..`, absolute paths, Windows
  drive letters, UNC paths, embedded NULs.
- **Symlink at extract target** (TOCTOU pre-extraction): refused by
  `zupt_safe_fopen_output()` using `O_NOFOLLOW` on POSIX. Windows path
  unchanged — relies on directory ACLs (documented limitation).
- **Malformed archive headers**: bounds-checked offsets (`encryption_header_off`,
  `index_offset`); rejected if outside file size.
- **Format parser overflow**: varint truncation, dedup-ref recursion,
  realloc-pair atomicity, length-overflow in LZ decoder — all fixed in
  prior 2.2.x sprints.
- **Cryptographic key reuse / nonce misuse**: per-block nonce is `base ⊕
  block_seq`; `base_nonce` is per-archive random; mac_key is KDF-split
  from enc_key (defense in depth even though SDK path doesn't use it).
- **Block-swap (reorder) attack on encrypted archives** (bug #16, fixed
  in 2.2.2 god-tier audit): MAC binds 8-byte AAD seq computed as
  `((file_index_in_archive + 1) << 32) | per_file_block_seq`. An attacker
  who swaps two valid encrypted blocks between positions in the archive
  produces blocks whose AAD no longer matches their position; both MAC
  candidates (v2 with AAD, v1 legacy fallback) reject the swapped block.
  Empty/partial output files are `unlink()`'d on auth failure.
  Limitation: dedup mode uses sentinel seq=0 (refs can't derive source
  AAD); plaintext XXH64 still provides per-block integrity.

### Path traversal — operational guidance

Even with the in-binary defenses, operators extracting untrusted archives
should:

1. Extract into a dedicated empty directory (not `~/Downloads` or `/tmp`).
2. Audit symlinks in the target directory before extraction.
3. Run extraction as a low-privilege user, never root.
4. On Windows, pre-create the target directory with restrictive ACLs
   (the `O_NOFOLLOW` defense is POSIX-only).

These are belt-and-suspenders — the in-binary defenses are the primary
control, but defense in depth is good practice.

### Out-of-scope (still)

- External independent audit (cost-bound, on roadmap)
- Side-channel testing on production hardware (timing leaks)
- Formal verification beyond Jasmin constant-time primitives

