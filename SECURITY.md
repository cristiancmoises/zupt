# Security Policy — Zupt v2.0.0

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

© 2026 Cristian Cezar Moisés — MIT License
