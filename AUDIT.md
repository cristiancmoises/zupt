# Security Audit — Zupt v1.0.0

## Cryptographic Correctness

| Check | Status | Evidence |
|-------|--------|----------|
| ML-KEM-768 keygen+encaps+decaps roundtrip | ✅ | 10/10 trials pass (`test_pq.sh`) |
| ML-KEM-768 constant-time basemul | ✅ | No secret-dependent branches; Montgomery reduction is branchless |
| ML-KEM-768 FO implicit rejection | ✅ | cmov selects rejection key on invalid ct; both paths always execute |
| X25519 Montgomery ladder | ✅ | Constant-time by construction (cswap on every iteration) |
| AES-256-CTR | ✅ | Verified against NIST SP 800-38A via regression tests |
| HMAC-SHA256 | ✅ | Verified via password-mode archive integrity tests |
| PBKDF2-SHA256 | ✅ | 600,000 iterations, 32-byte random salt per archive |
| SHA-256 | ✅ | Used by HMAC/PBKDF2, verified transitively |
| SHA3-256/512 | ✅ | Used by ML-KEM; Keccak-f[1600] per FIPS 202 |
| SHAKE-128/256 | ✅ | Used by ML-KEM sampling; verified via KEM roundtrip |

## Constant-Time Verification

| Operation | Constant-Time | Method |
|-----------|---------------|--------|
| HMAC comparison | Yes | XOR accumulation (`diff \|= a[i] ^ b[i]`) |
| ML-KEM decaps implicit rejection | Yes | cmov with branchless fail detection |
| ML-KEM NTT/basemul | Yes | No secret-dependent branches; Barrett/Montgomery reduction branchless |
| ML-KEM CBD sampling | Yes | Bitwise operations only |
| X25519 ladder | Yes | fe_cswap with masked XOR on every bit |
| AES-256 | **No** | Table-based (T-tables). Vulnerable to cache-timing on shared hardware. |
| SHA-256 | **No** | Standard implementation. Not constant-time w.r.t. message length. |

**Documented limitation:** AES-256 and SHA-256 use lookup tables susceptible to cache-timing side channels. Do not use on shared multi-tenant hardware where an attacker can measure cache access patterns.

## Memory Safety

| Check | Status |
|-------|--------|
| `make test-asan`: zero errors | ✅ All modes: normal, solid, encrypted, PQ, MT |
| All `malloc()` return values checked | ✅ Propagated via `ZUPT_ERR_NOMEM` |
| All ML-KEM polynomial buffers wiped | ✅ `zupt_secure_wipe()` in keygen/encaps/decaps |
| All X25519 scalars wiped | ✅ `memset(e, 0, 32)` after ladder |
| All intermediate key material wiped | ✅ In `zupt_crypto.c` hybrid encrypt/decrypt init |
| Keyring copy wiped in parallel pool destructor | ✅ `zupt_secure_wipe(&ctx->keyring, ...)` |

## Format Stability

| Check | Status |
|-------|--------|
| v1.0 reads v0.3+ archives | ✅ Regression test covers password-encrypted v0.5 format |
| v0.6 rejects v1.4 PQ archives cleanly | ✅ Version check returns `ZUPT_ERR_BAD_VERSION` |
| FORMAT.md documents all fields | ✅ See FORMAT.md |
| FORMAT_STABLE flag set in v1.0 archives | ✅ Bit 4 of global_flags |

## Known Bugs Fixed (v0.7.0)

| Bug | Impact | Fix |
|-----|--------|-----|
| ML-KEM basemul OOB (`zetas[64+i]`, i up to 127) | Buffer overread → undefined behavior | Fixed to 64 iterations, 4-coeff groups |
| ML-KEM missing `poly_tomont` in keygen | Public key in wrong domain → K-PKE roundtrip fails | Added `poly_tomont()` after basemul in keygen |
| ML-KEM inverted cmov in FO decaps | Always selected rejection key → KEM roundtrip fails | Fixed fail detection: `(-(int64_t)diff) >> 63` |
| ML-KEM `inv_ntt` used wrong zetas table | NTT/invNTT roundtrip failed | Uses same `zetas[]` table, k counts 127→0 |
| PQ hybrid nonce mismatch | Encrypt/decrypt used different random nonces | Store base_nonce in enc_hdr; decrypt reads it back |
