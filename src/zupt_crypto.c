/*
 * ZUPT — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Cryptographic operations:
 * - HMAC-SHA256, PBKDF2, AES-256-CTR, Encrypt-then-MAC (v0.2+)
 * - Hybrid PQ KEM: ML-KEM-768 + X25519 (v0.7.0)
 *
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
#define _GNU_SOURCE
#include "zupt.h"
#include "zupt_acsl.h"
#include "zupt_jasmin.h"
#include "zupt_cpuid.h"  /* CPU dispatch for the optional Jasmin AES-NI path */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#if defined(__linux__)
  #include <sys/syscall.h>
  #include <unistd.h>
#endif
#ifndef _WIN32
  #include <fcntl.h>
#endif

/* ═══════════════════════════════════════════════════════════════════
 * CONSTANT-TIME EQUALITY (single audited primitive)
 *
 * Returns 1 if the two buffers are equal and 0 otherwise. Its source-level
 * control flow and memory-access pattern are intended to depend only on `n`,
 * not the contents or mismatch position. This is the one place the MAC-tag
 * comparison is implemented; the three former inline byte-OR loops (the v1.6 strict
 * decrypt path, the v1.4/v1.5 legacy v2 candidate, and the F-08 archive-
 * integrity-trailer check) now all call here, so the property is audited
 * and timing-tested in exactly one location (see tests/test_ct_timing).
 *
 * A timing leak in a MAC comparison is a forgery oracle: if "wrong on
 * byte 0" returned faster than "wrong on byte 31", an attacker could
 * recover a valid tag byte-by-byte. The source therefore uses volatile byte
 * loads and an OR accumulator with no explicit early exit. Exact generated
 * code remains compiler- and platform-dependent and is covered by a
 * dudect-style regression when its positive control is conclusive.
 *
 * CT-REQUIRED: no secret-dependent branch or memory access. */
int zupt_ct_memeq(const void *a, const void *b, size_t n) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(pa[i] ^ pb[i]);   /* CT-REQUIRED: OR-accumulate, no break */
    /* Fold 0/non-zero -> 1/0 without a branch:
     *   diff==0      -> (0-1)>>8 == 0xFF...  &1 -> 1
     *   diff!=0      -> high bits clear        &1 -> 0 */
    return (int)((uint8_t)((((unsigned)diff) - 1u) >> 8) & 1u);
}

/* ═══════════════════════════════════════════════════════════════════
 * RANDOM BYTES (OS-native CSPRNG — NO FALLBACK)
 *
 * If the OS CSPRNG is unavailable, this aborts. Using rand() would
 * make salt/nonce predictable and destroy all security guarantees.
 * ═══════════════════════════════════════════════════════════════════ */

void zupt_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    /* Windows: RtlGenRandom (SystemFunction036) */
    HMODULE lib = LoadLibraryA("advapi32.dll");
    if (lib) {
        typedef BOOLEAN(WINAPI *RtlGenRandomFunc)(PVOID, ULONG);
        RtlGenRandomFunc fn = (RtlGenRandomFunc)(void(*)(void))GetProcAddress(lib, "SystemFunction036");
        if (fn && fn(buf, (ULONG)len)) { FreeLibrary(lib); return; }
        FreeLibrary(lib);
    }
    fprintf(stderr, "FATAL: Windows CSPRNG (RtlGenRandom) unavailable.\n");
    exit(1);
#else
    /* Linux/macOS/BSD: try getrandom(2) first, then /dev/urandom */
  #if defined(__linux__)
    #if defined(SYS_getrandom)
    ssize_t r = syscall(SYS_getrandom, buf, len, 0);
    if (r == (ssize_t)len) return;
    #endif
  #endif
    FILE *f = zupt_fopen_path("/dev/urandom", "rb");
    if (f) {
        size_t nread = fread(buf, 1, len, f);
        fclose(f);
        if (nread == len) return;
    }
    fprintf(stderr, "FATAL: /dev/urandom unavailable. Cannot generate secure random bytes.\n");
    exit(1);
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * HMAC-SHA256 (RFC 2104)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: HMAC-SHA256 (RFC 2104) */
/*@ requires klen <= 256;
  @ requires \valid_read(key + (0..klen-1));
  @ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(mac + (0..31));
  @ requires \separated(key + (0..klen-1), mac + (0..31));
  @ requires \separated(data + (0..dlen-1), mac + (0..31));
  @ assigns mac[0..31];
  @ ensures \initialized(mac + (0..31));
*/
void zupt_hmac_sha256(const uint8_t *key, size_t klen,
                      const uint8_t *data, size_t dlen,
                      uint8_t mac[32]) {
    zupt_hmac_ctx c;
    zupt_hmac_sha256_init(&c, key, klen);
    zupt_hmac_sha256_update(&c, data, dlen);
    zupt_hmac_sha256_final(&c, mac);
}

/* Incremental HMAC-SHA256 (RFC 2104).
 *
 * _init seeds two SHA-256 contexts with the ipad/opad key-prefix blocks
 * (one 64-byte compression each), so repeated MACs under the same key
 * never recompute those prefixes and the caller can stream the message
 * with _update instead of building a concat buffer. RFC 2104 defines
 *   HMAC(K,m) = H( (K^opad) || H( (K^ipad) || m ) )
 * and SHA-256's Merkle-Damgard update() is associative over the message,
 * so streaming m in segments yields byte-identical output to hashing a
 * single concatenated buffer. */
void zupt_hmac_sha256_init(zupt_hmac_ctx *c, const uint8_t *key, size_t klen) {
    uint8_t k_pad[64];
    uint8_t k_hash[32];

    /* If key > 64 bytes, hash it first (RFC 2104). */
    if (klen > 64) {
        zupt_sha256(key, klen, k_hash);
        key = k_hash; klen = 32;
    }

    /* inner = SHA256 seeded with (key XOR ipad) */
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < klen; i++) k_pad[i] ^= key[i];
    zupt_sha256_init(&c->inner);
    zupt_sha256_update(&c->inner, k_pad, 64);

    /* outer = SHA256 seeded with (key XOR opad) */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < klen; i++) k_pad[i] ^= key[i];
    zupt_sha256_init(&c->outer);
    zupt_sha256_update(&c->outer, k_pad, 64);

    zupt_secure_wipe(k_pad, 64);
    zupt_secure_wipe(k_hash, 32);
}

void zupt_hmac_sha256_update(zupt_hmac_ctx *c, const uint8_t *data, size_t dlen) {
    zupt_sha256_update(&c->inner, data, dlen);
}

void zupt_hmac_sha256_final(zupt_hmac_ctx *c, uint8_t mac[32]) {
    uint8_t inner[32];
    zupt_sha256_final(&c->inner, inner);
    zupt_sha256_update(&c->outer, inner, 32);
    zupt_sha256_final(&c->outer, mac);
    zupt_secure_wipe(inner, 32);
    /* Wipe the residual context state (contains key-dependent material). */
    zupt_secure_wipe(c, sizeof(*c));
}

/* ═══════════════════════════════════════════════════════════════════
 * PBKDF2-HMAC-SHA256 (RFC 8018)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: PBKDF2-HMAC-SHA256 (RFC 8018) */
/*@ requires pwlen <= 256;
  @ requires slen <= 252;
  @ requires olen > 0 && olen <= 64;
  @ requires iterations >= 1;
  @ requires \valid_read(pw + (0..pwlen-1));
  @ requires \valid_read(salt + (0..slen-1));
  @ requires \valid(output + (0..olen-1));
  @ assigns output[0..olen-1];
  @ ensures \initialized(output + (0..olen-1));
*/
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen,
                        const uint8_t *salt, size_t slen,
                        uint32_t iterations,
                        uint8_t *output, size_t olen) {
    /* Clamp salt length to fit in the stack buffer.
     * ZUPT always passes ZUPT_SALT_SIZE (32) so this is a safety net. */
    size_t effective_slen = slen;
    if (effective_slen > 252) effective_slen = 252;

    uint32_t block_num = 1;
    size_t pos = 0;

    while (pos < olen) {
        /* U_1 = HMAC(pw, salt || INT_32_BE(block_num)) */
        uint8_t salt_block[256];
        memcpy(salt_block, salt, effective_slen);
        salt_block[effective_slen+0] = (uint8_t)(block_num >> 24);
        salt_block[effective_slen+1] = (uint8_t)(block_num >> 16);
        salt_block[effective_slen+2] = (uint8_t)(block_num >> 8);
        salt_block[effective_slen+3] = (uint8_t)(block_num);

        uint8_t u[32], t[32];
        zupt_hmac_sha256(pw, pwlen, salt_block, effective_slen + 4, u);
        memcpy(t, u, 32);

        /* U_2 .. U_c: XOR chain */
        for (uint32_t i = 1; i < iterations; i++) {
            zupt_hmac_sha256(pw, pwlen, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }

        /* Copy to output */
        size_t chunk = olen - pos;
        if (chunk > 32) chunk = 32;
        memcpy(output + pos, t, chunk);
        pos += chunk;
        block_num++;

        /* Wipe per-block intermediates */
        zupt_secure_wipe(u, 32);
        zupt_secure_wipe(t, 32);
        zupt_secure_wipe(salt_block, sizeof(salt_block));
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * AES-256-CTR MODE
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: AES-256-CTR stream cipher */
/*@ requires \valid_read(key + (0..31));
  @ requires \valid_read(nonce + (0..15));
  @ requires \valid_read(in + (0..len-1));
  @ requires \valid(out + (0..len-1));
  @ requires \separated(in + (0..len-1), out + (0..len-1));
  @ assigns out[0..len-1];
  @ ensures \initialized(out + (0..len-1));
*/
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16],
                     const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t counter[16], keystream[16];
    memcpy(counter, nonce, 16);

#ifdef ZUPT_USE_JASMIN
    /* OPTIONAL ASSEMBLY PATH: AES-NI implementation uses no table lookups.
     * The checked-in assembly uses VEX-encoded instructions (vaesenc,
     * vmovdqu, vpxor, etc.) which require BOTH AES-NI AND AVX support.
     * Checking only has_aesni would SIGILL on CPUs with AES-NI but no AVX,
     * or where the OS hasn't enabled XSAVE for YMM state. */
    if (zupt_cpu.has_aesni && zupt_cpu.has_avx) {
        size_t full_blocks = len / 16;
        size_t tail_bytes = len % 16;

        if (full_blocks >= 4) {
            /* 4-block pipeline: processes 4 blocks per iteration */
            size_t pipe_blocks = (full_blocks / 4) * 4;
            zupt_aes256_ctr4(out, in, key, counter, pipe_blocks);
            size_t pipe_bytes = pipe_blocks * 16;
            in += pipe_bytes;
            out += pipe_bytes;
            full_blocks -= pipe_blocks;
        }

        /* Remaining 0-3 full blocks: single-block path */
        size_t pos = 0;
        for (size_t b = 0; b < full_blocks; b++) {
            zupt_aes256_blk(out + pos, in + pos, key, counter);
            pos += 16;
            /* Increment counter (big-endian, last 8 bytes) */
            for (int i = 15; i >= 8; i--) {
                if (++counter[i] != 0) break;
            }
        }
        in += pos;
        out += pos;

        /* Tail: partial last block */
        if (tail_bytes > 0) {
            uint8_t tmp_in[16], tmp_out[16];
            memset(tmp_in, 0, 16);
            memcpy(tmp_in, in, tail_bytes);
            zupt_aes256_blk(tmp_out, tmp_in, key, counter);
            memcpy(out, tmp_out, tail_bytes);
            zupt_secure_wipe(tmp_in, 16);
            zupt_secure_wipe(tmp_out, 16);
        }

        zupt_secure_wipe(counter, 16);
        zupt_secure_wipe(keystream, 16);
        return;
    }
#endif

    /* C table-based fallback */
    zupt_aes256_ctx ctx;
    zupt_aes256_init(&ctx, key);

    size_t pos = 0;
    while (pos < len) {
        zupt_aes256_encrypt_block(&ctx, counter, keystream);

        size_t chunk = len - pos;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++)
            out[pos + i] = in[pos + i] ^ keystream[i];
        pos += chunk;

        /* Increment counter (big-endian, last 8 bytes) */
        for (int i = 15; i >= 8; i--) {
            if (++counter[i] != 0) break;
        }
    }

    zupt_secure_wipe(&ctx, sizeof(ctx));
    zupt_secure_wipe(keystream, 16);
}

/* ═══════════════════════════════════════════════════════════════════
 * KEY DERIVATION
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: Key derivation from password + salt */
/*@ requires \valid(kr);
  @ requires \valid_read(salt + (0..31));
  @ requires \valid_read(nonce + (0..15));
  @ requires strlen(pw) <= 255;
  @ requires iterations >= 1;
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->salt[0..31],
  @         kr->base_nonce[0..15], kr->iterations, kr->active;
  @ ensures kr->active == 1;
*/
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw,
                      const uint8_t salt[32], const uint8_t nonce[16],
                      uint32_t iterations) {
    /* Init canaries if not already set */
    kr->canary_head = ZUPT_CANARY;
    kr->canary_tail = ZUPT_CANARY;

    memcpy(kr->salt, salt, ZUPT_SALT_SIZE);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE);
    kr->iterations = iterations;
    kr->active = 1;

    /* Derive 64 bytes: 32 enc_key + 32 mac_key */
    uint8_t material[64];
    zupt_pbkdf2_sha256((const uint8_t *)pw, strlen(pw),
                       salt, ZUPT_SALT_SIZE,
                       iterations, material, 64);
    memcpy(kr->enc_key, material, 32);
    memcpy(kr->mac_key, material + 32, 32);

    zupt_secure_wipe(material, 64);

    /* Lock key material in RAM — prevent swap to disk */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPT-THEN-MAC
 *
 * Output format: [16-byte per-block nonce] [ciphertext] [32-byte HMAC]
 * The HMAC covers the nonce and ciphertext.
 * Per-block nonce = base_nonce XOR (block_seq as LE 8 bytes in low half)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: Encrypt-then-MAC: produces [nonce][ciphertext][HMAC] */
/*@ requires \valid_read(&kr->enc_key[0..31]);
  @ requires \valid_read(&kr->mac_key[0..31]);
  @ requires \valid_read(&kr->base_nonce[0..15]);
  @ requires kr->active == 1;
  @ requires \valid_read(plain + (0..plen-1));
  @ requires \valid(olen);
  @ assigns *olen;
  @ ensures *olen == 16 + plen + 32;
*/
/* F-09 of v2.3.1: extended-AAD encrypt.
 *
 * The MAC input becomes  aad_extra || nonce || ciphertext || aad_seq.
 * Original zupt_encrypt_buffer is a thin wrapper with aad_extra=NULL, len=0
 * to preserve byte-exact MAC output for archives that don't bind the
 * preface. New v1.6 callers pass the canonical (block_type, codec_id,
 * block_flags, usz, csz, plaintext-XXH64) bytes to bind the per-block
 * frame preface into the MAC. */
uint8_t *zupt_encrypt_buffer_aad(const zupt_keyring_t *kr,
                                  const uint8_t *plain, size_t plen,
                                  uint64_t block_seq,
                                  const uint8_t *aad_extra, size_t aad_extra_len,
                                  size_t *olen) {
    *olen = ZUPT_NONCE_SIZE + plen + ZUPT_HMAC_SIZE;
    uint8_t *pkg = (uint8_t *)malloc(*olen);
    if (!pkg) return NULL;

    /* Per-block nonce: a fresh random 128-bit value for every block.
     *
     * SECURITY FIX (v4.2.0): the previous scheme derived the nonce as
     * base_nonce XOR block_seq, but dedup mode hard-codes block_seq == 0 for
     * every data block (the sentinel needed so cross-file dedup references MAC
     * the same way). That collapsed every dedup block's nonce to the single
     * per-archive base_nonce, reusing the AES-256-CTR keystream across distinct
     * plaintext blocks — a many-time-pad that leaks plaintext to a
     * ciphertext-only attacker, in every encryption mode (password, hybrid PQ,
     * full PQ). A random 128-bit nonce is unique with overwhelming probability
     * regardless of dedup or thread scheduling. The nonce is stored in the
     * package prefix and bound by the HMAC, and decrypt reads it back directly,
     * so this is an encrypt-side change only — the on-disk format, the MAC
     * transcript (which still uses block_seq as aad_seq), and the decrypt path
     * are all unchanged, and pre-4.2 archives still extract byte-exact. */
    uint8_t nonce[16];
    zupt_random_bytes(nonce, 16);

    /* Store nonce */
    memcpy(pkg, nonce, 16);

    /* Encrypt */
    zupt_aes256_ctr(kr->enc_key, nonce, plain, pkg + 16, plen);

    uint8_t aad_seq[8];
    for (int i = 0; i < 8; i++) aad_seq[i] = (uint8_t)(block_seq >> (i * 8));

    /* MAC over aad_extra || nonce || ciphertext || aad_seq, streamed
     * directly through the incremental HMAC — no concat buffer, no copy
     * of the (up to multi-MB) ciphertext. The segment order is identical
     * to the legacy concat layout, so the MAC bytes are unchanged: the
     * extra AAD goes first so a v1.6 reader with aad_extra_len=0
     * reproduces the legacy v2 MAC exactly (no positional drift). */
    zupt_hmac_ctx hctx;
    zupt_hmac_sha256_init(&hctx, kr->mac_key, ZUPT_HMAC_SIZE);
    if (aad_extra_len) zupt_hmac_sha256_update(&hctx, aad_extra, aad_extra_len);
    zupt_hmac_sha256_update(&hctx, pkg, 16 + plen);   /* nonce || ciphertext */
    zupt_hmac_sha256_update(&hctx, aad_seq, 8);
    zupt_hmac_sha256_final(&hctx, pkg + 16 + plen);

    return pkg;
}

uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr,
                              const uint8_t *plain, size_t plen,
                              uint64_t block_seq, size_t *olen) {
    return zupt_encrypt_buffer_aad(kr, plain, plen, block_seq, NULL, 0, olen);
}

/* FRAMA-C: Decrypt with MAC verification (Encrypt-then-MAC) */
/*@ requires \valid_read(&kr->enc_key[0..31]);
  @ requires \valid_read(&kr->mac_key[0..31]);
  @ requires kr->active == 1;
  @ requires pkglen >= 48;
  @ requires \valid_read(pkg + (0..pkglen-1));
  @ requires \valid(olen);
  @ assigns *olen;
  @ behavior auth_ok:
  @   ensures \result != \null ==> *olen == pkglen - 48;
  @ behavior auth_fail:
  @   ensures \result == \null ==> *olen == pkglen - 48;
*/
/* F-09 of v2.3.1: extended-AAD decrypt.
 *
 * When aad_extra_len > 0: the MAC input is
 *   aad_extra || nonce || ciphertext || aad_seq
 * and ONLY this candidate is checked. There is no v1-legacy fallback —
 * the caller signals "this archive uses extended AAD" by the very act of
 * passing aad_extra, and an attacker can't downgrade by clearing
 * aad_extra because the caller (decompress_block) gates the AAD on the
 * archive-level ZUPT_FLAG_AAD_PREFACE flag, which is itself MAC-protected
 * by the v1.5+ archive-integrity-trailer (F-08).
 *
 * When aad_extra_len == 0: identical to the legacy zupt_decrypt_buffer —
 * tries v2 MAC (with aad_seq) and falls back to v1 (no AAD). This path
 * preserves byte-exact behavior for v1.4 and v1.5 archives. */
uint8_t *zupt_decrypt_buffer_aad(const zupt_keyring_t *kr,
                                  const uint8_t *pkg, size_t pkglen,
                                  uint64_t block_seq,
                                  const uint8_t *aad_extra, size_t aad_extra_len,
                                  size_t *olen) {
    if (pkglen < ZUPT_NONCE_SIZE + ZUPT_HMAC_SIZE) return NULL;

    size_t clen = pkglen - ZUPT_NONCE_SIZE - ZUPT_HMAC_SIZE;
    *olen = clen;
    const uint8_t *stored_mac = pkg + ZUPT_NONCE_SIZE + clen;

    uint8_t aad_seq[8];
    for (int i = 0; i < 8; i++) aad_seq[i] = (uint8_t)(block_seq >> (i * 8));

    /* v1.6 extended-AAD path: strict, single candidate. */
    if (aad_extra_len > 0) {
        uint8_t expected[32];
        /* Stream aad_extra || nonce || ciphertext || aad_seq through the
         * incremental HMAC — same segment order as the encrypt side and
         * the legacy concat layout, so the expected MAC is byte-identical
         * with no per-block concat buffer or ciphertext copy. */
        zupt_hmac_ctx hctx;
        zupt_hmac_sha256_init(&hctx, kr->mac_key, ZUPT_HMAC_SIZE);
        zupt_hmac_sha256_update(&hctx, aad_extra, aad_extra_len);
        zupt_hmac_sha256_update(&hctx, pkg, ZUPT_NONCE_SIZE + clen);
        zupt_hmac_sha256_update(&hctx, aad_seq, 8);
        zupt_hmac_sha256_final(&hctx, expected);

        /* CT-REQUIRED: constant-time MAC compare via the audited primitive. */
        int mac_ok = zupt_ct_memeq(expected, stored_mac, 32);
        zupt_secure_wipe(expected, sizeof(expected));

        /* CT-REQUIRED: always decrypt even on MAC failure (timing-oracle
         * protection — match the legacy path's behaviour). */
        uint8_t *plain = (uint8_t *)malloc(clen);
        if (!plain) return NULL;
        uint8_t nonce[16];
        memcpy(nonce, pkg, 16);
        zupt_aes256_ctr(kr->enc_key, nonce, pkg + 16, plain, clen);

        if (!mac_ok) {
            zupt_secure_wipe(plain, clen);
            free(plain);
            return NULL;
        }
        return plain;
    }

    /* v1.4/v1.5 legacy fallback: original two-candidate path. */
    uint8_t expected_mac_v2[32];
    uint8_t expected_mac_v1[32];

    {
        /* v2 candidate: nonce || ciphertext || aad_seq, streamed (no copy). */
        zupt_hmac_ctx hctx;
        zupt_hmac_sha256_init(&hctx, kr->mac_key, ZUPT_HMAC_SIZE);
        zupt_hmac_sha256_update(&hctx, pkg, ZUPT_NONCE_SIZE + clen);
        zupt_hmac_sha256_update(&hctx, aad_seq, 8);
        zupt_hmac_sha256_final(&hctx, expected_mac_v2);
    }

    zupt_hmac_sha256(kr->mac_key, ZUPT_HMAC_SIZE,
                     pkg, ZUPT_NONCE_SIZE + clen,
                     expected_mac_v1);

#ifdef ZUPT_USE_JASMIN
    uint64_t diff_v2 = zupt_mac_verify_ct(expected_mac_v2, stored_mac);
    uint64_t diff_v1 = zupt_mac_verify_ct(expected_mac_v1, stored_mac);
#else
    uint64_t diff_v2 = 0, diff_v1 = 0;
    for (int i = 0; i < 32; i++) {
        diff_v2 |= (uint64_t)(expected_mac_v2[i] ^ stored_mac[i]);
        diff_v1 |= (uint64_t)(expected_mac_v1[i] ^ stored_mac[i]);
    }
#endif

    /* F-06 fix retained: fold to nonzero-indicator bit before AND. */
    uint64_t nz_v2 = (diff_v2 | (uint64_t)(-(int64_t)diff_v2)) >> 63;  /* CT-REQUIRED */
    uint64_t nz_v1 = (diff_v1 | (uint64_t)(-(int64_t)diff_v1)) >> 63;  /* CT-REQUIRED */
    uint64_t diff = nz_v2 & nz_v1;

    zupt_secure_wipe(expected_mac_v2, sizeof(expected_mac_v2));
    zupt_secure_wipe(expected_mac_v1, sizeof(expected_mac_v1));

    /* CT-REQUIRED: always decrypt even on MAC failure (timing-oracle protection). */
    uint8_t *plain = (uint8_t *)malloc(clen);
    if (!plain) return NULL;
    const uint8_t *nonce_ptr = pkg;
    zupt_aes256_ctr(kr->enc_key, nonce_ptr, pkg + 16, plain, clen);

    if (diff != 0) {
        zupt_secure_wipe(plain, clen);
        free(plain);
        return NULL;
    }
    return plain;
}

uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr,
                              const uint8_t *pkg, size_t pkglen,
                              uint64_t block_seq, size_t *olen) {
    return zupt_decrypt_buffer_aad(kr, pkg, pkglen, block_seq, NULL, 0, olen);
}

/* Write a key file without ever opening an existing directory entry. Private
 * material is created mode 0600 on POSIX independently of the caller's umask.
 * Windows uses CREATE_NEW and, for private material, a protected DACL granting
 * access only to the current token's user SID. A failed write, flush, or close
 * leaves the exclusively created incomplete or durability-uncertain file in
 * place for the user to review and remove. This deliberately avoids a
 * pathname-based cleanup after close:
 * another process with write access to the parent directory could otherwise
 * replace the entry and trick cleanup into deleting an unrelated file.
 *
 * This is intentionally shared with the optional pq-box module. Public-key
 * output is exclusive too: besides avoiding symlink truncation, that prevents
 * `keygen --pub -o private.key -k private.key` from destroying the only copy of
 * a private key. */
int zupt_keyfile_write_new(const char *path, const uint8_t *data, size_t length,
                           int private_material) {
    if (!path || path[0] == '\0' || (!data && length != 0) ||
        (private_material != 0 && private_material != 1)) {
        errno = EINVAL;
        return -1;
    }

#ifdef _WIN32
    if (length > (size_t)MAXDWORD) {
        errno = EFBIG;
        return -1;
    }
    wchar_t *wide_path = zupt_win_utf8_to_wide_alloc(path);
    if (!wide_path) {
        errno = EINVAL;
        return -1;
    }

    SECURITY_ATTRIBUTES attributes;
    SECURITY_DESCRIPTOR descriptor;
    SECURITY_ATTRIBUTES *attributes_ptr = NULL;
    HMODULE advapi = NULL;
    HANDLE token = NULL;
    TOKEN_USER *token_user = NULL;
    ACL *acl = NULL;

    if (private_material) {
        typedef BOOL (WINAPI *open_process_token_fn)(HANDLE, DWORD, PHANDLE);
        typedef BOOL (WINAPI *get_token_information_fn)(
            HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
        typedef DWORD (WINAPI *get_length_sid_fn)(PSID);
        typedef BOOL (WINAPI *initialize_acl_fn)(PACL, DWORD, DWORD);
        typedef BOOL (WINAPI *add_access_allowed_ace_fn)(
            PACL, DWORD, DWORD, PSID);
        typedef BOOL (WINAPI *initialize_security_descriptor_fn)(
            PSECURITY_DESCRIPTOR, DWORD);
        typedef BOOL (WINAPI *set_security_descriptor_dacl_fn)(
            PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
        typedef BOOL (WINAPI *set_security_descriptor_control_fn)(
            PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL,
            SECURITY_DESCRIPTOR_CONTROL);

        advapi = LoadLibraryW(L"advapi32.dll");
        if (!advapi) goto windows_security_error;
        open_process_token_fn open_process_token =
            (open_process_token_fn)(void (*)(void))
                GetProcAddress(advapi, "OpenProcessToken");
        get_token_information_fn get_token_information =
            (get_token_information_fn)(void (*)(void))
                GetProcAddress(advapi, "GetTokenInformation");
        get_length_sid_fn get_length_sid =
            (get_length_sid_fn)(void (*)(void))
                GetProcAddress(advapi, "GetLengthSid");
        initialize_acl_fn initialize_acl =
            (initialize_acl_fn)(void (*)(void))
                GetProcAddress(advapi, "InitializeAcl");
        add_access_allowed_ace_fn add_access_allowed_ace =
            (add_access_allowed_ace_fn)(void (*)(void))
                GetProcAddress(advapi, "AddAccessAllowedAce");
        initialize_security_descriptor_fn initialize_security_descriptor =
            (initialize_security_descriptor_fn)(void (*)(void))
                GetProcAddress(advapi, "InitializeSecurityDescriptor");
        set_security_descriptor_dacl_fn set_security_descriptor_dacl =
            (set_security_descriptor_dacl_fn)(void (*)(void))
                GetProcAddress(advapi, "SetSecurityDescriptorDacl");
        set_security_descriptor_control_fn set_security_descriptor_control =
            (set_security_descriptor_control_fn)(void (*)(void))
                GetProcAddress(advapi, "SetSecurityDescriptorControl");
        if (!open_process_token || !get_token_information || !get_length_sid ||
            !initialize_acl || !add_access_allowed_ace ||
            !initialize_security_descriptor || !set_security_descriptor_dacl ||
            !set_security_descriptor_control)
            goto windows_security_error;

        if (!open_process_token(GetCurrentProcess(), TOKEN_QUERY, &token))
            goto windows_security_error;
        DWORD token_size = 0;
        (void)get_token_information(token, TokenUser, NULL, 0, &token_size);
        if (token_size == 0) goto windows_security_error;
        token_user = (TOKEN_USER *)malloc(token_size);
        if (!token_user) {
            errno = ENOMEM;
            goto windows_security_cleanup;
        }
        if (!get_token_information(token, TokenUser, token_user, token_size,
                                   &token_size))
            goto windows_security_error;

        DWORD sid_size = get_length_sid(token_user->User.Sid);
        if (sid_size == 0 ||
            sid_size > MAXDWORD - (DWORD)sizeof(ACL) -
                           (DWORD)sizeof(ACCESS_ALLOWED_ACE))
            goto windows_security_error;
        DWORD acl_size = (DWORD)sizeof(ACL) +
                         (DWORD)sizeof(ACCESS_ALLOWED_ACE) -
                         (DWORD)sizeof(DWORD) + sid_size;
        acl = (ACL *)malloc(acl_size);
        if (!acl) {
            errno = ENOMEM;
            goto windows_security_cleanup;
        }
        if (!initialize_acl(acl, acl_size, ACL_REVISION) ||
            !add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL,
                                    token_user->User.Sid) ||
            !initialize_security_descriptor(&descriptor,
                                            SECURITY_DESCRIPTOR_REVISION) ||
            !set_security_descriptor_dacl(&descriptor, TRUE, acl, FALSE) ||
            !set_security_descriptor_control(&descriptor, SE_DACL_PROTECTED,
                                             SE_DACL_PROTECTED))
            goto windows_security_error;

        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = &descriptor;
        attributes.bInheritHandle = FALSE;
        attributes_ptr = &attributes;
    }

    HANDLE handle = CreateFileW(
        wide_path, GENERIC_WRITE | DELETE, 0, attributes_ptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
            FILE_FLAG_WRITE_THROUGH,
        NULL);
    {
        DWORD create_error = handle == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        free(acl);
        free(token_user);
        if (token) CloseHandle(token);
        if (advapi) FreeLibrary(advapi);
        acl = NULL;
        token_user = NULL;
        token = NULL;
        advapi = NULL;
        if (handle == INVALID_HANDLE_VALUE) {
            free(wide_path);
            errno = (create_error == ERROR_FILE_EXISTS ||
                     create_error == ERROR_ALREADY_EXISTS)
                        ? EEXIST : EACCES;
            return -1;
        }
    }

    DWORD written = 0;
    int failed = !WriteFile(handle, data, (DWORD)length, &written, NULL) ||
                 written != (DWORD)length || !FlushFileBuffers(handle);
    if (!CloseHandle(handle)) failed = 1;
    if (failed) {
        free(wide_path);
        errno = EIO;
        return -1;
    }
    free(wide_path);
    return 0;

windows_security_error:
    errno = EACCES;
windows_security_cleanup:
    free(acl);
    free(token_user);
    if (token) CloseHandle(token);
    if (advapi) FreeLibrary(advapi);
    free(wide_path);
    return -1;
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int descriptor = open(path, flags, private_material ? 0600 : 0666);
    if (descriptor < 0) return -1;

    int failed = 0;
    int saved_errno = 0;
    if (private_material && fchmod(descriptor, 0600) != 0) {
        failed = 1;
        saved_errno = errno;
    }
#ifndef O_CLOEXEC
    if (!failed) {
        int descriptor_flags = fcntl(descriptor, F_GETFD);
        if (descriptor_flags < 0 ||
            fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
            failed = 1;
            saved_errno = errno;
        }
    }
#endif
    size_t offset = 0;
    while (!failed && offset < length) {
        ssize_t amount = write(descriptor, data + offset, length - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            failed = 1;
            saved_errno = amount < 0 ? errno : EIO;
            break;
        }
        offset += (size_t)amount;
    }
    if (!failed && fsync(descriptor) != 0) {
        failed = 1;
        saved_errno = errno;
    }
    if (close(descriptor) != 0 && !failed) {
        failed = 1;
        saved_errno = errno;
    }
    if (failed) {
        errno = saved_errno ? saved_errno : EIO;
        return -1;
    }
    return 0;
#endif
}

/* Load and structurally validate one native key blob before exposing any key
 * bytes to a caller. The historical writers have always serialized the XXH64
 * trailer with zupt_le64_put(), so readers deliberately interpret it as
 * little-endian on every host. This newly enforces the existing format rather
 * than changing it; valid v1 files remain byte-for-byte compatible. */
static int load_native_key_blob(const char *path, const char magic[4],
                                uint8_t version, uint8_t private_flag,
                                size_t public_file_size,
                                size_t private_file_size,
                                int require_private,
                                uint8_t *buffer, size_t buffer_capacity,
                                size_t *file_size) {
    if (!path || !buffer || !file_size || public_file_size < 16 ||
        private_file_size <= public_file_size ||
        private_file_size > buffer_capacity) {
        errno = EINVAL;
        return -1;
    }
    *file_size = 0;
    FILE *stream = zupt_fopen_path(path, "rb");
    if (!stream) return -1;

    size_t length = fread(buffer, 1, private_file_size, stream);
    int trailing = fgetc(stream);
    int failed = ferror(stream) != 0;
    if (fclose(stream) != 0) failed = 1;

    int has_private = length >= 6 && buffer[5] == private_flag;
    size_t expected_size = has_private ? private_file_size : public_file_size;
    if (failed || trailing != EOF ||
        (length != public_file_size && length != private_file_size) ||
        memcmp(buffer, magic, 4) != 0 || buffer[4] != version ||
        (buffer[5] != 0 && buffer[5] != private_flag) ||
        buffer[6] != 0 || buffer[7] != 0 ||
        length != expected_size || (require_private && !has_private)) {
        zupt_secure_wipe(buffer, buffer_capacity);
        errno = EINVAL;
        return -1;
    }

    uint64_t stored_checksum = zupt_le64_get(buffer + length - 8);
    uint64_t computed_checksum = zupt_xxh64(buffer, length - 8, 0);
    if (stored_checksum != computed_checksum) {
        zupt_secure_wipe(buffer, buffer_capacity);
        errno = EINVAL;
        return -1;
    }
    *file_size = length;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID POST-QUANTUM KEM: ML-KEM-768 + X25519 (v0.7.0)
 *
 * Security model: Secure if EITHER ML-KEM-768 OR X25519 is secure.
 * Same approach as Signal (PQXDH), iMessage (PQ3), OpenSSH 9.0+.
 *
 * Key file format (.zupt-key):
 *   [4B]  magic "ZKEY"
 *   [1B]  version 0x01
 *   [1B]  flags: bit0=has_private
 *   [2B]  reserved
 *   [1184B] ml_kem_pk
 *   [32B]   x25519_pk
 *   [2400B] ml_kem_sk  (only if has_private)
 *   [32B]   x25519_sk  (only if has_private)
 *   [8B]  xxh64 checksum of all above
 * ═══════════════════════════════════════════════════════════════════ */

#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include "zupt_keccak.h"

#define ZKEY_MAGIC "ZKEY"
#define ZKEY_VERSION 0x01
#define ZKEY_FLAG_PRIVATE 0x01
#define ZKEY_PUB_SIZE  (8 + 1184 + 32)        /* header + ml_kem_pk + x25519_pk */
#define ZKEY_PRIV_SIZE (8 + 1184 + 32 + 2400 + 32) /* + ml_kem_sk + x25519_sk */
#define ZKEY_CHECKSUM_SIZE 8
#define ZKEY_PUB_FILE_SIZE  (ZKEY_PUB_SIZE + ZKEY_CHECKSUM_SIZE)
#define ZKEY_PRIV_FILE_SIZE (ZKEY_PRIV_SIZE + ZKEY_CHECKSUM_SIZE)

int zupt_hybrid_keygen(const char *keyfile) {
    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES] = {0};
    uint8_t ml_sk[MLKEM_SECRETKEYBYTES] = {0};
    uint8_t x_sk[32] = {0}, x_pk[32] = {0};
    uint8_t buf[ZKEY_PRIV_FILE_SIZE] = {0};
    const size_t total = ZKEY_PRIV_SIZE;
    int result = -1;

    /* Generate ML-KEM-768 keypair */
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) goto out;

    /* Generate X25519 keypair */
    zupt_random_bytes(x_sk, 32);
    zupt_x25519_base(x_pk, x_sk);

    memcpy(buf, ZKEY_MAGIC, 4);
    buf[4] = ZKEY_VERSION;
    buf[5] = ZKEY_FLAG_PRIVATE;
    buf[6] = buf[7] = 0; /* reserved */
    memcpy(buf + 8, ml_pk, 1184);
    memcpy(buf + 8 + 1184, x_pk, 32);
    memcpy(buf + 8 + 1184 + 32, ml_sk, 2400);
    memcpy(buf + 8 + 1184 + 32 + 2400, x_sk, 32);

    /* Checksum */
    zupt_le64_put(buf + total, zupt_xxh64(buf, total, 0));

    result = zupt_keyfile_write_new(keyfile, buf, sizeof(buf), 1);
out:
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, sizeof(x_sk));
    zupt_secure_wipe(buf, sizeof(buf));
    return result;
}

int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile) {
    uint8_t private_blob[ZKEY_PRIV_FILE_SIZE] = {0};
    uint8_t public_blob[ZKEY_PUB_FILE_SIZE] = {0};
    size_t private_size = 0;
    const size_t total = ZKEY_PUB_SIZE;
    int result = -1;
    if (load_native_key_blob(privfile, ZKEY_MAGIC, ZKEY_VERSION,
                             ZKEY_FLAG_PRIVATE, ZKEY_PUB_FILE_SIZE,
                             ZKEY_PRIV_FILE_SIZE, 1, private_blob,
                             sizeof(private_blob), &private_size) != 0)
        goto out;

    memcpy(public_blob, ZKEY_MAGIC, 4);
    public_blob[4] = ZKEY_VERSION;
    public_blob[5] = 0; /* no private key */
    public_blob[6] = public_blob[7] = 0;
    memcpy(public_blob + 8, private_blob + 8, 1184 + 32);

    zupt_le64_put(public_blob + total,
                  zupt_xxh64(public_blob, total, 0));

    result = zupt_keyfile_write_new(pubfile, public_blob,
                                    sizeof(public_blob), 0);
out:
    zupt_secure_wipe(private_blob, sizeof(private_blob));
    zupt_secure_wipe(public_blob, sizeof(public_blob));
    return result;
}

/* Read public key from a .zupt-key file (works for both pub and priv files) */
static int read_pubkey(const char *path, uint8_t ml_pk[1184], uint8_t x_pk[32]) {
    uint8_t blob[ZKEY_PRIV_FILE_SIZE] = {0};
    size_t file_size = 0;
    /* Accept a structurally valid private file here for compatibility: older
     * releases explicitly allowed encryption directly with either ZKEY role. */
    if (load_native_key_blob(path, ZKEY_MAGIC, ZKEY_VERSION,
                             ZKEY_FLAG_PRIVATE, ZKEY_PUB_FILE_SIZE,
                             ZKEY_PRIV_FILE_SIZE, 0, blob, sizeof(blob),
                             &file_size) != 0)
        return -1;
    memcpy(ml_pk, blob + 8, 1184);
    memcpy(x_pk, blob + 8 + 1184, 32);
    zupt_secure_wipe(blob, sizeof(blob));
    return 0;
}

/* Read private key from a .zupt-key file */
static int read_privkey(const char *path, uint8_t ml_pk[1184], uint8_t x_pk[32],
                        uint8_t ml_sk[2400], uint8_t x_sk[32]) {
    uint8_t blob[ZKEY_PRIV_FILE_SIZE] = {0};
    size_t file_size = 0;
    if (load_native_key_blob(path, ZKEY_MAGIC, ZKEY_VERSION,
                             ZKEY_FLAG_PRIVATE, ZKEY_PUB_FILE_SIZE,
                             ZKEY_PRIV_FILE_SIZE, 1, blob, sizeof(blob),
                             &file_size) != 0)
        return -1;
    memcpy(ml_pk, blob + 8, 1184);
    memcpy(x_pk, blob + 8 + 1184, 32);
    memcpy(ml_sk, blob + 8 + 1184 + 32, 2400);
    memcpy(x_sk, blob + 8 + 1184 + 32 + 2400, 32);
    zupt_secure_wipe(blob, sizeof(blob));
    return 0;
}

/*
 * HYBRID ENCRYPT INIT: Encapsulate with ML-KEM + X25519, derive archive keys.
 *
 * enc_hdr output (1121 bytes):
 *   [1B]    enc_type = 0x02 (PQ-Hybrid)
 *   [1088B] ml_kem_ciphertext
 *   [32B]   ephemeral_x25519_pubkey
 *
 * Key derivation:
 *   hybrid_ikm = ml_kem_ss XOR x25519_ss
 *   archive_key[64] = SHA-256(hybrid_ikm ‖ ml_kem_ct ‖ ephemeral_pk ‖ "ZUPT-HYBRID-v1")
 *   enc_key = archive_key[0:32], mac_key = archive_key[32:64]
 */
/* FRAMA-C: Hybrid PQ encrypt init — ML-KEM-768 + X25519 KEM */
/*@ requires \valid(kr);
  @ requires \valid_read(pubkeyfile);
  @ requires \valid(enc_hdr + (0..1199));
  @ requires \valid(enc_hdr_len);
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->base_nonce[0..15],
  @         kr->iterations, kr->active;
  @ assigns enc_hdr[0..1199], *enc_hdr_len;
  @ ensures \result == 0 ==> kr->active == 1;
  @ ensures \result == 0 ==> *enc_hdr_len == 1137;
*/
int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32];
    if (read_pubkey(pubkeyfile, ml_pk, x_pk) != 0) return -1;

    /* ML-KEM-768 encapsulation */
    uint8_t ml_ct[1088], ml_ss[32];
    if (zupt_mlkem768_encaps(ml_ct, ml_ss, ml_pk) != 0) return -1;

    /* X25519 ECDH */
    uint8_t eph_sk[32], eph_pk[32], x_ss[32];
    zupt_random_bytes(eph_sk, 32);
    zupt_x25519_base(eph_pk, eph_sk);
    zupt_x25519(x_ss, eph_sk, x_pk);

    /* Hybrid shared secret: XOR then hash with transcript */
    uint8_t hybrid_ikm[32];
    for (int i = 0; i < 32; i++) hybrid_ikm[i] = ml_ss[i] ^ x_ss[i];

    /* archive_key = SHA-256(hybrid_ikm ‖ ml_ct ‖ eph_pk ‖ "ZUPT-HYBRID-v1") */
    /* We need 64 bytes, so use SHA3-512 instead of SHA-256 */
    uint8_t kdf_input[32 + 1088 + 32 + 15];
    memcpy(kdf_input, hybrid_ikm, 32);
    memcpy(kdf_input + 32, ml_ct, 1088);
    memcpy(kdf_input + 32 + 1088, eph_pk, 32);
    memcpy(kdf_input + 32 + 1088 + 32, "ZUPT-HYBRID-v1", 15);

    uint8_t archive_key[64];
    zupt_sha3_512(kdf_input, sizeof(kdf_input), archive_key);

    /* Set up keyring */
    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    zupt_random_bytes(kr->base_nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    /* Lock key material in RAM */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    /* Build encryption header: enc_type(1) + ml_ct(1088) + eph_pk(32) + base_nonce(16) */
    enc_hdr[0] = ZUPT_ENC_PQ_HYBRID;
    memcpy(enc_hdr + 1, ml_ct, 1088);
    memcpy(enc_hdr + 1 + 1088, eph_pk, 32);
    memcpy(enc_hdr + 1 + 1088 + 32, kr->base_nonce, 16);
    *enc_hdr_len = 1 + 1088 + 32 + 16;  /* 1137 bytes */

    /* Wipe all intermediates */
    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(x_ss, 32);
    zupt_secure_wipe(eph_sk, 32);
    zupt_secure_wipe(hybrid_ikm, 32);
    zupt_secure_wipe(kdf_input, sizeof(kdf_input));
    zupt_secure_wipe(archive_key, 64);

    return 0;
}

/*
 * HYBRID DECRYPT INIT: Decapsulate with ML-KEM + X25519, derive archive keys.
 */
/* FRAMA-C: Hybrid PQ decrypt init — ML-KEM-768 + X25519 decaps */
/*@ requires \valid(kr);
  @ requires \valid_read(privkeyfile);
  @ requires enc_hdr_len >= 1137;
  @ requires \valid_read(enc_hdr + (0..enc_hdr_len-1));
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->base_nonce[0..15],
  @         kr->iterations, kr->active;
  @ ensures \result == 0 ==> kr->active == 1;
*/
int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len) {
    if (enc_hdr_len < 1 + 1088 + 32 + 16) return -1;  /* enc_type + ct + eph_pk + nonce */
    if (enc_hdr[0] != ZUPT_ENC_PQ_HYBRID) return -1;

    const uint8_t *ml_ct  = enc_hdr + 1;
    const uint8_t *eph_pk = enc_hdr + 1 + 1088;
    const uint8_t *nonce  = enc_hdr + 1 + 1088 + 32;

    uint8_t ml_pk[1184], x_pk[32], ml_sk[2400], x_sk[32];
    if (read_privkey(privkeyfile, ml_pk, x_pk, ml_sk, x_sk) != 0) {
        /* Wipe any partially-read secret-key material on error, matching the
         * pq-only decrypt path (a bad/truncated key file must not leave secret
         * bytes on the stack). */
        zupt_secure_wipe(ml_sk, sizeof(ml_sk));
        zupt_secure_wipe(x_sk, sizeof(x_sk));
        return -1;
    }

    /* ML-KEM-768 decapsulation */
    uint8_t ml_ss[32];
    zupt_mlkem768_decaps(ml_ss, ml_ct, ml_sk);

    /* X25519 ECDH with ephemeral pubkey */
    uint8_t x_ss[32];
    zupt_x25519(x_ss, x_sk, eph_pk);

    /* Same key derivation as encrypt */
    uint8_t hybrid_ikm[32];
    for (int i = 0; i < 32; i++) hybrid_ikm[i] = ml_ss[i] ^ x_ss[i];

    uint8_t kdf_input[32 + 1088 + 32 + 15];
    memcpy(kdf_input, hybrid_ikm, 32);
    memcpy(kdf_input + 32, ml_ct, 1088);
    memcpy(kdf_input + 32 + 1088, eph_pk, 32);
    memcpy(kdf_input + 32 + 1088 + 32, "ZUPT-HYBRID-v1", 15);

    uint8_t archive_key[64];
    zupt_sha3_512(kdf_input, sizeof(kdf_input), archive_key);

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE); /* Read from enc_hdr, NOT random */
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    /* Lock key material in RAM */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);
    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(x_ss, 32);
    zupt_secure_wipe(hybrid_ikm, 32);
    zupt_secure_wipe(kdf_input, sizeof(kdf_input));
    zupt_secure_wipe(archive_key, 64);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * FULL POST-QUANTUM KEM: ML-KEM-768 only (v4.2.0)
 *
 * Unlike the hybrid --pq mode (ML-KEM-768 + X25519), this mode uses
 * ML-KEM-768 ALONE — no classical X25519 component. It is "fully
 * post-quantum": confidentiality of the archive key rests solely on
 * ML-KEM (FIPS 203, IND-CCA2 with the Fujisaki-Okamoto transform /
 * implicit rejection that zupt_mlkem768_decaps implements).
 *
 * SECURITY NOTE: the hybrid --pq mode remains the recommended default.
 * A pure-PQ scheme has NO classical fallback, so a future break of
 * ML-KEM-768 leaves no second layer. Use --pq-only only when a strictly
 * post-quantum construction is a hard requirement (e.g. a policy that
 * forbids classical primitives entirely).
 *
 * Key file (ZPQK):
 *   [4B]    "ZPQK"
 *   [1B]    version 0x01
 *   [1B]    flags: bit0 = has_private
 *   [2B]    reserved
 *   [1184B] ml_kem_pk
 *   [2400B] ml_kem_sk   (only if has_private)
 *   [8B]    xxh64 of everything above
 *
 * enc_hdr (ZUPT_ENC_PQ_ONLY = 0x06), 1105 bytes:
 *   [1B]    0x06
 *   [1088B] ml_kem_ciphertext
 *   [16B]   base_nonce
 *
 * archive_key[64] = SHA3-512(ml_ss ‖ ml_ct ‖ "ZUPT-PQ-ONLY-v1")
 *   enc_key = archive_key[0:32], mac_key = archive_key[32:64]
 * The ML-KEM ciphertext is bound into the KDF transcript (defense in
 * depth) alongside the domain separator, which also prevents cross-mode
 * key reuse with the hybrid path (different label).
 * ═══════════════════════════════════════════════════════════════════ */

#define ZPQK_MAGIC        "ZPQK"
#define ZPQK_VERSION      0x01
#define ZPQK_FLAG_PRIVATE 0x01
#define ZPQK_HDR          8
#define ZPQK_PUB_SIZE     (ZPQK_HDR + 1184)
#define ZPQK_PRIV_SIZE    (ZPQK_HDR + 1184 + 2400)
#define ZPQK_CHECKSUM_SIZE 8
#define ZPQK_PUB_FILE_SIZE  (ZPQK_PUB_SIZE + ZPQK_CHECKSUM_SIZE)
#define ZPQK_PRIV_FILE_SIZE (ZPQK_PRIV_SIZE + ZPQK_CHECKSUM_SIZE)
#define ZUPT_PQ_ONLY_LABEL "ZUPT-PQ-ONLY-v1"   /* 15 bytes */

int zupt_pq_keygen(const char *keyfile) {
    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES] = {0};
    uint8_t ml_sk[MLKEM_SECRETKEYBYTES] = {0};
    uint8_t buf[ZPQK_PRIV_FILE_SIZE] = {0};
    const size_t total = ZPQK_PRIV_SIZE;
    int result = -1;
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) goto out;

    memcpy(buf, ZPQK_MAGIC, 4);
    buf[4] = ZPQK_VERSION;
    buf[5] = ZPQK_FLAG_PRIVATE;
    buf[6] = buf[7] = 0;
    memcpy(buf + ZPQK_HDR, ml_pk, 1184);
    memcpy(buf + ZPQK_HDR + 1184, ml_sk, 2400);

    zupt_le64_put(buf + total, zupt_xxh64(buf, total, 0));

    result = zupt_keyfile_write_new(keyfile, buf, sizeof(buf), 1);
out:
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(buf, sizeof(buf));
    return result;
}

int zupt_pq_export_pubkey(const char *privfile, const char *pubfile) {
    uint8_t private_blob[ZPQK_PRIV_FILE_SIZE] = {0};
    uint8_t public_blob[ZPQK_PUB_FILE_SIZE] = {0};
    size_t private_size = 0;
    const size_t total = ZPQK_PUB_SIZE;
    int result = -1;
    if (load_native_key_blob(privfile, ZPQK_MAGIC, ZPQK_VERSION,
                             ZPQK_FLAG_PRIVATE, ZPQK_PUB_FILE_SIZE,
                             ZPQK_PRIV_FILE_SIZE, 1, private_blob,
                             sizeof(private_blob), &private_size) != 0)
        goto out;

    memcpy(public_blob, ZPQK_MAGIC, 4);
    public_blob[4] = ZPQK_VERSION;
    public_blob[5] = 0;
    public_blob[6] = public_blob[7] = 0;
    memcpy(public_blob + ZPQK_HDR, private_blob + ZPQK_HDR, 1184);
    zupt_le64_put(public_blob + total,
                  zupt_xxh64(public_blob, total, 0));
    result = zupt_keyfile_write_new(pubfile, public_blob,
                                    sizeof(public_blob), 0);
out:
    zupt_secure_wipe(private_blob, sizeof(private_blob));
    zupt_secure_wipe(public_blob, sizeof(public_blob));
    return result;
}

static int read_pq_pubkey(const char *path, uint8_t ml_pk[1184]) {
    uint8_t blob[ZPQK_PRIV_FILE_SIZE] = {0};
    size_t file_size = 0;
    /* Preserve the historical convenience of encrypting with a valid private
     * ZPQK file while still validating its private role, size, and checksum. */
    if (load_native_key_blob(path, ZPQK_MAGIC, ZPQK_VERSION,
                             ZPQK_FLAG_PRIVATE, ZPQK_PUB_FILE_SIZE,
                             ZPQK_PRIV_FILE_SIZE, 0, blob, sizeof(blob),
                             &file_size) != 0)
        return -1;
    memcpy(ml_pk, blob + ZPQK_HDR, 1184);
    zupt_secure_wipe(blob, sizeof(blob));
    return 0;
}

static int read_pq_privkey(const char *path, uint8_t ml_pk[1184], uint8_t ml_sk[2400]) {
    uint8_t blob[ZPQK_PRIV_FILE_SIZE] = {0};
    size_t file_size = 0;
    if (load_native_key_blob(path, ZPQK_MAGIC, ZPQK_VERSION,
                             ZPQK_FLAG_PRIVATE, ZPQK_PUB_FILE_SIZE,
                             ZPQK_PRIV_FILE_SIZE, 1, blob, sizeof(blob),
                             &file_size) != 0)
        return -1;
    memcpy(ml_pk, blob + ZPQK_HDR, 1184);
    memcpy(ml_sk, blob + ZPQK_HDR + 1184, 2400);
    zupt_secure_wipe(blob, sizeof(blob));
    return 0;
}

/* archive_key = SHA3-512(ml_ss ‖ ml_ct ‖ label). Shared by encrypt/decrypt. */
static void pq_only_derive(const uint8_t ml_ss[32], const uint8_t ml_ct[1088],
                           uint8_t archive_key[64]) {
    uint8_t kdf_input[32 + 1088 + 15];
    memcpy(kdf_input, ml_ss, 32);
    memcpy(kdf_input + 32, ml_ct, 1088);
    memcpy(kdf_input + 32 + 1088, ZUPT_PQ_ONLY_LABEL, 15);
    zupt_sha3_512(kdf_input, sizeof(kdf_input), archive_key);
    zupt_secure_wipe(kdf_input, sizeof(kdf_input));
}

int zupt_pq_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                         uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t ml_pk[1184];
    if (read_pq_pubkey(pubkeyfile, ml_pk) != 0) return -1;

    uint8_t ml_ct[1088], ml_ss[32];
    if (zupt_mlkem768_encaps(ml_ct, ml_ss, ml_pk) != 0) return -1;

    uint8_t archive_key[64];
    pq_only_derive(ml_ss, ml_ct, archive_key);

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    zupt_random_bytes(kr->base_nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    enc_hdr[0] = ZUPT_ENC_PQ_ONLY;
    memcpy(enc_hdr + 1, ml_ct, 1088);
    memcpy(enc_hdr + 1 + 1088, kr->base_nonce, 16);
    *enc_hdr_len = 1 + 1088 + 16;   /* 1105 bytes */

    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(archive_key, 64);
    return 0;
}

int zupt_pq_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                         const uint8_t *enc_hdr, size_t enc_hdr_len) {
    if (enc_hdr_len < 1 + 1088 + 16) return -1;
    if (enc_hdr[0] != ZUPT_ENC_PQ_ONLY) return -1;
    const uint8_t *ml_ct = enc_hdr + 1;
    const uint8_t *nonce = enc_hdr + 1 + 1088;

    uint8_t ml_pk[1184], ml_sk[2400];
    if (read_pq_privkey(privkeyfile, ml_pk, ml_sk) != 0) {
        zupt_secure_wipe(ml_sk, sizeof(ml_sk));  /* wipe any partial secret from a truncated key file */
        return -1;
    }

    /* ML-KEM-768 decapsulation (FO implicit rejection: an invalid ciphertext
     * yields a pseudorandom shared secret, so a wrong/tampered ct produces a
     * wrong archive key and the per-block HMAC fails-closed at extract time). */
    uint8_t ml_ss[32];
    zupt_mlkem768_decaps(ml_ss, ml_ct, ml_sk);

    uint8_t archive_key[64];
    pq_only_derive(ml_ss, ml_ct, archive_key);

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(archive_key, 64);
    return 0;
}
