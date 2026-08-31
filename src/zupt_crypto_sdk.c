/* zupt_crypto_sdk.c — SDK-backed crypto for zupt v2.2+ archives.
 *
 * Replaces the legacy zupt_crypto.c hybrid path (XOR+SHA3-512 combiner) with
 * libvuptsdk's HKDF-SHA3-256 combiner + key commitment + HPKE binding +
 * anti-fault decap. Per-block AEAD switches from AES-256-CTR + HMAC-SHA256
 * to XChaCha20-Poly1305 (default) or AES-256-SIV (nonce-misuse-resistant).
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "zupt.h"

#ifdef ZUPT_WITH_SDK
#include "zuptsdk.h"
#include "zuptsdk_easy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The keyring layout zupt uses for legacy AES-CTR+HMAC stays as-is for
 * compatibility with non-SDK code paths (block formatting, etc.). The SDK
 * path stores its own session key in the keyring's enc_key slot and sets
 * a flag so block read/write routes through the SDK AEAD path. */

extern void zupt_random_bytes(uint8_t *buf, size_t len);

/* ─────────────────────────────────────────────────────────────────────
 * SDK keypair generation
 * ───────────────────────────────────────────────────────────────────── */
int zupt_sdk_hybrid_keygen(const char *privkeyfile, const char *pubkeyfile) {
    zuptsdk_ctx_t *ctx = NULL;
    zuptsdk_keypair_t *kp = NULL;
    int rc = -1;

    if (zuptsdk_ctx_create(&ctx) != 0) goto out;
    if (zuptsdk_keypair_generate(ctx, &kp) != 0) goto out;
    if (zuptsdk_keypair_save_private(kp, privkeyfile) != 0) goto out;
    if (pubkeyfile && zuptsdk_keypair_save_public(kp, pubkeyfile) != 0) goto out;

    rc = 0;
out:
    if (kp)  zuptsdk_keypair_destroy(kp);
    if (ctx) zuptsdk_ctx_destroy(ctx);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────
 * SDK encrypt-init: generates session key via SDK, writes SDK v2 header
 * into the archive's encryption header block.
 *
 * Layout written to enc_hdr buffer:
 *   [1B]    enc_type = ZUPT_ENC_PQ_SDK_V2
 *   [4B LE] sdk_hdr_len (u32)
 *   [N]     sdk_hdr (1408 bytes for v2)
 *   [16B]   wrapped_session_key (encrypted to recipient via SDK easy_encrypt)
 *   [16B]   wrap_tag
 *
 * Approach: we ask the SDK to encrypt a 32-byte random session key to the
 * recipient's pubkey. The SDK produces a self-contained blob (header + ct).
 * We embed the entire blob in our encryption header and use the recovered
 * session key as the per-archive AEAD key.
 * ───────────────────────────────────────────────────────────────────── */
int zupt_sdk_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                                  uint8_t *enc_hdr, size_t *enc_hdr_len) {
    /* Generate a random 32-byte session key */
    uint8_t session_key[32];
    zupt_random_bytes(session_key, 32);

    /* Encrypt the session key to the recipient using SDK easy API */
    uint8_t *blob = NULL;
    size_t blob_sz = 0;
    int rc = zuptsdk_easy_encrypt(pubkeyfile, session_key, 32, &blob, &blob_sz);
    if (rc != 0 || !blob) {
        zupt_secure_wipe(session_key, 32);
        return -1;
    }

    /* Layout: [1B type][4B blob_sz LE][blob] */
    if (1 + 4 + blob_sz > 1500) {
        free(blob);
        zupt_secure_wipe(session_key, 32);
        return -1;
    }

    enc_hdr[0] = ZUPT_ENC_PQ_SDK_V2;
    enc_hdr[1] =  blob_sz        & 0xFF;
    enc_hdr[2] = (blob_sz >>  8) & 0xFF;
    enc_hdr[3] = (blob_sz >> 16) & 0xFF;
    enc_hdr[4] = (blob_sz >> 24) & 0xFF;
    memcpy(enc_hdr + 5, blob, blob_sz);
    *enc_hdr_len = 5 + blob_sz;

    /* Set up keyring with session key. Split into enc_key + mac_key via
     * domain-separated SHA3 to avoid key reuse if any legacy code path
     * reads mac_key (defense in depth — SDK path doesn't actually use
     * mac_key for AEAD, but legacy fall-throughs would). */
    extern void zupt_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);
    uint8_t kdf_buf[32 + 16];
    memcpy(kdf_buf, session_key, 32);
    memcpy(kdf_buf + 32, "ZUPT-SDK-ENC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->enc_key);
    memcpy(kdf_buf + 32, "ZUPT-SDK-MAC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->mac_key);
    zupt_secure_wipe(kdf_buf, sizeof(kdf_buf));

    kr->canary_head = ZUPT_CANARY;
    zupt_random_bytes(kr->base_nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    free(blob);
    zupt_secure_wipe(session_key, 32);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * SDK decrypt-init: parses encryption header, recovers session key.
 * ───────────────────────────────────────────────────────────────────── */
int zupt_sdk_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                                  const uint8_t *enc_hdr, size_t enc_hdr_len) {
    if (enc_hdr_len < 5) return -1;
    if (enc_hdr[0] != ZUPT_ENC_PQ_SDK_V2) return -1;

    uint32_t blob_sz = (uint32_t)enc_hdr[1]
                     | ((uint32_t)enc_hdr[2] <<  8)
                     | ((uint32_t)enc_hdr[3] << 16)
                     | ((uint32_t)enc_hdr[4] << 24);
    if (blob_sz > enc_hdr_len - 5) return -1;
    if (blob_sz > 1500) return -1;

    const uint8_t *blob = enc_hdr + 5;

    /* Decrypt session key using SDK */
    uint8_t *session_key = NULL;
    size_t session_key_sz = 0;
    int rc = zuptsdk_easy_decrypt(privkeyfile, blob, blob_sz, &session_key, &session_key_sz);
    if (rc != 0 || !session_key || session_key_sz != 32) {
        if (session_key) zuptsdk_free(session_key);
        return -1;
    }

    extern void zupt_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);
    uint8_t kdf_buf[32 + 16];
    memcpy(kdf_buf, session_key, 32);
    memcpy(kdf_buf + 32, "ZUPT-SDK-ENC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->enc_key);
    memcpy(kdf_buf + 32, "ZUPT-SDK-MAC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->mac_key);
    zupt_secure_wipe(kdf_buf, sizeof(kdf_buf));

    kr->canary_head = ZUPT_CANARY;
    /* base_nonce will be overwritten per-block by the legacy path; in SDK
     * mode each block uses its own SDK-generated nonce. */
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    zuptsdk_secure_zero(session_key, 32);
    zuptsdk_free(session_key);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Argon2id-backed password encrypt-init (replaces PBKDF2 path)
 * ───────────────────────────────────────────────────────────────────── */
int zupt_sdk_password_encrypt_init(zupt_keyring_t *kr, const char *password,
                                    uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t salt[16];
    if (zuptsdk_easy_random_salt(salt) != 0) return -1;

    uint8_t key[32];
    if (zuptsdk_easy_derive_key(password, salt, key) != 0) return -1;

    /* Layout: [1B type=0x04][16B salt][16B nonce][1B kdf-profile].
     * The profile byte (v3.4.0) makes the header self-describing about
     * which Argon2id cost produced the archive — see ZUPT_ARGON2_PROFILE_*
     * in zupt.h. Readers older than 3.4.0 ignore it (they read fixed
     * offsets and only require len >= 33); it is covered by the F-08
     * archive-integrity trailer so it can't be stripped undetected. */
    enc_hdr[0] = ZUPT_ENC_PW_ARGON2;
    memcpy(enc_hdr + 1, salt, 16);
    zupt_random_bytes(enc_hdr + 17, 16);
    enc_hdr[33] = ZUPT_ARGON2_PROFILE_MODERATE;
    *enc_hdr_len = ZUPT_ARGON2_HDR_LEN_V2;

    extern void zupt_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);
    uint8_t kdf_buf[32 + 16];
    memcpy(kdf_buf, key, 32);
    memcpy(kdf_buf + 32, "ZUPT-SDK-ENC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->enc_key);
    memcpy(kdf_buf + 32, "ZUPT-SDK-MAC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->mac_key);
    zupt_secure_wipe(kdf_buf, sizeof(kdf_buf));

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->base_nonce, enc_hdr + 17, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    zupt_secure_wipe(key, 32);
    zupt_secure_wipe(salt, 16);
    return 0;
}

int zupt_sdk_password_decrypt_init(zupt_keyring_t *kr, const char *password,
                                    const uint8_t *enc_hdr, size_t enc_hdr_len) {
    if (enc_hdr_len < ZUPT_ARGON2_HDR_LEN_V1) return -1;
    if (enc_hdr[0] != ZUPT_ENC_PW_ARGON2) return -1;

    /* v3.4.0 self-describing KDF profile. Absent (33-byte header) means
     * the implicit legacy profile; present (>=34 bytes) names it
     * explicitly. Both currently map to the same libvuptsdk MODERATE
     * Argon2id derivation, so the key is identical and old archives keep
     * decrypting. An unrecognised profile is refused rather than guessed
     * — better a clear failure than a wrong key derivation. */
    if (enc_hdr_len >= ZUPT_ARGON2_HDR_LEN_V2) {
        uint8_t profile = enc_hdr[33];
        if (profile != ZUPT_ARGON2_PROFILE_LEGACY &&
            profile != ZUPT_ARGON2_PROFILE_MODERATE) {
            return -1;  /* unknown KDF profile — cannot derive correctly */
        }
    }

    const uint8_t *salt  = enc_hdr + 1;
    const uint8_t *nonce = enc_hdr + 17;

    uint8_t key[32];
    if (zuptsdk_easy_derive_key(password, salt, key) != 0) return -1;

    extern void zupt_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);
    uint8_t kdf_buf2[32 + 16];
    memcpy(kdf_buf2, key, 32);
    memcpy(kdf_buf2 + 32, "ZUPT-SDK-ENC-KEY", 16);
    zupt_sha3_256(kdf_buf2, sizeof(kdf_buf2), kr->enc_key);
    memcpy(kdf_buf2 + 32, "ZUPT-SDK-MAC-KEY", 16);
    zupt_sha3_256(kdf_buf2, sizeof(kdf_buf2), kr->mac_key);
    zupt_secure_wipe(kdf_buf2, sizeof(kdf_buf2));

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    zupt_secure_wipe(key, 32);
    return 0;
}

#else  /* !ZUPT_WITH_SDK */

/* Baseline build without the optional system libvuptsdk. The SDK-backed modes
 * — --pq-sdk and the Argon2id default password KDF — are unavailable. These
 * stubs let the project build and link from source with no prebuilt library;
 * callers fall back to native crypto (PBKDF2-SHA256 password KDF, native
 * ML-KEM-768 + X25519 via --pq) or report the requested mode as unsupported.
 * Rebuild with WITH_SDK=1 and the system development package to enable. */
#include <stdio.h>

static int sdk_unavailable(const char *what) {
    fprintf(stderr,
            "Error: this build has no libvuptsdk support, so %s is unavailable.\n"
            "       Use native crypto instead (password mode uses PBKDF2-SHA256; "
            "--pq uses ML-KEM-768 + X25519),\n"
            "       or rebuild with 'make WITH_SDK=1' and the system development package.\n", what);
    return -1;
}

int zupt_sdk_hybrid_keygen(const char *privkeyfile, const char *pubkeyfile) {
    (void)privkeyfile; (void)pubkeyfile;
    return sdk_unavailable("--pq-sdk key generation");
}
int zupt_sdk_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                                  uint8_t *enc_hdr, size_t *enc_hdr_len) {
    (void)kr; (void)pubkeyfile; (void)enc_hdr; (void)enc_hdr_len;
    return sdk_unavailable("--pq-sdk encryption");
}
int zupt_sdk_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                                  const uint8_t *enc_hdr, size_t enc_hdr_len) {
    (void)kr; (void)privkeyfile; (void)enc_hdr; (void)enc_hdr_len;
    return sdk_unavailable("--pq-sdk decryption");
}
int zupt_sdk_password_encrypt_init(zupt_keyring_t *kr, const char *password,
                                    uint8_t *enc_hdr, size_t *enc_hdr_len) {
    (void)kr; (void)password; (void)enc_hdr; (void)enc_hdr_len;
    return sdk_unavailable("the Argon2id password KDF");
}
int zupt_sdk_password_decrypt_init(zupt_keyring_t *kr, const char *password,
                                    const uint8_t *enc_hdr, size_t enc_hdr_len) {
    (void)kr; (void)password; (void)enc_hdr; (void)enc_hdr_len;
    return sdk_unavailable("the Argon2id password KDF (this archive needs it)");
}

#endif /* ZUPT_WITH_SDK */
