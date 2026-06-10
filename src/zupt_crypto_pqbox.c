/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * zupt_crypto_pqbox.c — ZUPT_ENC_PQ_BOX_V1 (0x05): hybrid PQ sealed-box
 * recipient encryption backed by vendored libpqvaptvupt (v0.6.0).
 *
 * Why a third PQ mode:
 *   - legacy --pq (0x02) combines the ML-KEM and X25519 shared secrets
 *     with XOR+SHA3 — functional, but not the modern recommendation;
 *   - --pq-sdk (0x03) is libzuptsdk's v2 envelope (kept for back-compat);
 *   - --pq-box (0x05) uses libpqvaptvupt's sealed box, which combines the
 *     two KEM secrets through HKDF-SHA256 Extract/Expand with a
 *     domain-separating info string ("pqvv-seal-v1") — the construction
 *     this project's own crypto standing orders prescribe. AES-256-CTR +
 *     HMAC-SHA256 Encrypt-then-MAC inside the box; if either KEM is
 *     broken later, the other still protects the session key.
 *
 * Envelope layout inside the ENC_HEADER block payload:
 *   [1B]  enc_type = ZUPT_ENC_PQ_BOX_V1 (0x05)
 *   [4B]  sealed_len (LE)
 *   [..]  pqvv_seal(recipient_pk, session_key[32])   — 32 + PQVV_OVERHEAD
 *
 * The 32-byte random session key is split into the archive's enc/mac keys
 * with domain-separated SHA3-256, mirroring the SDK path exactly so the
 * per-block AEAD machinery is shared and already regression-tested.
 *
 * Key files (this module owns the format; magic prevents cross-mode
 * key-type confusion at the file level):
 *   [8B]  "PQVVBOX1"
 *   [1B]  role: 'P' (public) | 'S' (secret)
 *   [..]  raw key bytes (PQVV_PUBLICKEYBYTES / PQVV_SECRETKEYBYTES)
 */
#include "zupt.h"
#include "zupt_keccak.h"
#include "pqvaptvupt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PQBOX_MAGIC     "PQVVBOX1"
#define PQBOX_MAGIC_LEN 8
#define PQBOX_HDR_LEN   (PQBOX_MAGIC_LEN + 1)
#define PQBOX_SEALED_SESSION (32u + PQVV_OVERHEAD)

static int pqbox_write_keyfile(const char *path, char role,
                               const uint8_t *key, size_t klen) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fwrite(PQBOX_MAGIC, 1, PQBOX_MAGIC_LEN, f) == PQBOX_MAGIC_LEN
          && fputc(role, f) != EOF
          && fwrite(key, 1, klen, f) == klen;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : -1;
}

/* Reads and validates a key file. Returns 0 and fills `key` on success. */
static int pqbox_read_keyfile(const char *path, char role,
                              uint8_t *key, size_t klen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t hdr[PQBOX_HDR_LEN];
    int ok = fread(hdr, 1, PQBOX_HDR_LEN, f) == PQBOX_HDR_LEN
          && memcmp(hdr, PQBOX_MAGIC, PQBOX_MAGIC_LEN) == 0
          && hdr[PQBOX_MAGIC_LEN] == (uint8_t)role
          && fread(key, 1, klen, f) == klen
          && fgetc(f) == EOF;   /* exact size — no trailing bytes */
    fclose(f);
    return ok ? 0 : -1;
}

int zupt_pqbox_keygen(const char *privkeyfile, const char *pubkeyfile) {
    uint8_t pk[PQVV_PUBLICKEYBYTES];
    uint8_t sk[PQVV_SECRETKEYBYTES];
    if (pqvv_keygen(pk, sk) != PQVV_OK) return -1;

    int rc = 0;
    if (pqbox_write_keyfile(privkeyfile, 'S', sk, sizeof(sk)) != 0) rc = -1;
    if (rc == 0 && pqbox_write_keyfile(pubkeyfile, 'P', pk, sizeof(pk)) != 0) rc = -1;
    zupt_secure_wipe(sk, sizeof(sk));
    return rc;
}

/* Encrypt-init: seal a fresh 32-byte session key to the recipient and
 * emit the ENC_HEADER payload. Mirrors zupt_sdk_hybrid_encrypt_init. */
int zupt_pqbox_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                            uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t pk[PQVV_PUBLICKEYBYTES];
    if (pqbox_read_keyfile(pubkeyfile, 'P', pk, sizeof(pk)) != 0) {
        fprintf(stderr, "Error: '%s' is not a pq-box PUBLIC key file.\n", pubkeyfile);
        return -1;
    }

    uint8_t session_key[32];
    zupt_random_bytes(session_key, 32);

    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    if (pqvv_seal(pk, session_key, 32, &sealed, &sealed_len) != PQVV_OK
        || sealed_len != PQBOX_SEALED_SESSION) {
        free(sealed);
        zupt_secure_wipe(session_key, sizeof(session_key));
        return -1;
    }

    enc_hdr[0] = ZUPT_ENC_PQ_BOX_V1;
    enc_hdr[1] = (uint8_t)(sealed_len & 0xff);
    enc_hdr[2] = (uint8_t)((sealed_len >> 8) & 0xff);
    enc_hdr[3] = (uint8_t)((sealed_len >> 16) & 0xff);
    enc_hdr[4] = (uint8_t)((sealed_len >> 24) & 0xff);
    memcpy(enc_hdr + 5, sealed, sealed_len);
    *enc_hdr_len = 5 + sealed_len;
    free(sealed);

    /* Session key → enc/mac keys, domain-separated SHA3 (identical shape
     * to the SDK path so all per-block machinery is shared). */
    uint8_t kdf_buf[32 + 16];
    memcpy(kdf_buf, session_key, 32);
    memcpy(kdf_buf + 32, "ZUPT-BOX-ENC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->enc_key);
    memcpy(kdf_buf + 32, "ZUPT-BOX-MAC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->mac_key);
    zupt_secure_wipe(kdf_buf, sizeof(kdf_buf));

    kr->canary_head = ZUPT_CANARY;
    zupt_random_bytes(kr->base_nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    zupt_secure_wipe(session_key, sizeof(session_key));
    return 0;
}

/* Decrypt-init: parse the 0x05 envelope, open with the recipient secret
 * key, rebuild the keyring. Fail-closed on any mismatch. */
int zupt_pqbox_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                            const uint8_t *payload, size_t payload_len) {
    if (payload_len < 5 || payload[0] != ZUPT_ENC_PQ_BOX_V1) return -1;
    uint32_t sealed_len = (uint32_t)payload[1]
                        | ((uint32_t)payload[2] << 8)
                        | ((uint32_t)payload[3] << 16)
                        | ((uint32_t)payload[4] << 24);
    if (sealed_len != PQBOX_SEALED_SESSION || payload_len < 5 + (size_t)sealed_len)
        return -1;

    uint8_t sk[PQVV_SECRETKEYBYTES];
    if (pqbox_read_keyfile(privkeyfile, 'S', sk, sizeof(sk)) != 0) {
        fprintf(stderr, "Error: '%s' is not a pq-box SECRET key file.\n", privkeyfile);
        return -1;
    }

    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int rc = pqvv_open(sk, payload + 5, sealed_len, &pt, &pt_len);
    zupt_secure_wipe(sk, sizeof(sk));
    if (rc != PQVV_OK || pt_len != 32 || !pt) {
        if (pt) { zupt_secure_wipe(pt, pt_len); free(pt); }
        return -1;   /* wrong key, tampered envelope — generic at call site */
    }
    uint8_t session_key[32];
    memcpy(session_key, pt, 32);
    zupt_secure_wipe(pt, pt_len);
    free(pt);

    uint8_t kdf_buf[32 + 16];
    memcpy(kdf_buf, session_key, 32);
    memcpy(kdf_buf + 32, "ZUPT-BOX-ENC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->enc_key);
    memcpy(kdf_buf + 32, "ZUPT-BOX-MAC-KEY", 16);
    zupt_sha3_256(kdf_buf, sizeof(kdf_buf), kr->mac_key);
    zupt_secure_wipe(kdf_buf, sizeof(kdf_buf));

    kr->canary_head = ZUPT_CANARY;
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    zupt_secure_wipe(session_key, sizeof(session_key));
    return 0;
}
