/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Deterministic ML-KEM-768 harness for FIPS 203 conformance testing against an
 * external reference (OpenSSL 3.5+). Uses the project's PUBLIC KEM API over raw
 * FIPS 203 byte strings (ek=1184, dk=2400, ct=1088, ss=32).
 *
 *   keygen              -> ek.bin, dk.bin   (d,z consumed from MLKEM_RAND if set)
 *   encaps <ek.bin>     -> ct.bin, ss.bin   (m consumed from MLKEM_RAND if set)
 *   decaps <dk.bin> <ct.bin> -> ss.bin
 *
 * When env MLKEM_RAND names a file, zupt_random_bytes() consumes it SEQUENTIALLY
 * (keygen reads d then z; encaps reads m), so the same FIPS 203 seed fed to a
 * reference implementation produces byte-identical ek/dk/ct/ss.
 *
 * Built by tests/test_mlkem_fips203.sh against src/zupt_mlkem.c + src/zupt_keccak.c
 * (no -DZUPT_USE_JASMIN, so the portable constant-time select is used). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "zupt_mlkem.h"

static FILE *g_rand; static int g_rand_init;
void zupt_random_bytes(uint8_t *buf, size_t len) {
    if (!g_rand_init) {
        const char *p = getenv("MLKEM_RAND");
        g_rand = fopen(p ? p : "/dev/urandom", "rb");
        g_rand_init = 1;
    }
    if (!g_rand || fread(buf, 1, len, g_rand) != len) { fprintf(stderr, "rand fail\n"); exit(2); }
}
int zupt_ct_memeq(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b; uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0 ? 1 : 0;
}
static void wr(const char *p, const uint8_t *b, size_t n) {
    FILE *f = fopen(p, "wb");
    if (!f || fwrite(b, 1, n, f) != n) { fprintf(stderr, "write %s\n", p); exit(2); } fclose(f);
}
static size_t rd(const char *p, uint8_t *b, size_t n) {
    FILE *f = fopen(p, "rb"); if (!f) { fprintf(stderr, "open %s\n", p); exit(2); }
    size_t g = fread(b, 1, n, f); fclose(f); return g;
}
int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "keygen")) {
        uint8_t ek[1184], dk[2400];
        if (zupt_mlkem768_keygen(ek, dk)) return 2;
        wr("ek.bin", ek, 1184); wr("dk.bin", dk, 2400); return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "encaps")) {
        uint8_t ek[1184], ct[1088], ss[32];
        if (rd(argv[2], ek, 1184) != 1184) return 2;
        if (zupt_mlkem768_encaps(ct, ss, ek)) return 2;
        wr("ct.bin", ct, 1088); wr("ss.bin", ss, 32); return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "decaps")) {
        uint8_t dk[2400], ct[1088], ss[32];
        if (rd(argv[2], dk, 2400) != 2400) return 2;
        if (rd(argv[3], ct, 1088) != 1088) return 2;
        if (zupt_mlkem768_decaps(ss, ct, dk)) return 2;
        wr("ss.bin", ss, 32); return 0;
    }
    fprintf(stderr, "usage: keygen | encaps <ek> | decaps <dk> <ct>\n");
    return 1;
}
