/*
 * ZUPT - LZ77 Compression Engine v2 (Zupt-LZ codec 0x0008)
 *
 * Improvements over v0.1:
 *   - 18-bit hash table (256K entries) for better match distribution
 *   - Lazy matching: try next position, emit better of the two
 *   - Longer chain search at high levels (up to 256 nodes)
 *   - Minimum match reduced from 4 to 3 for better ratio on text
 */
#include "zupt.h"
#include <string.h>
#include <stdlib.h>

#define LZ_MIN_MATCH     3
#define LZ_MAX_OFFSET    65535
#define LZ_HASH_BITS     18
#define LZ_HASH_SIZE     (1 << LZ_HASH_BITS)
#define LZ_HASH_MASK     (LZ_HASH_SIZE - 1)
#define LZ_WINDOW_SIZE   65535

static inline uint32_t lz_hash4(const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - LZ_HASH_BITS);
}

static inline size_t lz_write_extra(uint8_t *dst, size_t cap, size_t len) {
    size_t w = 0;
    while (len >= 255 && w < cap) { dst[w++] = 0xFF; len -= 255; }
    if (w < cap) dst[w++] = (uint8_t)len;
    return w;
}

static inline size_t lz_read_extra(const uint8_t *s, size_t slen, size_t *pos, size_t init) {
    size_t t = init;
    while (*pos < slen) { uint8_t b = s[(*pos)++]; t += b; if (b < 255) break; }
    return t;
}

/* Find best match at position ip */
static int32_t lz_find_match(const uint8_t *src, size_t src_len, size_t ip,
                             const int32_t *hash_table, const int32_t *chain,
                             int max_chain, int32_t *best_off) {
    if (ip + 4 > src_len) return 0;  /* lz_hash4 reads 4 bytes */
    uint32_t h = lz_hash4(src + ip);
    int32_t ref = hash_table[h];
    int32_t best_len = LZ_MIN_MATCH - 1;
    *best_off = 0;
    int count = 0;

    while (ref >= 0 && count < max_chain) {
        size_t dist = ip - (size_t)ref;
        if (dist > LZ_MAX_OFFSET || dist == 0) break;

        /* Quick check: compare last byte of current best + first bytes.
         * Bounds check: ip + best_len must be within src_len. */
        if ((size_t)best_len < src_len - ip &&
            src[ref + best_len] == src[ip + best_len] &&
            src[ref] == src[ip]) {
            int32_t mlen = 0;
            size_t max_m = src_len - ip;
            if (max_m > 65535) max_m = 65535;
            while (mlen < (int32_t)max_m && src[ref + mlen] == src[ip + mlen])
                mlen++;
            if (mlen > best_len) {
                best_len = mlen;
                *best_off = (int32_t)dist;
                if (mlen >= 256) break;
            }
        }
        size_t ci = (size_t)ref % LZ_WINDOW_SIZE;
        ref = chain[ci];
        count++;
    }
    return best_len >= LZ_MIN_MATCH ? best_len : 0;
}

static inline void lz_insert_hash(int32_t *hash_table, int32_t *chain,
                                   const uint8_t *src, size_t src_len, size_t ip) {
    if (ip + 4 <= src_len) {
        uint32_t h = lz_hash4(src + ip);
        size_t ci = ip % LZ_WINDOW_SIZE;
        chain[ci] = hash_table[h];
        hash_table[h] = (int32_t)ip;
    }
}

size_t zupt_lz_bound(size_t src_len) {
    return src_len + (src_len / 255) + 32;
}

/* ═══════════════════════════════════════════════════════════════════ */

size_t zupt_lz_compress(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, int level) {
    if (src_len == 0) return 0;
    if (level < 1) level = 1;
    if (level > 9) level = 9;

    /* Scale chain depth: level 1 -> 8, level 5 -> 64, level 9 -> 256 */
    int max_chain = 4 + (level * level * 3);
    /* Enable lazy matching at level >= 3 */
    int lazy = (level >= 3);

    int32_t *hash_table = (int32_t *)calloc(LZ_HASH_SIZE, sizeof(int32_t));
    int32_t *chain = (int32_t *)calloc(LZ_WINDOW_SIZE, sizeof(int32_t));
    if (!hash_table || !chain) { free(hash_table); free(chain); return 0; }
    memset(hash_table, 0xFF, LZ_HASH_SIZE * sizeof(int32_t));

    size_t ip = 0, op = 0, anchor = 0;

    while (ip + LZ_MIN_MATCH <= src_len) {
        int32_t off1 = 0;
        int32_t len1 = lz_find_match(src, src_len, ip, hash_table, chain, max_chain, &off1);

        if (len1 == 0) {
            lz_insert_hash(hash_table, chain, src, src_len, ip);
            ip++;
            continue;
        }

        /* Lazy matching: check next position for a better match */
        if (lazy && ip + 1 + LZ_MIN_MATCH <= src_len) {
            lz_insert_hash(hash_table, chain, src, src_len, ip);
            int32_t off2 = 0;
            int32_t len2 = lz_find_match(src, src_len, ip + 1, hash_table, chain, max_chain, &off2);
            if (len2 > len1 + 1) {
                /* Next position is better; skip current as a literal */
                ip++;
                len1 = len2;
                off1 = off2;
            }
        }

        /* Emit sequence */
        size_t lit_len = ip - anchor;
        size_t match_len = (size_t)len1;
        size_t match_extra = match_len - LZ_MIN_MATCH;

        if (op + 1 + (lit_len/255) + 1 + lit_len + 2 + (match_extra/255) + 1 > dst_cap) {
            free(hash_table); free(chain); return 0;
        }

        /* Token: high nibble = literal len, low nibble = match extra len */
        size_t tp = op++;
        uint8_t tl = (lit_len >= 15) ? 15 : (uint8_t)lit_len;
        uint8_t tm = (match_extra >= 15) ? 15 : (uint8_t)match_extra;
        dst[tp] = (tl << 4) | tm;

        if (lit_len >= 15)
            op += lz_write_extra(dst + op, dst_cap - op, lit_len - 15);
        memcpy(dst + op, src + anchor, lit_len); op += lit_len;

        dst[op++] = (uint8_t)(off1 & 0xFF);
        dst[op++] = (uint8_t)((off1 >> 8) & 0xFF);

        if (match_extra >= 15)
            op += lz_write_extra(dst + op, dst_cap - op, match_extra - 15);

        /* Update hash for all positions in the match */
        if (!lazy) lz_insert_hash(hash_table, chain, src, src_len, ip);
        size_t match_end = ip + match_len;
        ip++;
        for (; ip < match_end && ip + 4 <= src_len; ip++)
            lz_insert_hash(hash_table, chain, src, src_len, ip);
        ip = match_end;
        anchor = ip;
    }

    /* Final literals */
    {
        size_t lit_len = src_len - anchor;
        if (op + 1 + (lit_len/255) + 1 + lit_len > dst_cap) {
            free(hash_table); free(chain); return 0;
        }
        size_t tp = op++;
        uint8_t tl = (lit_len >= 15) ? 15 : (uint8_t)lit_len;
        dst[tp] = (tl << 4) | 0;
        if (lit_len >= 15)
            op += lz_write_extra(dst + op, dst_cap - op, lit_len - 15);
        memcpy(dst + op, src + anchor, lit_len); op += lit_len;
    }

    free(hash_table); free(chain);
    return op;
}

/* ═══════════════════════════════════════════════════════════════════ */

size_t zupt_lz_decompress(const uint8_t *src, size_t src_len,
                          uint8_t *dst, size_t dst_len) {
    size_t ip = 0, op = 0;

    while (ip < src_len) {
        uint8_t token = src[ip++];
        size_t lit_len = (token >> 4) & 0xF;
        size_t match_code = token & 0xF;

        if (lit_len == 15) lit_len = lz_read_extra(src, src_len, &ip, 15);

        if (lit_len > 0) {
            if (ip + lit_len > src_len || op + lit_len > dst_len) return 0;
            memcpy(dst + op, src + ip, lit_len);
            ip += lit_len; op += lit_len;
        }

        if (ip >= src_len) break;

        if (ip + 2 > src_len) return 0;
        size_t offset = (size_t)src[ip] | ((size_t)src[ip+1] << 8);
        ip += 2;
        if (offset == 0 || offset > op) return 0;

        size_t match_len = match_code + LZ_MIN_MATCH;
        if (match_code == 15)
            match_len = lz_read_extra(src, src_len, &ip, 15 + LZ_MIN_MATCH);

        if (op + match_len > dst_len) return 0;
        size_t ref = op - offset;
        for (size_t i = 0; i < match_len; i++)
            dst[op + i] = dst[ref + i];
        op += match_len;
    }
    return op;
}
