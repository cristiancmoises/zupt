/*
 * ZUPT - LZH Codec v4: High-Compression LZ77 + Canonical Huffman
 *
 * Key advances over v3:
 *   - 1MB sliding window (was 128KB) with 40 extended distance codes
 *   - Extended match lengths up to 4322 (was 258) with 7 extra length codes
 *   - Near-optimal parsing at levels 5-9 (multi-step lazy with cost heuristic)
 *   - 20-bit hash table (1M entries) with 4-byte rolling hash
 *   - RLE preprocessing for zero-heavy data (disk images, sparse files)
 *   - Huffman code-length compression (RLE of code lengths, ~100-300 bytes saved)
 *   - Level-adaptive window size, hash size, and chain depth
 *
 * Stream format:
 *   [1 byte: flags (bit0=RLE)]
 *   [4 bytes LE: RLE original size (if bit0)]
 *   [2 bytes LE: litlen symbol count]
 *   [2 bytes LE: dist symbol count]
 *   [compressed code lengths for litlen alphabet]
 *   [compressed code lengths for dist alphabet]
 *   [Huffman bitstream ... EOB]
 */
#include "zupt.h"
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * CONFIGURATION & TABLES
 * ═══════════════════════════════════════════════════════════════════ */

#define LZH_MIN_MATCH    3
#define LZH_MAX_CODELEN  15

/* Extended litlen alphabet: 0-255=literal, 256=EOB, 257-292=lengths */
#define LZH_MAX_LITLEN   293
/* Extended distance alphabet: 0-39 covering offsets up to 1MB */
#define LZH_MAX_DIST     40
/* Max match length supported by extended codes */
#define LZH_MAX_MATCH    4322

/* DEFLATE-compatible length codes 257-285 (lengths 3-258) */
static const uint16_t LEN_BASE[36] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
    67,83,99,115,131,163,195,227,258,
    /* Extended length codes 286-292 (lengths 259-4322) */
    259, 291, 355, 483, 739, 1251, 2275
};
static const uint8_t LEN_EXTRA[36] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,
    /* Extended: 5,6,7,8,9,10,11 */
    5,6,7,8,9,10,11
};
#define LEN_CODES 36

/* Extended distance codes 0-39 covering up to 1,048,576 */
static const uint32_t DIST_BASE[40] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
    1025,1537,2049,3073,4097,6145,8193,12289,16385,24577,
    /* Extended: codes 30-39 */
    32769,49153,65537,98305,131073,196609,262145,393217,524289,786433
};
static const uint8_t DIST_EXTRA[40] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,
    /* Extended */
    14,14,15,15,16,16,17,17,18,18
};

static int len_to_code(uint32_t len) {
    for (int i = LEN_CODES - 1; i >= 0; i--)
        if (len >= LEN_BASE[i]) return 257 + i;
    return 257;
}
static int dist_to_code(uint32_t d) {
    for (int i = LZH_MAX_DIST - 1; i >= 0; i--)
        if (d >= DIST_BASE[i]) return i;
    return 0;
}

/* Level-dependent configuration */
typedef struct {
    uint32_t win_size;   /* Sliding window */
    int      hash_bits;  /* Hash table size = 1 << hash_bits */
    int      max_chain;  /* Max chain search depth */
    int      lazy_depth; /* 0=greedy, 1=lazy, 2+=near-optimal */
    int      min_match;  /* Minimum match length */
} lzh_config_t;

static lzh_config_t lzh_config(int level) {
    lzh_config_t c;
    /* Always use 20-bit hash (4MB table) for correctness and quality.
     * Scale window size and chain depth by level for speed control. */
    switch (level) {
        case 1: c = (lzh_config_t){  65536, 20,  12, 0, 4}; break;
        case 2: c = (lzh_config_t){ 131072, 20,  24, 1, 4}; break;
        case 3: c = (lzh_config_t){ 131072, 20,  48, 1, 3}; break;
        case 4: c = (lzh_config_t){ 262144, 20,  96, 2, 3}; break;
        case 5: c = (lzh_config_t){ 524288, 20, 160, 2, 3}; break;
        case 6: c = (lzh_config_t){ 524288, 20, 256, 3, 3}; break; /* DEFAULT */
        case 7: c = (lzh_config_t){1048576, 20, 384, 3, 3}; break;
        case 8: c = (lzh_config_t){1048576, 20, 512, 4, 3}; break;
        case 9: c = (lzh_config_t){1048576, 20, 768, 5, 3}; break;
        default:c = (lzh_config_t){ 524288, 20, 256, 3, 3}; break;
    }
    return c;
}

/* ═══════════════════════════════════════════════════════════════════
 * RLE PREPROCESSOR (unchanged from v3)
 * ═══════════════════════════════════════════════════════════════════ */

static size_t rle_encode(const uint8_t *s, size_t n, uint8_t *d, size_t dc) {
    size_t ip=0, op=0;
    while (ip < n) {
        if (s[ip] == 0) {
            size_t run=0;
            while (ip+run < n && s[ip+run]==0 && run < 65535) run++;
            if (run == 1) {
                if (op+2>dc) return 0;
                d[op++]=0; d[op++]=0; ip++;
            } else {
                while (run > 0) {
                    size_t ch = run>255?255:run;
                    if (op+2>dc) return 0;
                    d[op++]=0; d[op++]=(uint8_t)ch;
                    ip+=ch; run-=ch;
                }
            }
        } else { if (op+1>dc) return 0; d[op++]=s[ip++]; }
    }
    return (op < n) ? op : 0;
}

static size_t rle_decode(const uint8_t *s, size_t n, uint8_t *d, size_t dc) {
    size_t ip=0, op=0;
    while (ip < n && op < dc) {
        if (s[ip]==0 && ip+1<n) {
            uint8_t c = s[ip+1]; ip+=2;
            if (c==0) { d[op++]=0; }
            else { if (op+c>dc) return 0; memset(d+op,0,c); op+=c; }
        } else { d[op++]=s[ip++]; }
    }
    return op;
}

/* ═══════════════════════════════════════════════════════════════════
 * BIT I/O
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct { uint8_t *buf; size_t cap, pos; uint64_t acc; int nb; } bitwr_t;
typedef struct { const uint8_t *buf; size_t len, pos; uint64_t acc; int nb; } bitrd_t;

static void bw_init(bitwr_t *w, uint8_t *b, size_t c) { w->buf=b;w->cap=c;w->pos=0;w->acc=0;w->nb=0; }
static void bw_put(bitwr_t *w, uint32_t v, int n) {
    w->acc |= (uint64_t)v << w->nb; w->nb += n;
    while (w->nb >= 8 && w->pos < w->cap) { w->buf[w->pos++]=(uint8_t)(w->acc&0xFF); w->acc>>=8; w->nb-=8; }
}
static void bw_flush(bitwr_t *w) {
    while (w->nb>0 && w->pos<w->cap) { w->buf[w->pos++]=(uint8_t)(w->acc&0xFF); w->acc>>=8; w->nb-=8; if(w->nb<0)w->nb=0; }
}
static void br_init(bitrd_t *r, const uint8_t *b, size_t l) { r->buf=b;r->len=l;r->pos=0;r->acc=0;r->nb=0; }
static uint32_t br_peek(bitrd_t *r, int n) {
    while (r->nb<n && r->pos<r->len) { r->acc|=(uint64_t)r->buf[r->pos++]<<r->nb; r->nb+=8; }
    return (uint32_t)(r->acc & ((1ULL<<n)-1));
}
static void br_skip(bitrd_t *r, int n) { r->acc>>=n; r->nb-=n; }
static uint32_t br_get(bitrd_t *r, int n) { uint32_t v=br_peek(r,n); br_skip(r,n); return v; }

/* ═══════════════════════════════════════════════════════════════════
 * HUFFMAN ENCODER / DECODER
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct { uint16_t code; uint8_t len; } hcode_t;
typedef struct { int16_t sym; uint8_t len; } hlut_t;

/* Min-heap for tree construction */
typedef struct { uint32_t f; int s; } hnode_t;
static void h_down(hnode_t *h, int n, int i) {
    while (1) {
        int b=i, l=2*i+1, r=2*i+2;
        if (l<n && h[l].f<h[b].f) b=l;
        if (r<n && h[r].f<h[b].f) b=r;
        if (b==i) break;
        hnode_t t=h[i]; h[i]=h[b]; h[b]=t; i=b;
    }
}
static void h_up(hnode_t *h, int i) {
    while (i>0) {
        int p=(i-1)/2;
        if (h[p].f<=h[i].f) break;
        hnode_t t=h[i]; h[i]=h[p]; h[p]=t; i=p;
    }
}

static void tree_depths(int nd, int depth, int *L, int *R, uint8_t *dp, int ns) {
    if (nd>=0 && nd<ns) { dp[nd]=(uint8_t)(depth>LZH_MAX_CODELEN?LZH_MAX_CODELEN:depth); return; }
    int x=-nd-1;
    tree_depths(L[x],depth+1,L,R,dp,ns);
    tree_depths(R[x],depth+1,L,R,dp,ns);
}

static void huff_build(const uint32_t *freq, int ns, hcode_t *codes) {
    int act=0;
    for (int i=0;i<ns;i++) if(freq[i]>0) act++;
    memset(codes,0,ns*sizeof(hcode_t));
    if (act==0) return;
    if (act==1) { for(int i=0;i<ns;i++) if(freq[i]>0){codes[i].len=1;codes[i].code=0;} return; }

    int cap=ns*2;
    int *L=(int*)calloc(cap,sizeof(int)), *R=(int*)calloc(cap,sizeof(int));
    hnode_t *hp=(hnode_t*)malloc(ns*sizeof(hnode_t));
    if(!L||!R||!hp){free(L);free(R);free(hp);return;}

    int hn=0;
    for(int i=0;i<ns;i++) if(freq[i]>0){hp[hn].f=freq[i];hp[hn].s=i;h_up(hp,hn);hn++;}

    int ni=0;
    while(hn>1){
        hnode_t a=hp[0];hp[0]=hp[--hn];if(hn>0)h_down(hp,hn,0);
        hnode_t b=hp[0];hp[0]=hp[--hn];if(hn>0)h_down(hp,hn,0);
        L[ni]=a.s; R[ni]=b.s;
        hnode_t in; in.f=a.f+b.f; in.s=-(ni+1); ni++;
        hp[hn]=in; h_up(hp,hn); hn++;
    }

    uint8_t *dp=(uint8_t*)calloc(ns,1);
    if(dp && hn==1) tree_depths(hp[0].s,0,L,R,dp,ns);

    /* Enforce max code length using Kraft-sum based redistribution.
     *
     * tree_depths() clamps depths to MAX_CODELEN silently, which can
     * over-subscribe the code (Kraft sum > 2^MAX). We detect this by
     * computing the integer Kraft sum directly, then fix by iteratively
     * splitting a shorter code into two longer ones while removing one
     * excess MAX-length code. Each iteration reduces Kraft by exactly 1. */
    {
        /* Count symbols per code length */
        int lcount[LZH_MAX_CODELEN + 1];
        memset(lcount, 0, sizeof(lcount));
        for (int i = 0; i < ns; i++)
            if (dp[i] > 0) lcount[dp[i]]++;

        /* Integer Kraft sum: symbol at length b costs 2^(MAX-b) units.
         * A valid prefix code requires sum == 2^MAX exactly. */
        uint32_t kraft = 0;
        for (int b = 1; b <= LZH_MAX_CODELEN; b++)
            kraft += (uint32_t)lcount[b] << (LZH_MAX_CODELEN - b);
        uint32_t target = 1u << LZH_MAX_CODELEN;

        if (kraft > target) {
            /* Over-subscribed. Each iteration:
             *   - Find the deepest occupied length b < MAX
             *   - Remove 1 symbol from b        (frees 2^(MAX-b) units)
             *   - Add 2 symbols at b+1           (costs 2*2^(MAX-b-1) = 2^(MAX-b) units)
             *   - Remove 1 symbol from MAX        (frees 2^0 = 1 unit)
             *   - Net: Kraft sum decreases by 1 */
            while (kraft > target) {
                /* Find deepest occupied length below MAX */
                int bits = LZH_MAX_CODELEN - 1;
                while (bits >= 1 && lcount[bits] == 0) bits--;
                if (bits < 1) break;

                lcount[bits]--;
                lcount[bits + 1] += 2;
                lcount[LZH_MAX_CODELEN]--;
                kraft--;
            }

            /* Reassign code lengths to symbols based on new counts.
             * Symbols with higher frequency get shorter codes. */
            int *sorted = (int *)malloc((size_t)ns * sizeof(int));
            if (sorted) {
                int sn = 0;
                for (int i = 0; i < ns; i++)
                    if (dp[i] > 0) sorted[sn++] = i;
                /* Insertion sort by frequency descending (ns <= 293) */
                for (int i = 1; i < sn; i++) {
                    int key = sorted[i];
                    int j = i - 1;
                    while (j >= 0 && freq[sorted[j]] < freq[key]) {
                        sorted[j + 1] = sorted[j];
                        j--;
                    }
                    sorted[j + 1] = key;
                }
                /* Assign lengths: shortest codes to most frequent symbols */
                int si = 0;
                for (int b = 1; b <= LZH_MAX_CODELEN; b++) {
                    for (int c = 0; c < lcount[b] && si < sn; c++)
                        dp[sorted[si++]] = (uint8_t)b;
                }
                free(sorted);
            }
        }
    }

    /* Canonical code assignment */
    int lc[LZH_MAX_CODELEN+1]; memset(lc,0,sizeof(lc));
    for(int i=0;i<ns;i++) if(dp[i]>0) lc[dp[i]]++;

    uint32_t nc[LZH_MAX_CODELEN+1]; memset(nc,0,sizeof(nc));
    uint32_t cv=0;
    for(int b=1;b<=LZH_MAX_CODELEN;b++){cv=(cv+lc[b-1])<<1;nc[b]=cv;}

    for(int i=0;i<ns;i++){
        if(dp[i]>0){
            codes[i].len=dp[i];
            uint16_t c=(uint16_t)nc[dp[i]]++;
            uint16_t rev=0;
            for(int b=0;b<dp[i];b++) rev|=((c>>b)&1)<<(dp[i]-1-b);
            codes[i].code=rev;
        }
    }
    free(dp);free(hp);free(L);free(R);
}

/* Build LUT for fast decode */
static void huff_lut(const uint8_t *lengths, int ns, hlut_t *lut) {
    int sz = 1<<LZH_MAX_CODELEN;
    for(int i=0;i<sz;i++){lut[i].sym=-1;lut[i].len=0;}

    int lc[LZH_MAX_CODELEN+1]; memset(lc,0,sizeof(lc));
    for(int i=0;i<ns;i++) if(lengths[i]>0) lc[lengths[i]]++;
    uint32_t nc[LZH_MAX_CODELEN+1]; memset(nc,0,sizeof(nc));
    uint32_t cv=0;
    for(int b=1;b<=LZH_MAX_CODELEN;b++){cv=(cv+lc[b-1])<<1;nc[b]=cv;}

    for(int i=0;i<ns;i++){
        if(lengths[i]==0) continue;
        int bits=lengths[i];
        uint16_t c=(uint16_t)nc[bits]++;
        uint16_t rev=0;
        for(int b=0;b<bits;b++) rev|=((c>>b)&1)<<(bits-1-b);
        int fill=1<<(LZH_MAX_CODELEN-bits);
        for(int j=0;j<fill;j++){int idx=rev|(j<<bits);lut[idx].sym=(int16_t)i;lut[idx].len=(uint8_t)bits;}
    }
}

static int huff_dec(bitrd_t *r, const hlut_t *lut) {
    uint32_t bits=br_peek(r,LZH_MAX_CODELEN);
    hlut_t e=lut[bits&((1<<LZH_MAX_CODELEN)-1)];
    if(e.sym<0) return -1;
    br_skip(r,e.len);
    return e.sym;
}

/* ═══════════════════════════════════════════════════════════════════
 * CODE LENGTH COMPRESSION (RLE, like DEFLATE's CL alphabet)
 *
 * Codes:
 *   0-15: literal code length
 *   16:   repeat previous length 3-6 times (2 extra bits)
 *   17:   repeat zero 3-10 times (3 extra bits)
 *   18:   repeat zero 11-138 times (7 extra bits)
 * ═══════════════════════════════════════════════════════════════════ */

static size_t cl_encode(const uint8_t *lens, int count, uint8_t *out, size_t ocap) {
    size_t op = 0;
    int i = 0;
    while (i < count && op < ocap) {
        if (lens[i] == 0) {
            /* Count consecutive zeros */
            int run = 1;
            while (i + run < count && lens[i + run] == 0 && run < 138) run++;
            while (run > 0) {
                if (run >= 11) {
                    int r = run > 138 ? 138 : run;
                    if (op + 2 > ocap) return 0;
                    out[op++] = 18;
                    out[op++] = (uint8_t)(r - 11);
                    i += r; run -= r;
                } else if (run >= 3) {
                    int r = run > 10 ? 10 : run;
                    if (op + 2 > ocap) return 0;
                    out[op++] = 17;
                    out[op++] = (uint8_t)(r - 3);
                    i += r; run -= r;
                } else {
                    if (op + 1 > ocap) return 0;
                    out[op++] = 0;
                    i++; run--;
                }
            }
        } else {
            uint8_t v = lens[i];
            if (op + 1 > ocap) return 0;
            out[op++] = v;
            i++;
            /* Check for repeats of same value */
            int run = 0;
            while (i + run < count && lens[i + run] == v && run < 6) run++;
            while (run >= 3) {
                int r = run > 6 ? 6 : run;
                if (op + 2 > ocap) return 0;
                out[op++] = 16;
                out[op++] = (uint8_t)(r - 3);
                i += r; run -= r;
            }
            /* Emit remaining as literals */
            while (run > 0) {
                if (op + 1 > ocap) return 0;
                out[op++] = v;
                i++; run--;
            }
        }
    }
    return op;
}

static int cl_decode(const uint8_t *in, size_t ilen, uint8_t *lens, int count) {
    size_t ip = 0;
    int li = 0;
    uint8_t prev = 0;
    while (li < count && ip < ilen) {
        uint8_t c = in[ip++];
        if (c <= 15) {
            lens[li++] = c;
            prev = c;
        } else if (c == 16) {
            if (ip >= ilen) return -1;
            int reps = 3 + in[ip++];
            for (int j = 0; j < reps && li < count; j++) lens[li++] = prev;
        } else if (c == 17) {
            if (ip >= ilen) return -1;
            int reps = 3 + in[ip++];
            for (int j = 0; j < reps && li < count; j++) lens[li++] = 0;
        } else if (c == 18) {
            if (ip >= ilen) return -1;
            int reps = 11 + in[ip++];
            for (int j = 0; j < reps && li < count; j++) lens[li++] = 0;
        } else return -1;
    }
    return (int)ip;
}

/* ═══════════════════════════════════════════════════════════════════
 * LZ77 MATCH FINDER
 * ═══════════════════════════════════════════════════════════════════ */

static inline uint32_t lzh_hash(const uint8_t *p, int bits) {
    uint32_t v; memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - bits);
}

typedef struct { int32_t len; uint32_t dist; } match_t;

static match_t find_match(const uint8_t *src, size_t slen, size_t ip,
                          const int32_t *ht, const int32_t *ch,
                          int max_chain, uint32_t win, int min_m) {
    match_t m = {0, 0};
    if (ip + 4 > slen) return m;
    int best = min_m - 1;
    int cnt = 0;
    /* Primary 4-byte hash lookup */
    uint32_t h = lzh_hash(src + ip, 20);
    int32_t ref = ht[h];
    while (ref >= 0 && cnt < max_chain) {
        size_t d = ip - (size_t)ref;
        if (d > win || d == 0) break;
        /* Quick rejection: check last byte of best match first.
         * Bounds check: ip + best must be within the buffer. Since ref < ip,
         * ref + best < ip + best, so checking ip + best suffices for both. */
        if ((size_t)best < slen - ip &&
            src[ref + best] == src[ip + best] && src[ref] == src[ip] && src[ref+1] == src[ip+1]) {
            int len = 0;
            size_t mx = slen - ip;
            if (mx > LZH_MAX_MATCH) mx = LZH_MAX_MATCH;
            /* Unrolled comparison */
            while (len + 8 <= (int)mx) {
                uint64_t a, b;
                memcpy(&a, src + ref + len, 8);
                memcpy(&b, src + ip + len, 8);
                if (a != b) break;
                len += 8;
            }
            while (len < (int)mx && src[ref + len] == src[ip + len]) len++;
            if (len > best) {
                best = len; m.len = len; m.dist = (uint32_t)d;
                if (len >= LZH_MAX_MATCH) break;
                if (len >= 512 && cnt > max_chain/4) break; /* Good enough */
            }
        }
        ref = ch[(size_t)ref % win];
        cnt++;
    }
    return (m.len >= min_m) ? m : (match_t){0, 0};
}

static void insert_hash(int32_t *ht, int32_t *ch, const uint8_t *src, size_t slen,
                        size_t ip, uint32_t win) {
    if (ip + 4 <= slen) {
        uint32_t h = lzh_hash(src + ip, 20);
        ch[ip % win] = ht[h];
        ht[h] = (int32_t)ip;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * LZ77 SYMBOL STREAM
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint16_t litlen;     /* 0-255=literal, 256=EOB, 257-292=length code */
    uint16_t dist_code;  /* distance code (0-39) */
    uint32_t match_len;  /* actual match length (for extra bits) */
    uint32_t match_dist; /* actual match distance (for extra bits) */
} lzsym_t;

/* Estimate bits for a match (for near-optimal parsing) */
static inline int match_cost(int len, uint32_t dist) {
    int lc = len_to_code(len) - 257;
    int dc = dist_to_code(dist);
    /* ~10 bits for length code + extra + ~10 bits for dist code + extra */
    return 10 + LEN_EXTRA[lc] + 10 + DIST_EXTRA[dc];
}

/* ═══════════════════════════════════════════════════════════════════
 * COMPRESS
 * ═══════════════════════════════════════════════════════════════════ */

size_t zupt_lzh_bound(size_t slen) {
    return slen + (slen / 8) + 2048;
}

size_t zupt_lzh_compress(const uint8_t *src, size_t slen,
                         uint8_t *dst, size_t dcap, int level) {
    if (slen == 0) return 0;
    if (level < 1) level = 1;
    if (level > 9) level = 9;
    lzh_config_t cfg = lzh_config(level);

    /* ─── RLE preprocessing ─── */
    uint8_t *rle_buf = NULL;
    const uint8_t *lz_in = src;
    size_t lz_len = slen;
    int rle_on = 0;

    size_t zeros = 0;
    for (size_t i = 0; i < slen; i++) if (src[i] == 0) zeros++;
    if (zeros > slen / 8) {
        rle_buf = (uint8_t *)malloc(slen);
        if (rle_buf) {
            size_t rs = rle_encode(src, slen, rle_buf, slen);
            if (rs > 0 && rs < slen * 9 / 10) { /* Must save >= 10% */
                lz_in = rle_buf; lz_len = rs; rle_on = 1;
            }
        }
    }

    /* ─── LZ77 parsing ─── */
    size_t ht_size = (size_t)1 << cfg.hash_bits;
    int32_t *ht = (int32_t *)malloc(ht_size * sizeof(int32_t));
    int32_t *ch = (int32_t *)calloc(cfg.win_size, sizeof(int32_t));
    size_t sym_cap = lz_len + 16;
    lzsym_t *syms = (lzsym_t *)malloc(sym_cap * sizeof(lzsym_t));
    if (!ht || !ch || !syms) { free(ht); free(ch); free(syms); free(rle_buf); return 0; }
    memset(ht, 0xFF, ht_size * sizeof(int32_t));

    size_t ns = 0, ip = 0;

    while (ip < lz_len) {
        match_t m1 = find_match(lz_in, lz_len, ip, ht, ch, cfg.max_chain, cfg.win_size, cfg.min_match);

        if (m1.len == 0) {
            syms[ns].litlen = lz_in[ip];
            syms[ns].dist_code = 0; syms[ns].match_len = 0; syms[ns].match_dist = 0;
            ns++;
            insert_hash(ht, ch, lz_in, lz_len, ip, cfg.win_size);
            ip++;
            continue;
        }

        /* Near-optimal: try next positions for better matches */
        if (cfg.lazy_depth >= 1 && ip + 1 < lz_len) {
            insert_hash(ht, ch, lz_in, lz_len, ip, cfg.win_size);
            match_t m2 = find_match(lz_in, lz_len, ip + 1, ht, ch, cfg.max_chain, cfg.win_size, cfg.min_match);
            if (m2.len > m1.len + 1) {
                /* Position ip+1 is much better; emit literal at ip */
                syms[ns].litlen = lz_in[ip]; syms[ns].dist_code=0; syms[ns].match_len=0; syms[ns].match_dist=0;
                ns++; ip++;
                m1 = m2;
                /* Check ip+2 for even higher lazy depths */
                if (cfg.lazy_depth >= 2 && ip + 1 < lz_len) {
                    insert_hash(ht, ch, lz_in, lz_len, ip, cfg.win_size);
                    match_t m3 = find_match(lz_in, lz_len, ip + 1, ht, ch, cfg.max_chain, cfg.win_size, cfg.min_match);
                    if (m3.len > m1.len + 1) {
                        syms[ns].litlen = lz_in[ip]; syms[ns].dist_code=0; syms[ns].match_len=0; syms[ns].match_dist=0;
                        ns++; ip++;
                        m1 = m3;
                        /* Check ip+3 for lazy_depth >= 3 */
                        if (cfg.lazy_depth >= 3 && ip + 1 < lz_len) {
                            insert_hash(ht, ch, lz_in, lz_len, ip, cfg.win_size);
                            match_t m4 = find_match(lz_in, lz_len, ip + 1, ht, ch, cfg.max_chain, cfg.win_size, cfg.min_match);
                            if (m4.len > m1.len + 1) {
                                syms[ns].litlen = lz_in[ip]; syms[ns].dist_code=0; syms[ns].match_len=0; syms[ns].match_dist=0;
                                ns++; ip++;
                                m1 = m4;
                            }
                        }
                    }
                }
            }
        }

        /* Emit match */
        int lc = len_to_code(m1.len);
        syms[ns].litlen = (uint16_t)lc;
        syms[ns].dist_code = (uint16_t)dist_to_code(m1.dist);
        syms[ns].match_len = (uint32_t)m1.len;
        syms[ns].match_dist = m1.dist;
        ns++;

        /* Update hash for positions inside match */
        if (cfg.lazy_depth < 1) insert_hash(ht, ch, lz_in, lz_len, ip, cfg.win_size);
        size_t end = ip + (size_t)m1.len;
        for (size_t j = ip + 1; j < end && j + 4 <= lz_len; j++)
            insert_hash(ht, ch, lz_in, lz_len, j, cfg.win_size);
        ip = end;
    }

    /* EOB */
    syms[ns].litlen = 256; syms[ns].dist_code = 0;
    syms[ns].match_len = 0; syms[ns].match_dist = 0;
    ns++;

    free(ht); free(ch);

    /* ─── Build Huffman trees ─── */
    uint32_t ll_freq[LZH_MAX_LITLEN]; memset(ll_freq, 0, sizeof(ll_freq));
    uint32_t d_freq[LZH_MAX_DIST];    memset(d_freq, 0, sizeof(d_freq));

    for (size_t i = 0; i < ns; i++) {
        if (syms[i].litlen < LZH_MAX_LITLEN) ll_freq[syms[i].litlen]++;
        if (syms[i].litlen >= 257 && syms[i].litlen <= 292)
            d_freq[syms[i].dist_code]++;
    }

    int ll_cnt = 257;
    for (int i = LZH_MAX_LITLEN - 1; i >= 257; i--) if (ll_freq[i] > 0) { ll_cnt = i + 1; break; }
    int d_cnt = 1;
    for (int i = LZH_MAX_DIST - 1; i >= 0; i--) if (d_freq[i] > 0) { d_cnt = i + 1; break; }

    hcode_t ll_codes[LZH_MAX_LITLEN];
    hcode_t d_codes[LZH_MAX_DIST];
    huff_build(ll_freq, ll_cnt, ll_codes);
    huff_build(d_freq, d_cnt, d_codes);
    if (ll_codes[256].len == 0) { ll_codes[256].len = 1; ll_codes[256].code = 0; }

    /* ─── Write output ─── */
    size_t op = 0;

    /* Flags */
    if (op >= dcap) { free(syms); free(rle_buf); return 0; }
    dst[op++] = rle_on ? 0x01 : 0x00;

    /* RLE original size */
    if (rle_on) {
        if (op + 4 > dcap) { free(syms); free(rle_buf); return 0; }
        uint32_t rs32 = (uint32_t)slen; /* original uncompressed size before RLE */
        memcpy(dst + op, &rs32, 4); op += 4;
    }

    /* Huffman table header */
    if (op + 4 > dcap) { free(syms); free(rle_buf); return 0; }
    uint16_t llc16 = (uint16_t)ll_cnt, dc16 = (uint16_t)d_cnt;
    memcpy(dst + op, &llc16, 2); op += 2;
    memcpy(dst + op, &dc16, 2); op += 2;

    /* Compress code lengths with RLE */
    uint8_t ll_lens[LZH_MAX_LITLEN], d_lens[LZH_MAX_DIST];
    for (int i = 0; i < ll_cnt; i++) ll_lens[i] = ll_codes[i].len;
    for (int i = 0; i < d_cnt; i++) d_lens[i] = d_codes[i].len;

    uint8_t cl_buf[2048];
    size_t ll_cl = cl_encode(ll_lens, ll_cnt, cl_buf, sizeof(cl_buf));
    if (ll_cl == 0) {
        /* Fallback: raw code lengths */
        if (op + 2 + ll_cnt + d_cnt > dcap) { free(syms); free(rle_buf); return 0; }
        uint16_t raw_len = (uint16_t)ll_cnt;
        memcpy(dst + op, &raw_len, 2); op += 2;
        memcpy(dst + op, ll_lens, ll_cnt); op += ll_cnt;
    } else {
        if (op + 2 + ll_cl > dcap) { free(syms); free(rle_buf); return 0; }
        uint16_t cl16 = (uint16_t)(ll_cl | 0x8000); /* High bit = compressed */
        memcpy(dst + op, &cl16, 2); op += 2;
        memcpy(dst + op, cl_buf, ll_cl); op += ll_cl;
    }

    size_t d_cl = cl_encode(d_lens, d_cnt, cl_buf, sizeof(cl_buf));
    if (d_cl == 0) {
        if (op + 2 + d_cnt > dcap) { free(syms); free(rle_buf); return 0; }
        uint16_t raw_len = (uint16_t)d_cnt;
        memcpy(dst + op, &raw_len, 2); op += 2;
        memcpy(dst + op, d_lens, d_cnt); op += d_cnt;
    } else {
        if (op + 2 + d_cl > dcap) { free(syms); free(rle_buf); return 0; }
        uint16_t cl16 = (uint16_t)(d_cl | 0x8000);
        memcpy(dst + op, &cl16, 2); op += 2;
        memcpy(dst + op, cl_buf, d_cl); op += d_cl;
    }

    /* ─── Huffman bitstream ─── */
    bitwr_t bw;
    bw_init(&bw, dst + op, dcap - op);

    for (size_t i = 0; i < ns; i++) {
        uint16_t s = syms[i].litlen;
        if (s < (uint16_t)ll_cnt && ll_codes[s].len > 0)
            bw_put(&bw, ll_codes[s].code, ll_codes[s].len);

        if (s >= 257 && s <= 292) {
            int li = s - 257;
            if (li < LEN_CODES && LEN_EXTRA[li] > 0)
                bw_put(&bw, syms[i].match_len - LEN_BASE[li], LEN_EXTRA[li]);
            int dc = syms[i].dist_code;
            if (dc < d_cnt && d_codes[dc].len > 0)
                bw_put(&bw, d_codes[dc].code, d_codes[dc].len);
            if (dc < LZH_MAX_DIST && DIST_EXTRA[dc] > 0)
                bw_put(&bw, syms[i].match_dist - DIST_BASE[dc], DIST_EXTRA[dc]);
        }
    }
    bw_flush(&bw);
    op += bw.pos;

    free(syms); free(rle_buf);
    return (op < slen) ? op : 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * DECOMPRESS
 * ═══════════════════════════════════════════════════════════════════ */

size_t zupt_lzh_decompress(const uint8_t *src, size_t slen,
                           uint8_t *dst, size_t dlen) {
    if (slen < 5) return 0;
    size_t ip = 0;

    uint8_t flags = src[ip++];
    int rle_on = (flags & 0x01);
    uint32_t rle_orig = 0;
    if (rle_on) {
        if (ip + 4 > slen) return 0;
        memcpy(&rle_orig, src + ip, 4); ip += 4;
    }

    /* Read Huffman table header */
    if (ip + 4 > slen) return 0;
    uint16_t ll_cnt, d_cnt;
    memcpy(&ll_cnt, src + ip, 2); ip += 2;
    memcpy(&d_cnt, src + ip, 2); ip += 2;
    if (ll_cnt > LZH_MAX_LITLEN || d_cnt > LZH_MAX_DIST) return 0;

    uint8_t ll_lens[LZH_MAX_LITLEN]; memset(ll_lens, 0, sizeof(ll_lens));
    uint8_t d_lens[LZH_MAX_DIST]; memset(d_lens, 0, sizeof(d_lens));

    /* Read litlen code lengths */
    if (ip + 2 > slen) return 0;
    uint16_t ll_hdr; memcpy(&ll_hdr, src + ip, 2); ip += 2;
    if (ll_hdr & 0x8000) {
        /* Compressed code lengths */
        size_t cl_len = ll_hdr & 0x7FFF;
        if (ip + cl_len > slen) return 0;
        int used = cl_decode(src + ip, cl_len, ll_lens, ll_cnt);
        if (used < 0) return 0;
        ip += cl_len;
    } else {
        /* Raw code lengths */
        if (ip + ll_hdr > slen) return 0;
        memcpy(ll_lens, src + ip, ll_hdr); ip += ll_hdr;
    }

    /* Read dist code lengths */
    if (ip + 2 > slen) return 0;
    uint16_t d_hdr; memcpy(&d_hdr, src + ip, 2); ip += 2;
    if (d_hdr & 0x8000) {
        size_t cl_len = d_hdr & 0x7FFF;
        if (ip + cl_len > slen) return 0;
        int used = cl_decode(src + ip, cl_len, d_lens, d_cnt);
        if (used < 0) return 0;
        ip += cl_len;
    } else {
        if (ip + d_hdr > slen) return 0;
        memcpy(d_lens, src + ip, d_hdr); ip += d_hdr;
    }

    /* Build LUTs */
    size_t lut_sz = (size_t)(1 << LZH_MAX_CODELEN) * sizeof(hlut_t);
    hlut_t *ll_lut = (hlut_t *)malloc(lut_sz);
    hlut_t *d_lut  = (hlut_t *)malloc(lut_sz);
    if (!ll_lut || !d_lut) { free(ll_lut); free(d_lut); return 0; }
    huff_lut(ll_lens, ll_cnt, ll_lut);
    huff_lut(d_lens, d_cnt, d_lut);

    /* Decode */
    bitrd_t br;
    br_init(&br, src + ip, slen - ip);

    uint8_t *out_buf; size_t out_cap;
    uint8_t *rle_tmp = NULL;
    if (rle_on) {
        out_cap = dlen;
        rle_tmp = (uint8_t *)malloc(out_cap);
        if (!rle_tmp) { free(ll_lut); free(d_lut); return 0; }
        out_buf = rle_tmp;
    } else {
        out_buf = dst; out_cap = dlen;
    }

    size_t op = 0;
    while (1) {
        int sym = huff_dec(&br, ll_lut);
        if (sym < 0 || sym >= LZH_MAX_LITLEN) break;

        if (sym < 256) {
            if (op >= out_cap) break;
            out_buf[op++] = (uint8_t)sym;
        } else if (sym == 256) {
            break; /* EOB */
        } else {
            int li = sym - 257;
            if (li >= LEN_CODES) break;
            uint32_t length = LEN_BASE[li];
            if (LEN_EXTRA[li] > 0) length += br_get(&br, LEN_EXTRA[li]);

            int dsym = huff_dec(&br, d_lut);
            if (dsym < 0 || dsym >= LZH_MAX_DIST) break;
            uint32_t distance = DIST_BASE[dsym];
            if (DIST_EXTRA[dsym] > 0) distance += br_get(&br, DIST_EXTRA[dsym]);

            if (distance == 0 || distance > op || op + length > out_cap) break;
            size_t ref = op - distance;
            /* Byte-by-byte for overlapping copies */
            for (uint32_t j = 0; j < length; j++)
                out_buf[op + j] = out_buf[ref + j];
            op += length;
        }
    }

    free(ll_lut); free(d_lut);

    if (rle_on) {
        size_t final = rle_decode(rle_tmp, op, dst, dlen);
        free(rle_tmp);
        return final;
    }
    return op;
}
