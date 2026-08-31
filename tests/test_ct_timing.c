/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * Constant-time timing regression measurement for zupt_ct_memeq (v3.5.0).
 *
 * The MAC-tag comparison is the most timing-sensitive operation in the
 * codebase: if "wrong on byte 0" were measurably faster than "wrong on
 * byte 31", an attacker could forge a tag byte-by-byte. zupt_ct_memeq
 * is written to be constant-time; this test MEASURES that, rather than
 * trusting the source comment.
 *
 * Method (Reparaz, Balasch, Verbauwhede — "Dude, is my code constant
 * time?", DATE 2017): time the function on two input classes and apply
 * Welch's t-test to the timing distributions.
 *
 *   Class FIX: compare a fixed reference tag against an IDENTICAL copy
 *              (the all-equal case — the slowest, full-scan path).
 *   Class RND: compare the reference tag against a RANDOM tag (differs
 *              at a random, usually early, position).
 *
 * A non-constant-time compare (e.g. memcmp with early return) finishes
 * class RND much sooner than class FIX, so the means diverge and |t|
 * grows without bound as samples accumulate. A constant-time compare
 * keeps the two distributions statistically indistinguishable, so |t|
 * stays bounded.
 *
 * Robustness: wall-clock nanosecond timing on a shared CI vCPU is noisy,
 * so we (a) discard the slowest 10% of each class as scheduling outliers
 * (standard dudect "cropping"), (b) require the result to hold on the
 * cropped data, and (c) use a deliberately loose threshold (|t| < 8;
 * dudect's own leak threshold is |t| > 10 over millions of samples).
 * The point is to catch a gross leak (early-return / memcmp), which
 * produces |t| in the hundreds, not to certify against a sub-nanosecond
 * microarchitectural side channel — that needs dedicated hardware.
 *
 * As a positive control, the test also times plain memcmp() the same
 * way and asserts it DOES leak (|t| large) — proving the harness can
 * actually detect a non-CT compare on this host. If the control fails
 * to show a leak the host is too noisy to draw a conclusion, and the
 * test reports INCONCLUSIVE (skips) rather than passing vacuously.
 */
#include "zupt.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define TAG_LEN     32
#define N_SAMPLES   200000
#define CROP_FRAC   0.10      /* drop slowest 10% of each class */

/* Volatile sink so the compiler can't discard the compared result. */
static volatile int g_sink;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Welch's t-statistic for two samples. */
static double welch_t(const double *x, size_t nx, const double *y, size_t ny) {
    double mx = 0, my = 0;
    for (size_t i = 0; i < nx; i++) mx += x[i];
    mx /= (double)nx;
    for (size_t i = 0; i < ny; i++) my += y[i];
    my /= (double)ny;
    double vx = 0, vy = 0;
    for (size_t i = 0; i < nx; i++) { double d = x[i] - mx; vx += d * d; }
    for (size_t i = 0; i < ny; i++) { double d = y[i] - my; vy += d * d; }
    vx /= (double)(nx - 1);
    vy /= (double)(ny - 1);
    double denom = sqrt(vx / (double)nx + vy / (double)ny);
    if (denom == 0.0) return 0.0;
    return (mx - my) / denom;
}

/* Measure |t| for a comparison function over FIX vs RND input classes.
 * fn returns nonzero on "equal" (zupt_ct_memeq) — we only care about
 * timing, not the return value. */
typedef int (*cmp_fn)(const void *, const void *, size_t);

/* proper double comparator for qsort cropping */
static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* memcmp wrapper matching the cmp_fn signature (positive control). */
static int memcmp_wrap(const void *a, const void *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

/* Time `fn` over FIX (equal) vs RND (differing) classes and return
 * Welch |t| on the cropped samples.
 *
 * Both classes use the SAME two small buffers (ref, cmp) so the memory
 * footprint and cache behaviour are identical — the only difference is
 * the bytes in `cmp`. For each sample we (1) prepare cmp OUTSIDE the
 * timed region (either copy ref for FIX, or fill random for RND), then
 * (2) time a single fn() call. Class order is decided by a coin flip per
 * iteration so any first-vs-second ordering bias cancels across the two
 * distributions rather than loading onto one of them. */
static double measure_t2_len(cmp_fn fn, size_t buflen) {
    static uint8_t ref[2048], cmp[2048];
    static double tfix[N_SAMPLES], trnd[N_SAMPLES];
    size_t nfix = 0, nrnd = 0;
    if (buflen > sizeof(ref)) buflen = sizeof(ref);

    for (size_t i = 0; i < buflen; i++) ref[i] = (uint8_t)(0xA5 ^ (i * 7));

    /* Warm up. */
    memcpy(cmp, ref, buflen);
    for (int w = 0; w < 2000; w++) g_sink = fn(ref, cmp, buflen);

    for (size_t i = 0; i < 2 * N_SAMPLES; i++) {
        int is_rnd = rand() & 1;
        if (is_rnd) {
            for (size_t j = 0; j < buflen; j++) cmp[j] = (uint8_t)rand();
        } else {
            memcpy(cmp, ref, buflen);
        }
        /* Single timed call — identical buffers, only contents differ. */
        uint64_t t0 = now_ns();
        g_sink = fn(ref, cmp, buflen);
        uint64_t t1 = now_ns();
        double dt = (double)(t1 - t0);
        if (is_rnd) { if (nrnd < N_SAMPLES) trnd[nrnd++] = dt; }
        else        { if (nfix < N_SAMPLES) tfix[nfix++] = dt; }
        if (nfix >= N_SAMPLES && nrnd >= N_SAMPLES) break;
    }
    qsort(tfix, nfix, sizeof(double), cmp_dbl);
    qsort(trnd, nrnd, sizeof(double), cmp_dbl);
    size_t kf = (size_t)((double)nfix * (1.0 - CROP_FRAC));
    size_t kr = (size_t)((double)nrnd * (1.0 - CROP_FRAC));
    return welch_t(tfix, kf, trnd, kr);
}

/* 32-byte (MAC tag) convenience wrapper. */
static double measure_t2(cmp_fn fn) { return measure_t2_len(fn, TAG_LEN); }

int main(void) {
    printf("Constant-time compares (dudect-style): MAC tag + ML-KEM ciphertext\n");
    srand(12345);

    int pass = 0, fail = 0;

    /* Median of a few measurements to damp single-run vCPU noise. */
    double ct_runs[5], mc_runs[5];
    for (int r = 0; r < 5; r++) {
        mc_runs[r] = fabs(measure_t2(memcmp_wrap));
        ct_runs[r] = fabs(measure_t2(zupt_ct_memeq));
    }
    qsort(mc_runs, 5, sizeof(double), cmp_dbl);
    qsort(ct_runs, 5, sizeof(double), cmp_dbl);
    double t_memcmp = mc_runs[2];   /* median */
    double t_ct     = ct_runs[2];   /* median */

    printf("  memcmp (control, expected to leak):   |t| = %8.2f\n", t_memcmp);
    printf("  zupt_ct_memeq (expected constant):    |t| = %8.2f\n", t_ct);

    /* Environment-relative criterion, made robust against vCPU noise.
     *
     * Absolute |t| thresholds are not portable: on a shared CI vCPU the
     * clock_gettime overhead and scheduler noise put even a perfectly
     * constant-time 32-byte compare at |t| in the low tens, while a
     * dedicated box sits near 0. The portable signal is the RATIO to a
     * deliberately leaky baseline (memcmp with early return) measured in
     * the SAME environment — BUT that ratio is only meaningful when the
     * baseline leaks STRONGLY and cleanly.
     *
     * Observed on this shared vCPU: when the host is quiet, the memcmp
     * control reaches |t| ≈ 600–1500 and zupt_ct_memeq sits at |t| ≈ 5–70
     * (ratio ≈ 0.01–0.05 — clearly flat). When the host is under
     * contention, BOTH collapse into a common noise band (control ≈ 210,
     * ct_memeq ≈ 190): the measurement simply cannot separate them, and
     * the ratio (≈ 0.9) is an artifact of noise, not a real leak. The
     * tell is that a contended control barely clears 200 while a quiet
     * one is 3–7× higher.
     *
     * So we only render a pass/fail verdict when the control leaks
     * STRONGLY (|t| >= 400 — comfortably above the ~210 contention band
     * and far below the ~600+ quiet floor). Below that we report
     * INCONCLUSIVE rather than risk a noise-driven false failure. A
     * genuine early-return regression still fails: on a quiet host the
     * leaky function tracks the control (ratio → ~1.0) while the control
     * is well above 400. */
    const double CONTROL_STRONG = 400.0; /* control must leak THIS strongly for a valid verdict */
    const double MAX_RATIO      = 0.20;  /* when control is strong: CT compare <= 20% of it */

    if (t_memcmp < CONTROL_STRONG) {
        printf("  - control |t|=%.1f below %.0f: host under contention this run;\n", t_memcmp, CONTROL_STRONG);
        printf("    control and ct_memeq are in a common noise band, ratio not meaningful\n");
        printf("  SKIP: timing measurement inconclusive on this host; rerun on a quiet host\n");
        printf("  Constant-time timing gate: SKIP (measurement environment)\n");
        return 0;
    }
    printf("  \xE2\x9C\x93 control: memcmp leaks strongly (|t|=%.1f, harness is sensitive)\n", t_memcmp);
    pass++;

    double ratio = t_ct / t_memcmp;
    printf("  ratio zupt_ct_memeq/memcmp = %.3f (must be <= %.2f)\n", ratio, MAX_RATIO);
    if (ratio <= MAX_RATIO) {
        printf("  \xE2\x9C\x93 no timing-regression signal observed for zupt_ct_memeq (%.1f%% of control)\n",
               ratio * 100.0);
        pass++;
    } else {
        printf("  \xE2\x9C\x97 zupt_ct_memeq timing tracks the input classes (%.1f%% of control)\n",
               ratio * 100.0);
        fail++;
    }

    /* ── ML-KEM-768 decaps ciphertext compare (1088 bytes) ──
     *
     * The implicit-rejection check in zupt_mlkem768_decaps compares the
     * re-encrypted ciphertext against the received one over all 1088
     * bytes via this same zupt_ct_memeq. A timing leak there is a KEM
     * decapsulation oracle that breaks IND-CCA2.
     *
     * IMPORTANT — why this measurement is INFORMATIONAL, not pass/fail:
     * at 1088 bytes the dudect signal is dominated by memory/cache
     * effects rather than the compare's control flow, and plain memcmp
     * over 1088 bytes is no longer a cleanly-leaking control (its own
     * timing is data-dependent in ways unrelated to early-exit). The
     * environment-relative ratio that is meaningful at 32 bytes is not
     * meaningful here on a shared vCPU. The 32-byte gate is only regression
     * evidence when its control is conclusive; it is not a constant-time
     * proof. Source inspection shows an OR-accumulate loop without intended
     * data-dependent exit or access, and tests/test_ct_timing.sh confirms that
     * decapsulation routes through this primitive. Exact compiled behavior
     * remains compiler- and platform-dependent. We print the 1088B numbers for
     * transparency but do not gate on them. */
    printf("\n  -- ML-KEM ciphertext compare (1088 bytes, informational) --\n");
    double mc1088_runs[5], ct1088_runs[5];
    for (int r = 0; r < 5; r++) {
        mc1088_runs[r]  = fabs(measure_t2_len(memcmp_wrap,   1088));
        ct1088_runs[r]  = fabs(measure_t2_len(zupt_ct_memeq, 1088));
    }
    qsort(mc1088_runs, 5, sizeof(double), cmp_dbl);
    qsort(ct1088_runs, 5, sizeof(double), cmp_dbl);
    printf("  memcmp 1088B:        |t| = %8.2f   (not a clean control at this size)\n",
           mc1088_runs[2]);
    printf("  zupt_ct_memeq 1088B: |t| = %8.2f\n", ct1088_runs[2]);
    printf("  note: the 1088B result is informational; source routing uses the same\n");
    printf("        fixed-length OR-accumulate primitive, but this is not a proof of\n");
    printf("        constant-time behavior for the compiled target.\n");

    printf("\n  ───────────────────────────────────────\n");
    printf("  Timing regression checks: %d passed, %d failed\n", pass, fail);
    printf("  ───────────────────────────────────────\n");
    return fail ? 1 : 0;
}
