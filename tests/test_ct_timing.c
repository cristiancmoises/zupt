/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * Fixed/equal versus random/differing timing regression for zupt_ct_memeq.
 * Each bounded batch contains balanced, shuffled records. All comparators
 * reuse those records and the same copy path; no class-dependent generation
 * occurs immediately before the timed call. Comparator order rotates across
 * batches and runs. Both raw and independently 10%-cropped statistics are
 * reported; the existing cropped-median gate remains 400.0 / 0.20.
 *
 * Calibration uses a deliberately early-exiting volatile-byte scan; libc
 * memcmp is diagnostic only. The label-only negative control always compares
 * equal bytes. These roles are fixed before collecting any measurements.
 * Invalid/weak controls or label-only separation are INCONCLUSIVE, not PASS.
 * This is a regression measurement, not a constant-time proof.
 */
#include "zupt.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define TAG_LEN       32
#define N_SAMPLES     200000
#define CROP_FRAC     0.10
#define BATCH_SAMPLES 256
#define MAX_LEN       2048
#define N_RUNS        5

enum {
    CASE_MEMCMP,
    CASE_TARGET,
    CASE_LABEL_ONLY,
    CASE_EARLY_EXIT,
    N_CASES
};

static const double CONTROL_STRONG = 400.0;
static const double MAX_RATIO = 0.20;
static volatile int g_sink;

typedef int (*cmp_fn)(const void *, const void *, size_t);

struct timing_record {
    uint8_t bytes[MAX_LEN];
    unsigned random_class;
};

struct timing_stats {
    double raw_t, cropped_t;
};

static int now_ns(uint64_t *out) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    *out = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    return 0;
}

static int moments(const double *x, size_t n, double *mean, double *variance) {
    if (n < 2) return -1;
    *mean = 0.0;
    for (size_t i = 0; i < n; i++) {
        if (!isfinite(x[i])) return -1;
        *mean += x[i];
    }
    *mean /= (double)n;
    *variance = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = x[i] - *mean;
        *variance += d * d;
    }
    *variance /= (double)(n - 1);
    return isfinite(*mean) && isfinite(*variance) ? 0 : -1;
}

static double welch_t(const double *x, size_t nx, const double *y, size_t ny) {
    double mx, my, vx, vy;
    if (moments(x, nx, &mx, &vx) != 0 || moments(y, ny, &my, &vy) != 0)
        return NAN;
    double denom = sqrt(vx / (double)nx + vy / (double)ny);
    if (denom == 0.0)
        return mx == my ? 0.0 : copysign(INFINITY, mx - my);
    return (mx - my) / denom;
}

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    /* Verdicts reject invalid gated statistics after median calculation;
     * diagnostic NaNs still need a consistent qsort ordering. */
    if (isnan(x)) return isnan(y) ? 0 : 1;
    if (isnan(y)) return -1;
    return (x > y) - (x < y);
}

static int memcmp_wrap(const void *a, const void *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

/* A label-only negative control: the measured inputs never depend on label.
 * It still receives the same prepared buffers and invokes the real primitive. */
static int label_only_wrap(const void *a, const void *b, size_t n) {
    (void)b;
    return zupt_ct_memeq(a, a, n);
}

/* Positive control with an intentionally observable early exit. */
static int early_exit_wrap(const void *a, const void *b, size_t n) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    for (size_t i = 0; i < n; i++)
        if (pa[i] != pb[i]) return 0;
    return 1;
}

static int make_batch(struct timing_record *records, size_t count,
                      const uint8_t *ref, size_t buflen) {
    if (count == 0 || count > BATCH_SAMPLES || (count & 1u) ||
        buflen == 0 || buflen > MAX_LEN)
        return -1;
    for (size_t i = 0; i < count; i++) {
        records[i].random_class = (unsigned)(i & 1u);
        /* Generation is completed for the entire batch before measurement. */
        for (size_t j = 0; j < buflen; j++)
            records[i].bytes[j] = (uint8_t)rand();
        if (!records[i].random_class)
            memcpy(records[i].bytes, ref, buflen);
        else if (memcmp(records[i].bytes, ref, buflen) == 0)
            records[i].bytes[0] ^= 1u;
    }
    /* Shuffle complete records, not separate class-dependent memory banks. */
    for (size_t i = count - 1; i > 0; i--) {
        size_t j = (size_t)rand() % (i + 1);
        struct timing_record swap = records[i];
        records[i] = records[j];
        records[j] = swap;
    }
    return 0;
}

/* One label-independent copy path, also exercised by the deterministic test. */
static void prepare_input(uint8_t *cmp, const struct timing_record *record,
                          size_t buflen) {
    memcpy(cmp, record->bytes, buflen);
}

static unsigned case_at(unsigned run, size_t batch, unsigned step,
                        unsigned cases) {
    return (unsigned)(((size_t)run + batch + step) % cases);
}

static int finish_stats(double *fix, double *rnd, size_t count,
                        unsigned run, const char *name, struct timing_stats *out) {
    double fm, fv, rm, rv;
    if (moments(fix, count, &fm, &fv) || moments(rnd, count, &rm, &rv))
        return -1;
    out->raw_t = welch_t(fix, count, rnd, count);
    printf("  run %u %-12s n=%zu/%zu raw t=%+.2f mean=%.2f/%.2f var=%.2f/%.2f",
           run + 1, name, count, count, out->raw_t, fm, rm, fv, rv);
    qsort(fix, count, sizeof(double), cmp_dbl);
    qsort(rnd, count, sizeof(double), cmp_dbl);
    size_t kept = (size_t)((double)count * (1.0 - CROP_FRAC));
    if (moments(fix, kept, &fm, &fv) || moments(rnd, kept, &rm, &rv))
        return -1;
    out->cropped_t = welch_t(fix, kept, rnd, kept);
    printf("; cropped n=%zu/%zu t=%+.2f mean=%.2f/%.2f var=%.2f/%.2f\n",
           kept, kept, out->cropped_t, fm, rm, fv, rv);
    return isnan(out->raw_t) || isnan(out->cropped_t) ? -1 : 0;
}

static int measure_cases(size_t buflen, unsigned run, unsigned cases,
                         struct timing_stats out[N_CASES]) {
    static struct timing_record records[BATCH_SAMPLES];
    static double times[N_CASES][2][N_SAMPLES];
    uint8_t ref[MAX_LEN], cmp[MAX_LEN];
    size_t counts[N_CASES][2] = {{0}};
    cmp_fn functions[N_CASES] = {
        memcmp_wrap, zupt_ct_memeq, label_only_wrap, early_exit_wrap
    };
    const char *names[N_CASES] = {"memcmp", "ct_memeq", "label-only", "early-exit"};
#ifdef ZUPT_CT_TIMING_LEAKY_TARGET
    /* A test-only sensitivity fixture; the negative control stays real. */
    functions[CASE_TARGET] = early_exit_wrap;
    names[CASE_TARGET] = "leaky-target";
#endif
    if (buflen == 0 || buflen > MAX_LEN || cases == 0 || cases > N_CASES)
        return -1;
    for (size_t i = 0; i < buflen; i++) ref[i] = (uint8_t)(0xA5 ^ (i * 7));
    memcpy(cmp, ref, buflen);
    for (unsigned c = 0; c < cases; c++)
        for (unsigned w = 0; w < 2000; w++)
            g_sink = functions[c](ref, cmp, buflen);

    size_t batch = 0;
    for (size_t per_class = 0; per_class < N_SAMPLES; batch++) {
        size_t count = 2 * (N_SAMPLES - per_class);
        if (count > BATCH_SAMPLES) count = BATCH_SAMPLES;
        if (make_batch(records, count, ref, buflen) != 0) return -1;
        for (unsigned step = 0; step < cases; step++) {
            unsigned c = case_at(run, batch, step, cases);
            for (size_t i = 0; i < count; i++) {
                prepare_input(cmp, &records[i], buflen);
                uint64_t t0, t1;
                if (now_ns(&t0) != 0) return -1;
                g_sink = functions[c](ref, cmp, buflen);
                if (now_ns(&t1) != 0 || t1 < t0) return -1;
                unsigned label = records[i].random_class;
                times[c][label][counts[c][label]++] = (double)(t1 - t0);
            }
        }
        per_class += count / 2;
    }
    for (unsigned c = 0; c < cases; c++) {
        if (counts[c][0] != N_SAMPLES || counts[c][1] != N_SAMPLES ||
            finish_stats(times[c][0], times[c][1], N_SAMPLES,
                         run, names[c], &out[c]) != 0)
            return -1;
    }
    return 0;
}

/* 0: conclusive regression PASS; 1: FAIL; 2: invalid measurement;
 * 77: INCONCLUSIVE. Never normalize against infinity to fabricate a pass. */
static int timing_verdict(double control, double target, double label_only) {
    if (isnan(control) || isnan(target) || isnan(label_only) ||
        control < 0.0 || target < 0.0 || label_only < 0.0)
        return 2;
    if (!isfinite(control) || !isfinite(label_only) ||
        control < CONTROL_STRONG || label_only / control > MAX_RATIO)
        return 77;
    return target / control <= MAX_RATIO ? 0 : 1;
}

/* Call only after every matched control tuple has been validated. */
static double matched_ratio_median(double runs[N_CASES][N_RUNS]) {
    double ratios[N_RUNS];
    for (unsigned r = 0; r < N_RUNS; r++)
        ratios[r] = runs[CASE_TARGET][r] / runs[CASE_EARLY_EXIT][r];
    qsort(ratios, N_RUNS, sizeof(double), cmp_dbl);
    return ratios[N_RUNS / 2];
}

static int campaign_verdict(double runs[N_CASES][N_RUNS], double medians[N_CASES]) {
    for (unsigned c = 0; c < N_CASES; c++) {
        double sorted[N_RUNS];
        memcpy(sorted, runs[c], sizeof(sorted));
        qsort(sorted, N_RUNS, sizeof(double), cmp_dbl);
        medians[c] = sorted[N_RUNS / 2];
    }
    /* Do not assemble valid controls from unrelated runs' medians. All
     * predeclared runs must have matched valid controls; select none away. */
    int matched_controls = 0;
    for (unsigned r = 0; r < N_RUNS; r++) {
        int verdict = timing_verdict(runs[CASE_EARLY_EXIT][r],
                                     runs[CASE_TARGET][r], runs[CASE_LABEL_ONLY][r]);
        if (verdict == 2) return 2;
        if (verdict == 77) matched_controls = 77;
    }
    if (matched_controls != 0) return matched_controls;
    int median_verdict = timing_verdict(medians[CASE_EARLY_EXIT],
                                      medians[CASE_TARGET], medians[CASE_LABEL_ONLY]);
    if (median_verdict != 0) return median_verdict;
    /* Require the ratio of medians AND the matched-ratio median;
     * no favorable runs or denominator are selected to obtain a PASS. */
    return matched_ratio_median(runs) <= MAX_RATIO ? 0 : 1;
}

int main(void) {
    printf("Constant-time regression measurement: balanced common preparation\n");
    printf("  calibration=early-exit; libc=diagnostic; thresholds=400.0/0.20\n");
#ifdef ZUPT_CT_TIMING_LEAKY_TARGET
    printf("  Sensitivity fixture: deliberately early-exiting target, not zupt_ct_memeq\n");
#else
    printf("  Production target: zupt_ct_memeq\n");
#endif
    srand(12345);
    double runs[N_CASES][N_RUNS];
    for (unsigned r = 0; r < N_RUNS; r++) {
        struct timing_stats stats[N_CASES];
        if (measure_cases(TAG_LEN, r, N_CASES, stats) != 0) {
            fprintf(stderr, "Timing measurement ERROR: timer/statistics/input failure\n");
            return 2;
        }
        for (unsigned c = 0; c < N_CASES; c++)
            runs[c][r] = fabs(stats[c].cropped_t);
    }
    double medians[N_CASES];
    int verdict = campaign_verdict(runs, medians);
    printf("  cropped median |t|: memcmp=%.2f target=%.2f label-only=%.2f early-exit=%.2f\n",
           medians[CASE_MEMCMP], medians[CASE_TARGET], medians[CASE_LABEL_ONLY],
           medians[CASE_EARLY_EXIT]);
    if (isfinite(medians[CASE_EARLY_EXIT]) && medians[CASE_EARLY_EXIT] >= CONTROL_STRONG)
        printf("  t-statistic ratios to early-exit: target=%.3f label-only=%.3f; limit=%.2f\n",
               medians[CASE_TARGET] / medians[CASE_EARLY_EXIT],
               medians[CASE_LABEL_ONLY] / medians[CASE_EARLY_EXIT], MAX_RATIO);
    if (verdict == 0 || verdict == 1)
        printf("  matched-run target/control ratio median=%.3f; limit=%.2f\n",
               matched_ratio_median(runs), MAX_RATIO);
    if (verdict == 77)
        printf("  Constant-time timing gate: INCONCLUSIVE (weak/invalid controls or label-only separation)\n");
    else if (verdict == 0)
        printf("  Constant-time timing gate: PASS (no regression signal under these controls)\n");
    else if (verdict == 1)
        printf("  Constant-time timing gate: FAIL (target exceeds unchanged %.2f ratio)\n", MAX_RATIO);
    else {
        fprintf(stderr, "  Constant-time timing gate: ERROR (invalid statistic)\n");
        return 2;
    }

    /* The same selected target at the ML-KEM ciphertext length, informational
     * only. A sensitivity build keeps its deliberately leaky target here too.
     * These measurements do not certify compiled-target constant-time behavior. */
    printf("\n  -- 1088-byte comparison, informational --\n");
    for (unsigned r = 0; r < N_RUNS; r++) {
        struct timing_stats stats[N_CASES];
        if (measure_cases(1088, r, 2, stats) != 0) {
            fprintf(stderr, "Informational timing measurement ERROR\n");
            return 2;
        }
    }
    printf("  Measurements are regression evidence, not a constant-time proof.\n");
    return verdict;
}
