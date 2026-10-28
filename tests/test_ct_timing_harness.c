/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exercise the actual timing helpers, not a duplicated statistics algorithm.
 * Unequal constant distributions must not be reported as zero timing signal.
 */
#include <stdlib.h>
#include <time.h>
static unsigned long random_calls;
static int clock_failure;
static int counted_rand(void);
static int checked_clock(clockid_t clock_id, struct timespec *ts);
int timing_main(void);
#define rand counted_rand
#define clock_gettime checked_clock
#define main timing_main
#include "test_ct_timing.c"
#undef main
#undef clock_gettime
#undef rand

static int counted_rand(void) {
    random_calls++;
    return rand();
}

static int checked_clock(clockid_t clock_id, struct timespec *ts) {
    return clock_failure ? -1 : clock_gettime(clock_id, ts);
}

int main(void) {
    /* NaN diagnostic rows still pass through qsort before verdict checks.
     * They must not compare equal to every finite or infinite value. */
    double sortable[] = { NAN, INFINITY, -INFINITY, 0.0, 1.0, NAN };
    double zero = 0.0, nan = NAN;
    if (cmp_dbl(&nan, &zero) <= 0 || cmp_dbl(&zero, &nan) >= 0 ||
        cmp_dbl(&nan, &nan) != 0) {
        fprintf(stderr, "FAIL: NaN must have a consistent position in the statistics ordering\n");
        return 1;
    }
    qsort(sortable, sizeof(sortable) / sizeof(sortable[0]), sizeof(double), cmp_dbl);
    if (sortable[0] != -INFINITY || sortable[1] != 0.0 || sortable[2] != 1.0 ||
        sortable[3] != INFINITY || !isnan(sortable[4]) || !isnan(sortable[5])) {
        fprintf(stderr, "FAIL: sorting statistics must keep numbers ordered before NaN\n");
        return 1;
    }
    const double equal[] = { 5.0, 5.0, 5.0, 5.0 };
    const double later[] = { 9.0, 9.0, 9.0, 9.0 };
    const double varied_a[] = { 1.0, 2.0, 3.0 };
    const double varied_b[] = { 4.0, 5.0, 6.0 };
    double separated = welch_t(equal, 4, later, 4);
    if (!isinf(separated) || separated >= 0.0 ||
        !isinf(welch_t(later, 4, equal, 4)) || welch_t(later, 4, equal, 4) <= 0.0) {
        fprintf(stderr, "FAIL: unequal zero-variance classes must retain their signal (t=%g)\n", separated);
        return 1;
    }
    double ordinary = welch_t(varied_a, 3, varied_b, 3);
    if (welch_t(equal, 4, equal, 4) != 0.0 || !isfinite(ordinary) ||
        fabs(ordinary + 3.6742346141747673) > 1e-12) {
        fprintf(stderr, "FAIL: equal or ordinary Welch statistic is incorrect\n");
        return 1;
    }
    const double invalid[] = { NAN, 1.0, 2.0 };
    if (!isnan(welch_t(equal, 1, later, 4)) ||
        !isnan(welch_t(invalid, 3, varied_b, 3))) {
        fprintf(stderr, "FAIL: invalid samples must not become zero signal\n");
        return 1;
    }
    uint64_t timestamp = 123;
    clock_failure = 1;
    if (now_ns(&timestamp) == 0 || timestamp != 123) {
        fprintf(stderr, "FAIL: timer failure must be propagated\n");
        return 1;
    }
    clock_failure = 0;
    if (now_ns(&timestamp) != 0) return 1;

    static struct timing_record records[BATCH_SAMPLES];
    uint8_t ref[MAX_LEN], prepared[MAX_LEN], again[MAX_LEN];
    for (size_t i = 0; i < sizeof(ref); i++) ref[i] = (uint8_t)(0xA5 ^ (i * 7));
    const size_t lengths[] = { 32, 1088, MAX_LEN };
    const size_t batches[] = { 2, 128, BATCH_SAMPLES };
    srand(12345);
    for (size_t l = 0; l < sizeof(lengths) / sizeof(lengths[0]); l++) {
        for (size_t b = 0; b < sizeof(batches) / sizeof(batches[0]); b++) {
            size_t count = batches[b], len = lengths[l], labels[2] = {0, 0};
            if (make_batch(records, count, ref, len) != 0) return 1;
            for (size_t i = 0; i < count; i++) {
                unsigned label = records[i].random_class;
                if (label > 1 || (memcmp(ref, records[i].bytes, len) != 0) != (int)label) {
                    fprintf(stderr, "FAIL: shuffled records must preserve class/input pairing\n");
                    return 1;
                }
                labels[label]++;
                unsigned long before = random_calls;
                prepare_input(prepared, &records[i], len);
                records[i].random_class ^= 1u;
                prepare_input(again, &records[i], len);
                records[i].random_class ^= 1u;
                if (before != random_calls || memcmp(prepared, again, len) != 0 ||
                    memcmp(prepared, records[i].bytes, len) != 0) {
                    fprintf(stderr, "FAIL: immediate preparation must be RNG-free and label-independent\n");
                    return 1;
                }
                if (label_only_wrap(ref, prepared, len) != 1 ||
                    early_exit_wrap(ref, prepared, len) != !label) {
                    fprintf(stderr, "FAIL: negative/early-exit control inputs are incorrect\n");
                    return 1;
                }
            }
            if (labels[0] != count / 2 || labels[1] != count / 2) {
                fprintf(stderr, "FAIL: final partial batches must remain balanced\n");
                return 1;
            }
        }
    }
    if (make_batch(records, 0, ref, 32) == 0 ||
        make_batch(records, 3, ref, 32) == 0 ||
        make_batch(records, BATCH_SAMPLES + 2, ref, 32) == 0 ||
        make_batch(records, 2, ref, MAX_LEN + 1) == 0) {
        fprintf(stderr, "FAIL: invalid batches must be rejected\n");
        return 1;
    }
    for (unsigned cases = 2; cases <= N_CASES; cases += 2) {
        unsigned first[N_CASES] = {0};
        for (unsigned batch = 0; batch < cases; batch++) {
            unsigned seen[N_CASES] = {0};
            first[case_at(0, batch, 0, cases)]++;
            for (unsigned step = 0; step < cases; step++)
                seen[case_at(0, batch, step, cases)]++;
            for (unsigned c = 0; c < cases; c++)
                if (seen[c] != 1) return 1;
        }
        for (unsigned c = 0; c < cases; c++)
            if (first[c] != 1) {
                fprintf(stderr, "FAIL: comparator order must be counterbalanced\n");
                return 1;
            }
    }
    /* A vectorized libc comparison need not separate these classes. The
     * deliberate early-exit control, not libc, calibrates the target. */
    double calibrated[N_CASES][N_RUNS] = {
        {   1,   1,   1,   1,   1 },
        { 100, 100, 100, 100, 100 },
        {   0,   0,   0,   0,   0 },
        { 500, 500, 500, 500, 500 }
    };
    double calibrated_medians[N_CASES];
    if (campaign_verdict(calibrated, calibrated_medians) != 0) {
        fprintf(stderr, "FAIL: weak diagnostic libc must not invalidate a strong early-exit calibration\n");
        return 1;
    }
    double weak_calibration[N_CASES][N_RUNS] = {
        { 500, 500, 500, 500, 500 },
        { 100, 100, 100, 100, 100 },
        {   0,   0,   0,   0,   0 },
        { 399.99, 500, 500, 500, 500 }
    };
    if (campaign_verdict(weak_calibration, calibrated_medians) != 77) {
        fprintf(stderr, "FAIL: strong diagnostic libc must not replace a weak matched calibration\n");
        return 1;
    }
    double leaky_target[N_CASES][N_RUNS] = {
        {   1,   1,   1,   1,   1 },
        { 500, 500, 500, 500, 500 },
        {   0,   0,   0,   0,   0 },
        { 500, 500, 500, 500, 500 }
    };
    if (campaign_verdict(leaky_target, calibrated_medians) != 1) {
        fprintf(stderr, "FAIL: a target matching the deliberate leak must fail calibration\n");
        return 1;
    }
    const struct {
        double control, target, label_only;
        int expected;
    } verdicts[] = {
        { 443.04, 177.13, 0.0, 1 }, /* Original failure's ratio still fails. */
        { 500.0, 100.0, 0.0, 0 },
        { 500.0, 100.0001, 0.0, 1 },
        { 399.99, 0.0, 0.0, 77 },
        { 400.0, 80.0, 80.0, 0 },
        { 500.0, 0.0, 100.0001, 77 },
        { 0.0, 0.0, 0.0, 77 },
        { INFINITY, 0.0, 0.0, 77 },
        { 500.0, INFINITY, 0.0, 1 },
        { 500.0, 0.0, INFINITY, 77 },
        { NAN, 0.0, 0.0, 2 },
        { 500.0, NAN, 0.0, 2 },
        { 500.0, 0.0, NAN, 2 },
        { -1.0, 0.0, 0.0, 2 },
        { 500.0, -1.0, 0.0, 2 },
        { 500.0, 0.0, -1.0, 2 }
    };
    for (size_t i = 0; i < sizeof(verdicts) / sizeof(verdicts[0]); i++) {
        int actual = timing_verdict(verdicts[i].control, verdicts[i].target,
                                   verdicts[i].label_only);
        if (actual != verdicts[i].expected) {
            fprintf(stderr, "FAIL: verdict case %zu expected %d, got %d\n",
                    i, verdicts[i].expected, actual);
            return 1;
        }
    }
    double unmatched[N_CASES][N_RUNS] = {
        {   1,   1,   1,   1,   1 },
        {   0,   0,   0,   0,   0 },
        {   0, 200,   0,   0, 200 },
        { 500, 500, 300, 300, 500 }
    };
    double medians[N_CASES];
    if (campaign_verdict(unmatched, medians) != 77) {
        fprintf(stderr, "FAIL: unmatched control medians must not fabricate a conclusive PASS\n");
        return 1;
    }
    double matched[N_CASES][N_RUNS] = {
        {   1,   1,   1,   1,   1 },
        {  99,  99,  99, 101, 101 },
        {   0,   0,   0,   0,   0 },
        { 500, 500, 500, 500, 500 }
    };
    if (campaign_verdict(matched, medians) != 0 || medians[CASE_TARGET] != 99) return 1;
    matched[CASE_TARGET][2] = 101;
    if (campaign_verdict(matched, medians) != 1) return 1;
    matched[CASE_EARLY_EXIT][0] = INFINITY;
    if (campaign_verdict(matched, medians) != 77) return 1;
    matched[CASE_TARGET][0] = NAN;
    if (campaign_verdict(matched, medians) != 2) return 1;
    double drifting[N_CASES][N_RUNS] = {
        {   1,    1,    1,    1,    1 },
        { 101,  201,    0,  401,    0 },
        {   0,    0,    0,    0,    0 },
        { 500, 1000, 1500, 2000, 2500 }
    };
    if (campaign_verdict(drifting, medians) != 1) {
        fprintf(stderr, "FAIL: majority matched-ratio failures must not become aggregate PASS\n");
        return 1;
    }
    double paired = matched_ratio_median(drifting);
    if (!isfinite(paired) || fabs(paired - 0.2005) > 1e-12) return 1;
    double legacy_failure[N_CASES][N_RUNS] = {
        {     1,    1,    1,    1,    1 },
        { 10000,  199,  299,  401,  499 },
        {     0,    0,    0,    0,    0 },
        {   500, 1000, 1500, 2000, 2500 }
    };
    if (campaign_verdict(legacy_failure, medians) != 1) {
        fprintf(stderr, "FAIL: paired-ratio check must retain the original ratio-of-medians requirement\n");
        return 1;
    }
    paired = matched_ratio_median(legacy_failure);
    if (!isfinite(paired) || fabs(paired - 0.1996) > 1e-12) return 1;

    /* Diagnostic libc cannot supply or invalidate the positive control. */
    calibrated[CASE_MEMCMP][0] = INFINITY;
    calibrated[CASE_MEMCMP][1] = NAN;
    if (campaign_verdict(calibrated, calibrated_medians) != 0) return 1;
    calibrated[CASE_EARLY_EXIT][0] = 399.99;
    if (campaign_verdict(calibrated, calibrated_medians) != 77) return 1;
    calibrated[CASE_TARGET][N_RUNS - 1] = NAN;
    if (campaign_verdict(calibrated, calibrated_medians) != 2) return 1;
    puts("Timing-harness deterministic statistics/preparation/controls/verdicts: PASS");
    return 0;
}
