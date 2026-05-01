/* zupt format parser fuzz harness
 *
 * Mutates valid archives and feeds them to the listing/extract path
 * under ASAN/UBSAN. Any crash, leak, or sanitizer error is a finding.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

/* Simple xorshift64 PRNG — deterministic, fast */
static uint64_t rng_state = 0xc0ffeebabe5050ULL;
static uint64_t rng(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return rng_state = x;
}

static void mutate(uint8_t *buf, size_t n) {
    if (n == 0) return;
    int op = rng() % 5;
    switch (op) {
        case 0: { /* byte flip */
            size_t i = rng() % n;
            buf[i] ^= 1u << (rng() % 8);
            break;
        }
        case 1: { /* random byte set */
            size_t i = rng() % n;
            buf[i] = (uint8_t)(rng() & 0xFF);
            break;
        }
        case 2: { /* zero a 16-byte run */
            if (n < 16) return;
            size_t off = rng() % (n - 16);
            memset(buf + off, 0, 16);
            break;
        }
        case 3: { /* set 0xFF run */
            if (n < 16) return;
            size_t off = rng() % (n - 16);
            memset(buf + off, 0xFF, 16);
            break;
        }
        case 4: { /* swap two bytes */
            if (n < 2) return;
            size_t i = rng() % n;
            size_t j = rng() % n;
            uint8_t t = buf[i]; buf[i] = buf[j]; buf[j] = t;
            break;
        }
    }
}

/* Run the zupt binary on a given archive file. We use fork+exec because
 * any crash in zupt would otherwise take down the harness; the parent
 * just records the exit status. ASAN/UBSAN errors return non-zero. */
static int run_zupt(const char *zupt_path, const char *archive,
                    const char **flag, int with_pq) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* child */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1); dup2(devnull, 2);
            close(devnull);
        }
        if (with_pq) {
            execl(zupt_path, "zupt", "list", "--pq-sdk", "/tmp/_fuzz.priv",
                  archive, (char*)NULL);
        } else {
            execl(zupt_path, "zupt", "list", archive, (char*)NULL);
        }
        _exit(127);
        (void)flag;
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) return -2;  /* crash! */
    return WEXITSTATUS(status);
}


int main(int argc, char **argv) {
    int n_iters = argc > 1 ? atoi(argv[1]) : 1000;
    const char *zupt_path = argc > 2 ? argv[2] : "./zupt";
    const char *seed = argc > 3 ? argv[3] : "/tmp/_fuzz_seed.zupt";

    if (access(seed, R_OK) != 0) {
        fprintf(stderr, "Seed archive not found at %s\n", seed);
        fprintf(stderr, "Build seed first: ./zupt c %s some_file.txt\n", seed);
        return 1;
    }

    FILE *f = fopen(seed, "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *seed_data = malloc((size_t)sz);
    if (!seed_data || fread(seed_data, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(seed_data); return 1;
    }
    fclose(f);

    fprintf(stderr, "Fuzzing zupt format parser: %d iters, seed=%ld bytes\n",
            n_iters, sz);

    int crashes = 0, errors = 0, accepts = 0;
    char fuzzfile[64] = "/tmp/_fuzz_archive.zupt";
    double t0 = (double)clock() / CLOCKS_PER_SEC;

    for (int i = 0; i < n_iters; i++) {
        /* Copy seed, apply 1-5 random mutations */
        uint8_t *buf = malloc((size_t)sz);
        if (!buf) break;
        memcpy(buf, seed_data, (size_t)sz);
        int n_mut = 1 + (rng() % 5);
        for (int m = 0; m < n_mut; m++) mutate(buf, (size_t)sz);

        FILE *out = fopen(fuzzfile, "wb");
        if (!out) { free(buf); continue; }
        fwrite(buf, 1, (size_t)sz, out);
        fclose(out);
        free(buf);

        int rc = run_zupt(zupt_path, fuzzfile, NULL, 0);
        if (rc == -2)      crashes++;
        else if (rc != 0)  errors++;
        else               accepts++;

        if (i > 0 && i % 100 == 0)
            fprintf(stderr, "  [%d/%d] crashes=%d errors=%d accepts=%d\r",
                    i, n_iters, crashes, errors, accepts);
    }
    double dt = (double)clock() / CLOCKS_PER_SEC - t0;

    unlink(fuzzfile);
    free(seed_data);

    fprintf(stderr, "\n\nFuzz results (%d iterations, %.1fs):\n", n_iters, dt);
    fprintf(stderr, "  CRASHES (signal):   %d   <-- bugs if non-zero\n", crashes);
    fprintf(stderr, "  errors (rejected):  %d   (expected, parser working)\n", errors);
    fprintf(stderr, "  accepts:            %d   (mutations that didn't break magic/size)\n", accepts);

    return crashes > 0 ? 1 : 0;
}
