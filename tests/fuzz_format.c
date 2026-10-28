/* zupt format parser fuzz harness
 *
 * Mutates a seed archive and feeds it to the listing path. Instrumented
 * children must not have sanitizer failures counted as parser rejections.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
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
            size_t off = rng() % (n - 16 + 1);
            memset(buf + off, 0, 16);
            break;
        }
        case 3: { /* set 0xFF run */
            if (n < 16) return;
            size_t off = rng() % (n - 16 + 1);
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

/* Diagnostics may contain binary archive names, so do not stop at a NUL. */
static int contains(const char *data, size_t size, const char *text) {
    size_t length = strlen(text);
    if (size < length) return 0;
    for (size_t i = 0; i <= size - length; i++)
        if (!memcmp(data + i, text, length)) return 1;
    return 0;
}

/* A normal parser rejection and a sanitizer's exit can both return 1.
 * Inspect at most 64 KiB of diagnostics as well as the status; excess output or
 * inability to run a child is a failed test, not an expected rejection.
 * An anonymous file avoids pipe backpressure while waiting for the child.
 * Run this harness with external child file-size and runtime limits: the
 * inspection bound does not limit how much the child can write before exit. */
static int run_zupt(const char *zupt_path, const char *archive,
                    const char **flag, int with_pq) {
    (void)flag;
    FILE *diagnostics = tmpfile();
    if (!diagnostics) {
        perror("Harness diagnostics file");
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("Harness fork");
        fclose(diagnostics);
        return -1;
    }
    if (pid == 0) {
        if (dup2(fileno(diagnostics), STDERR_FILENO) < 0) _exit(126);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull < 0) { perror("open /dev/null"); _exit(126); }
        if (dup2(devnull, STDOUT_FILENO) < 0) { perror("redirect stdout"); _exit(126); }
        if (devnull != STDOUT_FILENO && devnull != STDERR_FILENO) close(devnull);
        if (fileno(diagnostics) != STDOUT_FILENO && fileno(diagnostics) != STDERR_FILENO)
            close(fileno(diagnostics));
        if (with_pq) {
            execl(zupt_path, "zupt", "list", "--pq-sdk", "/tmp/_fuzz.priv",
                  archive, (char*)NULL);
        } else {
            execl(zupt_path, "zupt", "list", archive, (char*)NULL);
        }
        perror("exec zupt");
        _exit(127);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != pid) {
        perror("Harness waitpid");
        fclose(diagnostics);
        return -1;
    }
    if (fseek(diagnostics, 0, SEEK_SET)) {
        perror("Harness diagnostics rewind");
        fclose(diagnostics);
        return -1;
    }
    char output[65536];
    size_t size = fread(output, 1, sizeof(output), diagnostics);
    int excessive = fgetc(diagnostics) != EOF;
    int io_error = ferror(diagnostics);
    fclose(diagnostics);
    if (io_error || excessive) {
        fprintf(stderr, "Harness diagnostics %s\n",
                io_error ? "read failed" : "exceeded 65536 bytes");
        return -1;
    }
    if (contains(output, size, "AddressSanitizer") ||
        contains(output, size, "LeakSanitizer") ||
        contains(output, size, "UndefinedBehaviorSanitizer") ||
        contains(output, size, "runtime error:")) {
        fputs("Sanitizer diagnostic from child:\n", stderr);
        if (fwrite(output, 1, size, stderr) != size) return -1;
        return -3;
    }
    if (WIFSIGNALED(status)) return -2;
    if (!WIFEXITED(status) || WEXITSTATUS(status) >= 126) {
        if (size && fwrite(output, 1, size, stderr) != size) return -1;
        if (WIFEXITED(status))
            fprintf(stderr, "Child execution failed with status %d\n",
                    WEXITSTATUS(status));
        else
            fputs("Child execution ended without an exit status\n", stderr);
        return -1;
    }
    return WEXITSTATUS(status);
}


int main(int argc, char **argv) {
    int n_iters = 1000;
    if (argc > 1) {
        char *end;
        errno = 0;
        long requested = strtol(argv[1], &end, 10);
        if (errno || *end || end == argv[1] || requested <= 0 || requested > INT_MAX) {
            fputs("Iteration count must be a positive int\n", stderr);
            return 1;
        }
        n_iters = (int)requested;
    }
    const char *zupt_path = argc > 2 ? argv[2] : "./zupt";
    const char *seed = argc > 3 ? argv[3] : "/tmp/_fuzz_seed.zupt";

    if (access(seed, R_OK) != 0) {
        fprintf(stderr, "Seed archive not found at %s\n", seed);
        fprintf(stderr, "Build seed first: ./zupt c %s some_file.txt\n", seed);
        return 1;
    }

    FILE *f = fopen(seed, "rb");
    if (!f) return 1;
    if (fseek(f, 0, SEEK_END)) { fclose(f); return 1; }
    long sz = ftell(f);
    if (sz <= 0 || (uintmax_t)sz > SIZE_MAX || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return 1;
    }
    uint8_t *seed_data = malloc((size_t)sz);
    if (!seed_data || fread(seed_data, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(seed_data); return 1;
    }
    fclose(f);

    fprintf(stderr, "Fuzzing zupt format parser: %d iters, seed=%ld bytes\n",
            n_iters, sz);

    int crashes = 0, errors = 0, accepts = 0, findings = 0, failures = 0, completed = 0;
    const char *temp_root = getenv("TMPDIR");
    if (!temp_root || !*temp_root) temp_root = "/tmp";
    char fuzzdir[PATH_MAX], fuzzfile[PATH_MAX];
    int length = snprintf(fuzzdir, sizeof(fuzzdir), "%s/zupt-format.XXXXXX", temp_root);
    if (length < 0 || (size_t)length >= sizeof(fuzzdir) ||
        (size_t)length + sizeof("/input.zupt") > sizeof(fuzzfile)) {
        fputs("Harness temporary directory path too long\n", stderr);
        free(seed_data);
        return 1;
    }
    if (!mkdtemp(fuzzdir)) {
        perror("Harness temporary directory");
        free(seed_data);
        return 1;
    }
    memcpy(fuzzfile, fuzzdir, (size_t)length);
    memcpy(fuzzfile + length, "/input.zupt", sizeof("/input.zupt"));
    int input_created = 0, input_complete = 0;
    double t0 = (double)clock() / CLOCKS_PER_SEC;

    for (int i = 0; i < n_iters; i++) {
        /* Copy seed, apply 1-5 random mutations */
        uint8_t *buf = malloc((size_t)sz);
        if (!buf) { failures++; break; }
        memcpy(buf, seed_data, (size_t)sz);
        int n_mut = 1 + (rng() % 5);
        for (int m = 0; m < n_mut; m++) mutate(buf, (size_t)sz);

        /* Exclusive creation inside the private directory also rejects a leaf
         * left behind by a child instead of following or truncating it. */
        int descriptor = open(fuzzfile, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (descriptor < 0) {
            perror("Harness mutation input");
            free(buf); failures++; break;
        }
        input_created = 1;
        FILE *out = fdopen(descriptor, "wb");
        if (!out) {
            perror("Harness mutation stream");
            close(descriptor);
            free(buf); failures++; break;
        }
        int write_failed = fwrite(buf, 1, (size_t)sz, out) != (size_t)sz;
        if (fclose(out)) write_failed = 1;
        free(buf);
        if (write_failed) {
            fputs("Harness mutation write failed\n", stderr);
            failures++; break;
        }
        input_complete = 1;

        int rc = run_zupt(zupt_path, fuzzfile, NULL, 0);
        completed++;
        if (rc == -3)      findings++;
        else if (rc == -2) crashes++;
        else if (rc < 0)  failures++;
        else if (rc != 0)  errors++;
        else               accepts++;
        if (findings || crashes || failures) break;
        if (unlink(fuzzfile)) {
            perror("Harness mutation input cleanup");
            failures++; break;
        }
        input_created = input_complete = 0;

        if (i > 0 && i % 100 == 0)
            fprintf(stderr, "  [%d/%d] crashes=%d errors=%d accepts=%d\r",
                    i, n_iters, crashes, errors, accepts);
    }
    double dt = (double)clock() / CLOCKS_PER_SEC - t0;

    /* Stop on the first fatal outcome and keep its input for replay. Partial
     * writes are harness failures, not complete parser reproducers. */
    if (input_created) {
        struct stat info;
        if (!lstat(fuzzfile, &info) && S_ISREG(info.st_mode))
            fprintf(stderr, "Retained %sfuzz input: %s\n",
                    input_complete ? "" : "incomplete ", fuzzfile);
        else {
            fprintf(stderr, "Fuzz input unavailable; retained directory: %s\n", fuzzdir);
            failures++;
        }
    } else if (rmdir(fuzzdir)) {
        perror("Harness temporary directory cleanup");
        fprintf(stderr, "Retained fuzz directory: %s\n", fuzzdir);
        failures++;
    }
    free(seed_data);

    fprintf(stderr, "\n\nFuzz results (%d iterations, %.1fs):\n", n_iters, dt);
    fprintf(stderr, "  completed:         %d/%d\n", completed, n_iters);
    fprintf(stderr, "  CRASHES (signal):   %d   <-- bugs if non-zero\n", crashes);
    fprintf(stderr, "  sanitizer findings:%d\n", findings);
    fprintf(stderr, "  harness failures:  %d\n", failures);
    fprintf(stderr, "  errors (rejected):  %d   (expected, parser working)\n", errors);
    fprintf(stderr, "  accepts:            %d   (mutations that didn't break magic/size)\n", accepts);

    return crashes || findings || failures || completed != n_iters ? 1 : 0;
}
