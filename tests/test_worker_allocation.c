/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (c) 2026 Cristian Cezar Moisés */
/* Faults in the real CLI's first STORE block, not in codec implementations. */
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                         void *(*entry)(void *), void *argument);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                         void *(*entry)(void *), void *argument);

enum fault_mode { NO_FAULT, CBUF_FAULT, PAYLOAD_FAULT };
struct worker_record {
    unsigned id;
    void *(*entry)(void *);
    void *argument;
};

static struct worker_record workers[2];
static unsigned starts;
static enum fault_mode mode;
static _Thread_local int worker_id = -1;
static _Thread_local unsigned allocations;
static _Thread_local unsigned injections;

/* No stdio or allocation in fault diagnostics, including error handling. */
static void emit(const char *message, size_t length)
{
    while (length != 0) {
        ssize_t written = write(STDERR_FILENO, message, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) _Exit(125);
        message += (size_t)written;
        length -= (size_t)written;
    }
}

#define EMIT(message) emit(message, sizeof(message) - 1)
#define FIXTURE_ERROR(message) do { \
    EMIT("WORKER-ALLOC FIXTURE-ERROR " message "\n"); \
    _Exit(125); \
} while (0)

void *__wrap_malloc(size_t size)
{
    if (worker_id >= 0) {
        if (worker_id != 0) FIXTURE_ERROR("unexpected allocation in idle worker");
        allocations++;
        if (allocations == 1 && size == 76288) {
            EMIT("WORKER-ALLOC MALLOC 0 76288\n");
        } else if (allocations == 2 && size == 65536) {
            EMIT("WORKER-ALLOC MALLOC 0 65536\n");
        } else {
            FIXTURE_ERROR("unexpected worker allocation order or size");
        }
        if ((mode == CBUF_FAULT && allocations == 1) ||
            (mode == PAYLOAD_FAULT && allocations == 2)) {
            if (injections != 0) FIXTURE_ERROR("duplicate injection");
            injections++;
            if (mode == CBUF_FAULT) EMIT("WORKER-ALLOC INJECT cbuf\n");
            else EMIT("WORKER-ALLOC INJECT payload\n");
            errno = ENOMEM;
            return NULL;
        }
    }
    void *result = __real_malloc(size);
    if (result == NULL && size != 0) FIXTURE_ERROR("unexpected real malloc failure");
    return result;
}

static void *worker_entry(void *argument)
{
    const struct worker_record *record = argument;
    worker_id = (int)record->id;
    void *result = record->entry(record->argument);
    if (record->id == 0) {
        unsigned expected = mode == CBUF_FAULT ? 1U : 2U;
        if (allocations != expected || injections != (mode == NO_FAULT ? 0U : 1U))
            FIXTURE_ERROR("worker did not complete the expected allocation sequence");
        EMIT("WORKER-ALLOC DONE 0\n");
    } else {
        if (allocations != 0 || injections != 0) FIXTURE_ERROR("idle worker was not idle");
        EMIT("WORKER-ALLOC DONE 1\n");
    }
    worker_id = -1;
    return result;
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                         void *(*entry)(void *), void *argument)
{
    if (worker_id != -1 || starts >= 2) FIXTURE_ERROR("unexpected worker creation");
    /* Only the creating main thread reads configuration, before any worker. */
    if (starts == 0) {
        const char *value = getenv("ZUPT_TEST_WORKER_ALLOC");
        if (value == NULL) FIXTURE_ERROR("missing fault mode");
        if (strcmp(value, "none") == 0) mode = NO_FAULT;
        else if (strcmp(value, "cbuf") == 0) mode = CBUF_FAULT;
        else if (strcmp(value, "payload") == 0) mode = PAYLOAD_FAULT;
        else FIXTURE_ERROR("invalid fault mode");
    }
    struct worker_record *record = &workers[starts];
    record->id = starts++;
    record->entry = entry;
    record->argument = argument;
    int result = __real_pthread_create(thread, attributes, worker_entry, record);
    if (result != 0) FIXTURE_ERROR("unexpected real worker startup failure");
    if (record->id == 0) EMIT("WORKER-ALLOC START 0\n");
    else EMIT("WORKER-ALLOC START 1\n");
    return result;
}
