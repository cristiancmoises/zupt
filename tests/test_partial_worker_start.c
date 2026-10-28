/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (c) 2026 Cristian Cezar Moisés */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministically fail worker startup in the real dynamically linked CLI. */
int pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                   void *(*entry)(void *), void *argument) {
    static atomic_uint attempts;
    const char *limit_text = getenv("ZUPT_TEST_THREAD_FAIL_AFTER");
    if (limit_text) {
        unsigned limit = (unsigned)strtoul(limit_text, NULL, 10);
        unsigned attempt = atomic_fetch_add(&attempts, 1);
        if (attempt >= limit) {
            fprintf(stderr, "TEST: deny worker startup after %u successful attempts\n", limit);
            return EAGAIN;
        }
    }
    void *symbol = dlsym(RTLD_NEXT, "pthread_create");
    int (*create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
    _Static_assert(sizeof(create) == sizeof(symbol), "POSIX dlsym pointer size");
    if (!symbol) return EAGAIN;
    memcpy(&create, &symbol, sizeof(create));
    int result = create(thread, attributes, entry, argument);
    if (result) fputs("TEST: unexpected real worker startup failure\n", stderr);
    return result;
}
