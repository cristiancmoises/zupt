/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 * Exercise the actual Win32 wrapper with deterministic startup failures.
 */
#ifndef _WIN32
#error This fixture requires Windows headers and a Windows runtime.
#endif

/* Include platform/CRT headers before substituting only the tested boundary. */
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int fail_allocation;
static int fail_start;
static unsigned allocation_calls;
static unsigned free_calls;
static unsigned begin_calls;
static void *live_trampoline;
static HANDLE worker_gate;
static unsigned (__stdcall *pending_entry)(void *);
static void *pending_argument;

static void *counted_malloc(size_t size) {
    allocation_calls++;
    if (fail_allocation) return NULL;
    if (live_trampoline) abort();
    live_trampoline = malloc(size);
    return live_trampoline;
}

static void counted_free(void *pointer) {
    if (!pointer || pointer != live_trampoline) abort();
    free_calls++;
    live_trampoline = NULL;
    free(pointer);
}

static unsigned __stdcall gated_entry(void *argument) {
    (void)argument;
    if (WaitForSingleObject(worker_gate, INFINITE) != WAIT_OBJECT_0) abort();
    return pending_entry(pending_argument);
}

static uintptr_t injected_beginthreadex(void *security, unsigned stack_size,
        unsigned (__stdcall *entry)(void *), void *argument, unsigned flags,
        unsigned *thread_id) {
    begin_calls++;
    if (fail_start) return 0;
    pending_entry = entry;
    pending_argument = argument;
    return _beginthreadex(security, stack_size, gated_entry, NULL, flags, thread_id);
}

#define malloc counted_malloc
#define free counted_free
#define _beginthreadex injected_beginthreadex
#include "../src/zupt_thread.h"
#undef _beginthreadex
#undef free
#undef malloc

#define CHECK(condition, message) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", message); return 1; } \
} while (0)

typedef struct {
    unsigned calls;
    unsigned marker;
} worker_state_t;

static void *test_worker(void *argument) {
    worker_state_t *state = (worker_state_t *)argument;
    state->calls++;
    state->marker = 0x1234u;
    return NULL;
}

static void reset_counts(void) {
    if (live_trampoline) abort();
    allocation_calls = 0;
    free_calls = 0;
    begin_calls = 0;
    fail_allocation = 0;
    fail_start = 0;
}

static int allocation_failure(void) {
    worker_state_t state = {0, 0xabcdu};
    zthread_t thread = NULL;
    reset_counts();
    fail_allocation = 1;
    CHECK(zthread_create(&thread, test_worker, &state) != 0,
          "allocation failure must reject startup");
    CHECK(allocation_calls == 1 && !live_trampoline && free_calls == 0,
          "allocation failure must leave no trampoline");
    CHECK(begin_calls == 0 && state.calls == 0 && state.marker == 0xabcdu,
          "allocation failure must not launch or alter the caller argument");
    return 0;
}

static int thread_failure(void) {
    worker_state_t state = {0, 0xabcdu};
    zthread_t thread = NULL;
    reset_counts();
    fail_start = 1;
    CHECK(zthread_create(&thread, test_worker, &state) != 0 && !thread,
          "thread-start failure must reject startup");
    CHECK(allocation_calls == 1 && begin_calls == 1,
          "thread-start failure must reach the allocated trampoline");
    CHECK(!live_trampoline && free_calls == 1,
          "thread-start failure must free its trampoline exactly once");
    CHECK(state.calls == 0 && state.marker == 0xabcdu,
          "thread-start failure must preserve the caller argument");
    return 0;
}

static int successful_thread(void) {
    worker_state_t state = {0, 0xabcdu};
    zthread_t thread = NULL;
    reset_counts();
    worker_gate = CreateEventA(NULL, TRUE, FALSE, NULL);
    CHECK(worker_gate != NULL, "cannot create worker gate");
    CHECK(zthread_create(&thread, test_worker, &state) == 0 && thread,
          "successful startup must return a thread handle");
    CHECK(allocation_calls == 1 && begin_calls == 1 && live_trampoline &&
          free_calls == 0 && state.calls == 0,
          "successful startup must leave trampoline ownership with the worker");
    CHECK(SetEvent(worker_gate), "cannot release worker gate");
    CHECK(zthread_join(thread) == 0, "cannot join successful worker");
    CHECK(!live_trampoline && free_calls == 1 && state.calls == 1 &&
          state.marker == 0x1234u,
          "worker must receive its argument and free its trampoline exactly once");
    CHECK(CloseHandle(worker_gate), "cannot close worker gate");
    worker_gate = NULL;
    return 0;
}

int main(void) {
    if (allocation_failure() || thread_failure() || successful_thread()) return 1;
#ifdef ZUPT_TEST_WIN32_MODEL
    puts("PASS: modeled Win32 thread-start trampoline ownership (3 cases)");
#else
    puts("PASS: native Win32 thread-start trampoline ownership (3 cases)");
#endif
    return 0;
}
