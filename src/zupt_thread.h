/*
 * ZUPT v0.6.0 — Platform Threading Abstraction
 *
 * Header-only. Wraps pthreads (Linux/macOS) and Win32 threads.
 * No semaphores (not portable to macOS). No barriers (not on Windows).
 * Uses C11 stdatomic.h when available, InterlockedExchange on MSVC.
 *
 * All threading primitives are used ONLY through these wrappers.
 */
#ifndef ZUPT_THREAD_H
#define ZUPT_THREAD_H

#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════════
 * ATOMIC INTEGER
 * ═══════════════════════════════════════════════════════════════════ */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) && !defined(_MSC_VER)
  #include <stdatomic.h>
  typedef atomic_int zatomic_int;
  static inline int  zatomic_load(const zatomic_int *p) { return atomic_load(p); }
  static inline void zatomic_store(zatomic_int *p, int v) { atomic_store(p, v); }
  static inline int  zatomic_add(zatomic_int *p, int v) { return atomic_fetch_add(p, v); }
#elif defined(_MSC_VER)
  typedef volatile long zatomic_int;
  static inline int  zatomic_load(const zatomic_int *p) { return (int)*p; }
  static inline void zatomic_store(zatomic_int *p, int v) { InterlockedExchange(p, (long)v); }
  static inline int  zatomic_add(zatomic_int *p, int v) { return (int)InterlockedExchangeAdd(p, (long)v); }
#else
  /* Fallback: volatile int. Correct on x86 with single-writer patterns.
   * For multi-writer patterns (zatomic_add), we only use this for the
   * error flag which is set-once, so torn reads are harmless. */
  typedef volatile int zatomic_int;
  static inline int  zatomic_load(const zatomic_int *p) { return *p; }
  static inline void zatomic_store(zatomic_int *p, int v) { *p = v; }
  static inline int  zatomic_add(zatomic_int *p, int v) { int old = *p; *p += v; return old; }
#endif

/* ═══════════════════════════════════════════════════════════════════
 * THREAD / MUTEX / CONDVAR
 * ═══════════════════════════════════════════════════════════════════ */

#ifdef _WIN32
  /* ─── Win32 ─── */
  #include <windows.h>
  #include <process.h>

  typedef HANDLE zthread_t;
  typedef CRITICAL_SECTION zmutex_t;
  typedef CONDITION_VARIABLE zcond_t;

  typedef struct { void *(*func)(void*); void *arg; } zthread_trampoline_t;

  static unsigned __stdcall zthread_win_entry(void *p) {
      zthread_trampoline_t *t = (zthread_trampoline_t *)p;
      t->func(t->arg);
      free(t);
      return 0;
  }

  static inline int zthread_create(zthread_t *t, void *(*func)(void*), void *arg) {
      zthread_trampoline_t *tramp = (zthread_trampoline_t *)malloc(sizeof(*tramp));
      if (!tramp) return -1;
      tramp->func = func; tramp->arg = arg;
      *t = (HANDLE)_beginthreadex(NULL, 0, zthread_win_entry, tramp, 0, NULL);
      return *t ? 0 : -1;
  }
  static inline int zthread_join(zthread_t t) {
      WaitForSingleObject(t, INFINITE);
      CloseHandle(t);
      return 0;
  }

  static inline void zmutex_init(zmutex_t *m)    { InitializeCriticalSection(m); }
  static inline void zmutex_destroy(zmutex_t *m)  { DeleteCriticalSection(m); }
  static inline void zmutex_lock(zmutex_t *m)     { EnterCriticalSection(m); }
  static inline void zmutex_unlock(zmutex_t *m)   { LeaveCriticalSection(m); }

  static inline void zcond_init(zcond_t *c)       { InitializeConditionVariable(c); }
  static inline void zcond_destroy(zcond_t *c)    { (void)c; /* no-op on Win32 */ }
  static inline void zcond_wait(zcond_t *c, zmutex_t *m) {
      SleepConditionVariableCS(c, m, INFINITE);
  }
  static inline void zcond_signal(zcond_t *c)     { WakeConditionVariable(c); }
  static inline void zcond_broadcast(zcond_t *c)  { WakeAllConditionVariable(c); }

  static inline int zupt_cpu_count(void) {
      SYSTEM_INFO si; GetSystemInfo(&si);
      return (int)si.dwNumberOfProcessors;
  }

#else
  /* ─── POSIX (Linux, macOS, *BSD) ─── */
  #include <pthread.h>
  #include <unistd.h>
  #include <stdlib.h>

  typedef pthread_t zthread_t;
  typedef pthread_mutex_t zmutex_t;
  typedef pthread_cond_t zcond_t;

  static inline int zthread_create(zthread_t *t, void *(*func)(void*), void *arg) {
      return pthread_create(t, NULL, func, arg);
  }
  static inline int zthread_join(zthread_t t) {
      return pthread_join(t, NULL);
  }

  static inline void zmutex_init(zmutex_t *m)    { pthread_mutex_init(m, NULL); }
  static inline void zmutex_destroy(zmutex_t *m)  { pthread_mutex_destroy(m); }
  static inline void zmutex_lock(zmutex_t *m)     { pthread_mutex_lock(m); }
  static inline void zmutex_unlock(zmutex_t *m)   { pthread_mutex_unlock(m); }

  static inline void zcond_init(zcond_t *c)       { pthread_cond_init(c, NULL); }
  static inline void zcond_destroy(zcond_t *c)    { pthread_cond_destroy(c); }
  static inline void zcond_wait(zcond_t *c, zmutex_t *m) { pthread_cond_wait(c, m); }
  static inline void zcond_signal(zcond_t *c)     { pthread_cond_signal(c); }
  static inline void zcond_broadcast(zcond_t *c)  { pthread_cond_broadcast(c); }

  static inline int zupt_cpu_count(void) {
      long n = sysconf(_SC_NPROCESSORS_ONLN);
      return n > 0 ? (int)n : 1;
  }
#endif

/* ═══════════════════════════════════════════════════════════════════
 * THREAD COUNT — auto-detect with cap
 * ═══════════════════════════════════════════════════════════════════ */

#define ZUPT_MAX_THREADS 64

static inline int zupt_resolve_threads(int requested) {
    int n;
    if (requested <= 0) n = zupt_cpu_count();
    else n = requested;
    if (n < 1) n = 1;
    if (n > ZUPT_MAX_THREADS) n = ZUPT_MAX_THREADS;
    return n;
}

#endif /* ZUPT_THREAD_H */
