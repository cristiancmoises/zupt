/*
 * Zupt — CPU Feature Detection
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Detects AES-NI, PCLMUL, AVX2, SSE4.1 at runtime.
 * Used to dispatch AES-256-CTR to hardware path when available.
 */
#include "zupt_cpuid.h"
#include <string.h>

/* Global instance */
zupt_cpu_features_t zupt_cpu = {0, 0, 0, 0};

/* ═══════════════════════════════════════════════════════════════════
 * CPUID intrinsics — platform-specific
 * ═══════════════════════════════════════════════════════════════════ */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #define ZUPT_HAS_CPUID 1
#else
  #define ZUPT_HAS_CPUID 0
#endif

#if ZUPT_HAS_CPUID

#if defined(_MSC_VER)
  #include <intrin.h>
  static void zupt_cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx) {
      int regs[4];
      __cpuidex(regs, leaf, subleaf);
      *eax = regs[0]; *ebx = regs[1]; *ecx = regs[2]; *edx = regs[3];
  }
#elif defined(__GNUC__) || defined(__clang__)
  #include <cpuid.h>
  static void zupt_cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx) {
      unsigned int a = 0, b = 0, c = 0, d = 0;
      __cpuid_count((unsigned int)leaf, (unsigned int)subleaf, a, b, c, d);
      *eax = (int)a; *ebx = (int)b; *ecx = (int)c; *edx = (int)d;
  }
#else
  /* Inline assembly fallback */
  static void zupt_cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx) {
      __asm__ __volatile__ (
          "cpuid"
          : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
          : "a"(leaf), "c"(subleaf)
      );
  }
#endif

void zupt_detect_cpu(zupt_cpu_features_t *f) {
    memset(f, 0, sizeof(*f));

    int eax, ebx, ecx, edx;

    /* Check max supported leaf */
    zupt_cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    int max_leaf = eax;

    if (max_leaf >= 1) {
        zupt_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
        f->has_aesni  = (ecx >> 25) & 1;  /* ECX bit 25 */
        f->has_pclmul = (ecx >>  1) & 1;  /* ECX bit 1  */
        f->has_sse41  = (ecx >> 19) & 1;  /* ECX bit 19 */
    }

    if (max_leaf >= 7) {
        zupt_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        f->has_avx2 = (ebx >> 5) & 1;     /* EBX bit 5  */
    }
}

#else /* Non-x86 architecture */

void zupt_detect_cpu(zupt_cpu_features_t *f) {
    memset(f, 0, sizeof(*f));
    /* No AES-NI on ARM/RISC-V/etc — use table fallback */
}

#endif /* ZUPT_HAS_CPUID */
