/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT — optional x86_64 crypto assembly declarations
 * Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
 *
 * Four declarations below correspond to checked-in jasminc output. The
 * zupt_aes256_ctr4 implementation is separately identified hand-written
 * assembly matching an algorithm-only .jazz description. These functions
 * replace C fallbacks when built with -DZUPT_USE_JASMIN.
 *
 * Calling convention: System V AMD64 ABI.
 * Pointer args passed in RDI, RSI, RDX, RCX, R8, R9.
 *
 * All five optional declarations are wired when the feature is enabled.
 */
#ifndef ZUPT_JASMIN_H
#define ZUPT_JASMIN_H

#ifdef ZUPT_USE_JASMIN
#include <stdint.h>

/* JASMIN PATH: CT-intended MAC comparison (4×u64 XOR accumulation).
 * Returns 0 if all 32 bytes match, nonzero if any differ.
 * Replaces XOR loop in zupt_decrypt_buffer(). */
extern uint64_t zupt_mac_verify_ct(const void *expected, const void *actual);

/* JASMIN PATH: CT-intended conditional select (4×u64 masked select).
 * if cond==0: copies a→out. if cond!=0: copies b→out.
 * Replaces cmov in zupt_mlkem768_decaps(). */
extern void zupt_ct_select_32(void *out, const void *a,
                               const void *b, uint64_t cond);

/* JASMIN PATH: CT-intended conditional swap (4×u64 masked XOR swap).
 * if cond==0: no-op. if cond==1: swaps a↔b in place.
 * Replaces fe_cswap in zupt_x25519.c.
 * Operates on exactly four consecutive u64 values; the X25519 caller handles
 * its fifth 51-bit limb separately. */
extern void zupt_fe_cswap(void *a, void *b, uint64_t cond);

/* JASMIN PATH: AES-256 single-block encrypt via AES-NI.
 * out = AES-256-ECB(key, ctr) XOR in.
 * FIX v2.0.0: Stack offset bug resolved — round keys at correct
 * 16-byte aligned offsets. Requires AES-NI (checked via CPUID).
 *
 * Args (System V ABI):
 *   out_ptr (RDI): destination for 16-byte result
 *   in_blk  (RSI): pointer to 16-byte plaintext block
 *   key     (RDX): pointer to 32-byte AES-256 key (two u128)
 *   ctr_blk (RCX): pointer to 16-byte counter block
 */
extern void zupt_aes256_blk(void *out, const void *in,
                              const void *key, const void *ctr);

/* HAND-WRITTEN ASSEMBLY PATH: AES-256-CTR 4-block pipeline via AES-NI.
 * Processes nblocks×16 bytes with 4-way interleaving.
 * Counter is updated in-place (big-endian increment in bytes [8..15]).
 * Requires AES-NI. Falls back to zupt_aes256_blk for remaining 1-3 blocks.
 *
 * Args: out(RDI), in(RSI), key(RDX), ctr(RCX), nblocks(R8)
 */
extern void zupt_aes256_ctr4(void *out, const void *in,
                               const void *key, void *ctr,
                               uint64_t nblocks);

#endif /* ZUPT_USE_JASMIN */
#endif /* ZUPT_JASMIN_H */
