/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT — optional x86_64 crypto assembly declarations
 * Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
 *
 * All five declarations correspond to checked-in Jasmin 2026.09.0 output.
 * The source gate checks regeneration, exported symbols and modeled safety
 * under caller preconditions. These functions replace C fallbacks when
 * built with -DZUPT_USE_JASMIN. A .s build alone is not formal proof.
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
 * cond must be 0 or 1: copies a→out for 0 and b→out for 1.
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
 * 16-byte aligned offsets. Requires AES-NI and OS-enabled AVX; the C
 * wrapper checks both before dispatch.
 *
 * Args (System V ABI):
 *   out_ptr (RDI): destination for 16-byte result
 *   in_blk  (RSI): pointer to 16-byte plaintext block
 *   key     (RDX): pointer to 32-byte AES-256 key (two u128)
 *   ctr_blk (RCX): pointer to 16-byte counter block
 */
extern void zupt_aes256_blk(void *out, const void *in,
                              const void *key, const void *ctr);

/* JASMIN PATH: AES-256-CTR pipeline with four interleaved AES lanes.
 * Encrypt nblocks*16 bytes; handle 1-3 remaining blocks with the same
 * expanded schedule. Increment only ctr[8..15], big-endian modulo 2^64,
 * and preserve ctr[0..7]. Requires AES-NI and OS-enabled AVX.
 * For positive nblocks: key is readable for 32 bytes, ctr writable for 16,
 * and in/out readable/writable for nblocks*16 bytes. All spans must be live,
 * valid and nonwrapping, with nblocks <= SIZE_MAX/16. Input/output may be
 * identical or disjoint, not partly overlapping. Counter must be disjoint
 * from key/input/output; key must be disjoint from writable output.
 * Zero blocks touch no caller memory. No pointers or schedule are retained.
 *
 * Args: out(RDI), in(RSI), key(RDX), ctr(RCX), nblocks(R8)
 */
extern void zupt_aes256_ctr4(void *out, const void *in,
                               const void *key, void *ctr,
                               uint64_t nblocks);

#endif /* ZUPT_USE_JASMIN */
#endif /* ZUPT_JASMIN_H */
