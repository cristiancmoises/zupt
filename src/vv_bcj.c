/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * VaptVupt — x86 BCJ (Branch/Call/Jump) filter.
 *
 * Purpose: improve compression of x86/x86-64 machine code. Near CALL (0xE8)
 * and JMP (0xE9) instructions carry a 32-bit little-endian *relative*
 * displacement. The same call target reached from different instruction
 * positions yields a *different* relative displacement, so to the
 * compressor these look like noise. Converting the displacement to an
 * absolute form (add the instruction's stream position) makes repeated
 * references to the same target encode identically, which the LZ+ANS stage
 * then compresses well. The inverse runs on decode, before the bytes are
 * handed back to the caller.
 *
 * The x86 transform is adapted from Igor Pavlov's public-domain LZMA SDK
 * Bra86.c state machine. The exact SDK revision used by the original
 * integration was not retained; see THIRD-PARTY-NOTICES.md. The algorithm is
 * exactly reversible on arbitrary input: applying the filter and then its
 * inverse reproduces the input byte-for-byte. Deterministic randomized and
 * adversarial regressions exercise inverse(forward(x)) == x; do not "optimize"
 * the masking logic without rerunning them.
 *
 * The buffer is transformed in place. `encoding` is non-zero for the
 * forward (compress-side) transform, zero for the inverse (decode-side).
 * The last up-to-4 bytes are never touched (no room for a full operand),
 * which is consistent between forward and inverse.
 */

#include "vv_bcj.h"
#include <stddef.h>
#include <stdint.h>

/* A near-branch displacement's most-significant byte is treated as a sign
 * extension: only 0x00 or 0xFF are considered "convertible". */
static inline int bcj_test_msb(uint8_t b) { return b == 0x00 || b == 0xFF; }

/*
 * Transform data[0..size) in place. `ip` is the stream position of byte 0
 * (always 0 for whole-buffer use). Returns the number of bytes processed
 * (the prefix that may have been modified); the caller does not need it for
 * whole-buffer use. Mirrors the reference state machine exactly so that the
 * forward and inverse are perfect inverses.
 */
size_t vv_bcj_x86(uint8_t *data, size_t size, uint32_t ip, int encoding) {
    if (size < 5)
        return 0;

    size_t pos = 0;
    uint32_t mask = 0;          /* rolling mask of recent E8/E9 sightings */
    size_t limit = size - 4;    /* last position with a full 4-byte operand */
    ip += 5;                    /* displacement is relative to end of insn */

    for (;;) {
        /* Scan forward to the next byte that looks like E8/E9 ( & 0xFE == E8 ). */
        uint8_t *p = data + pos;
        uint8_t *end = data + limit;
        for (; p < end; p++)
            if ((*p & 0xFE) == 0xE8)
                break;

        {
            size_t d = (size_t)(p - data) - pos;   /* bytes skipped */
            pos = (size_t)(p - data);
            if (p >= end) {
                return pos;                         /* done */
            }
            if (d > 2) {
                mask = 0;
            } else {
                mask >>= (unsigned)d;
                if (mask != 0 &&
                    (mask > 4 || mask == 3 ||
                     bcj_test_msb(p[(size_t)(mask >> 1) + 1]))) {
                    mask = (mask >> 1) | 4;
                    pos++;
                    continue;
                }
            }
        }

        if (bcj_test_msb(p[4])) {
            uint32_t v = ((uint32_t)p[4] << 24) | ((uint32_t)p[3] << 16) |
                         ((uint32_t)p[2] << 8)  | ((uint32_t)p[1]);
            uint32_t cur = ip + (uint32_t)pos;
            pos += 5;
            if (encoding) v += cur; else v -= cur;
            if (mask != 0) {
                unsigned sh = (mask & 6) << 2;
                if (bcj_test_msb((uint8_t)((v >> sh) & 0xFF))) {
                    v ^= (((uint32_t)0x100 << sh) - 1);
                    if (encoding) v += cur; else v -= cur;
                }
                mask = 0;
            }
            p[1] = (uint8_t)(v & 0xFF);
            p[2] = (uint8_t)((v >> 8) & 0xFF);
            p[3] = (uint8_t)((v >> 16) & 0xFF);
            p[4] = (uint8_t)((0u - ((v >> 24) & 1u)) & 0xFF);
        } else {
            mask = (mask >> 1) | 4;
            pos++;
        }
    }
}

/*
 * AArch64 (ARM64) BL + ADRP filter.
 *
 * AArch64 instructions are fixed 32-bit, little-endian, 4-byte aligned. Two
 * instruction classes carry PC-relative immediates worth converting:
 *
 *   BL (branch-with-link, "call"): opcode bits [31:26] == 0b100101, with a
 *   26-bit signed immediate in bits [25:0] giving the target as a *word*
 *   offset relative to the instruction (byte offset = imm26 * 4).
 *
 *   ADRP (address of 4 KiB page, PC-relative): bit [31] == 1 and bits
 *   [28:24] == 0b10000 (mask 0x9F000000 == 0x90000000), with a 21-bit signed
 *   immediate split as immlo = bits [30:29] and immhi = bits [23:5], giving a
 *   page offset relative to the instruction's own page.
 *
 * As on x86, the same callee or the same global reached from different sites
 * yields different relative immediates; converting them to an absolute form
 * (BL: absolute word index; ADRP: absolute page index) makes repeated
 * references encode identically, which the LZ+ANS stage then compresses.
 *
 * Both conversions add/subtract the instruction's own index modulo the
 * immediate width (2^26 for BL, 2^21 for ADRP) and write only the immediate
 * bits back — every opcode/register bit is preserved exactly. The decode
 * pass therefore recognises the identical set of instructions, and the
 * modular arithmetic is a perfect bijection on arbitrary input: bytes that
 * merely look like BL/ADRP are transformed and untransformed identically, so
 * the round trip is lossless regardless of content. The unconditional-branch
 * encoding (B, opcode 000101) and everything else are left untouched.
 *
 * `ip` is the stream position of byte 0 (use 0 for whole-buffer transforms).
 * `encoding` != 0 = forward (relative -> absolute), 0 = inverse. Bytes are
 * processed in aligned 4-byte words; a trailing partial word is left as-is,
 * consistently between forward and inverse.
 */
size_t vv_bcj_arm64(uint8_t *data, size_t size, uint32_t ip, int encoding) {
    if (size < 4)
        return 0;

    size_t pos = 0;
    size_t limit = size & ~(size_t)3;   /* whole 4-byte words only */

    for (; pos < limit; pos += 4) {
        uint32_t insn = (uint32_t)data[pos] |
                        ((uint32_t)data[pos + 1] << 8) |
                        ((uint32_t)data[pos + 2] << 16) |
                        ((uint32_t)data[pos + 3] << 24);

        if ((insn >> 26) == 0x25u) {
            /* BL: 26-bit word offset. */
            uint32_t imm = insn & 0x03FFFFFFu;
            uint32_t cur = (ip + (uint32_t)pos) >> 2;       /* word index */
            if (encoding) imm = (imm + cur) & 0x03FFFFFFu;
            else          imm = (imm - cur) & 0x03FFFFFFu;
            insn = (insn & 0xFC000000u) | imm;
        } else if ((insn & 0x9F000000u) == 0x90000000u) {
            /* ADRP: 21-bit page offset, immlo=[30:29], immhi=[23:5]. */
            uint32_t imm = ((insn >> 29) & 0x3u) | (((insn >> 5) & 0x7FFFFu) << 2);
            uint32_t cur = (ip + (uint32_t)pos) >> 12;      /* page index */
            if (encoding) imm = (imm + cur) & 0x001FFFFFu;
            else          imm = (imm - cur) & 0x001FFFFFu;
            insn = (insn & 0x9F00001Fu)
                 | ((imm & 0x3u) << 29)
                 | (((imm >> 2) & 0x7FFFFu) << 5);
        } else {
            continue;
        }

        data[pos]     = (uint8_t)(insn & 0xFF);
        data[pos + 1] = (uint8_t)((insn >> 8) & 0xFF);
        data[pos + 2] = (uint8_t)((insn >> 16) & 0xFF);
        data[pos + 3] = (uint8_t)((insn >> 24) & 0xFF);
    }
    return pos;
}

/*
 * Detect the executable architecture of `data` to pick a BCJ filter.
 * Recognises ELF, PE (MZ/PE), and little-endian Mach-O thin binaries. Every
 * field read is length-checked, so the function is safe on truncated or
 * non-executable input; in that case it returns VV_FILTER_NONE.
 */
vv_filter_kind_t vv_bcj_detect(const uint8_t *data, size_t size) {
    if (!data)
        return VV_FILTER_NONE;

    /* ELF: 0x7F 'E' 'L' 'F'. e_ident[EI_DATA] at offset 5 (1=LE, 2=BE);
     * e_machine is a 2-byte field at offset 18. */
    if (size >= 20 && data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F') {
        unsigned mach = (data[5] == 2)
            ? (((unsigned)data[18] << 8) | data[19])    /* big-endian */
            : ((unsigned)data[18] | ((unsigned)data[19] << 8)); /* little-endian */
        if (mach == 62 || mach == 3)   return VV_FILTER_X86;    /* EM_X86_64, EM_386 */
        if (mach == 183)               return VV_FILTER_ARM64;  /* EM_AARCH64 */
        return VV_FILTER_NONE;
    }

    /* PE/COFF: "MZ", then a 4-byte PE-header offset at 0x3C, then "PE\0\0"
     * and a 2-byte little-endian Machine field. */
    if (size >= 0x40 && data[0] == 'M' && data[1] == 'Z') {
        uint32_t pe = (uint32_t)data[0x3C] | ((uint32_t)data[0x3D] << 8) |
                      ((uint32_t)data[0x3E] << 16) | ((uint32_t)data[0x3F] << 24);
        if ((size_t)pe + 6 <= size && data[pe] == 'P' && data[pe + 1] == 'E' &&
            data[pe + 2] == 0 && data[pe + 3] == 0) {
            unsigned mach = (unsigned)data[pe + 4] | ((unsigned)data[pe + 5] << 8);
            if (mach == 0x8664 || mach == 0x014C) return VV_FILTER_X86;   /* AMD64, I386 */
            if (mach == 0xAA64)                   return VV_FILTER_ARM64; /* ARM64 */
        }
        return VV_FILTER_NONE;
    }

    /* Mach-O thin (little-endian on disk): magic 0xFEEDFACE/0xFEEDFACF, then
     * a 4-byte little-endian cputype. CPU_ARCH_ABI64 = 0x01000000. */
    if (size >= 8) {
        uint32_t magic = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        if (magic == 0xFEEDFACEu || magic == 0xFEEDFACFu) {
            unsigned cpu = (unsigned)data[4] | ((unsigned)data[5] << 8) |
                           ((unsigned)data[6] << 16) | ((unsigned)data[7] << 24);
            if (cpu == 0x01000007u || cpu == 7u) return VV_FILTER_X86;   /* x86_64, i386 */
            if (cpu == 0x0100000Cu)              return VV_FILTER_ARM64; /* arm64 */
        }
    }

    return VV_FILTER_NONE;
}
