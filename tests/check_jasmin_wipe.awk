# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Verify the compiler-pinned AES round-key stack wipe and epilogue sequence.

NF == 0 || $1 ~ /^#/ {
    next
}

$1 == "vpxor" && NF == 4 && $2 == "%xmm2," && $3 == "%xmm2," && $4 == "%xmm2" {
    if (wiping)
        invalid = 1
    wiping = 1
    next
}

!wiping {
    if ($1 ~ /^ret[qwl]?$/)
        invalid = 1
    next
}

returned {
    # Only these metadata directives occur after the pinned compiler's return.
    # Other dot-prefixed lines can emit bytes or introduce code labels.
    if ($0 ~ /^[[:space:]]*\.ident[[:space:]]+"[^"]*"[[:space:]]*$/ ||
        $0 ~ /^[[:space:]]*\.section[[:space:]]+"\.note\.GNU-stack",[[:space:]]+"",[[:space:]]+%progbits[[:space:]]*$/)
        next
    invalid = 1
    next
}

!aligned {
    if (NF == 3 && $1 == "andq" && $2 == "$-16," && $3 == "%rsp")
        aligned = 1
    else
        invalid = 1
    next
}

!allocated {
    expected_frame = slots * 16
    if (NF == 3 && $1 == "subq" && $2 == "$" expected_frame "," && $3 == "%rsp")
        allocated = 1
    else
        invalid = 1
    next
}

count < slots {
    expected = count == slots - 1 ? "(%rsp)" : sprintf("%d(%%rsp)", 16 * (slots - 1 - count))
    if (NF != 3 || $1 != "vmovdqu" || $2 != "%xmm2," || $3 != expected)
        invalid = 1
    else
        ++count
    next
}

!restored {
    if (NF == 3 && $1 == "movq" && $2 == "%rsi," && $3 == "%rsp")
        restored = 1
    else
        invalid = 1
    next
}

{
    if (NF == 1 && $1 == "ret")
        returned = 1
    else
        invalid = 1
}

END {
    if (!wiping || !aligned || !allocated || !returned || !restored || count != slots || invalid) {
        print "FAIL: generated AES round-key stack wipe differs from the pinned pattern"
        exit 1
    }
    printf "PASS: generated AES has %d u128 zero stores covering %d bytes\n", slots, slots * 16
}
