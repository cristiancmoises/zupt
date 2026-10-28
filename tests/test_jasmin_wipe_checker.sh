#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Exercise the emitted AES stack-wipe checker independently of Jasmin tools.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
checker=$repo_root/tests/check_jasmin_wipe.awk
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-jasmin-wipe-checker.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

write_wipe() {
    target=$1
    extra=${2:-}
    slots=${3:-15}
    {
        printf 'vpxor %%xmm2, %%xmm2, %%xmm2\n'
        printf 'andq $-16, %%rsp\n'
        printf 'subq $%s, %%rsp\n' "$((slots * 16))"
        offset=$(((slots - 1) * 16))
        while [ "$offset" -gt 0 ]; do
            printf 'vmovdqu %%xmm2, %s(%%rsp)\n' "$offset"
            offset=$((offset - 16))
        done
        printf 'vmovdqu %%xmm2, (%%rsp)\n'
        if [ -n "$extra" ]; then
            printf '%s\n' "$extra"
        fi
    } >"$target"
}

write_wipe "$test_tmp/valid.s"
printf 'movq %%rsi, %%rsp\nret\n.ident "test"\n' >>"$test_tmp/valid.s"
write_wipe "$test_tmp/valid-ctr4.s" '' 16
printf 'movq %%rsi, %%rsp\nret\n.section ".note.GNU-stack", "", %%progbits\n' >>"$test_tmp/valid-ctr4.s"

write_wipe "$test_tmp/extra-write.s" 'movb $1, (%rsp)'
printf 'movq %%rsi, %%rsp\nret\n' >>"$test_tmp/extra-write.s"

write_wipe "$test_tmp/missing-restore.s"
printf 'ret\n' >>"$test_tmp/missing-restore.s"

write_wipe "$test_tmp/wrong-offset.s"
sed 's/224(%rsp)/208(%rsp)/' "$test_tmp/wrong-offset.s" >"$test_tmp/wrong-offset.tmp"
mv "$test_tmp/wrong-offset.tmp" "$test_tmp/wrong-offset.s"
printf 'movq %%rsi, %%rsp\nret\n' >>"$test_tmp/wrong-offset.s"

write_wipe "$test_tmp/after-return.s"
printf 'movq %%rsi, %%rsp\nret\nmovb $1, (%%rsp)\n' >>"$test_tmp/after-return.s"

sed 's/^vpxor/# vpxor/' "$test_tmp/valid.s" >"$test_tmp/comment-marker.s"
sed 's/^vpxor.*/.ascii "vpxor %xmm2, %xmm2, %xmm2"/' \
    "$test_tmp/valid.s" >"$test_tmp/ascii-marker.s"
{ printf 'ret\n'; sed '/^\.ident/d' "$test_tmp/valid.s"; } >"$test_tmp/early-return.s"
{ sed '/^\.ident/d' "$test_tmp/valid.s"; printf '.byte 0xc3\n'; } >"$test_tmp/byte-after-return.s"
{ sed '/^\.ident/d' "$test_tmp/valid.s"; printf '.Lafter: movb $1, (%%rsp)\n'; } >"$test_tmp/dot-label-after-return.s"
sed 's/^ret$/ret $8/' "$test_tmp/valid.s" >"$test_tmp/return-operand.s"
for instruction in andq subq vmovdqu movq ret; do
    sed "/^$instruction/s/\$/ ; movb \$1, (%rsp)/" \
        "$test_tmp/valid.s" >"$test_tmp/extra-$instruction.s"
done

failures=0
check_case() {
    name=$1
    expected=$2
    actual=0
    awk -v slots="${3:-15}" -f "$checker" "$test_tmp/$name.s" >"$test_tmp/$name.log" 2>&1 || actual=$?
    if [ "$actual" -ne "$expected" ]; then
        printf 'FAIL: %s returned %s, expected %s\n' "$name" "$actual" "$expected" >&2
        cat "$test_tmp/$name.log" >&2
        failures=$((failures + 1))
        return
    fi
    printf 'PASS: AES wipe checker %s case\n' "$name"
}

check_case valid 0
check_case valid-ctr4 0 16
check_case extra-write 1
check_case missing-restore 1
check_case wrong-offset 1
check_case after-return 1
check_case comment-marker 1
check_case ascii-marker 1
check_case early-return 1
check_case byte-after-return 1
check_case dot-label-after-return 1
check_case return-operand 1
for instruction in andq subq vmovdqu movq ret; do
    check_case "extra-$instruction" 1
done

if [ "$failures" -ne 0 ]; then
    printf 'FAIL: AES wipe checker controls found %s failures\n' "$failures" >&2
    exit 1
fi
printf 'PASS: AES wipe checker rejects unexpected cleanup instructions\n'
