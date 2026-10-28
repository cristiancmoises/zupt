#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "$0")/.."
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-rust-varint.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

export CARGO_TARGET_DIR="$work/target"
# Cargo gets an explicit two-job budget rather than an inherited Make jobserver.
unset CARGO_MAKEFLAGS MAKEFLAGS MFLAGS
if [[ ${1:-} == --audit && $# == 1 ]]; then
    "${CARGO:-cargo}" fmt --manifest-path rust/varint/Cargo.toml --all -- --check
    "${CARGO:-cargo}" clippy --manifest-path rust/varint/Cargo.toml \
        --locked --offline --all-targets --jobs 2 -- -D warnings
    exit 0
fi
[[ $# == 0 ]] || { printf 'Usage: %s [--audit]\n' "$0" >&2; exit 2; }

# Follow the existing make-compatible compiler/flag splitting convention.
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:--O2 -g} -D_DEFAULT_SOURCE -Iinclude -Isrc \
    -Wall -Wextra -Werror -std=c11 -ffunction-sections -fdata-sections \
    -c src/zupt_format.c -o "$work/format.o"
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:--O2 -g} -D_DEFAULT_SOURCE -Iinclude -Isrc \
    -Wall -Wextra -Werror -std=c11 ${LDFLAGS:-} -Wl,--gc-sections \
    tests/test_rust_varint_oracle.c "$work/format.o" -o "$work/oracle" ${LDLIBS:-}

export ZUPT_VARINT_ORACLE="$work/oracle"
export ZUPT_VARINT_TEST_DIR="$work"
for profile in debug release; do
    flags=()
    [[ $profile != release ]] || flags+=(--release)
    "${CARGO:-cargo}" test --manifest-path rust/varint/Cargo.toml \
        --locked --offline --jobs 2 --no-fail-fast "${flags[@]}" -- --test-threads=2 --nocapture
done
