#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu

test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
analysis_script=${STATIC_ANALYSIS_SCRIPT:-$test_root/tests/test_static_analysis.sh}
real_find=$(command -v find)
real_sort=$(command -v sort)
real_grep=$(command -v grep)
case "$real_find:$real_sort:$real_grep" in
    /*:/*:/*) ;;
    *) echo 'FAIL: absolute find, sort and grep paths are required' >&2; exit 1 ;;
esac
cd -- "$test_root"
test_tmp=$(mktemp -d)
trap 'rm -rf -- "$test_tmp"' EXIT HUP INT TERM

cat >"$test_tmp/compiler" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$STATIC_COMPILER_CALLS"
if [ "$STATIC_HARNESS_CASE" = silent-conversion ]; then
    case " $* " in
        *" -Wconversion "*) exit 17 ;;
    esac
fi
previous=
for argument do
    if [ "$previous" = -c ] && [ ! -f "$argument" ]; then
        echo "compiler fixture source missing: $argument" >&2
        exit 18
    fi
    previous=$argument
done
if [ "$STATIC_HARNESS_CASE" = disappearing-shani ]; then
    # This trigger may move only a source owned by this harness's private tmp.
    case "$STATIC_PRIVATE_TMP" in
        /*) ;;
        *) echo 'invalid private fixture parent' >&2; exit 19 ;;
    esac
    if [ "$STATIC_FIXTURE_ROOT" != "$STATIC_PRIVATE_TMP/source-fixture" ] ||
            [ "$(pwd -P)" != "$STATIC_FIXTURE_ROOT" ] ||
            [ "$STATIC_FIXTURE_ROOT" = "$STATIC_WORKTREE_ROOT" ]; then
        echo 'compiler refused a non-private source fixture' >&2
        exit 19
    fi
    if [ -f "$STATIC_FIXTURE_ROOT/src/zupt_sha256_shani.c" ]; then
        mv "$STATIC_FIXTURE_ROOT/src/zupt_sha256_shani.c" \
            "$STATIC_FIXTURE_ROOT/saved-shani.c" || exit 19
    fi
fi
case "$STATIC_HARNESS_CASE: $* " in
    conversion-warning:*" -Wconversion "*)
        echo 'warning: injected conversion warning' >&2 ;;
    shani-warning:*" -Wconversion "*" src/zupt_sha256_shani.c "*)
        echo 'warning: injected SHA-NI conversion warning' >&2 ;;
esac
exit 0
EOF
cat >"$test_tmp/cppcheck" <<'EOF'
#!/bin/sh
case "$STATIC_HARNESS_CASE: $* " in
    cppcheck-warning:*" --enable=warning,performance "*)
        echo 'warning: injected cppcheck warning' >&2 ;;
    cppcheck-style:*" --enable=style "*)
        echo 'style: injected knownConditionTrueFalse' >&2 ;;
    cppcheck-error:*)
        case " $* " in
            *" --enable="*) ;;
            *) echo 'error: injected cppcheck error' >&2 ;;
        esac ;;
esac
exit 0
EOF
cat >"$test_tmp/grep" <<'EOF'
#!/bin/sh
selected=0
for argument do
    case "$STATIC_HARNESS_CASE:$argument" in
        count-*:*"/$STATIC_GREP_TARGET") selected=1 ;;
        positive-after:'zupt_atomic_output_finish(output, rc == ZUPTSDK_OK)')
            selected=1 ;;
        forbidden-*:*)
            case "$STATIC_GREP_TARGET:$argument" in
                varint:s\>=64*|disk:'lstat(target_path'|sdk:'chmod(dst, mode)'|roundtrip:'(^|[^[:alnum:]_])(stat|lstat)'*)
                    selected=1 ;;
            esac ;;
    esac
done
if [ "$selected" -eq 1 ]; then
    case "$STATIC_HARNESS_CASE" in
        count-after|forbidden-after|positive-after)
            status=0
            "$STATIC_REAL_GREP" "$@" || status=$?
            [ "$status" -le 1 ] || exit "$status" ;;
        count-empty) exit 0 ;;
        count-malformed) echo 'not-a-count'; exit 0 ;;
        count-zero-match) echo 0; exit 0 ;;
        count-positive-no-match) echo 1; exit 1 ;;
        count-huge) echo 18446744073709551616; exit 0 ;;
    esac
    echo "injected grep failure 73: $STATIC_GREP_TARGET" >&2
    exit 73
fi
exec "$STATIC_REAL_GREP" "$@"
EOF
cat >"$test_tmp/find" <<'EOF'
#!/bin/sh
case "$STATIC_HARNESS_CASE" in
    find-before)
        echo 'injected find inventory failure 71' >&2
        exit 71 ;;
    find-after)
        "$STATIC_REAL_FIND" "$@" || exit "$?"
        echo 'injected find inventory failure 71' >&2
        exit 71 ;;
    empty-find) exit 0 ;;
    *) exec "$STATIC_REAL_FIND" "$@" ;;
esac
EOF
cat >"$test_tmp/sort" <<'EOF'
#!/bin/sh
case "$STATIC_HARNESS_CASE" in
    sort-before)
        echo 'injected sort inventory failure 72' >&2
        exit 72 ;;
    sort-after)
        "$STATIC_REAL_SORT" "$@" || exit "$?"
        echo 'injected sort inventory failure 72' >&2
        exit 72 ;;
    *) exec "$STATIC_REAL_SORT" "$@" ;;
esac
EOF
chmod +x "$test_tmp/compiler" "$test_tmp/cppcheck" "$test_tmp/find" "$test_tmp/sort" "$test_tmp/grep"

export STATIC_REAL_FIND="$real_find" STATIC_REAL_SORT="$real_sort"
export STATIC_REAL_GREP="$real_grep" STATIC_GREP_TARGET=
export STATIC_COMPILER_CALLS="$test_tmp/compiler-calls.log"
STATIC_HARNESS_CASE=silent-conversion
export STATIC_HARNESS_CASE

if PATH="$test_tmp:$PATH" CC="$test_tmp/compiler" \
        bash "$analysis_script" \
        >"$test_tmp/output.log" 2>&1; then
    echo 'FAIL: static-analysis gate accepted a silent compiler failure' >&2
    exit 1
fi
"$real_grep" -F 'conversion compiler exited with status 17' "$test_tmp/output.log" >/dev/null
"$real_grep" -F 'Static analysis:' "$test_tmp/output.log" >/dev/null
echo 'PASS: static-analysis gate rejects silent compiler failures'

# Real source discovery and ordering must still reach the compiler on success.
STATIC_HARNESS_CASE=clean
: > "$STATIC_COMPILER_CALLS"
if ! PATH="$test_tmp:$PATH" CC="$test_tmp/compiler" \
        bash "$analysis_script" >"$test_tmp/clean.log" 2>&1; then
    echo 'FAIL: static-analysis clean baseline was rejected' >&2
    cat "$test_tmp/clean.log" >&2
    exit 1
fi
test -s "$STATIC_COMPILER_CALLS"
"$real_grep" -E 'strict GCC -Werror clean on [1-9][0-9]* files' "$test_tmp/clean.log" >/dev/null
echo 'PASS: static-analysis source-backed clean baseline'

# A failed producer may emit a full valid inventory before failing. Neither
# those names nor an empty successful inventory may advance to compilation.
failures=0
for STATIC_HARNESS_CASE in find-before find-after sort-before sort-after empty-find; do
    : > "$STATIC_COMPILER_CALLS"
    output=$test_tmp/$STATIC_HARNESS_CASE.log
    status=0
    PATH="$test_tmp:$PATH" CC="$test_tmp/compiler" \
        bash "$analysis_script" >"$output" 2>&1 || status=$?
    case_failed=0
    if [ "$status" -eq 0 ]; then
        echo "FAIL: static-analysis gate accepted $STATIC_HARNESS_CASE inventory" >&2
        case_failed=1
    fi
    if [ -s "$STATIC_COMPILER_CALLS" ]; then
        echo "FAIL: $STATIC_HARNESS_CASE inventory reached the compiler" >&2
        case_failed=1
    fi
    diagnostic=
    case "$STATIC_HARNESS_CASE" in
        find-*) diagnostic='injected find inventory failure 71' ;;
        sort-*) diagnostic='injected sort inventory failure 72' ;;
    esac
    if [ -n "$diagnostic" ] && ! "$real_grep" -F "$diagnostic" "$output" >/dev/null; then
        echo "FAIL: $STATIC_HARNESS_CASE producer diagnostic was lost" >&2
        case_failed=1
    fi
    if [ "$case_failed" -eq 0 ]; then
        echo "PASS: static-analysis gate rejects $STATIC_HARNESS_CASE inventory before compilation"
    else
        failures=$((failures + 1))
    fi
done

# A grep result is evidence only when both its status and output are valid.
# Keep assertions outside the injected PATH, including checks for diagnostics.
reject_case() {
    label=$1
    diagnostic=$2
    output=$test_tmp/$label.log
    status=0
    (cd -- "${source_root:-$test_root}" &&
        PATH="$test_tmp:$PATH" CC="$test_tmp/compiler" \
            bash "$analysis_script") >"$output" 2>&1 || status=$?
    if [ "$status" -eq 0 ]; then
        echo "FAIL: static-analysis gate accepted $label" >&2
        failures=$((failures + 1))
    elif [ -n "$diagnostic" ] && ! "$real_grep" -F "$diagnostic" "$output" >/dev/null; then
        echo "FAIL: $label diagnostic was lost" >&2
        failures=$((failures + 1))
    else
        echo "PASS: static-analysis gate rejects $label"
    fi
}

for STATIC_GREP_TARGET in conversion.log shani-conversion.log \
        cppcheck-warning.log cppcheck-style.log cppcheck-error.log; do
    for STATIC_HARNESS_CASE in count-before count-after count-empty count-malformed; do
        diagnostic=
        case "$STATIC_HARNESS_CASE" in
            count-before|count-after)
                diagnostic="injected grep failure 73: $STATIC_GREP_TARGET" ;;
        esac
        reject_case "$STATIC_HARNESS_CASE-$STATIC_GREP_TARGET" "$diagnostic"
    done
done
for STATIC_GREP_TARGET in conversion.log cppcheck-warning.log; do
    for STATIC_HARNESS_CASE in count-zero-match count-positive-no-match; do
        reject_case "$STATIC_HARNESS_CASE-$STATIC_GREP_TARGET" ''
    done
done
STATIC_GREP_TARGET=conversion.log
STATIC_HARNESS_CASE=count-huge
reject_case count-huge-conversion.log '18446744073709551616 -Wconversion warnings'
for STATIC_GREP_TARGET in varint disk sdk roundtrip; do
    for STATIC_HARNESS_CASE in forbidden-before forbidden-after; do
        reject_case "$STATIC_HARNESS_CASE-$STATIC_GREP_TARGET" \
            "injected grep failure 73: $STATIC_GREP_TARGET"
    done
done
STATIC_GREP_TARGET=sdk-final
STATIC_HARNESS_CASE=positive-after
reject_case positive-after-sdk-final 'injected grep failure 73: sdk-final'

# Positive controls use real grep over actual warning/finding output.
STATIC_GREP_TARGET=
for STATIC_HARNESS_CASE in conversion-warning shani-warning \
        cppcheck-warning cppcheck-style cppcheck-error; do
    reject_case "$STATIC_HARNESS_CASE" ''
done

# Minimal private sources exercise missing SHA-NI and forbidden-source controls
# without renaming or rewriting any worktree source. The compiler double above
# checks source existence, so unrelated missing conversion inputs cannot pass.
source_root=$test_tmp/source-fixture
mkdir -p "$source_root/src" "$source_root/sdk/src" "$source_root/sdk/tests"
for source in main format dedup disk crypto crypto_sdk crypto_pqbox aes256 \
        sha256 xxh parallel cpuid filetype mlock predict x25519; do
    : > "$source_root/src/zupt_$source.c"
done
cat > "$source_root/src/zupt_main.c" <<'EOF'
c_lflag &= (tcflag_t)~ECHO
EOF
cat > "$source_root/src/zupt_disk.c" <<'EOF'
tgt_fd = open(target_path
fstat(tgt_fd, &opened_st)
EOF
cat > "$source_root/sdk/src/zuptsdk.c" <<'EOF'
zupt_atomic_output_open(dst, &fo)
fchmod(fileno(fo), mode)
zupt_atomic_output_finish(output, rc == ZUPTSDK_OK)
EOF
cat > "$source_root/sdk/tests/test_sdk_roundtrip.c" <<'EOF'
fstat(fd, &info)
fstat(fd, info)
EOF
STATIC_HARNESS_CASE=clean
: > "$STATIC_COMPILER_CALLS"
reject_case missing-shani ''
if [ -s "$STATIC_COMPILER_CALLS" ]; then
    echo 'FAIL: missing SHA-NI source reached the compiler' >&2
    failures=$((failures + 1))
fi
: > "$source_root/src/zupt_sha256_shani.c"
if (cd -- "$source_root" && PATH="$test_tmp:$PATH" CC="$test_tmp/compiler" \
        bash "$analysis_script") >"$test_tmp/fixture-clean.log" 2>&1; then
    echo 'PASS: static-analysis private source fixture clean baseline'
else
    echo 'FAIL: static-analysis private source fixture clean baseline was rejected' >&2
    cat "$test_tmp/fixture-clean.log" >&2
    failures=$((failures + 1))
fi

export STATIC_PRIVATE_TMP="$test_tmp" STATIC_FIXTURE_ROOT="$source_root"
export STATIC_WORKTREE_ROOT="$test_root"
STATIC_HARNESS_CASE=disappearing-shani
reject_case disappearing-shani 'compiler fixture source missing:'
if [ -f "$source_root/saved-shani.c" ]; then
    mv "$source_root/saved-shani.c" "$source_root/src/zupt_sha256_shani.c"
else
    echo 'FAIL: compiler did not trigger private SHA-NI source disappearance' >&2
    failures=$((failures + 1))
fi
STATIC_HARNESS_CASE=clean

for forbidden_source in varint disk sdk roundtrip; do
    case "$forbidden_source" in
        varint)
            source=$source_root/src/zupt_format.c
            pattern='if(s>=64 && (x&0x80))return -1;'
            diagnostic='varint decoder has the dead' ;;
        disk)
            source=$source_root/src/zupt_disk.c
            pattern='lstat(target_path'
            diagnostic='disk restore has a path-check/open TOCTOU pattern' ;;
        sdk)
            source=$source_root/sdk/src/zuptsdk.c
            pattern='chmod(dst, mode)'
            diagnostic='SDK key save has a path-based chmod TOCTOU pattern' ;;
        roundtrip)
            source=$source_root/sdk/tests/test_sdk_roundtrip.c
            pattern='stat(path, &info)'
            diagnostic='SDK regression uses path-level stat/lstat' ;;
    esac
    cp "$source" "$test_tmp/saved-source"
    printf '%s\n' "$pattern" >> "$source"
    reject_case "forbidden-source-$forbidden_source" "$diagnostic"
    cp "$test_tmp/saved-source" "$source"
done
if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures static-analysis harness cases" >&2
    exit 1
fi
