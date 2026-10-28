#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu
case $(uname -s) in
    Linux*) ;;
    *) echo 'SKIP: fuzz-build wrapper regression requires Linux'; exit 0 ;;
esac
test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf -- "$test_tmp"' EXIT HUP INT TERM
test_name=setup
mkdir -p "$test_tmp/tools" "$test_tmp/cli with spaces" "$test_tmp/path-decoy"

# These doubles exercise shell orchestration only. The real C, archive-format
# and fuzz regressions remain in test_fuzz_build.sh and its integration run.
cat >"$test_tmp/tools/cc" <<'EOF'
#!/bin/sh
set -eu
test "${FUZZ_WRAPPER_MOCK_ONLY:-}" = 1 || exit 99
if test "$#" = 1 && test "$1" = --version; then
    printf 'cc:version\n' >>"$MOCK_CASE/trace"
    printf 'mock GCC compiler\n'
    exit 0
fi
compile=0
output=
while test "$#" -gt 0; do
    case $1 in
        -c) compile=1 ;;
        -o) shift; output=$1 ;;
    esac
    shift
done
test "$compile" = 1 && test -n "$output" || exit 98
printf 'cc:compile\n' >>"$MOCK_CASE/trace"
: >"$output"
EOF
cat >"$test_tmp/tools/fuzz" <<'EOF'
#!/bin/sh
set -eu
test "${FUZZ_WRAPPER_MOCK_ONLY:-}" = 1 || exit 99
# In particular, closed stdin must remain a failure in this synthetic run.
cat >/dev/null || exit 41
# Selection cases stop at the controlled CLI result before real fault oracles.
test -z "${ZUPT_FUZZ_IO_MODE:-}" || exit 98
EOF
cat >"$test_tmp/tools/cli" <<'EOF'
#!/bin/sh
set -eu
test "${FUZZ_WRAPPER_MOCK_ONLY:-}" = 1 || exit 99
printf '%s\n' "$0" >>"$MOCK_CASE/cli.paths"
case $1 in
    c)
        printf '%s\n' "$@" >"$MOCK_CASE/cli.create.args"
        test "$#" = 4 && test "$2" = -s && test -d "$4" || exit 98
        case $0 in
            */project/zupt)
                printf 'cli:fallback-create\n' >>"$MOCK_CASE/trace"
                exit 37
                ;;
        esac
        printf 'cli:create\n' >>"$MOCK_CASE/trace"
        test "$MOCK_CREATE_STATUS" = 0 || exit "$MOCK_CREATE_STATUS"
        printf 'synthetic archive seed\n' >"$3"
        ;;
    t)
        printf '%s\n' "$@" >"$MOCK_CASE/cli.test.args"
        test "$#" = 2 && test -s "$2" || exit 98
        printf 'cli:test\n' >>"$MOCK_CASE/trace"
        exit "$MOCK_TEST_STATUS"
        ;;
    *) exit 98 ;;
esac
EOF
cat >"$test_tmp/tools/make" <<'EOF'
#!/bin/sh
set -eu
test "${FUZZ_WRAPPER_MOCK_ONLY:-}" = 1 || exit 99
call=1
if test -f "$MOCK_CASE/make.count"; then
    call=$(($(cat "$MOCK_CASE/make.count") + 1))
fi
printf '%s\n' "$call" >"$MOCK_CASE/make.count"
printf '%s\n' "$@" >"$MOCK_CASE/make.$call.args"
project=
targets=
while test "$#" -gt 0; do
    case $1 in
        -C) shift; project=$1 ;;
        -*|*=*) ;;
        *)
            targets=${targets:+$targets }$1
            ;;
    esac
    shift
done
test -d "$project" || exit 98
printf 'make:%s\n' "$targets" >>"$MOCK_CASE/trace"
if test "$call" = 1 && test "$MOCK_MAKE_STATUS" != 0; then
    exit "$MOCK_MAKE_STATUS"
fi
case $targets in
    'fuzz-build'|'fuzz-build all')
        cp "$MOCK_TOOLS/fuzz" "$project/fuzz_decompress"
        cp "$MOCK_TOOLS/fuzz" "$project/fuzz_vv_decompress"
        chmod +x "$project/fuzz_decompress" "$project/fuzz_vv_decompress"
        if test "$targets" = 'fuzz-build all'; then
            cp "$MOCK_TOOLS/cli" "$project/zupt"
            chmod +x "$project/zupt"
        fi
        ;;
    fuzz_vv_decompress|fuzz_decompress)
        cp "$MOCK_TOOLS/fuzz" "$project/$targets"
        chmod +x "$project/$targets"
        ;;
    *) exit 98 ;;
esac
EOF
cat >"$test_tmp/path-decoy/local-cli" <<'EOF'
#!/bin/sh
printf 'cli:PATH-decoy\n' >>"$MOCK_CASE/trace"
exit 89
EOF
cp "$test_tmp/tools/cli" "$test_tmp/cli with spaces/zupt"
chmod +x "$test_tmp/tools/cc" "$test_tmp/tools/make" \
    "$test_tmp/cli with spaces/zupt" "$test_tmp/path-decoy/local-cli"

fail() {
    printf 'FAIL: %s: %s\n' "$test_name" "$*" >&2
    if test -f "$test_case/output.log"; then
        cat "$test_case/output.log" >&2
    fi
    exit 1
}

run_case() {
    test_name=$1
    test_case=$test_tmp/$test_name
    mkdir "$test_case"
    : >"$test_case/trace"
    cp "$test_tmp/tools/cli" "$test_case/local-cli"
    chmod +x "$test_case/local-cli"
    : >"$test_case/nonexecutable"
    chmod 644 "$test_case/nonexecutable"
    mkdir "$test_case/directory"
    test_status=0
    (
        unset FUZZ_TEST_CLI
        case $2 in
            unset) ;;
            absolute) FUZZ_TEST_CLI=$test_tmp/'cli with spaces/zupt' ;;
            relative) FUZZ_TEST_CLI=local-cli ;;
            empty) FUZZ_TEST_CLI= ;;
            missing) FUZZ_TEST_CLI=$test_case/missing ;;
            nonexecutable) FUZZ_TEST_CLI=$test_case/nonexecutable ;;
            directory) FUZZ_TEST_CLI=$test_case/directory ;;
            *) exit 98 ;;
        esac
        if test "$2" != unset; then export FUZZ_TEST_CLI; fi
        CC=$test_tmp/tools/cc
        MAKE=$test_tmp/tools/make
        MOCK_TOOLS=$test_tmp/tools
        MOCK_CASE=$test_case
        MOCK_MAKE_STATUS=${3:-0}
        MOCK_CREATE_STATUS=${4:-0}
        MOCK_TEST_STATUS=${5:-0}
        FUZZ_WRAPPER_MOCK_ONLY=1
        CFLAGS=-O0
        CPPFLAGS=
        LDLIBS=
        PATH=$test_tmp/path-decoy:$PATH
        export CC MAKE MOCK_TOOLS MOCK_CASE MOCK_MAKE_STATUS \
            MOCK_CREATE_STATUS MOCK_TEST_STATUS FUZZ_WRAPPER_MOCK_ONLY \
            CFLAGS CPPFLAGS LDLIBS PATH
        cd "$test_case"
        sh "$test_root/tests/test_fuzz_build.sh"
    ) >"$test_case/output.log" 2>&1 || test_status=$?
}

assert_status() {
    test "$test_status" = "$1" || fail "expected exit $1, got $test_status"
}

assert_trace() {
    printf '%s\n' "$1" >"$test_case/trace.expected"
    if ! cmp -s "$test_case/trace.expected" "$test_case/trace"; then
        diff -u "$test_case/trace.expected" "$test_case/trace" >&2 || :
        fail 'unexpected command order or selected CLI'
    fi
}

assert_targets() {
    make_call=$1
    shift
    sed -n '/^fuzz-build$/p; /^all$/p; /^fuzz_vv_decompress$/p; /^fuzz_decompress$/p' \
        "$test_case/make.$make_call.args" >"$test_case/targets.actual"
    printf '%s\n' "$@" >"$test_case/targets.expected"
    cmp -s "$test_case/targets.expected" "$test_case/targets.actual" || \
        fail "unexpected targets in make invocation $make_call"
}

assert_builds() {
    assert_targets 1 fuzz-build "$@"
    assert_targets 2 fuzz_vv_decompress
    assert_targets 3 fuzz_decompress
    test "$(cat "$test_case/make.count")" = 3 || fail 'unexpected extra build'
}

assert_cli_args() {
    project=$(sed -n '2p' "$test_case/make.1.args")
    seed_root=${project%/project}
    printf '%s\n' c -s "$seed_root/seed.zupt" "$seed_root/input" \
        >"$test_case/cli.create.expected"
    cmp -s "$test_case/cli.create.expected" "$test_case/cli.create.args" || \
        fail 'seed creation arguments were split or changed'
    if test "$2" = test; then
        printf '%s\n' t "$seed_root/seed.zupt" >"$test_case/cli.test.expected"
        cmp -s "$test_case/cli.test.expected" "$test_case/cli.test.args" || \
            fail 'seed test arguments were split or changed'
        printf '%s\n' "$1" "$1" >"$test_case/cli.paths.expected"
    else
        test ! -e "$test_case/cli.test.args" || fail 'tested seed after creation failed'
        printf '%s\n' "$1" >"$test_case/cli.paths.expected"
    fi
    cmp -s "$test_case/cli.paths.expected" "$test_case/cli.paths" || \
        fail 'CLI path was not the selected absolute executable'
}

build_trace='cc:version
make:fuzz-build
cc:compile
cc:compile
make:fuzz_vv_decompress
make:fuzz_decompress'

# With no override, the nested build must retain all and its local CLI.
run_case fallback unset
assert_status 37
assert_trace 'cc:version
make:fuzz-build all
cc:compile
cc:compile
make:fuzz_vv_decompress
make:fuzz_decompress
cli:fallback-create'
assert_builds all
project=$(sed -n '2p' "$test_case/make.1.args")
assert_cli_args "$project/zupt" create

# An absolute executable containing spaces replaces only the seed CLI.
run_case absolute absolute 0 0 24
assert_status 24
assert_trace "$build_trace
cli:create
cli:test"
assert_builds
assert_cli_args "$test_tmp/cli with spaces/zupt" test

# A bare relative name resolves against cwd even with a same-name PATH decoy.
run_case relative relative 0 0 24
assert_status 24
assert_trace "$build_trace
cli:create
cli:test"
assert_builds
assert_cli_args "$test_case/local-cli" test

# Every invalid explicit override fails before even compiler discovery.
for invalid in empty missing nonexecutable directory; do
    run_case "invalid-$invalid" "$invalid"
    assert_status 1
    test ! -s "$test_case/trace" || fail 'ran a compiler, build or CLI before validation'
    test ! -e "$test_case/make.count" || fail 'attempted a build before validation'
    grep -F 'FUZZ_TEST_CLI' "$test_case/output.log" >/dev/null || \
        fail 'missing invalid-override diagnostic'
done

run_case make-failure absolute 29
assert_status 29
assert_trace 'cc:version
make:fuzz-build'
assert_targets 1 fuzz-build
test "$(cat "$test_case/make.count")" = 1 || fail 'continued after first build failed'

run_case create-failure absolute 0 23
assert_status 23
assert_trace "$build_trace
cli:create"
assert_builds
assert_cli_args "$test_tmp/cli with spaces/zupt" create

run_case test-failure absolute 0 0 24
assert_status 24
assert_trace "$build_trace
cli:create
cli:test"
assert_builds
assert_cli_args "$test_tmp/cli with spaces/zupt" test

printf 'PASS: fuzz-build CLI selection, validation, quoting and failure propagation\n'
