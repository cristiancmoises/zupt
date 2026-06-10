#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Sprint 2.4.4 regression test: `make dist` reproducibility.
#
# Asserts that running `make dist` twice on the same source tree
# produces byte-identical tarballs (same sha256, same size). This is
# the foundational property for downstream Debian / AUR / Homebrew
# packaging — without it, distros can't pin a sha256 for the source
# tarball in their recipes.
#
# Also asserts that the dist tarball contains the right things:
#   - source code (src/, include/, tests/)
#   - the three libzuptsdk symlinks + the real .so file
#   - no built binaries (zupt, test_vectors, *.o)
#   - no .git/ tree
#
# Exit non-zero on first failure.

set -u

PASS=0
FAIL=0
P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

# Run from the project root regardless of where the test was invoked.
cd "$(dirname "$0")/.."

# 1. First dist build
make dist >/tmp/dist1.log 2>&1
RC=$?
if [ $RC -ne 0 ]; then
    echo "  ✗ make dist failed on first run; see /tmp/dist1.log"
    tail -10 /tmp/dist1.log
    exit 1
fi
VERSION=$(grep '^#define ZUPT_VERSION_STRING' include/zupt.h | awk -F'"' '{print $2}')
# v3.0.0: TARGET=vaptvupt, so the tarball is now /tmp/vaptvupt-${VERSION}.tar.gz.
# Test both possible filenames so this works on any future rename.
TARBALL="/tmp/vaptvupt-${VERSION}.tar.gz"
[ ! -f "$TARBALL" ] && TARBALL="/tmp/zupt-${VERSION}.tar.gz"
# Derive top-level dir inside the tarball from the filename
TARBALL_BASE=$(basename "$TARBALL" .tar.gz)   # e.g. vaptvupt-3.0.0
if [ ! -f "$TARBALL" ]; then
    echo "  ✗ expected $TARBALL not produced"
    exit 1
fi
P "first make dist produced $TARBALL"
SHA1=$(sha256sum "$TARBALL" | awk '{print $1}')
SIZE1=$(wc -c < "$TARBALL")
cp "$TARBALL" "${TARBALL%.tar.gz}.first.tar.gz"

# 2. Second dist build — should produce byte-identical tarball
make dist >/tmp/dist2.log 2>&1
RC=$?
if [ $RC -ne 0 ]; then
    echo "  ✗ make dist failed on second run; see /tmp/dist2.log"
    tail -10 /tmp/dist2.log
    exit 1
fi
SHA2=$(sha256sum "$TARBALL" | awk '{print $1}')
SIZE2=$(wc -c < "$TARBALL")
if [ "$SHA1" = "$SHA2" ]; then
    P "byte-identical sha256 across two runs: $SHA1"
else
    F "sha256 diverged: $SHA1 vs $SHA2"
fi
if [ "$SIZE1" = "$SIZE2" ]; then
    P "byte-identical size: $SIZE1"
else
    F "size diverged: $SIZE1 vs $SIZE2"
fi

# 3. Content checks
NUM_FILES=$(tar tzf "$TARBALL" | wc -l)
if [ "$NUM_FILES" -gt 100 ]; then
    P "tarball has $NUM_FILES entries (sanity: > 100)"
else
    F "tarball suspiciously small: $NUM_FILES entries"
fi

if tar tzf "$TARBALL" | grep -q "${TARBALL_BASE}/src/zupt_format.c"; then
    P "src/zupt_format.c present"
else
    F "src/zupt_format.c missing"
fi

if tar tzf "$TARBALL" | grep -q "${TARBALL_BASE}/include/zupt.h"; then
    P "include/zupt.h present"
else
    F "include/zupt.h missing"
fi

# All three libzuptsdk variants
SO_REAL=$(tar tzf "$TARBALL" | grep -c "libzuptsdk.so.2.0.0$")
SO_LINKS=$(tar tzf "$TARBALL" | grep -cE "libzuptsdk.so$|libzuptsdk.so.2$")
if [ "$SO_REAL" = "1" ] && [ "$SO_LINKS" = "2" ]; then
    P "libzuptsdk: 1 real .so + 2 symlinks"
else
    F "libzuptsdk shipping wrong: real=$SO_REAL links=$SO_LINKS (expected 1 + 2)"
fi

# No built binaries (vaptvupt or legacy zupt symlink or test_* harnesses)
if tar tzf "$TARBALL" | grep -qE "(vaptvupt|zupt)-${VERSION}/(vaptvupt|zupt)(\$|_asan\$)|(vaptvupt|zupt)-${VERSION}/test_vectors\$|(vaptvupt|zupt)-${VERSION}/test_vaptvupt\$"; then
    F "tarball contains built binaries"
else
    P "tarball contains no built binaries"
fi

# No .o files
if tar tzf "$TARBALL" | grep -qE "\.o$"; then
    F "tarball contains stale .o files"
else
    P "tarball contains no .o files"
fi

# No .git
if tar tzf "$TARBALL" | grep -q "\.git/"; then
    F "tarball contains .git/ tree"
else
    P "tarball contains no .git/ tree"
fi

# 4. Build & smoke-test from the dist tarball
WORK=$(mktemp -d)
( cd "$WORK" && tar xzf "$TARBALL" && cd "${TARBALL_BASE}" && make -j"$(nproc)" >/tmp/distbuild.log 2>&1 ) || {
    F "build from dist tarball failed; see /tmp/distbuild.log"
    rm -rf "$WORK"
    [ "$FAIL" = 0 ] || exit 1
}
# v3.0.0: binary may be named `vaptvupt` (default) or legacy `zupt`.
# Pick whichever the dist-tarball build produced.
DISTBIN=""
for cand in vaptvupt zupt; do
    if [ -x "$WORK/${TARBALL_BASE}/$cand" ]; then DISTBIN="$WORK/${TARBALL_BASE}/$cand"; break; fi
done
if [ -n "$DISTBIN" ]; then
    P "binary builds from dist tarball ($(basename "$DISTBIN"))"
    "$DISTBIN" version > /tmp/distver.txt 2>&1
    if grep -q "$VERSION" /tmp/distver.txt; then
        P "built binary reports correct version ($VERSION)"
    else
        F "binary version mismatch: $(cat /tmp/distver.txt)"
    fi
else
    F "no binary produced from dist build"
fi
rm -rf "$WORK"

# Cleanup
rm -f "/tmp/zupt-${VERSION}.first.tar.gz"

echo ""
echo "  ───────────────────────────────────────"
echo "  dist reproducibility: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
