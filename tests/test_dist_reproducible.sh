#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

set -Eeuo pipefail

export LC_ALL=C
umask 077

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' "$root/include/zupt.h")
[[ -n $version ]] || { printf 'FAIL: cannot determine version\n' >&2; exit 1; }

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf 'FAIL: sha256sum or shasum is required\n' >&2
        return 1
    fi
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-dist-test.XXXXXXXX")
trap 'chmod -R u+rwX "$tmp" 2>/dev/null || true; rm -rf -- "$tmp"' EXIT HUP INT TERM

first=$tmp/zupt-$version.first.tar.gz
second=$tmp/zupt-$version.second.tar.gz

make -C "$root" DIST_TARBALL="$first" dist
make -C "$root" DIST_TARBALL="$second" dist

first_sha=$(sha256_file "$first")
second_sha=$(sha256_file "$second")
[[ $first_sha == "$second_sha" ]] || {
    printf 'FAIL: source archive hashes differ: %s %s\n' "$first_sha" "$second_sha" >&2
    exit 1
}
cmp -- "$first" "$second"
printf 'PASS: two source archives are byte-identical (%s)\n' "$first_sha"

# Git adds the archived commit ID to a PAX header when given a commit object.
# Exercise the real dist rule in an isolated repository and prove that changing
# only an export-ignored checksum recipe cannot perturb the release tarball.
ignored_repo=$tmp/export-ignored-repo
mkdir -p "$ignored_repo/include" "$ignored_repo/packaging/homebrew" \
    "$ignored_repo/sdk"
cp -- "$root/Makefile" "$ignored_repo/Makefile"
cp -- "$root/include/zupt.h" "$ignored_repo/include/zupt.h"
cp -- "$root/sdk/Makefile.sdk" "$ignored_repo/sdk/Makefile.sdk"
printf '/packaging/homebrew/** export-ignore\n' >"$ignored_repo/.gitattributes"
printf '1788134400\n' >"$ignored_repo/.source-date-epoch"
printf '#!/usr/bin/env bash\nexit 0\n' >"$ignored_repo/source-audit.sh"
printf 'normal exported source\n' >"$ignored_repo/source.txt"
printf 'sha256 "REPLACE_AFTER_FINAL_RELEASE_ARCHIVE_IS_BUILT"\n' \
    >"$ignored_repo/packaging/homebrew/zupt.rb"
chmod +x "$ignored_repo/source-audit.sh"
git -C "$ignored_repo" init -q
git -C "$ignored_repo" add -- .
git -C "$ignored_repo" -c user.name='ZUPT release test' \
    -c user.email='release-test@invalid.example' commit -qm 'initial source'

ignored_first=$tmp/export-ignored.first.tar.gz
ignored_second=$tmp/export-ignored.second.tar.gz
make -C "$ignored_repo" --no-print-directory \
    SOURCE_AUDIT=source-audit.sh DIST_TARBALL="$ignored_first" dist
printf 'sha256 "final-release-digest"\n' \
    >"$ignored_repo/packaging/homebrew/zupt.rb"
git -C "$ignored_repo" add -- packaging/homebrew/zupt.rb
git -C "$ignored_repo" -c user.name='ZUPT release test' \
    -c user.email='release-test@invalid.example' commit -qm 'pin release checksum'
make -C "$ignored_repo" --no-print-directory \
    SOURCE_AUDIT=source-audit.sh DIST_TARBALL="$ignored_second" dist
cmp -- "$ignored_first" "$ignored_second" || {
    printf 'FAIL: export-ignored-only commit changed source archive bytes\n' >&2
    exit 1
}
printf 'PASS: export-ignored-only commit leaves source archive byte-identical (%s)\n' \
    "$(sha256_file "$ignored_first")"

bash "$root/scripts/check-source-only.sh" --archive "$first"

members_file=$tmp/archive-members.txt
tar -tzf "$first" >"$members_file"
member_count=$(wc -l <"$members_file")
((member_count > 100)) || { printf 'FAIL: source archive has too few entries\n' >&2; exit 1; }
prefix=zupt-$version/
for required in src/zupt_main.c include/zupt.h Makefile scripts/check-source-only.sh; do
    grep -Fxq "$prefix$required" "$members_file" || {
        printf 'FAIL: source archive is missing %s\n' "$required" >&2
        exit 1
    }
done
if grep -Eq '/(\.git|build|dist|out|target)(/|$)' "$members_file"; then
    printf 'FAIL: source archive contains an internal/generated directory\n' >&2
    exit 1
fi
printf 'PASS: source archive layout and required sources\n'

tar -xzf "$first" -C "$tmp"
tree=$tmp/zupt-$version
bash "$tree/scripts/check-source-only.sh" --tree "$tree"
make -C "$tree" clean
make -C "$tree" -j"${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 2)}" \
    WITH_SDK=0 WITH_PQBOX=0 V=1
make -C "$tree" WITH_SDK=0 WITH_PQBOX=0 check
bash "$tree/scripts/test-installed-zupt.sh" "$tree/zupt"
make -C "$tree" clean
bash "$tree/scripts/check-source-only.sh" --tree "$tree"
printf 'PASS: clean source archive builds, checks and passes the functional smoke test\n'
