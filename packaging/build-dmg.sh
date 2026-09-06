#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

set -Eeuo pipefail

umask 022
export LC_ALL=C

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

[[ $(uname -s) == Darwin ]] || die 'DMG packages must be built and tested on macOS'

test_macos_binary() (
    set -Eeuo pipefail

    local candidate=$1 binary test_root archive_size
    if [[ $candidate == */* ]]; then
        [[ -x $candidate ]] || die "executable not found: $candidate"
        binary=$(cd "$(dirname "$candidate")" && pwd -P)/$(basename "$candidate")
    else
        binary=$(command -v "$candidate" || true)
        [[ -n $binary ]] || die "executable not found on PATH: $candidate"
    fi

    for command_name in cmp dd diff find grep shasum sort; do
        command -v "$command_name" >/dev/null 2>&1 || \
            die "required smoke-test command not found: $command_name"
    done

    test_root=$(mktemp -d "${TMPDIR:-/tmp}/zupt-macos-smoke.XXXXXX")
    trap 'chmod -R u+rwX "$test_root" 2>/dev/null || true; rm -rf "$test_root"' \
        EXIT HUP INT TERM
    mkdir -p "$test_root/input/subdir" "$test_root/output" \
        "$test_root/password-output" "$test_root/escape-output" "$test_root/outside"
    printf 'ZUPT macOS package smoke test\n' > "$test_root/input/text file.txt"
    printf 'conteúdo UTF-8\n' > "$test_root/input/subdir/café-安全.txt"
    : > "$test_root/input/empty file"
    dd if=/dev/urandom of="$test_root/input/subdir/random.bin" \
        bs=4096 count=8 >/dev/null 2>&1
    printf 'do-not-overwrite\n' > "$test_root/outside/sentinel"

    "$binary" --version > "$test_root/version.log" 2>&1
    grep -q '^zupt ' "$test_root/version.log"
    "$binary" --help > "$test_root/help.log" 2>&1
    grep -q '^Usage:' "$test_root/help.log"
    if "$binary" --definitely-invalid-option >/dev/null 2>&1; then
        die 'invalid option returned success'
    fi

    (
        cd "$test_root"
        "$binary" compress plain.zupt input
        "$binary" test plain.zupt
        "$binary" extract -o output plain.zupt
    )
    diff -r "$test_root/input" "$test_root/output/input"
    (
        cd "$test_root/input"
        find . -type f -exec shasum -a 256 {} \; | sort
    ) > "$test_root/original.sha256"
    (
        cd "$test_root/output/input"
        find . -type f -exec shasum -a 256 {} \; | sort
    ) > "$test_root/extracted.sha256"
    cmp "$test_root/original.sha256" "$test_root/extracted.sha256"

    (
        cd "$test_root"
        "$binary" compress -p 'ZUPT-test-password-2026!' \
            password.zupt 'input/text file.txt'
        "$binary" test -p 'ZUPT-test-password-2026!' password.zupt
        "$binary" extract -p 'ZUPT-test-password-2026!' \
            -o password-output password.zupt
    )
    cmp "$test_root/input/text file.txt" \
        "$test_root/password-output/input/text file.txt"
    if "$binary" extract -p incorrect-password -o "$test_root/wrong-password" \
        "$test_root/password.zupt" >/dev/null 2>&1; then
        die 'incorrect password returned success'
    fi

    archive_size=$(wc -c < "$test_root/plain.zupt")
    ((archive_size > 32)) || die 'archive unexpectedly small'
    dd if="$test_root/plain.zupt" of="$test_root/corrupt.zupt" bs=1 \
        count="$((archive_size - 17))" >/dev/null 2>&1
    if "$binary" test "$test_root/corrupt.zupt" >/dev/null 2>&1; then
        die 'truncated archive returned success'
    fi

    ln -s "$test_root/outside" "$test_root/escape-output/input"
    "$binary" extract -o "$test_root/escape-output" \
        "$test_root/plain.zupt" >/dev/null 2>&1 || true
    [[ $(<"$test_root/outside/sentinel") == do-not-overwrite ]] || \
        die 'extraction overwrote outside sentinel'
    [[ ! -e $test_root/outside/text\ file.txt && ! -e $test_root/outside/subdir ]] || \
        die 'extraction escaped through a destination symlink'

    [[ $(id -u) -ne 0 ]] || die 'macOS package smoke test unexpectedly ran as root'
    printf 'PASS: native macOS package functional test suite\n'
)

if [[ ${1:-} == --test-binary ]]; then
    (($# == 2)) || die 'usage: build-dmg.sh --test-binary PATH'
    test_macos_binary "$2"
    exit 0
elif (($# != 0)); then
    die 'usage: build-dmg.sh [--test-binary PATH]'
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

header_version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
version=${VERSION:-$header_version}
[[ -n $version && $version == "$header_version" ]] || \
    die "VERSION '$version' does not match include/zupt.h '$header_version'"
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid package version: $version"
native_arch=$(uname -m)
arch=${ARCH:-$native_arch}
[[ $arch == "$native_arch" ]] || \
    die "ARCH=$arch does not match the native macOS architecture $native_arch"

dist_dir=${DIST_DIR:-${TMPDIR:-/tmp}/zupt-release}
mkdir -p "$dist_dir"
dist_dir=$(cd "$dist_dir" && pwd -P)
output=$dist_dir/ZUPT-${version}-macOS-${arch}.dmg
[[ ! -e $output ]] || die "refusing to overwrite existing output: $output"

for command_name in make clang hdiutil otool plutil shasum; do
    command -v -- "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done
run_checks=${RUN_CHECKS:-1}
[[ $run_checks == 0 || $run_checks == 1 ]] || die 'RUN_CHECKS must be 0 or 1'
if [[ $run_checks == 1 ]]; then
    command -v git >/dev/null 2>&1 || die 'git is required when RUN_CHECKS=1'
fi

jobs=${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || printf '1')}
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-dmg.XXXXXXXX")
app=$work/ZUPT.app
contents=$app/Contents
dmg_root=$work/dmg-root
dmg_tmp=$work/$(basename "$output")
mkdir -p "$contents/MacOS" "$contents/Resources" "$dmg_root"

cleanup() {
    make -C "$repo_root" clean >/dev/null 2>&1 || true
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

printf '[dmg] source-only build of ZUPT %s (%s)\n' "$version" "$arch"
make clean
make -j"$jobs" CC=clang V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0
if [[ $run_checks == 1 ]]; then
    make CC=clang V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 check
fi
test_macos_binary "$repo_root/zupt"

install -m 0755 zupt "$contents/MacOS/zupt"
for document in README.md README.pt-BR.md DOCUMENTACAO.pt-BR.md CHANGELOG.md LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 NOTICE THIRD-PARTY-NOTICES.md; do
    [[ ! -f $document ]] || install -m 0644 "$document" "$contents/Resources/"
done

if otool -l "$contents/MacOS/zupt" | grep -q 'cmd LC_RPATH'; then
    otool -l "$contents/MacOS/zupt" >&2
    die 'macOS executable contains LC_RPATH'
fi
if otool -L "$contents/MacOS/zupt" | grep -Eqi \
    '(vendor/|libvuptsdk|libpqvaptvupt|/home/|/Users/[^/]+/|/opt/(homebrew|local)/|/usr/local/)'; then
    otool -L "$contents/MacOS/zupt" >&2
    die 'macOS executable references a build path or vendored optional library'
fi

cat > "$contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>dev.zupt.cli</string>
  <key>CFBundleName</key><string>ZUPT</string>
  <key>CFBundleDisplayName</key><string>ZUPT</string>
  <key>CFBundleExecutable</key><string>zupt</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
</dict>
</plist>
EOF
plutil -lint "$contents/Info.plist"

if [[ -n ${CODESIGN_IDENTITY:-} ]]; then
    codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$app"
    codesign --verify --deep --strict "$app"
fi

cp -R "$app" "$dmg_root/ZUPT.app"
cat > "$dmg_root/Install ZUPT.command" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
installer_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source_binary=$installer_dir/ZUPT.app/Contents/MacOS/zupt
target_dir=/usr/local/bin
if [[ ! -d $target_dir || ! -w $target_dir ]]; then
    target_dir=${XDG_BIN_HOME:-$HOME/.local/bin}
    mkdir -p "$target_dir"
fi
install -m 0755 "$source_binary" "$target_dir/zupt"
printf 'Installed %s\n' "$target_dir/zupt"
"$target_dir/zupt" --version
EOF
chmod 0755 "$dmg_root/Install ZUPT.command"
for document in README.md README.pt-BR.md DOCUMENTACAO.pt-BR.md CHANGELOG.md LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 NOTICE THIRD-PARTY-NOTICES.md; do
    [[ ! -f $document ]] || install -m 0644 "$document" "$dmg_root/"
done

hdiutil create -fs HFS+ -srcfolder "$dmg_root" -volname "ZUPT $version" \
    -format UDZO -ov "$dmg_tmp"
hdiutil verify "$dmg_tmp"

mv "$dmg_tmp" "$output"
shasum -a 256 "$output"
printf 'PASS: built and native-binary-tested %s\n' "$output"
