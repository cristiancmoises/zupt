#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

set -Eeuo pipefail
export LC_ALL=C

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

pass_count=0
fail_count=0
skip_count=0
pass() { pass_count=$((pass_count + 1)); printf 'PASS: %s\n' "$*"; }
fail() { fail_count=$((fail_count + 1)); printf 'FAIL: %s\n' "$*" >&2; }
skip() { skip_count=$((skip_count + 1)); printf 'SKIP: %s\n' "$*"; }

has_exact_line_crlf_safe() {
    local expected=$1 path=$2 line
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        if [[ $line == "$expected" ]]; then
            return 0
        fi
    done < "$path"
    return 1
}

version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
[[ -n $version ]] || { printf 'FAIL: cannot determine upstream version\n' >&2; exit 1; }

for script in packaging/build-deb.sh packaging/build-rpm.sh \
    packaging/build-appimage.sh packaging/build-gui-appimage.sh \
    packaging/build-gui-deb.sh packaging/build-gui-rpm.sh \
    gui/packaging/appimage/build-appimage.sh packaging/build-dmg.sh \
    scripts/check-source-only.sh scripts/export-opensuse-package.sh \
    scripts/test-installed-zupt.sh packaging/opensuse/source-audit.sh; do
    if bash -n "$script"; then pass "$script shell syntax"; else fail "$script shell syntax"; fi
done

if ! command -v make >/dev/null 2>&1; then
    skip 'make unavailable for Debian rules syntax'
elif make -n -f packaging/debian/rules override_dh_auto_build >/dev/null; then
    pass 'Debian rules make syntax'
else
    fail 'Debian rules make syntax'
fi

check_recipe_version() {
    local recipe=$1 recipe_version=$2
    if [[ $recipe_version == "$version" ]]; then
        pass "$recipe version is $version"
    else
        fail "$recipe version is '$recipe_version' (expected $version)"
    fi
}

check_recipe_version AUR \
    "$(sed -n 's/^pkgver=//p' packaging/aur/PKGBUILD)"
check_recipe_version Debian \
    "$(sed -n '1s/^zupt (\([^-]*\)-.*/\1/p' packaging/debian/changelog)"
check_recipe_version Fedora \
    "$(awk '/^Version:/{print $2; exit}' packaging/rpm/zupt.spec)"
check_recipe_version Homebrew \
    "$(sed -n 's/^[[:space:]]*version "\([^"]*\)".*/\1/p' packaging/homebrew/zupt.rb)"
check_recipe_version Nix \
    "$(sed -n 's/^[[:space:]]*version = "\([^"]*\)";.*/\1/p' packaging/nix/flake.nix | head -1)"
check_recipe_version Guix \
    "$(sed -n 's/^(define %zupt-version "\([^"]*\)")/\1/p' packaging/guix/zupt.scm)"
check_recipe_version openSUSE \
    "$(awk '/^Version:/{print $2; exit}' packaging/opensuse/zupt.spec)"
check_recipe_version GUI-Deb-Control \
    "$(awk '/^Version:/{print $2; exit}' gui/packaging/deb/control)"

if grep -Fqx "VERSION=\${VERSION:-$version}" install.sh && \
   has_exact_line_crlf_safe \
       "if not defined VERSION set \"VERSION=$version\"" \
       gui/packaging/windows/build-windows.bat && \
   grep -Fqx "Depends: python3 (>= 3.9), python3-pyqt6 | python3-pyside6.qtwidgets, zupt (= $version)" \
       gui/packaging/deb/control; then
    pass 'installer and static GUI package defaults match the upstream version'
else
    fail 'installer or static GUI package defaults do not match the upstream version'
fi

if grep -En 'REPLACE_AFTER|REPLACE_WITH|sha256sums=\(.SKIP.|base32 .REPLACE' \
    packaging/aur/PKGBUILD packaging/homebrew/zupt.rb packaging/guix/zupt.scm; then
    if git tag --points-at HEAD 2>/dev/null | grep -Fxq "v$version"; then
        fail 'tagged release recipes contain an unpinned source checksum'
    else
        pass 'release recipe checksums are explicitly pending final archive generation'
    fi
else
    pass 'release recipe source checksums are pinned'
fi

if [[ -x packaging/debian/rules ]]; then
    pass 'Debian rules is executable'
else
    fail 'Debian rules is not executable'
fi
if command -v dpkg-parsechangelog >/dev/null 2>&1; then
    if dpkg-parsechangelog -l packaging/debian/changelog >/dev/null; then
        pass 'Debian changelog parses'
    else
        fail 'Debian changelog does not parse'
    fi
else
    skip 'dpkg-parsechangelog unavailable'
fi

if command -v ruby >/dev/null 2>&1; then
    if ruby -c packaging/homebrew/zupt.rb >/dev/null; then
        pass 'Homebrew formula Ruby syntax'
    else
        fail 'Homebrew formula Ruby syntax'
    fi
else
    skip 'Ruby unavailable for Homebrew syntax'
fi

if command -v nix-instantiate >/dev/null 2>&1; then
    if nix-instantiate --parse packaging/nix/flake.nix >/dev/null; then
        pass 'Nix flake syntax'
    else
        fail 'Nix flake syntax'
    fi
else
    skip 'nix-instantiate unavailable for flake syntax'
fi

if command -v guile >/dev/null 2>&1; then
    if guile -c '(use-modules (guix gexp)) (call-with-input-file "packaging/guix/zupt.scm" (lambda (p) (let loop ((x (read p))) (unless (eof-object? x) (loop (read p))))))'; then
        pass 'Guix recipe reader syntax'
    else
        fail 'Guix recipe reader syntax'
    fi
else
    skip 'Guile unavailable for Guix syntax'
fi

if command -v xmllint >/dev/null 2>&1; then
    if xmllint --noout packaging/opensuse/_service; then
        pass 'openSUSE service XML'
    else
        fail 'openSUSE service XML'
    fi
elif python3 -c 'import xml.etree.ElementTree as E; E.parse("packaging/opensuse/_service")' 2>/dev/null; then
    pass 'openSUSE service XML (Python parser)'
else
    fail 'openSUSE service XML'
fi

service=packaging/opensuse/_service
spec=packaging/opensuse/zupt.spec
if grep -Fq '<service name="obs_scm"' "$service" && \
   grep -Fq '<param name="url">https://github.com/cristiancmoises/zupt.git</param>' "$service" && \
   grep -Fq "<param name=\"revision\">refs/tags/v$version</param>" "$service" && \
   grep -Fq '<param name="submodules">disable</param>' "$service" && \
   grep -Fq '<param name="lfs">disable</param>' "$service" && \
   grep -Fq '<service name="tar" mode="buildtime"' "$service" && \
   grep -Fq '<service name="recompress" mode="buildtime"' "$service"; then
    pass 'openSUSE services use canonical immutable source-only input'
else
    fail 'openSUSE services do not use the required immutable source-only input'
fi

if grep -Fq 'APPIMAGE_RUNTIME_COMPLIANCE_FILE' packaging/build-appimage.sh && \
   grep -Fq 'APPIMAGE_RUNTIME_COMPLIANCE_FILE' packaging/build-gui-appimage.sh && \
   grep -Fq 'AppImage-runtime-compliance.txt' packaging/build-appimage.sh && \
   grep -Fq 'AppImage-runtime-compliance.txt' packaging/build-gui-appimage.sh; then
    pass 'AppImage helpers require and bundle external compliance evidence'
else
    fail 'AppImage helper compliance policy is incomplete'
fi

if ! grep -Eiq 'release-appimage|appimagetool|APPIMAGE_RUNTIME_FILE|[.]AppImage' \
        .github/workflows/ci.yml .github/workflows/cross-platform.yml \
        .github/workflows/promote-release.yml; then
    pass 'release workflows do not build or promote AppImage assets'
else
    fail 'a release workflow still builds or promotes an AppImage asset'
fi

if grep -Fq 'archive declared-size limit exceeded before extraction' scripts/check-source-only.sh && \
   grep -Fq 'global archive declared-size budget exceeded' scripts/check-source-only.sh && \
   grep -Fq 'SOURCE_AUDIT_ARCHIVE_SECONDS' scripts/check-source-only.sh && \
   grep -Fq 'compressed archive declared size is rejected before extraction' tests/test_source_only.sh; then
    pass 'source scanner bounds archive members, expansion and CPU time before extraction'
else
    fail 'source scanner archive resource bounds or regressions are incomplete'
fi

tumbleweed_job=$(sed -n '/^  tumbleweed-rpm:/,/^  gui-rpm-package:/p' \
    .github/workflows/ci.yml)
fedora_gui_job=$(sed -n '/^  gui-rpm-package:/,/^  linux-portable:/p' \
    .github/workflows/ci.yml)
# These matches intentionally assert the literal Actions variable in YAML.
# shellcheck disable=SC2016
if grep -Fq 'git config --global --add safe.directory "$GITHUB_WORKSPACE"' \
        <<<"$tumbleweed_job" && \
   grep -Fq 'if rpm -q busybox-gawk >/dev/null 2>&1; then' \
        <<<"$tumbleweed_job" && \
   grep -Fq 'zypper --non-interactive remove busybox-gawk' \
        <<<"$tumbleweed_job" && \
   grep -Fq 'git config --global --add safe.directory "$GITHUB_WORKSPACE"' \
        <<<"$fedora_gui_job"; then
    pass 'RPM container jobs trust the exact workspace and replace busybox-gawk'
else
    fail 'RPM container workspace trust or busybox-gawk replacement is incomplete'
fi

# These are literal shell expressions required inside the promotion workflow.
# shellcheck disable=SC2016
if grep -Fq 'zupt-gui_${VERSION}_all.deb' .github/workflows/promote-release.yml && \
   grep -Fq 'zupt-gui-$VERSION-1.noarch.rpm' .github/workflows/promote-release.yml && \
   grep -Fq 'zupt-gui-$VERSION-1.src.rpm' .github/workflows/promote-release.yml && \
   grep -Fq 'zupt-$VERSION-linux-x86_64.tar.xz' .github/workflows/promote-release.yml && \
   grep -Fq 'zupt-gui-$VERSION-portable.zip' .github/workflows/promote-release.yml && \
   grep -Fq 'zupt >= $VERSION' .github/workflows/promote-release.yml; then
    pass 'release promotion allowlists gated CLI and GUI package formats'
else
    fail 'release promotion is missing a gated package format or dependency check'
fi

if ! grep -Eqi 'git[.]securityops[.]co|forgejo|canonical server|GitHub mirror' \
        .github/workflows/promote-release.yml && \
   grep -Fq 'GitHub is the canonical upstream release' \
        .github/workflows/promote-release.yml; then
    pass 'GitHub is the sole canonical release target'
else
    fail 'release promotion still depends on a non-GitHub canonical forge'
fi

if grep -Fq 'path: out/*.zip' .github/workflows/cross-platform.yml && \
   ! grep -Fq 'out/*.exe' .github/workflows/cross-platform.yml && \
   grep -Fq 'windows_zip_name=' .github/workflows/promote-release.yml && \
   ! grep -Fq 'windows_exe_name=' .github/workflows/promote-release.yml; then
    pass 'Windows release policy promotes the notice-bearing ZIP only'
else
    fail 'Windows workflow still permits a bare EXE release asset'
fi

windows_notices_ok=1
for notice in MINGW-CRT-COPYING.txt COPYING.MinGW-w64-runtime.txt \
    COPYING.MinGW-w64.txt GCC-COPYING3.txt \
    GCC-RUNTIME-LIBRARY-EXCEPTION.txt; do
    grep -Fq "$notice" .github/workflows/cross-platform.yml || \
        windows_notices_ok=0
    grep -Fq "$notice" .github/workflows/promote-release.yml || \
        windows_notices_ok=0
done
if ((windows_notices_ok)); then
    pass 'static Windows bundle preserves MinGW and GCC runtime notices'
else
    fail 'static Windows bundle omits MinGW or GCC runtime notices'
fi

if grep -Eiq 'AppImage.*(not|excluded|outside)' SECURITY.md && \
   grep -Eiq 'AppImage.*(not|excluded|outside)' THREAT_MODEL.md && \
   grep -Eiq 'AppImage.*(not|excluded|outside)' AUDIT.md && \
   grep -Eiq 'AppImage.*(not|excluded|outside)' doc/zupt.1; then
    pass 'current security and user documentation records release exclusions'
else
    fail 'current documentation still permits an AppImage or bare EXE claim'
fi

handoff_legal_ok=1
for legal_file in LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-COMMERCIAL \
    LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 \
    NOTICE THIRD-PARTY-NOTICES.md; do
    grep -Fq "$legal_file" scripts/export-opensuse-package.sh || \
        handoff_legal_ok=0
done
if ((handoff_legal_ok)) && \
   grep -Fq 'handoff legal file is missing or empty' scripts/export-opensuse-package.sh; then
    pass 'openSUSE handoff includes and checks complete public legal payload'
else
    fail 'openSUSE handoff omits or does not validate a public legal file'
fi

if grep -Fq 'PYTHON-NOTICE.txt' gui/packaging/windows/build-windows.bat && \
   grep -Fq 'PYINSTALLER-NOTICE.txt' gui/packaging/windows/build-windows.bat && \
   grep -Fq 'QT-NOTICE.txt' gui/packaging/windows/build-windows.bat && \
   grep -Fq 'PYSIDE6-NOTICE.txt' gui/packaging/windows/build-windows.bat && \
   grep -Fq 'PYQT6-NOTICE.txt' gui/packaging/windows/build-windows.bat; then
    pass 'downstream Windows GUI helper requires every runtime notice class'
else
    fail 'downstream Windows GUI helper permits incomplete runtime notices'
fi

if grep -Eq '^Name:[[:space:]]+zupt$' "$spec" && \
   grep -Eq '^Source0:[[:space:]]+%\{name\}-%\{version\}\.tar\.gz$' "$spec" && \
   grep -Eq '^License:[[:space:]]+AGPL-3\.0-or-later AND GPL-3\.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND CC0-1\.0$' "$spec" && \
   grep -Eq '^Provides:[[:space:]]+bundled\(vaptvupt-codec\) = 2\.65\.3$' "$spec" && \
   grep -Eq '^Provides:[[:space:]]+vaptvupt = %\{version\}-%\{release\}$' "$spec" && \
   grep -Eq '^Obsoletes:[[:space:]]+vaptvupt < %\{version\}$' "$spec" && \
   grep -Fq 'WITH_SDK=0 WITH_PQBOX=0' "$spec" && \
   grep -Fq 'INSTALL_LEGACY_ALIAS=0' "$spec" && \
   grep -Fq 'INSTALL_LICENSES=0' "$spec" && \
   grep -Fq '%{_bindir}/zupt' "$spec" && \
   ! grep -Fq '%{_bindir}/vaptvupt' "$spec"; then
    pass 'openSUSE spec source, license, features and alias policy'
else
    fail 'openSUSE spec source, license, features or alias policy'
fi

if grep -Fq 'LICENSE-BSD-3-Clause' packaging/build-deb.sh && \
   grep -Fq 'LICENSE-CC0-1.0' packaging/build-deb.sh && \
   [[ $(grep -Fc 'LICENSE-BSD-3-Clause' packaging/build-dmg.sh) -ge 2 ]] && \
   [[ $(grep -Fc 'LICENSE-CC0-1.0' packaging/build-dmg.sh) -ge 2 ]] && \
   grep -Fq 'LICENSE-BSD-3-Clause' packaging/build-appimage.sh && \
   grep -Fq 'LICENSE-CC0-1.0' packaging/build-appimage.sh && \
   grep -Fq 'LICENSE-BSD-3-Clause' packaging/build-gui-appimage.sh && \
   grep -Fq 'LICENSE-CC0-1.0' packaging/build-gui-appimage.sh && \
   grep -Fq 'LICENSE-BSD-3-Clause' .github/workflows/cross-platform.yml && \
   grep -Fq 'LICENSE-CC0-1.0' .github/workflows/cross-platform.yml && \
   grep -Fq 'LICENSE-BSD-3-Clause' .github/workflows/promote-release.yml && \
   grep -Fq 'LICENSE-CC0-1.0' .github/workflows/promote-release.yml && \
   grep -Fq 'LICENSE-BSD-3-Clause' packaging/debian/zupt.docs && \
   grep -Fq 'LICENSE-CC0-1.0' packaging/debian/zupt.docs; then
    pass 'binary bundle paths preserve BSD-3-Clause and CC0-1.0 texts'
else
    fail 'a binary bundle path omits BSD-3-Clause or CC0-1.0 text'
fi

if grep -Fq 'LICENSE-BSD-3-Clause' gui/packaging/flatpak/dev.zupt.gui.yml && \
   grep -Fq 'LICENSE-CC0-1.0' gui/packaging/flatpak/dev.zupt.gui.yml && \
   grep -Fq 'ZUPT_WINDOWS_RUNTIME_NOTICES_DIR' gui/packaging/windows/build-windows.bat && \
   grep -Fq 'MANIFEST.txt' gui/packaging/windows/build-windows.bat && \
   grep -Fq 'LICENSE-BSD-3-Clause' packaging/windows/zupt-gui.iss && \
   grep -Fq 'LICENSE-CC0-1.0' packaging/windows/zupt-gui.iss && \
   grep -Fq 'RuntimeNoticesDir' packaging/windows/zupt-gui.iss && \
   grep -Fq 'LICENSE-BSD-3-Clause' sdk/Makefile.sdk && \
   grep -Fq 'LICENSE-CC0-1.0' sdk/Makefile.sdk && \
   grep -Fq 'LICENSE-BSD-3-Clause' packaging/homebrew/zupt.rb && \
   grep -Fq 'LICENSE-CC0-1.0' packaging/nix/flake.nix && \
   grep -Fq 'LICENSEDIR' Makefile && \
   grep -Fq 'LICENSE-BSD-3-Clause' Makefile && \
   grep -Fq 'LICENSE-GUI' gui/install.sh; then
    pass 'auxiliary bundles install project and external-runtime notices'
else
    fail 'an auxiliary bundle omits project or external-runtime notices'
fi

if command -v rpmspec >/dev/null 2>&1; then
    if rpmspec -P "$spec" >/dev/null; then
        pass 'openSUSE spec parses with rpmspec'
    else
        fail 'openSUSE spec rpmspec parse'
    fi
else
    skip 'rpmspec unavailable'
fi

if command -v shellcheck >/dev/null 2>&1; then
    shell_files=(
        packaging/build-deb.sh
        packaging/build-rpm.sh
        packaging/build-appimage.sh
        packaging/build-gui-appimage.sh
        packaging/build-gui-deb.sh
        packaging/build-gui-rpm.sh
        gui/packaging/appimage/build-appimage.sh
        packaging/build-dmg.sh
        packaging/opensuse/source-audit.sh
        scripts/check-source-only.sh
        scripts/export-opensuse-package.sh
        scripts/test-installed-zupt.sh
        tests/test_source_only.sh
        tests/test_packaging_syntax.sh
    )
    if shellcheck -x "${shell_files[@]}"; then
        pass 'ShellCheck tracked shell scripts'
    else
        fail 'ShellCheck tracked shell scripts'
    fi
else
    skip 'ShellCheck unavailable'
fi

for workflow in .github/workflows/*.yml; do
    if grep -Eq 'pull_request_target:' "$workflow"; then
        fail "$workflow uses pull_request_target"
    else
        pass "$workflow avoids pull_request_target"
    fi
    if grep -Eqi 'git[[:space:]]+push|credential\.helper[[:space:]]+store' "$workflow"; then
        fail "$workflow contains unsafe publishing command"
    else
        pass "$workflow avoids direct Git credential mutation"
    fi
done

printf 'SUMMARY: PASS=%d FAIL=%d SKIP=%d\n' "$pass_count" "$fail_count" "$skip_count"
((fail_count == 0))
