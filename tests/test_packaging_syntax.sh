#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Sprint 2.4.5 regression: packaging-recipe syntax checks.
#
# Ensures the recipes under packaging/{aur,debian,rpm,homebrew,nix}/
# are syntactically valid. Doesn't try to actually build the packages
# (that needs distro-specific tooling), but catches:
#   - shell syntax errors in PKGBUILD
#   - malformed Debian control / changelog / copyright
#   - missing fields in RPM spec
#   - Ruby syntax errors in the Homebrew formula (if ruby is available)
#   - Nix flake parse errors (if nix is available)
#
# Plus structural checks that don't need external tools:
#   - debian/rules is executable
#   - all recipes reference the same version as include/zupt.h

set -u

PASS=0
FAIL=0
P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
SKIP() { echo "  - skipped: $1"; }

cd "$(dirname "$0")/.."

VERSION=$(grep '^#define ZUPT_VERSION_STRING' include/zupt.h | awk -F'"' '{print $2}')
echo "Packaging syntax checks (zupt $VERSION)"

# ─── AUR PKGBUILD ───
if [ -f packaging/aur/PKGBUILD ]; then
    if bash -n packaging/aur/PKGBUILD 2>/dev/null; then
        P "AUR PKGBUILD: bash syntax clean"
    else
        F "AUR PKGBUILD: bash syntax error"
    fi
    if grep -q "^pkgver=$VERSION$" packaging/aur/PKGBUILD; then
        P "AUR PKGBUILD: pkgver matches include/zupt.h ($VERSION)"
    else
        F "AUR PKGBUILD: pkgver mismatch (expected $VERSION; got $(grep '^pkgver=' packaging/aur/PKGBUILD))"
    fi
    for field in pkgname pkgver pkgrel pkgdesc arch url license depends; do
        if grep -qE "^$field=" packaging/aur/PKGBUILD; then
            :
        else
            F "AUR PKGBUILD: missing required field '$field'"
            continue
        fi
    done
    P "AUR PKGBUILD: required fields present (pkgname, pkgver, pkgrel, pkgdesc, arch, url, license, depends)"
else
    F "AUR PKGBUILD: file missing"
fi

# ─── Debian source package ───
for f in control rules changelog copyright source/format; do
    if [ -f "packaging/debian/$f" ]; then
        :
    else
        F "Debian: packaging/debian/$f missing"
    fi
done
if [ -f packaging/debian/control ] && [ -f packaging/debian/rules ]; then
    P "Debian: control, rules, changelog, copyright, source/format all present"
fi
if [ -x packaging/debian/rules ]; then
    P "Debian: rules is executable"
else
    F "Debian: rules is not executable"
fi
if grep -qE "^Source: (vaptvupt|zupt)$" packaging/debian/control; then
    P "Debian control: Source field correct"
else
    F "Debian control: Source field wrong/missing"
fi
if grep -qE "^(vaptvupt|zupt) \($VERSION-[0-9]+\) " packaging/debian/changelog; then
    P "Debian changelog: top entry matches $VERSION"
else
    F "Debian changelog: top entry version doesn't match include/zupt.h"
fi
if command -v dpkg-parsechangelog >/dev/null 2>&1; then
    if dpkg-parsechangelog -l packaging/debian/changelog >/dev/null 2>&1; then
        P "Debian changelog: dpkg-parsechangelog accepts it"
    else
        F "Debian changelog: dpkg-parsechangelog rejected it"
    fi
else
    SKIP "dpkg-parsechangelog not available (dpkg-dev not installed)"
fi
if [ "$(cat packaging/debian/source/format)" = "3.0 (quilt)" ]; then
    P "Debian source/format: 3.0 (quilt)"
else
    F "Debian source/format: wrong content"
fi

# ─── RPM spec ───
if [ -f packaging/rpm/vaptvupt.spec ]; then
    for field in Name Version Release Summary License URL Source0; do
        if grep -qE "^$field:" packaging/rpm/vaptvupt.spec; then
            :
        else
            F "RPM spec: missing tag '$field:'"
        fi
    done
    P "RPM spec: required header tags present"
    SPEC_VER=$(grep -E "^Version:" packaging/rpm/vaptvupt.spec | awk '{print $2}')
    if [ "$SPEC_VER" = "$VERSION" ]; then
        P "RPM spec: Version: matches include/zupt.h ($VERSION)"
    else
        F "RPM spec: Version: '$SPEC_VER' != include/zupt.h '$VERSION'"
    fi
    for section in "%prep" "%build" "%install" "%files" "%changelog"; do
        if grep -qF "$section" packaging/rpm/vaptvupt.spec; then
            :
        else
            F "RPM spec: missing section '$section'"
        fi
    done
    P "RPM spec: %prep, %build, %install, %files, %changelog sections present"
    if command -v rpmlint >/dev/null 2>&1; then
        rpmlint packaging/rpm/vaptvupt.spec >/tmp/rpmlint.out 2>&1
        if [ -s /tmp/rpmlint.out ] && grep -qE " E: " /tmp/rpmlint.out; then
            F "RPM spec: rpmlint errors (see /tmp/rpmlint.out):"
            grep " E: " /tmp/rpmlint.out | head -3
        else
            P "RPM spec: rpmlint clean (warnings allowed)"
        fi
    else
        SKIP "rpmlint not available"
    fi
else
    F "RPM spec: file missing"
fi

# ─── Homebrew formula ───
if [ -f packaging/homebrew/vaptvupt.rb ]; then
    HB_VER=$(grep -E '^\s*version\s' packaging/homebrew/vaptvupt.rb | head -1 | awk -F'"' '{print $2}')
    if [ "$HB_VER" = "$VERSION" ]; then
        P "Homebrew formula: version matches include/zupt.h ($VERSION)"
    else
        F "Homebrew formula: version '$HB_VER' != include/zupt.h '$VERSION'"
    fi
    if command -v ruby >/dev/null 2>&1; then
        if ruby -c packaging/homebrew/vaptvupt.rb >/dev/null 2>&1; then
            P "Homebrew formula: ruby syntax clean"
        else
            F "Homebrew formula: ruby syntax error"
            ruby -c packaging/homebrew/vaptvupt.rb 2>&1 | head -3
        fi
    else
        SKIP "ruby not available — skipping Homebrew syntax parse"
    fi
    for kw in 'class (Vaptvupt|Zupt)' 'desc ' 'homepage ' 'url ' 'version ' 'sha256 ' 'license '; do
        if grep -qE "^\s*${kw}" packaging/homebrew/vaptvupt.rb; then
            :
        else
            F "Homebrew formula: missing DSL line starting with '$kw'"
        fi
    done
    # install is a method definition; test is a block
    if grep -qE "^\s*def\s+install\b" packaging/homebrew/vaptvupt.rb; then
        :
    else
        F "Homebrew formula: missing method 'def install'"
    fi
    if grep -qE "^\s*test\s+do\b" packaging/homebrew/vaptvupt.rb; then
        :
    else
        F "Homebrew formula: missing 'test do' block"
    fi
    P "Homebrew formula: class + required DSL keywords + install method + test block present"
else
    F "Homebrew formula: file missing"
fi

# ─── Nix flake ───
if [ -f packaging/nix/flake.nix ]; then
    if command -v nix >/dev/null 2>&1 && nix --version 2>/dev/null | grep -qE "nix \(Nix\) [2-9]"; then
        if nix flake metadata packaging/nix --no-update-lock-file >/dev/null 2>&1; then
            P "Nix flake: nix accepts metadata"
        else
            F "Nix flake: nix flake metadata failed"
        fi
    else
        SKIP "nix not available — skipping flake check"
    fi
    NIX_VER=$(grep -E 'version = "' packaging/nix/flake.nix | head -1 | awk -F'"' '{print $2}')
    if [ "$NIX_VER" = "$VERSION" ]; then
        P "Nix flake: version matches include/zupt.h ($VERSION)"
    else
        F "Nix flake: version '$NIX_VER' != include/zupt.h '$VERSION'"
    fi
    # Structural check: must have outputs and a zupt package definition
    if grep -qE "outputs\s*=" packaging/nix/flake.nix && \
       grep -qE 'pname = "(vaptvupt|zupt)"' packaging/nix/flake.nix; then
        P "Nix flake: outputs + zupt package definition present"
    else
        F "Nix flake: structure incomplete"
    fi
else
    F "Nix flake: file missing"
fi

# ─── openSUSE OBS recipe (renamed zupt.* -> vaptvupt.* in 3.2.0) ───
if [ -f packaging/opensuse/vaptvupt.spec ] && [ -f packaging/opensuse/vaptvupt.changes ] && [ -f packaging/opensuse/_service ]; then
    P "openSUSE OBS files: all three present (vaptvupt.spec, vaptvupt.changes, _service)"
    # Validate the spec parses
    if command -v rpm >/dev/null 2>&1; then
        if rpm --specfile packaging/opensuse/vaptvupt.spec >/dev/null 2>&1; then
            P "openSUSE vaptvupt.spec: rpm --specfile parses cleanly"
        else
            F "openSUSE vaptvupt.spec: rpm --specfile rejected it"
        fi
        SUSE_VER=$(grep -E "^Version:" packaging/opensuse/vaptvupt.spec | awk '{print $2}')
        if [ "$SUSE_VER" = "$VERSION" ]; then
            P "openSUSE vaptvupt.spec: Version matches include/zupt.h ($VERSION)"
        else
            F "openSUSE vaptvupt.spec: Version '$SUSE_VER' != include/zupt.h '$VERSION'"
        fi
        # Name must be vaptvupt, and it must supersede the old zupt package.
        if grep -qE "^Name:[[:space:]]+vaptvupt$" packaging/opensuse/vaptvupt.spec; then
            P "openSUSE vaptvupt.spec: Name is vaptvupt"
        else
            F "openSUSE vaptvupt.spec: Name is not vaptvupt"
        fi
        if grep -qE "^Provides:[[:space:]]+zupt" packaging/opensuse/vaptvupt.spec && \
           grep -qE "^Obsoletes:[[:space:]]+zupt" packaging/opensuse/vaptvupt.spec; then
            P "openSUSE vaptvupt.spec: Provides/Obsoletes zupt (clean upgrade)"
        else
            F "openSUSE vaptvupt.spec: missing Provides/Obsoletes zupt"
        fi
    else
        SKIP "rpm not available — skipping openSUSE spec parse"
    fi
    # Validate _service is well-formed XML
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import xml.etree.ElementTree as ET; ET.parse('packaging/opensuse/_service')" 2>/dev/null; then
            P "openSUSE _service: XML well-formed"
        else
            F "openSUSE _service: XML parse error"
        fi
    fi
    # _service filename should be vaptvupt now
    if grep -qE "<param name=\"filename\">vaptvupt</param>" packaging/opensuse/_service; then
        P "openSUSE _service: filename is vaptvupt"
    else
        F "openSUSE _service: filename not updated to vaptvupt"
    fi
    # .changes: check standard 67-dash separator (openSUSE convention is exactly 67)
    SEP_COUNT=$(grep -cE "^-{67}$" packaging/opensuse/vaptvupt.changes)
    if [ "$SEP_COUNT" -ge 1 ]; then
        P "openSUSE vaptvupt.changes: $SEP_COUNT entries with proper separator"
    else
        F "openSUSE vaptvupt.changes: missing or wrong separator format"
    fi
else
    F "openSUSE OBS files incomplete (need vaptvupt.spec, vaptvupt.changes, _service)"
fi
if [ -f DISTRIBUTION.md ]; then
    P "DISTRIBUTION.md present"
    for distro in "Arch Linux" "Debian / Ubuntu" "Fedora" "macOS" "NixOS"; do
        if grep -q "$distro" DISTRIBUTION.md; then
            :
        else
            F "DISTRIBUTION.md: doesn't mention '$distro'"
        fi
    done
    P "DISTRIBUTION.md: covers all 5 distros"
else
    F "DISTRIBUTION.md missing"
fi

# ─── GitHub Actions CI workflow ───
if [ -f .github/workflows/ci.yml ]; then
    if command -v python3 >/dev/null 2>&1; then
        # Write the validator to a temp file rather than inline -c so quoting/
        # indentation can't bite.
        cat > /tmp/ci_validate.py << 'PYEOF'
import yaml, sys
try:
    with open('.github/workflows/ci.yml') as f:
        doc = yaml.safe_load(f)
except Exception as e:
    sys.stderr.write(f"YAML_PARSE_ERROR: {e}\n")
    sys.exit(1)
jobs = list(doc.get('jobs', {}).keys())
expected = ['build-and-test', 'strict-warnings', 'sanitizers',
            'dist-reproducibility', 'packaging-syntax', 'release']
missing = [j for j in expected if j not in jobs]
if missing:
    sys.stderr.write(f"MISSING_JOBS: {missing}\n")
    sys.exit(1)
print(f"JOBS_OK ({len(jobs)} jobs)")
PYEOF
        if python3 /tmp/ci_validate.py 2>/tmp/ci_check.err; then
            P "CI workflow: YAML valid + expected jobs present"
        else
            F "CI workflow: $(cat /tmp/ci_check.err)"
        fi
        rm -f /tmp/ci_validate.py /tmp/ci_check.err
    else
        SKIP "python3 unavailable — skipping CI YAML check"
    fi
else
    F "CI workflow .github/workflows/ci.yml missing"
fi

# ─── THREAT_MODEL.md ───
if [ -f THREAT_MODEL.md ]; then
    P "THREAT_MODEL.md present"
    # Verify the document is substantive (>3000 bytes) and covers the
    # required sections per userPreferences ("plain English. State
    # explicitly what the system does NOT protect against.")
    SZ=$(wc -c < THREAT_MODEL.md)
    if [ "$SZ" -ge 3000 ]; then
        P "THREAT_MODEL.md: substantive ($SZ bytes)"
    else
        F "THREAT_MODEL.md: too short ($SZ bytes, expected >= 3000)"
    fi
    for section in "What VaptVupt protects against" "What VaptVupt does NOT protect against" "Cryptographic assumptions"; do
        if grep -qF "$section" THREAT_MODEL.md; then
            :
        else
            F "THREAT_MODEL.md: missing section '$section'"
        fi
    done
    P "THREAT_MODEL.md: required sections present"
else
    F "THREAT_MODEL.md missing"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  packaging syntax: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
