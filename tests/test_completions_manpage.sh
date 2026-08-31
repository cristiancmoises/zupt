#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

set -Eeuo pipefail

cd "$(dirname "$0")/.."

pass_count=0
fail_count=0
skip_count=0
pass() { pass_count=$((pass_count + 1)); printf '  PASS: %s\n' "$1"; }
fail() { fail_count=$((fail_count + 1)); printf '  FAIL: %s\n' "$1"; }
skip() { skip_count=$((skip_count + 1)); printf '  SKIP: %s\n' "$1"; }

version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
[[ -n $version ]] || { printf 'FAIL: cannot determine version\n' >&2; exit 1; }
printf 'ZUPT %s completion and manual-page checks\n' "$version"

completion_files=(
    completions/zupt.bash
    completions/_zupt
    completions/zupt.fish
)

for file in "${completion_files[@]}"; do
    [[ -f $file ]] && pass "$file exists" || fail "$file is missing"
done

if bash -n completions/zupt.bash; then
    pass 'bash completion parses'
else
    fail 'bash completion has a syntax error'
fi

if command -v zsh >/dev/null 2>&1; then
    if zsh -n completions/_zupt; then
        pass 'zsh completion parses'
    else
        fail 'zsh completion has a syntax error'
    fi
else
    skip 'zsh is unavailable'
fi

if command -v fish >/dev/null 2>&1; then
    if fish -n completions/zupt.fish; then
        pass 'fish completion parses'
    else
        fail 'fish completion has a syntax error'
    fi
else
    skip 'fish is unavailable'
fi

if grep -qxF 'complete -F _zupt zupt' completions/zupt.bash &&
   ! grep -Eq '^complete[[:space:]].*[[:space:]]vaptvupt([[:space:]]|$)' completions/zupt.bash; then
    pass 'bash registers only zupt'
else
    fail 'bash completion is not limited to the primary zupt command'
fi

if [[ $(sed -n '1p' completions/_zupt) == '#compdef zupt' ]]; then
    pass 'zsh registers only zupt'
else
    fail 'zsh #compdef is not limited to zupt'
fi

if grep -q '^complete -c zupt' completions/zupt.fish &&
   ! grep -q '^complete -c vaptvupt\([[:space:]]\|$\)' completions/zupt.fish; then
    pass 'fish registers only zupt'
else
    fail 'fish completion is not limited to the primary zupt command'
fi

required_flags=(
    password-prompt pass-file pass-fd allow-legacy-no-ait kdf comment comment-file
    pq pq-only pq-sdk pq-box dedup solid force verbose threads
    level block store fast lzhp vaptvupt compare output key pub
    sdk box pqonly help version
)

for file in "${completion_files[@]}"; do
    missing=()
    for flag in "${required_flags[@]}"; do
        if ! grep -qF -- "--$flag" "$file" &&
           ! grep -qE -- "-l[[:space:]]+$flag([[:space:]]|$)" "$file"; then
            missing+=("--$flag")
        fi
    done
    if ((${#missing[@]} == 0)); then
        pass "$file covers current critical flags"
    else
        fail "$file is missing: ${missing[*]}"
    fi
done

unsupported_flags=(quiet jobs codec keyfile sync no-mtime strip-components block-size)
for file in "${completion_files[@]}"; do
    advertised=()
    for flag in "${unsupported_flags[@]}"; do
        if grep -qF -- "--$flag" "$file" ||
           grep -qE -- "-l[[:space:]]+$flag([[:space:]]|$)" "$file"; then
            advertised+=("--$flag")
        fi
    done
    if ((${#advertised[@]} == 0)); then
        pass "$file does not advertise unsupported flags"
    else
        fail "$file advertises unsupported flags: ${advertised[*]}"
    fi
done

if [[ ! -e doc/vaptvupt.1 && ! -L doc/vaptvupt.1 ]]; then
    pass 'former primary man page is absent from the source tree'
else
    fail 'doc/vaptvupt.1 remains despite the zupt-only default installation'
fi

manpage=doc/zupt.1
if [[ ! -f $manpage ]]; then
    fail "$manpage is missing"
else
    required_sections=(NAME SYNOPSIS DESCRIPTION COMMANDS PASSWORD\ INPUT EXAMPLES EXIT\ STATUS LICENSE)
    missing_sections=()
    for section in "${required_sections[@]}"; do
        grep -qxF ".SH $section" "$manpage" || missing_sections+=("$section")
    done
    if ((${#missing_sections[@]} == 0)); then
        pass 'manpage contains required sections'
    else
        fail "manpage is missing sections: ${missing_sections[*]}"
    fi

    if grep -qF "ZUPT $version" "$manpage"; then
        pass 'manpage version matches include/zupt.h'
    else
        fail 'manpage version does not match include/zupt.h'
    fi

    required_man_flags=(
        password-prompt pass-file pass-fd allow-legacy-no-ait kdf comment comment-file
        pq pq-only pq-sdk pq-box dedup solid force verbose threads
        level block store fast lzhp vaptvupt compare output key pub
        sdk box pqonly help version
    )
    missing=()
    for flag in "${required_man_flags[@]}"; do
        grep -qF -- "--$flag" "$manpage" || missing+=("--$flag")
    done
    if ((${#missing[@]} == 0)); then
        pass 'manpage documents current critical flags'
    else
        fail "manpage is missing: ${missing[*]}"
    fi

    advertised=()
    for flag in "${unsupported_flags[@]}"; do
        grep -qF -- "--$flag" "$manpage" && advertised+=("--$flag")
    done
    if ((${#advertised[@]} == 0)); then
        pass 'manpage does not document unsupported flags'
    else
        fail "manpage documents unsupported flags: ${advertised[*]}"
    fi

    if grep -qF 'Plain archives provide compression checksums' "$manpage" &&
       grep -qF 'does not restore ownership' "$manpage" &&
       grep -qF 'Automatic codec selection' "$manpage"; then
        pass 'manpage states current integrity, metadata, and codec behavior'
    else
        fail 'manpage is missing current behavioral limits'
    fi

    if grep -q '^\.B 2$\|^\.B 3$\|^\.B 4$\|^\.B 5$' "$manpage"; then
        fail 'manpage advertises exit statuses not emitted by the CLI'
    else
        pass 'manpage documents only emitted exit statuses'
    fi

    lint_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-man-lint.XXXXXXXX")
    trap 'rm -rf -- "$lint_tmp"' EXIT HUP INT TERM
    if command -v mandoc >/dev/null 2>&1; then
        if mandoc -Tlint "$manpage" >"$lint_tmp/mandoc.log" 2>&1; then
            pass 'mandoc lint passes'
        else
            fail 'mandoc lint reports diagnostics'
            sed -n '1,10p' "$lint_tmp/mandoc.log"
        fi
    elif command -v groff >/dev/null 2>&1; then
        if groff -mandoc -Tutf8 "$manpage" >"$lint_tmp/rendered" 2>"$lint_tmp/groff.log" &&
           [[ ! -s $lint_tmp/groff.log ]] &&
           (($(wc -l <"$lint_tmp/rendered") > 50)); then
            pass 'groff renders the manpage without diagnostics'
        else
            fail 'groff manpage rendering failed or emitted diagnostics'
            sed -n '1,10p' "$lint_tmp/groff.log"
        fi
    else
        skip 'mandoc and groff are unavailable'
    fi
    rm -rf -- "$lint_tmp"
    trap - EXIT HUP INT TERM
fi

printf '\nSummary: PASS=%d FAIL=%d SKIP=%d\n' "$pass_count" "$fail_count" "$skip_count"
((fail_count == 0))
