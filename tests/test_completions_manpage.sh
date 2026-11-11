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

missing_install_tools=()
for tool in make install gzip; do
    command -v "$tool" >/dev/null 2>&1 || missing_install_tools+=("$tool")
done
if ((${#missing_install_tools[@]})); then
    skip "install failure checks require: ${missing_install_tools[*]}"
else
    install_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-install-check.XXXXXXXX")
    trap 'rm -rf -- "$install_tmp"' EXIT HUP INT TERM
    fixture=$install_tmp/source
    mkdir -p "$fixture/sdk" "$fixture/doc" "$fixture/completions" "$install_tmp/tools"
    cp Makefile LICENSE "$fixture/"
    cp sdk/Makefile.sdk "$fixture/sdk/"
    cp doc/zupt.1 "$fixture/doc/"
    cp "${completion_files[@]}" "$fixture/completions/"
    # Exercise the real install recipes without compiling or running the CLI.
    cat > "$fixture/zupt" <<'SH'
#!/bin/sh
printf 'unexpected CLI invocation\n' >> "$INSTALL_TEST_COMPILE_LOG"
exit 99
SH
    cat > "$fixture/no-compile" <<'SH'
#!/usr/bin/env bash
case $1 in
    --version) printf 'install-test compiler metadata only\n' ;;
    -dumpmachine) printf 'x86_64-unknown-linux-gnu\n' ;;
    *) printf 'unexpected compiler invocation\n' >> "$INSTALL_TEST_COMPILE_LOG"; exit 99 ;;
esac
SH
    export INSTALL_TEST_COMPILE_LOG=$install_tmp/compile.log
    : > "$INSTALL_TEST_COMPILE_LOG"
    cat > "$install_tmp/tools/intercept" <<'SH'
#!/usr/bin/env bash
set -eu
tool=${0##*/}
target=${!#}
printf '%s %s\n' "$tool" "$target" >> "$INSTALL_TEST_TRACE"
if [[ $tool == "$INSTALL_TEST_FAIL_TOOL" && $target == "$INSTALL_TEST_FAIL_PATH" ]]; then
    printf 'FAIL %s %s\n' "$tool" "$target" >> "$INSTALL_TEST_TRACE"
    printf 'injected %s failure: %s\n' "$tool" "$target" >&2
    if [[ $tool == gzip ]]; then printf 'partial-gzip-output\n'; fi
    exit 73
fi
real_tool=INSTALL_TEST_REAL_$tool
exec "${!real_tool}" "$@"
SH
    chmod +x "$fixture/no-compile" "$install_tmp/tools/intercept"
    for tool in mkdir install gzip chmod ln; do
        printf -v "INSTALL_TEST_REAL_$tool" '%s' "$(command -v "$tool")"
        export "INSTALL_TEST_REAL_$tool"
        ln -s intercept "$install_tmp/tools/$tool"
    done
    make_bin=$(command -v make)

    run_install() {
        local label=$1 tool=$2 target=$3 aliases=$4
        shift 4
        dest=$install_tmp/$label
        install_log=$install_tmp/$label.log
        install_trace=$install_tmp/$label.trace
        mkdir -p "$dest"
        # A failed mkdir must stop even if a usable directory already exists.
        if [[ $tool == mkdir ]]; then mkdir -p "$dest$target"; fi
        if [[ $target == /* ]]; then target=$dest$target; fi
        : > "$install_trace"
        if PATH="$install_tmp/tools:$PATH" INSTALL_TEST_TRACE="$install_trace" \
           INSTALL_TEST_FAIL_TOOL="$tool" INSTALL_TEST_FAIL_PATH="$target" \
           "$make_bin" --no-print-directory -s -j1 -C "$fixture" -o zupt \
               CC="$fixture/no-compile" TARGET_MACHINE=x86_64-unknown-linux-gnu \
               WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 V=0 LICENSE_FILES=LICENSE \
               INSTALL_LEGACY_ALIAS="$aliases" DESTDIR="$dest" PREFIX=/usr "$@" install \
               > "$install_log" 2>&1; then
            install_status=0
        else
            install_status=$?
        fi
        printf '\nInstall case %s: make exit %s\n' "$label" "$install_status"
        cat "$install_log" "$install_trace"
    }

    # Each fault runs the real recipe against a fresh DESTDIR. A later
    # tool call or success message would hide the injected command's failure.
    while IFS='|' read -r label tool target reported; do
        run_install "$label" "$tool" "$target" 1
        if [[ $target == /* ]]; then target=$dest$target; fi
        partial_ok=1
        if [[ $tool == gzip && $(cat "$dest/usr/share/man/man1/zupt.1.gz") != partial-gzip-output ]]; then
            partial_ok=0
        fi
        if ((install_status != 0 && partial_ok)) &&
           [[ $(sed -n '$p' "$install_trace") == "FAIL $tool $target" ]] &&
           ! grep -qF "Installed: $dest$reported" "$install_log" &&
           ! grep -qF "Installed: $dest/usr/bin/zupt" "$install_log"; then
            pass "$label stops install without a false success or dependent tool call"
        else
            fail "$label hides a failed install command or continues afterward"
        fi
    done <<'CASES'
license-directory|mkdir|/usr/share/licenses/zupt|/usr/bin/zupt
license-copy|install|/usr/share/licenses/zupt/|/usr/bin/zupt
cli-alias|ln|/usr/bin/vaptvupt|/usr/bin/zupt
man-directory|mkdir|/usr/share/man/man1|/usr/share/man/man1/zupt.1.gz
man-gzip|gzip|doc/zupt.1|/usr/share/man/man1/zupt.1.gz
man-mode|chmod|/usr/share/man/man1/zupt.1.gz|/usr/share/man/man1/zupt.1.gz
man-alias|ln|/usr/share/man/man1/vaptvupt.1.gz|/usr/share/man/man1/zupt.1.gz
bash-directory|mkdir|/usr/share/bash-completion/completions|/usr/share/bash-completion/completions/zupt
bash-copy|install|/usr/share/bash-completion/completions/zupt|/usr/share/bash-completion/completions/zupt
bash-alias|ln|/usr/share/bash-completion/completions/vaptvupt|/usr/share/bash-completion/completions/zupt
zsh-directory|mkdir|/usr/share/zsh/site-functions|/usr/share/zsh/site-functions/_zupt
zsh-copy|install|/usr/share/zsh/site-functions/_zupt|/usr/share/zsh/site-functions/_zupt
zsh-alias|ln|/usr/share/zsh/site-functions/_vaptvupt|/usr/share/zsh/site-functions/_zupt
fish-directory|mkdir|/usr/share/fish/vendor_completions.d|/usr/share/fish/vendor_completions.d/zupt.fish
fish-copy|install|/usr/share/fish/vendor_completions.d/zupt.fish|/usr/share/fish/vendor_completions.d/zupt.fish
fish-alias|ln|/usr/share/fish/vendor_completions.d/vaptvupt.fish|/usr/share/fish/vendor_completions.d/zupt.fish
CASES

    run_install default '' '' 0
    if ((install_status == 0)) && cmp "$fixture/zupt" "$dest/usr/bin/zupt" &&
       gzip -t "$dest/usr/share/man/man1/zupt.1.gz" &&
       [[ -f $dest/usr/share/licenses/zupt/LICENSE ]] &&
       cmp completions/zupt.bash "$dest/usr/share/bash-completion/completions/zupt" &&
       cmp completions/_zupt "$dest/usr/share/zsh/site-functions/_zupt" &&
       cmp completions/zupt.fish "$dest/usr/share/fish/vendor_completions.d/zupt.fish" &&
       [[ ! -L $dest/usr/bin/vaptvupt ]]; then
        pass 'default staged install succeeds without the legacy alias'
    else
        fail 'default staged install changed'
    fi
    run_install aliases '' '' 1
    if ((install_status == 0)) && [[ -L $dest/usr/bin/vaptvupt &&
        -L $dest/usr/share/man/man1/vaptvupt.1.gz &&
        -L $dest/usr/share/bash-completion/completions/vaptvupt &&
        -L $dest/usr/share/zsh/site-functions/_vaptvupt &&
        -L $dest/usr/share/fish/vendor_completions.d/vaptvupt.fish ]] &&
       cmp "$fixture/zupt" "$dest/usr/bin/vaptvupt" &&
       cmp "$dest/usr/share/man/man1/zupt.1.gz" "$dest/usr/share/man/man1/vaptvupt.1.gz" &&
       cmp completions/zupt.bash "$dest/usr/share/bash-completion/completions/vaptvupt" &&
       cmp completions/_zupt "$dest/usr/share/zsh/site-functions/_vaptvupt" &&
       cmp completions/zupt.fish "$dest/usr/share/fish/vendor_completions.d/vaptvupt.fish"; then
        pass 'opt-in staged legacy aliases are preserved'
    else
        fail 'opt-in staged legacy aliases changed'
    fi
    run_install configured '' '' 0 BINDIR=/custom/bin MAN1DIR=/custom/man \
        LICENSEDIR=/custom/licenses BASHCOMPDIR=/custom/bash \
        ZSHCOMPDIR=/custom/zsh FISHCOMPDIR=/custom/fish
    if ((install_status == 0)) && cmp "$fixture/zupt" "$dest/custom/bin/zupt" &&
       gzip -t "$dest/custom/man/zupt.1.gz" && [[ -f $dest/custom/licenses/LICENSE ]] &&
       cmp completions/zupt.bash "$dest/custom/bash/zupt" &&
       cmp completions/_zupt "$dest/custom/zsh/_zupt" &&
       cmp completions/zupt.fish "$dest/custom/fish/zupt.fish"; then
        pass 'staged install honors configured directories'
    else
        fail 'staged install ignored configured directories'
    fi
    rm "$fixture/doc/zupt.1" "$fixture/completions/zupt.bash" \
        "$fixture/completions/_zupt" "$fixture/completions/zupt.fish"
    run_install optional-absent '' '' 0 INSTALL_LICENSES=0
    if ((install_status == 0)) && cmp "$fixture/zupt" "$dest/usr/bin/zupt" &&
       [[ ! -e $dest/usr/share ]] &&
       grep -qF 'Warning: man page not found: doc/zupt.1' "$install_log"; then
        pass 'absent optional manpage/completions and disabled licenses remain supported'
    else
        fail 'absent optional install inputs caused a failure'
    fi
    if [[ ! -s $INSTALL_TEST_COMPILE_LOG ]]; then
        pass 'install checks never compile or execute the placeholder CLI'
    else
        fail 'install checks unexpectedly invoked the compiler or CLI'
    fi
    rm -rf -- "$install_tmp"
    trap - EXIT HUP INT TERM
fi

printf '\nSummary: PASS=%d FAIL=%d SKIP=%d\n' "$pass_count" "$fail_count" "$skip_count"
((fail_count == 0))
