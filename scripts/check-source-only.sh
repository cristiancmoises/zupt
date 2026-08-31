#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Audit ZUPT source trees and archives for compiled or unsafe content.

set -Eeuo pipefail

PROGRAM=${0##*/}
ROOT=
ROOT_REQUESTED=0
DATA_MANIFEST=
REPOSITORY_AUDIT=1
HAVE_EXTERNAL_TARGET=0
declare -a TAGS=()
declare -a ARCHIVES=()
declare -a TREES=()
TAG_COUNT=0
ARCHIVE_COUNT=0
TREE_COUNT=0

FAILURES=0
SCANNED=0
ARCHIVES_SCANNED=0
MAX_ARCHIVE_DEPTH=${SOURCE_AUDIT_MAX_DEPTH:-5}
MAX_ARCHIVES=${SOURCE_AUDIT_MAX_ARCHIVES:-1000}
MAX_ARCHIVE_MEMBERS=${SOURCE_AUDIT_MAX_MEMBERS:-10000}
MAX_ARCHIVE_LIST_KIB=${SOURCE_AUDIT_MAX_LIST_KIB:-16384}
MAX_ARCHIVE_KIB=${SOURCE_AUDIT_MAX_KIB:-524288}
MAX_TOTAL_ARCHIVE_KIB=${SOURCE_AUDIT_MAX_TOTAL_KIB:-1048576}
ARCHIVE_TIMEOUT_SECONDS=${SOURCE_AUDIT_ARCHIVE_SECONDS:-60}
FORCE_PORTABLE_WATCHDOG=${SOURCE_AUDIT_FORCE_WATCHDOG:-0}
TOTAL_ARCHIVE_BYTES=0

for limit in "$MAX_ARCHIVE_DEPTH" "$MAX_ARCHIVES" "$MAX_ARCHIVE_MEMBERS" \
        "$MAX_ARCHIVE_LIST_KIB" "$MAX_ARCHIVE_KIB" \
        "$MAX_TOTAL_ARCHIVE_KIB" "$ARCHIVE_TIMEOUT_SECONDS"; do
    [[ $limit =~ ^[0-9]+$ ]] || {
        printf 'ERROR: source-audit limits must be non-negative integers\n' >&2
        exit 2
    }
done
[[ $FORCE_PORTABLE_WATCHDOG == 0 || $FORCE_PORTABLE_WATCHDOG == 1 ]] || {
    printf 'ERROR: SOURCE_AUDIT_FORCE_WATCHDOG must be 0 or 1\n' >&2
    exit 2
}
((ARCHIVE_TIMEOUT_SECONDS > 0)) || {
    printf 'ERROR: source-audit archive timeout must be positive\n' >&2
    exit 2
}
((MAX_ARCHIVE_LIST_KIB <= 2147483647 && MAX_ARCHIVE_KIB <= 2147483647 &&
   MAX_TOTAL_ARCHIVE_KIB <= 2147483647)) || {
    printf 'ERROR: source-audit KiB limits are too large for safe accounting\n' >&2
    exit 2
}

AUDIT_TMP=$(mktemp -d "${TMPDIR:-/tmp}/zupt-source-audit.XXXXXXXX")
# shellcheck disable=SC2317 # Invoked indirectly by trap.
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$AUDIT_TMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

for required_tool in file od tr grep find head wc awk; do
    if ! command -v "$required_tool" >/dev/null 2>&1; then
        printf 'ERROR: source audit requires %s\n' "$required_tool" >&2
        exit 2
    fi
done
unset required_tool

usage() {
    cat <<EOF
Usage: $PROGRAM [--root DIR] [--tag REV] [--archive FILE] [--tree DIR]
                [--data-manifest FILE]

Without an external target, audit the Git index, the complete working tree,
and git archive HEAD.  --tag adds an immutable Git revision archive to that
repository audit.  --archive and --tree audit standalone inputs and do not
require a Git repository unless --tag is also supplied.  A data manifest may
allow a necessary .bin fixture using four tab-separated fields per record:
path, purpose, provenance, and SPDX license.  Magic-byte checks still apply.
EOF
}

while (($#)); do
    case $1 in
        --root)
            (($# >= 2)) || { printf 'ERROR: --root requires a directory\n' >&2; exit 2; }
            ROOT=$2
            ROOT_REQUESTED=1
            shift 2
            ;;
        --tag)
            (($# >= 2)) || { printf 'ERROR: --tag requires a revision\n' >&2; exit 2; }
            TAGS+=("$2")
            TAG_COUNT=$((TAG_COUNT + 1))
            shift 2
            ;;
        --archive)
            (($# >= 2)) || { printf 'ERROR: --archive requires a file\n' >&2; exit 2; }
            ARCHIVES+=("$2")
            ARCHIVE_COUNT=$((ARCHIVE_COUNT + 1))
            HAVE_EXTERNAL_TARGET=1
            shift 2
            ;;
        --tree)
            (($# >= 2)) || { printf 'ERROR: --tree requires a directory\n' >&2; exit 2; }
            TREES+=("$2")
            TREE_COUNT=$((TREE_COUNT + 1))
            HAVE_EXTERNAL_TARGET=1
            shift 2
            ;;
        --data-manifest)
            (($# >= 2)) || { printf 'ERROR: --data-manifest requires a file\n' >&2; exit 2; }
            DATA_MANIFEST=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            (($# == 0)) || { printf 'ERROR: unexpected operand\n' >&2; exit 2; }
            ;;
        *)
            printf 'ERROR: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ((HAVE_EXTERNAL_TARGET)) && ((ROOT_REQUESTED == 0)) && ((TAG_COUNT == 0)); then
    REPOSITORY_AUDIT=0
fi

unicode_format_control() {
    local codepoint=$1
    ((codepoint == 0x00ad ||
      (codepoint >= 0x0600 && codepoint <= 0x0605) ||
      codepoint == 0x061c || codepoint == 0x06dd || codepoint == 0x070f ||
      (codepoint >= 0x0890 && codepoint <= 0x0891) ||
      codepoint == 0x08e2 || codepoint == 0x180e ||
      (codepoint >= 0x200b && codepoint <= 0x200f) ||
      (codepoint >= 0x202a && codepoint <= 0x202e) ||
      (codepoint >= 0x2060 && codepoint <= 0x206f) ||
      codepoint == 0xfeff ||
      (codepoint >= 0xfff9 && codepoint <= 0xfffb) ||
      codepoint == 0x110bd || codepoint == 0x110cd ||
      (codepoint >= 0x13430 && codepoint <= 0x1343f) ||
      (codepoint >= 0x1bca0 && codepoint <= 0x1bca3) ||
      (codepoint >= 0x1d173 && codepoint <= 0x1d17a) ||
      codepoint == 0xe0001 ||
      (codepoint >= 0xe0020 && codepoint <= 0xe007f)))
}

safe_path_for_output() {
    local path=$1
    local output='' character='' sequence='' escaped=''
    local LC_ALL=C byte byte2 byte3 byte4 codepoint index length
    length=${#path}
    for ((index = 0; index < length; index++)); do
        character=${path:index:1}
        printf -v byte '%d' "'$character"
        # Bash 3.2 can sign-extend bytes >= 0x80 when converting a character
        # with %d. Normalize to an unsigned octet before UTF-8 validation and
        # diagnostic escaping.
        byte=$((byte & 0xff))

        if ((byte < 0x20 || byte == 0x7f)); then
            printf -v escaped '\\x%02x' "$byte"
            output+=$escaped
            continue
        fi
        if ((byte < 0x80)); then
            if [[ $character == \\ ]]; then
                output+="${character}${character}"
            else
                output+=$character
            fi
            continue
        fi

        codepoint=0
        sequence=
        if ((byte >= 0xc2 && byte <= 0xdf && index + 1 < length)); then
            character=${path:index+1:1}
            printf -v byte2 '%d' "'$character"
            byte2=$((byte2 & 0xff))
            if ((byte2 >= 0x80 && byte2 <= 0xbf)); then
                codepoint=$(((byte & 0x1f) << 6 | (byte2 & 0x3f)))
                sequence=${path:index:2}
            fi
        elif ((byte >= 0xe0 && byte <= 0xef && index + 2 < length)); then
            character=${path:index+1:1}
            printf -v byte2 '%d' "'$character"
            byte2=$((byte2 & 0xff))
            character=${path:index+2:1}
            printf -v byte3 '%d' "'$character"
            byte3=$((byte3 & 0xff))
            if ((byte3 >= 0x80 && byte3 <= 0xbf &&
                ((byte == 0xe0 && byte2 >= 0xa0 && byte2 <= 0xbf) ||
                 (byte >= 0xe1 && byte <= 0xec && byte2 >= 0x80 && byte2 <= 0xbf) ||
                 (byte == 0xed && byte2 >= 0x80 && byte2 <= 0x9f) ||
                 (byte >= 0xee && byte <= 0xef && byte2 >= 0x80 && byte2 <= 0xbf)))); then
                codepoint=$(((byte & 0x0f) << 12 | (byte2 & 0x3f) << 6 |
                    (byte3 & 0x3f)))
                sequence=${path:index:3}
            fi
        elif ((byte >= 0xf0 && byte <= 0xf4 && index + 3 < length)); then
            character=${path:index+1:1}
            printf -v byte2 '%d' "'$character"
            byte2=$((byte2 & 0xff))
            character=${path:index+2:1}
            printf -v byte3 '%d' "'$character"
            byte3=$((byte3 & 0xff))
            character=${path:index+3:1}
            printf -v byte4 '%d' "'$character"
            byte4=$((byte4 & 0xff))
            if ((byte3 >= 0x80 && byte3 <= 0xbf &&
                byte4 >= 0x80 && byte4 <= 0xbf &&
                ((byte == 0xf0 && byte2 >= 0x90 && byte2 <= 0xbf) ||
                 (byte >= 0xf1 && byte <= 0xf3 && byte2 >= 0x80 && byte2 <= 0xbf) ||
                 (byte == 0xf4 && byte2 >= 0x80 && byte2 <= 0x8f)))); then
                codepoint=$(((byte & 0x07) << 18 | (byte2 & 0x3f) << 12 |
                    (byte3 & 0x3f) << 6 | (byte4 & 0x3f)))
                sequence=${path:index:4}
            fi
        fi

        if [[ -z $sequence ]]; then
            printf -v escaped '\\x%02x' "$byte"
            output+=$escaped
        elif ((codepoint >= 0x80 && codepoint <= 0x9f)) ||
                ((codepoint >= 0x2028 && codepoint <= 0x2029)) ||
                unicode_format_control "$codepoint"; then
            if ((codepoint <= 0xffff)); then
                printf -v escaped '\\u%04x' "$codepoint"
            else
                printf -v escaped '\\U%08x' "$codepoint"
            fi
            output+=$escaped
            index=$((index + ${#sequence} - 1))
        else
            output+=$sequence
            index=$((index + ${#sequence} - 1))
        fi
    done
    printf '%s' "$output"
}

canonicalize_allow_missing() {
    local path=$1
    if realpath -m -- / >/dev/null 2>&1; then
        realpath -m -- "$path"
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$path" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
    else
        printf 'ERROR: canonical path checking needs GNU realpath or python3\n' >&2
        return 1
    fi
}

fail_path() {
    local scope=$1 path=$2 reason=$3
    FAILURES=$((FAILURES + 1))
    printf 'FAIL [%s] %s (%s)\n' "$scope" "$(safe_path_for_output "$path")" "$reason"
}

path_stays_below_root() {
    local candidate=${1//\\//}
    local component
    local depth=0
    local IFS=/
    local -a components=()

    [[ $candidate != /* && $candidate != //* ]] || return 1
    [[ ! $candidate =~ ^[[:alpha:]]: ]] || return 1
    read -r -a components <<< "$candidate"
    # Bash 3.2 treats an empty array expansion as unset under `set -u`.
    # The + guard expands to no words for an empty path component list.
    for component in ${components[@]+"${components[@]}"}; do
        case $component in
            ''|.) ;;
            ..)
                ((depth > 0)) || return 1
                depth=$((depth - 1))
                ;;
            *) depth=$((depth + 1)) ;;
        esac
    done
}

check_link_target() {
    local entry=$1 target=$2 scope=$3 display=${4:-$1}
    local parent combined

    [[ $target != /* && $target != //* && ! $target =~ ^[[:alpha:]]: ]] || {
        fail_path "$scope" "$display" 'absolute symlink target'
        return
    }
    parent=${entry%/*}
    [[ $parent != "$entry" ]] || parent=.
    combined=$parent/$target
    if ! path_stays_below_root "$combined"; then
        fail_path "$scope" "$display" 'symlink escapes audit root'
    fi
}

forbidden_extension() {
    local path=$1 lower
    lower=$(LC_ALL=C printf '%s' "${path##*/}" | tr '[:upper:]' '[:lower:]')
    case $lower in
        *.o|*.obj|*.so|*.so.*|*.a|*.la|*.dll|*.dylib|*.exe|*.com|\
        *.class|*.jar|*.war|*.wasm|*.pyc|*.pyo|*.rpm|*.deb|*.appimage|\
        *.msi|*.apk|*.ipa|*.dmg|*.elf|*.ko|*.mod|*.lib|*.pdb|*.out)
            return 0
            ;;
    esac
    return 1
}

is_declared_binary_data() {
    local logical=$1 candidate line path purpose provenance license extra
    [[ -n $DATA_MANIFEST && -r $DATA_MANIFEST ]] || return 1
    candidate=${logical##*!}
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -n $line && ${line:0:1} != '#' ]] || continue
        IFS=$'\t' read -r path purpose provenance license extra <<< "$line"
        if [[ $path == "$candidate" && -n $purpose && -n $provenance &&
              -n $license && -z ${extra:-} ]]; then
            return 0
        fi
    done < "$DATA_MANIFEST"
    return 1
}

magic_kind() {
    local file=$1 hex machine sections flags
    hex=$(LC_ALL=C od -An -v -tx1 -N 512 "$file" 2>/dev/null | tr -d '[:space:]') || return 1
    [[ -n $hex ]] || return 1

    if [[ $hex == 7f454c46* && ${hex:16:6} =~ ^4149(01|02)$ ]]; then
        printf 'AppImage executable'
        return 0
    fi
    case $hex in
        7f454c46*) printf 'ELF executable or object'; return 0 ;;
        4d5a*) printf 'PE/MZ executable'; return 0 ;;
        feedface*|cefaedfe*|feedfacf*|cffaedfe*|cafebabe*|bebafeca*|cafebabf*|bfbafeca*)
            printf 'Mach-O, universal binary, or Java class'; return 0 ;;
        213c617263683e0a64656269616e2d62696e617279*) printf 'Debian package'; return 0 ;;
        213c617263683e0a*) printf 'ar archive or static library'; return 0 ;;
        213c7468696e3e0a*) printf 'GNU thin archive or static library'; return 0 ;;
        edabeedb*) printf 'RPM package'; return 0 ;;
        0061736d*) printf 'WebAssembly bytecode'; return 0 ;;
        6465780a*) printf 'Dalvik bytecode'; return 0 ;;
        1b4c7561*) printf 'Lua bytecode'; return 0 ;;
        4243c0de*) printf 'LLVM bitcode'; return 0 ;;
    esac

    # CPython bytecode starts with a version magic ending in CRLF, followed by
    # a small flags word.  Requiring the complete 16-byte header avoids treating
    # ordinary text beginning with CRLF as bytecode.
    if ((${#hex} >= 32)) && [[ ${hex:4:4} == 0d0a ]] &&
       [[ ${hex:8:8} =~ ^(00000000|01000000|02000000|03000000)$ ]]; then
        printf 'Python bytecode'
        return 0
    fi

    # A COFF object starts with a known machine identifier and a non-zero,
    # reasonably bounded section count in its fixed-size 20-byte header.
    if ((${#hex} >= 40)); then
        machine=${hex:0:4}
        sections=${hex:4:4}
        flags=${hex:32:8}
        case $machine in
            4c01|6486|c001|c201|c401|64aa|6601|f001|f701|bc0e|5001|d301)
                if [[ $sections != 0000 && $sections != 00000000 && $flags =~ ^[[:xdigit:]]{8}$ ]]; then
                    printf 'COFF object'
                    return 0
                fi
                ;;
        esac
    fi
    return 1
}

file_utility_kind() {
    local file=$1 description mime
    command -v file >/dev/null 2>&1 || return 1
    description=$(LC_ALL=C file -b "$file" 2>/dev/null) || return 1
    mime=$(LC_ALL=C file -b --mime-type "$file" 2>/dev/null) || mime=
    case $description in
        *ELF*) printf 'ELF executable or object'; return 0 ;;
        *PE32*|*MS-DOS\ executable*) printf 'PE/MZ executable'; return 0 ;;
        *Mach-O*|*COFF*) printf 'Mach-O or COFF compiled code'; return 0 ;;
        *RPM*package*|*Debian\ binary\ package*) printf 'binary distribution package'; return 0 ;;
        *current\ ar\ archive*|*thin\ archive*)
            printf 'ar archive or static library'; return 0 ;;
    esac
    case $mime in
        application/x-executable|application/x-pie-executable|application/x-sharedlib|\
        application/x-object|application/x-archive|application/x-dosexec|\
        application/x-rpm|application/vnd.debian.binary-package|application/wasm|\
        application/java-vm)
            printf 'compiled code or binary package'
            return 0
            ;;
    esac
    return 1
}

looks_like_archive() {
    local file=$1 logical=$2 hex lower
    lower=$(LC_ALL=C printf '%s' "$logical" | tr '[:upper:]' '[:lower:]')
    case $lower in
        *.tar|*.tar.gz|*.tgz|*.tar.xz|*.txz|*.tar.bz2|*.tbz|*.tbz2|\
        *.tar.zst|*.tzst|*.zip|*.jar|*.war|*.deb|*.apk|*.ipa|*.cpio)
            return 0
            ;;
        *.7z|*.rar)
            return 0
            ;;
    esac
    hex=$(LC_ALL=C od -An -v -tx1 -N 512 "$file" 2>/dev/null | tr -d '[:space:]') || return 1
    case $hex in
        504b0304*|504b0506*|504b0708*|1f8b*|425a68*|fd377a585a00*|\
        28b52ffd*|213c617263683e0a*|213c7468696e3e0a*|edabeedb*|3037303730*|\
        377abcaf271c*|526172211a0700*|526172211a070100*) return 0 ;;
    esac
    [[ ${hex:514:10} == 7573746172 ]]
}

is_reference_source() {
    local logical=$1 base=${1##*/}
    case $logical in
        *scripts/check-source-only.sh|*tests/test_source_only.sh|\
        *packaging/opensuse/source-audit.sh)
            return 1
            ;;
    esac
    case $base in
        Makefile|makefile|GNUmakefile|CMakeLists.txt|*.mk|*.cmake|*.sh|*.bash|\
        *.c|*.h|*.cc|*.hh|*.cpp|*.hpp|*.py|*.pl|*.rb|*.spec|*.service|\
        *.yml|*.yaml|Dockerfile|Containerfile)
            return 0
            ;;
    esac
    return 1
}

check_removed_library_reference() {
    local file=$1 logical=$2 scope=$3
    is_reference_source "$logical" || return 0
    LC_ALL=C grep -Iq . "$file" 2>/dev/null || return 0
    if LC_ALL=C grep -Eaq -- \
        'libvuptsdk[.]so|vendor/(vuptsdk|pqvaptvupt)/[^[:space:]"'"'"'`]*[.](so([.][0-9A-Za-z._-]+)?|a|o)([^0-9A-Za-z._-]|$)' \
        "$file" 2>/dev/null; then
        fail_path "$scope" "$logical" 'reference to removed vendored library'
    fi
}

archive_tool() {
    if command -v bsdtar >/dev/null 2>&1; then
        printf 'bsdtar'
    elif command -v tar >/dev/null 2>&1; then
        printf 'tar'
    else
        return 1
    fi
}

run_archive_command() {
    local command_pid watchdog_pid status
    if [[ $FORCE_PORTABLE_WATCHDOG == 0 ]] && \
            command -v timeout >/dev/null 2>&1 && \
            timeout --help 2>&1 | grep -F -- '--kill-after' >/dev/null; then
        timeout --kill-after=2 "${ARCHIVE_TIMEOUT_SECONDS}s" "$@"
    else
        "$@" &
        command_pid=$!
        (
            local elapsed=0
            while kill -0 "$command_pid" 2>/dev/null; do
                if ((elapsed >= ARCHIVE_TIMEOUT_SECONDS)); then
                    kill -TERM "$command_pid" 2>/dev/null || exit 0
                    sleep 1
                    kill -KILL "$command_pid" 2>/dev/null || true
                    exit 0
                fi
                sleep 1
                elapsed=$((elapsed + 1))
            done
        ) &
        watchdog_pid=$!
        if wait "$command_pid"; then status=0; else status=$?; fi
        kill "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
        return "$status"
    fi
}

archive_declared_bytes() {
    local tool=$1 verbose=$2 size_field=3
    if "$tool" --version 2>/dev/null | grep -Eqi 'bsdtar|libarchive'; then
        size_field=5
    fi
    awk -v field="$size_field" -v max_kib="$MAX_ARCHIVE_KIB" '
        BEGIN { total = 0; status = 0; max = max_kib * 1024 }
        {
            if (NF < field || $field !~ /^[0-9]+$/) {
                status = 2
                exit
            }
            size = $field + 0
            if (size > max - total) {
                status = 3
                exit
            }
            total += size
        }
        END {
            if (status == 0) printf "%.0f\n", total
            exit status
        }
    ' "$verbose"
}

extracted_regular_bytes() {
    local root=$1 file size total=0 max_bytes=$((MAX_ARCHIVE_KIB * 1024))
    while IFS= read -r -d '' file; do
        size=$(LC_ALL=C wc -c <"$file" | tr -d '[:space:]')
        [[ $size =~ ^[0-9]+$ ]] || return 2
        ((size <= max_bytes - total)) || return 3
        total=$((total + size))
    done < <(find -P "$root" -type f -print0)
    printf '%s\n' "$total"
}

scan_archive() {
    local archive=$1 logical=$2 scope=$3 depth=$4
    local tool archive_dir list verbose extract_dir member vline target count validation_start
    local list_limit_marker verbose_limit_marker declared_bytes actual_bytes
    local file_limit_blocks status limit_reason
    local max_total_bytes

    if ((depth > MAX_ARCHIVE_DEPTH)); then
        fail_path "$scope" "$logical" 'nested archive depth limit exceeded'
        return
    fi
    if ! tool=$(archive_tool); then
        fail_path "$scope" "$logical" 'no supported archive inspection tool'
        return
    fi

    if ((ARCHIVES_SCANNED >= MAX_ARCHIVES)); then
        fail_path "$scope" "$logical" 'global archive count limit exceeded'
        return
    fi
    ARCHIVES_SCANNED=$((ARCHIVES_SCANNED + 1))
    archive_dir=$(mktemp -d "$AUDIT_TMP/archive.XXXXXXXX")
    list=$archive_dir/list
    verbose=$archive_dir/verbose
    extract_dir=$archive_dir/root
    list_limit_marker=$archive_dir/member-limit
    verbose_limit_marker=$archive_dir/metadata-limit
    mkdir -p "$extract_dir"

    if ! run_archive_command "$tool" -tf "$archive" 2>/dev/null | \
        head -c "$((MAX_ARCHIVE_LIST_KIB * 1024 + 1))" | awk \
        -v max="$MAX_ARCHIVE_MEMBERS" \
        -v max_bytes="$((MAX_ARCHIVE_LIST_KIB * 1024))" \
        -v marker="$list_limit_marker" '
            { bytes += length($0) + 1 }
            bytes > max_bytes {
                print "archive member-name budget exceeded" > marker
                exit 43
            }
            NR > max {
                print "archive member limit exceeded" > marker
                exit 42
            }
            { print }
        ' >"$list"; then
        if [[ -s $list_limit_marker ]]; then
            limit_reason=$(<"$list_limit_marker")
            fail_path "$scope" "$logical" "$limit_reason"
        else
            fail_path "$scope" "$logical" 'archive cannot be listed safely'
        fi
        return
    fi
    count=$(LC_ALL=C wc -l <"$list" | tr -d '[:space:]')
    if ((count == 0)); then
        fail_path "$scope" "$logical" 'archive has no inspectable members'
        return
    fi
    if ((count > MAX_ARCHIVE_MEMBERS)); then
        fail_path "$scope" "$logical" 'archive member limit exceeded'
        return
    fi

    validation_start=$FAILURES
    while IFS= read -r member || [[ -n $member ]]; do
        if ! path_stays_below_root "$member"; then
            fail_path "$scope" "$logical!$member" 'archive member escapes extraction root'
        fi
    done <"$list"

    if ! run_archive_command "$tool" -tvf "$archive" 2>/dev/null | \
        head -c "$((MAX_ARCHIVE_LIST_KIB * 2048 + 1))" | awk \
        -v max="$count" -v max_bytes="$((MAX_ARCHIVE_LIST_KIB * 2048))" \
        -v marker="$verbose_limit_marker" '
            { bytes += length($0) + 1 }
            bytes > max_bytes || NR > max {
                print "archive metadata output limit exceeded" > marker
                exit 44
            }
            { print }
        ' >"$verbose"; then
        if [[ -s $verbose_limit_marker ]]; then
            limit_reason=$(<"$verbose_limit_marker")
            fail_path "$scope" "$logical" "$limit_reason"
        else
            fail_path "$scope" "$logical" 'archive metadata cannot be inspected safely'
        fi
        return
    fi
    if [[ $(wc -l <"$verbose" | tr -d '[:space:]') != "$count" ]]; then
        fail_path "$scope" "$logical" 'archive metadata does not match member list'
        return
    fi
    if declared_bytes=$(archive_declared_bytes "$tool" "$verbose"); then
        :
    else
        status=$?
        if ((status == 3)); then
            fail_path "$scope" "$logical" 'archive declared-size limit exceeded before extraction'
        else
            fail_path "$scope" "$logical" 'archive member sizes cannot be accounted safely'
        fi
        return
    fi
    max_total_bytes=$((MAX_TOTAL_ARCHIVE_KIB * 1024))
    if ((declared_bytes > max_total_bytes - TOTAL_ARCHIVE_BYTES)); then
        fail_path "$scope" "$logical" 'global archive declared-size budget exceeded'
        return
    fi
    TOTAL_ARCHIVE_BYTES=$((TOTAL_ARCHIVE_BYTES + declared_bytes))
    exec 3<"$list" 4<"$verbose"
    while IFS= read -r member <&3 || [[ -n $member ]]; do
        IFS= read -r vline <&4 || vline=
        case $vline in
            l*' -> '*)
                target=${vline##* -> }
                check_link_target "$member" "$target" "$scope" "$logical!$member"
                ;;
            h*' link to '*)
                target=${vline##* link to }
                if ! path_stays_below_root "$target"; then
                    fail_path "$scope" "$logical!$member" 'hardlink escapes extraction root'
                fi
                ;;
            b*|c*|p*|s*)
                fail_path "$scope" "$logical!$member" 'special archive member is not source data'
                ;;
        esac
    done
    exec 3<&- 4<&-

    # Keep validation ahead of mutation when presented with hostile input.
    if ((FAILURES > validation_start)); then
        return
    fi

    # POSIX file-size limits use 512-byte blocks; twice the KiB limit is a
    # conservative per-file ceiling. The declared total above remains tighter.
    file_limit_blocks=$((MAX_ARCHIVE_KIB * 2 + 2))
    if ! (
        ulimit -f "$file_limit_blocks" 2>/dev/null || true
        run_archive_command "$tool" --no-same-owner --no-same-permissions \
            -xf "$archive" \
            -C "$extract_dir" > /dev/null 2>&1
    ); then
        fail_path "$scope" "$logical" 'archive cannot be extracted for inspection'
        return
    fi
    if actual_bytes=$(extracted_regular_bytes "$extract_dir"); then
        :
    else
        fail_path "$scope" "$logical" 'archive expanded-size limit exceeded'
        return
    fi
    if ((actual_bytes > declared_bytes)); then
        fail_path "$scope" "$logical" 'archive expanded beyond its declared member sizes'
        return
    fi
    scan_tree "$extract_dir" "$scope" "$depth" "$logical"
}

scan_regular() {
    local file=$1 logical=$2 scope=$3 depth=$4 kind lower
    SCANNED=$((SCANNED + 1))

    if [[ ! -r $file ]]; then
        fail_path "$scope" "$logical" 'file cannot be read for audit'
        return
    fi

    if forbidden_extension "$logical"; then
        fail_path "$scope" "$logical" 'forbidden compiled/package extension'
    fi
    lower=$(LC_ALL=C printf '%s' "$logical" | tr '[:upper:]' '[:lower:]')
    case $lower in
        *.bin)
            if ! is_declared_binary_data "$logical"; then
                fail_path "$scope" "$logical" \
                    'undeclared .bin data (manifest needs purpose, provenance, and SPDX license)'
            fi
            ;;
    esac
    if LC_ALL=C grep -Eaqm1 '^version https://git-lfs[.]github[.]com/spec/v1\r?$' "$file" 2>/dev/null; then
        fail_path "$scope" "$logical" 'unresolved Git LFS pointer'
    fi
    if kind=$(magic_kind "$file"); then
        fail_path "$scope" "$logical" "$kind"
    elif kind=$(file_utility_kind "$file"); then
        fail_path "$scope" "$logical" "$kind"
    fi
    check_removed_library_reference "$file" "$logical" "$scope"

    if looks_like_archive "$file" "$logical"; then
        scan_archive "$file" "$logical" "$scope" "$((depth + 1))"
    fi
}

scan_tree() {
    local tree=$1 scope=$2 depth=${3:-0} prefix=${4:-}
    local path relative logical target resolved canonical_tree

    if [[ ! -d $tree ]]; then
        fail_path "$scope" "$tree" 'tree does not exist'
        return
    fi
    canonical_tree=$(canonicalize_allow_missing "$tree") || {
        fail_path "$scope" "$tree" 'cannot canonicalize audit root'
        return
    }
    while IFS= read -r -d '' path; do
        relative=${path#"$tree"/}
        logical=$relative
        [[ -z $prefix ]] || logical=$prefix!$relative
        if [[ -L $path ]]; then
            target=$(readlink "$path")
            check_link_target "$relative" "$target" "$scope" "$logical"
            resolved=$(canonicalize_allow_missing "$path") || {
                fail_path "$scope" "$logical" 'cannot canonicalize symlink'
                continue
            }
            case $resolved in
                "$canonical_tree"|"$canonical_tree"/*) ;;
                *) fail_path "$scope" "$logical" 'symlink resolves outside audit root' ;;
            esac
        elif [[ -f $path ]]; then
            scan_regular "$path" "$logical" "$scope" "$depth"
        else
            fail_path "$scope" "$logical" 'unsupported special filesystem entry'
        fi
    done < <(find -P "$tree" -path "$tree/.git" -prune -o \
        \( -type f -o -type l -o \( ! -type d \) \) -print0)
}

scan_index() {
    local repo=$1 record metadata logical mode object stage blob target
    local serial=0

    while IFS= read -r -d '' record; do
        metadata=${record%%$'\t'*}
        logical=${record#*$'\t'}
        read -r mode object stage <<< "$metadata"
        [[ $stage == 0 ]] || continue
        case $mode in
            100*)
                serial=$((serial + 1))
                blob=$AUDIT_TMP/index.$serial
                if git -C "$repo" cat-file blob "$object" >"$blob" 2>/dev/null; then
                    scan_regular "$blob" "$logical" tracked 0
                else
                    fail_path tracked "$logical" 'cannot read indexed blob'
                fi
                ;;
            120000)
                if target=$(git -C "$repo" cat-file blob "$object" 2>/dev/null); then
                    check_link_target "$logical" "$target" tracked
                else
                    fail_path tracked "$logical" 'cannot read indexed symlink'
                fi
                ;;
            160000) fail_path tracked "$logical" 'Git submodule entry is not source-only' ;;
            *) fail_path tracked "$logical" 'unsupported Git index mode' ;;
        esac
    done < <(git -C "$repo" ls-files --stage -z)
}

scan_git_archive() {
    local repo=$1 revision=$2 label=$3 tarball
    tarball=$(mktemp "$AUDIT_TMP/git-archive.XXXXXXXX")
    if ! git -C "$repo" archive --format=tar "$revision" >"$tarball" 2>/dev/null; then
        fail_path "$label" "$revision" 'cannot create Git source archive'
        return
    fi
    scan_archive "$tarball" "$revision.tar" "$label" 0
}

if ((REPOSITORY_AUDIT)); then
    if [[ -z $ROOT ]]; then
        if ! ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
            printf 'ERROR: not inside a Git repository; use --tree or --archive\n' >&2
            exit 2
        fi
    fi
    if ! ROOT=$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null); then
        printf 'ERROR: --root is not a Git repository\n' >&2
        exit 2
    fi

    scan_index "$ROOT"
    scan_tree "$ROOT" working-tree 0
    if git -C "$ROOT" rev-parse --verify -q 'HEAD^{commit}' >/dev/null; then
        scan_git_archive "$ROOT" HEAD git-archive-HEAD
    else
        fail_path git-archive-HEAD HEAD 'repository has no commit'
    fi
    if ((TAG_COUNT)); then
        for target in "${TAGS[@]}"; do
            if git -C "$ROOT" rev-parse --verify -q "$target^{commit}" >/dev/null; then
                scan_git_archive "$ROOT" "$target" "git-archive-$target"
            else
                fail_path git-tag "$target" 'revision does not resolve to a commit'
            fi
        done
    fi
fi

if ((TREE_COUNT)); then
    for target in "${TREES[@]}"; do
        if [[ -d $target ]]; then
            target=$(canonicalize_allow_missing "$target") || {
                fail_path standalone-tree "$target" 'cannot canonicalize tree'
                continue
            }
            scan_tree "$target" standalone-tree 0
        else
            fail_path standalone-tree "$target" 'tree does not exist'
        fi
    done
fi

if ((ARCHIVE_COUNT)); then
    for target in "${ARCHIVES[@]}"; do
        if [[ -f $target ]]; then
            target=$(canonicalize_allow_missing "$target") || {
                fail_path standalone-archive "$target" 'cannot canonicalize archive'
                continue
            }
            scan_archive "$target" "${target##*/}" standalone-archive 0
        else
            fail_path standalone-archive "$target" 'archive does not exist'
        fi
    done
fi

if ((FAILURES == 0)); then
    printf 'PASS source-only: %d files, %d archives\n' "$SCANNED" "$ARCHIVES_SCANNED"
    exit 0
fi
printf 'FAIL source-only: %d finding(s), %d files, %d archives\n' \
    "$FAILURES" "$SCANNED" "$ARCHIVES_SCANNED"
exit 1
