# bash completion for vaptvupt (with `zupt` legacy alias)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Install (system-wide):
#   sudo install -m 644 completions/vaptvupt.bash /usr/share/bash-completion/completions/vaptvupt
#   sudo ln -sf vaptvupt /usr/share/bash-completion/completions/zupt
# or for a single user:
#   cp completions/vaptvupt.bash ~/.local/share/bash-completion/completions/vaptvupt
#
# Reload your shell or `source` the file to pick up changes.

_vaptvupt() {
    local cur prev words cword
    _init_completion -n = 2>/dev/null || {
        # _init_completion missing on this host; fall back to manual setup.
        local IFS=$' \t\n'
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        cword=$COMP_CWORD
        words=("${COMP_WORDS[@]}")
    }

    local subcommands="compress c extract x list l test t info bench disk keygen version help"
    local global_opts="-v --verbose -q --quiet -t --threads -h --help"

    # First positional → subcommand
    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return 0
    fi

    local subcmd="${words[1]}"

    case "$prev" in
        -p|--password)
            # Don't complete passwords from filesystem
            COMPREPLY=()
            return 0
            ;;
        -l|--level)
            COMPREPLY=( $(compgen -W "1 2 3 4 5 6 7 8 9" -- "$cur") )
            return 0
            ;;
        --kdf)
            COMPREPLY=( $(compgen -W "argon2id pbkdf2" -- "$cur") )
            return 0
            ;;
        -t|--threads)
            COMPREPLY=( $(compgen -W "0 1 2 4 8 16 32" -- "$cur") )
            return 0
            ;;
        -b|--block)
            COMPREPLY=( $(compgen -W "65536 131072 262144 524288 1048576" -- "$cur") )
            return 0
            ;;
        -o|--output)
            _filedir -d
            return 0
            ;;
        --pq|--pq-sdk)
            # Key files (no extension constraint)
            _filedir
            return 0
            ;;
        --comment-file)
            _filedir
            return 0
            ;;
        -c|--comment)
            # Free-form text; no useful completion
            COMPREPLY=()
            return 0
            ;;
        -k)
            _filedir
            return 0
            ;;
    esac

    case "$subcmd" in
        compress|c)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "
                    -l --level -b --block -s --store -f --fast
                    --vv --vaptvupt --lzhp
                    -p --password --kdf
                    -c --comment --comment-file
                    --pq --pq-sdk
                    --dedup -D --solid
                    -v --verbose -q --quiet -t --threads
                    $global_opts
                " -- "$cur") )
            else
                _filedir
            fi
            ;;
        extract|x)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "
                    -o --output -p --password
                    --pq --pq-sdk
                    -v --verbose -t --threads
                    $global_opts
                " -- "$cur") )
            else
                _filedir 'zupt'
            fi
            ;;
        list|l|test|t)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "
                    -p --password --pq --pq-sdk
                    -v --verbose
                    $global_opts
                " -- "$cur") )
            else
                _filedir 'zupt'
            fi
            ;;
        info)
            _filedir 'zupt'
            ;;
        disk)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "backup restore" -- "$cur") )
            elif [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "
                    -p --password --pq --pq-sdk
                    --kdf -c --comment --comment-file
                    -v --verbose
                " -- "$cur") )
            else
                _filedir
            fi
            ;;
        keygen)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--sdk --pq-sdk -o --pub -k" -- "$cur") )
            else
                _filedir
            fi
            ;;
        bench)
            _filedir
            ;;
        version|help)
            COMPREPLY=()
            ;;
        *)
            _filedir
            ;;
    esac
    return 0
}

complete -F _vaptvupt vaptvupt
# v3.0.0: legacy `zupt` name retained as an alias.
complete -F _vaptvupt zupt
