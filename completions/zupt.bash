# bash completion for ZUPT
# SPDX-License-Identifier: AGPL-3.0-or-later

_zupt()
{
    local cur prev command disk_command
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    command=${COMP_WORDS[1]-}
    disk_command=${COMP_WORDS[2]-}

    case $prev in
        -l|--level)
            COMPREPLY=( $(compgen -W '1 2 3 4 5 6 7 8 9' -- "$cur") )
            return
            ;;
        -b|--block|-t|--threads|--pass-fd|-p|--password|-c|--comment)
            return
            ;;
        --kdf)
            COMPREPLY=( $(compgen -W 'pbkdf2 argon2id' -- "$cur") )
            return
            ;;
        -o|--output|-k|--key|--pass-file|--comment-file|--pq|--pq-only|--pq-sdk|--pq-box)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return
            ;;
    esac

    if (( COMP_CWORD == 1 )); then
        COMPREPLY=( $(compgen -W \
            'compress c extract x list l test t info i bench b disk keygen version help --version -V --help -h' \
            -- "$cur") )
        return
    fi

    local password_options='-p --password --password-prompt --pass-file --pass-fd'
    local pq_options='--pq --pq-only --pq-sdk --pq-box'
    local legacy_read_option='--allow-legacy-no-ait'
    local common_read_options="-v --verbose $password_options $pq_options $legacy_read_option"

    case $command in
        compress|c)
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W \
                    "-l --level -b --block -s --store -f --fast --vv --vaptvupt --lzhp
                     $password_options --kdf -c --comment --comment-file $pq_options
                     -D --dedup -S --solid -y --force -v --verbose -t --threads" \
                    -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
        extract|x)
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W \
                    "-o --output $common_read_options -t --threads" -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -X '!*.zupt' -- "$cur") )
            fi
            ;;
        list|l|test|t)
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "$common_read_options" -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -X '!*.zupt' -- "$cur") )
            fi
            ;;
        info|i)
            COMPREPLY=( $(compgen -f -X '!*.zupt' -- "$cur") )
            ;;
        bench|b)
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W '--compare' -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
        disk)
            if (( COMP_CWORD == 2 )); then
                COMPREPLY=( $(compgen -W 'backup restore' -- "$cur") )
            elif [[ $cur == -* ]]; then
                local disk_options
                disk_options="-l --level -b --block -s --store --vv --vaptvupt --lzhp
                              $password_options --kdf -c --comment --comment-file
                              --pq --pq-only -D --dedup -v --verbose -t --threads"
                if [[ $disk_command == restore ]]; then
                    disk_options+=" $legacy_read_option"
                fi
                COMPREPLY=( $(compgen -W \
                    "$disk_options" \
                    -- "$cur") )
            elif [[ $disk_command == restore ]]; then
                COMPREPLY=( $(compgen -f -X '!*.zupt' -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
        keygen)
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W \
                    '-o --output --pub -k --key --pq-only --pqonly --sdk --pq-sdk --box --pq-box' \
                    -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
    esac
}

complete -F _zupt zupt
