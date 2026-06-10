# Fish completions for zupt
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Install:
#   sudo install -m 644 completions/zupt.fish /usr/share/fish/vendor_completions.d/
# or for a single user:
#   cp completions/zupt.fish ~/.config/fish/completions/

# ─── Subcommands ───
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'compress c' -d 'Create an archive'
complete -c zupt -f -n '__fish_use_subcommand' -a 'compress c' -d 'Create an archive'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'extract x'  -d 'Extract an archive'
complete -c zupt -f -n '__fish_use_subcommand' -a 'extract x'  -d 'Extract an archive'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'list l'     -d 'List archive entries'
complete -c zupt -f -n '__fish_use_subcommand' -a 'list l'     -d 'List archive entries'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'test t'     -d 'Verify archive integrity'
complete -c zupt -f -n '__fish_use_subcommand' -a 'test t'     -d 'Verify archive integrity'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'info'       -d 'Archive metadata (no key needed)'
complete -c zupt -f -n '__fish_use_subcommand' -a 'info'       -d 'Archive metadata (no key needed)'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'bench'      -d 'Benchmark compression levels'
complete -c zupt -f -n '__fish_use_subcommand' -a 'bench'      -d 'Benchmark compression levels'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'disk'       -d 'Full-disk backup/restore'
complete -c zupt -f -n '__fish_use_subcommand' -a 'disk'       -d 'Full-disk backup/restore'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'keygen'     -d 'Generate a key file'
complete -c zupt -f -n '__fish_use_subcommand' -a 'keygen'     -d 'Generate a key file'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'version'    -d 'Print version info'
complete -c zupt -f -n '__fish_use_subcommand' -a 'version'    -d 'Print version info'
complete -c vaptvupt -f -n '__fish_use_subcommand' -a 'help'       -d 'Print help'
complete -c zupt -f -n '__fish_use_subcommand' -a 'help'       -d 'Print help'

# Helper predicates
function __fish_zupt_using_subcommand
    set -l cmd (commandline -opc)
    if test (count $cmd) -gt 1
        contains -- $cmd[2] $argv
        return $status
    end
    return 1
end

# ─── Compress options ───
set -l compress_cmds compress c
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s l -l level    -d 'Compression level (1-9, default 7)' -x -a '1 2 3 4 5 6 7 8 9'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s l -l level    -d 'Compression level (1-9, default 7)' -x -a '1 2 3 4 5 6 7 8 9'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s b -l block    -d 'Block size in bytes' -x
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s b -l block    -d 'Block size in bytes' -x
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s s -l store    -d 'Store without compression'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s s -l store    -d 'Store without compression'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s f -l fast     -d 'Use fast LZ codec'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s f -l fast     -d 'Use fast LZ codec'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l vv -l vaptvupt -d 'Use VaptVupt codec'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l vv -l vaptvupt -d 'Use VaptVupt codec'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l lzhp          -d 'Use Zupt-LZHP codec (no SIMD needed)'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l lzhp          -d 'Use Zupt-LZHP codec (no SIMD needed)'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s p -l password -d 'Encrypt with password (prompted if empty)' -x
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s p -l password -d 'Encrypt with password (prompted if empty)' -x
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l kdf           -d 'Password KDF' -x -a 'argon2id pbkdf2'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l kdf           -d 'Password KDF' -x -a 'argon2id pbkdf2'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s c -l comment  -d 'Embed archive comment (UTF-8, ≤4096 B)' -x
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s c -l comment  -d 'Embed archive comment (UTF-8, ≤4096 B)' -x
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l comment-file  -d 'Read comment from file' -r
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l comment-file  -d 'Read comment from file' -r
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l pq            -d 'Legacy PQ public key' -r
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l pq            -d 'Legacy PQ public key' -r
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l pq-sdk        -d 'PQ public key (libzuptsdk)' -r
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l pq-sdk        -d 'PQ public key (libzuptsdk)' -r
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s D -l dedup    -d 'Block-level deduplication'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s D -l dedup    -d 'Block-level deduplication'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -l solid         -d 'Solid mode (single stream)'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -l solid         -d 'Solid mode (single stream)'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s v -l verbose  -d 'Verbose output'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s v -l verbose  -d 'Verbose output'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s q -l quiet    -d 'Suppress non-error output'
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s q -l quiet    -d 'Suppress non-error output'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $compress_cmds" -s t -l threads  -d 'Thread count (0=auto)' -x
complete -c zupt -n "__fish_zupt_using_subcommand $compress_cmds" -s t -l threads  -d 'Thread count (0=auto)' -x

# ─── Extract / List / Test options ───
set -l rw_cmds extract x list l test t
complete -c vaptvupt -n "__fish_zupt_using_subcommand $rw_cmds" -s o -l output   -d 'Output directory' -x -a '(__fish_complete_directories)'
complete -c zupt -n "__fish_zupt_using_subcommand $rw_cmds" -s o -l output   -d 'Output directory' -x -a '(__fish_complete_directories)'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $rw_cmds" -s p -l password -d 'Decryption password' -x
complete -c zupt -n "__fish_zupt_using_subcommand $rw_cmds" -s p -l password -d 'Decryption password' -x
complete -c vaptvupt -n "__fish_zupt_using_subcommand $rw_cmds" -l pq            -d 'Legacy PQ private key' -r
complete -c zupt -n "__fish_zupt_using_subcommand $rw_cmds" -l pq            -d 'Legacy PQ private key' -r
complete -c vaptvupt -n "__fish_zupt_using_subcommand $rw_cmds" -l pq-sdk        -d 'PQ private key (libzuptsdk)' -r
complete -c zupt -n "__fish_zupt_using_subcommand $rw_cmds" -l pq-sdk        -d 'PQ private key (libzuptsdk)' -r
complete -c vaptvupt -n "__fish_zupt_using_subcommand $rw_cmds" -s v -l verbose  -d 'Verbose output (surfaces top-MAC/SDK details on failure)'
complete -c zupt -n "__fish_zupt_using_subcommand $rw_cmds" -s v -l verbose  -d 'Verbose output (surfaces top-MAC/SDK details on failure)'
complete -c vaptvupt -n "__fish_zupt_using_subcommand $rw_cmds" -s t -l threads  -d 'Thread count' -x
complete -c zupt -n "__fish_zupt_using_subcommand $rw_cmds" -s t -l threads  -d 'Thread count' -x

# ─── Disk subcommand ───
complete -c vaptvupt -f -n "__fish_zupt_using_subcommand disk; and not __fish_seen_subcommand_from backup restore" \
complete -c zupt -f -n "__fish_zupt_using_subcommand disk; and not __fish_seen_subcommand_from backup restore" \
    -a 'backup' -d 'Read a block device into an archive'
complete -c vaptvupt -f -n "__fish_zupt_using_subcommand disk; and not __fish_seen_subcommand_from backup restore" \
complete -c zupt -f -n "__fish_zupt_using_subcommand disk; and not __fish_seen_subcommand_from backup restore" \
    -a 'restore' -d 'Write an archive to a block device'

# ─── Keygen options ───
complete -c vaptvupt -n '__fish_zupt_using_subcommand keygen' -l sdk     -d 'Generate SDK v2 keypair'
complete -c zupt -n '__fish_zupt_using_subcommand keygen' -l sdk     -d 'Generate SDK v2 keypair'
complete -c vaptvupt -n '__fish_zupt_using_subcommand keygen' -l pq-sdk  -d 'Same as --sdk'
complete -c zupt -n '__fish_zupt_using_subcommand keygen' -l pq-sdk  -d 'Same as --sdk'
complete -c vaptvupt -n '__fish_zupt_using_subcommand keygen' -s o       -d 'Output keyfile path' -r
complete -c zupt -n '__fish_zupt_using_subcommand keygen' -s o       -d 'Output keyfile path' -r
complete -c vaptvupt -n '__fish_zupt_using_subcommand keygen' -l pub     -d 'Export public key from -k'
complete -c zupt -n '__fish_zupt_using_subcommand keygen' -l pub     -d 'Export public key from -k'
complete -c vaptvupt -n '__fish_zupt_using_subcommand keygen' -s k       -d 'Source private keyfile' -r
complete -c zupt -n '__fish_zupt_using_subcommand keygen' -s k       -d 'Source private keyfile' -r
