# fish completion for ZUPT
# SPDX-License-Identifier: AGPL-3.0-or-later

function __fish_zupt_needs_command
    set -l tokens (commandline -opc)
    test (count $tokens) -eq 1
end

function __fish_zupt_using_command
    set -l tokens (commandline -opc)
    test (count $tokens) -gt 1; and contains -- $tokens[2] $argv
end

function __fish_zupt_disk_needs_command
    set -l tokens (commandline -opc)
    test (count $tokens) -eq 2; and test "$tokens[2]" = disk
end

function __fish_zupt_disk_using_command
    set -l tokens (commandline -opc)
    test (count $tokens) -gt 2; and test "$tokens[2]" = disk; and contains -- $tokens[3] $argv
end

complete -c zupt -f -n __fish_zupt_needs_command \
    -a 'compress c' -d 'Create an archive'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a 'extract x' -d 'Extract an archive'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a 'list l' -d 'List archive entries'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a 'test t' -d 'Verify archive integrity'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a 'info i' -d 'Show archive framing metadata'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a 'bench b' -d 'Benchmark compression levels'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a disk -d 'Back up or restore a disk image'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a keygen -d 'Generate or export a recipient key'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a version -d 'Show version and build information'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a help -d 'Show command help'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a '--version -V' -d 'Show version and build information'
complete -c zupt -f -n __fish_zupt_needs_command \
    -a '--help -h' -d 'Show command help'

set -l compress_condition '__fish_zupt_using_command compress c'
complete -c zupt -n "$compress_condition" -s l -l level \
    -d 'Compression level' -x -a '1 2 3 4 5 6 7 8 9'
complete -c zupt -n "$compress_condition" -s b -l block \
    -d 'Block size in bytes' -x
complete -c zupt -n "$compress_condition" -s s -l store \
    -d 'Store without compression'
complete -c zupt -n "$compress_condition" -s f -l fast \
    -d 'Use fast LZ codec'
complete -c zupt -n "$compress_condition" -l vv -l vaptvupt \
    -d 'Force VaptVupt LZ + ANS codec'
complete -c zupt -n "$compress_condition" -l lzhp \
    -d 'Force portable LZHP codec'
complete -c zupt -n "$compress_condition" -l kdf \
    -d 'Password KDF' -x -a 'pbkdf2 argon2id'
complete -c zupt -n "$compress_condition" -s c -l comment \
    -d 'Store an archive comment' -x
complete -c zupt -n "$compress_condition" -l comment-file \
    -d 'Read archive comment from file' -r
complete -c zupt -n "$compress_condition" -s D -l dedup \
    -d 'Enable block-level deduplication'
complete -c zupt -n "$compress_condition" -s S -l solid \
    -d 'Use a solid single compression stream'
complete -c zupt -n "$compress_condition" -s y -l force \
    -d 'Overwrite an existing non-.zupt output'
complete -c zupt -n "$compress_condition" -s t -l threads \
    -d 'Compression thread count' -x

set -l read_condition '__fish_zupt_using_command compress c extract x list l test t'
complete -c zupt -n "$read_condition" -s p -l password \
    -d 'Password in process arguments' -x
complete -c zupt -n "$read_condition" -l password-prompt \
    -d 'Read password interactively without echo'
complete -c zupt -n "$read_condition" -l pass-file \
    -d 'Read password from first line of file' -r
complete -c zupt -n "$read_condition" -l pass-fd \
    -d 'Read password from inherited file descriptor' -x
complete -c zupt -n "$read_condition" -l pq \
    -d 'Native ML-KEM-768 + X25519 hybrid key' -r
complete -c zupt -n "$read_condition" -l pq-only \
    -d 'Native ML-KEM-768-only key' -r
complete -c zupt -n "$read_condition" -l pq-sdk \
    -d 'Optional system libvuptsdk key' -r
complete -c zupt -n "$read_condition" -l pq-box \
    -d 'Optional system libpqvaptvupt key' -r
complete -c zupt -n "$read_condition" -s v -l verbose \
    -d 'Additional progress or diagnostic output'

set -l legacy_read_condition '__fish_zupt_using_command extract x list l test t'
complete -c zupt -n "$legacy_read_condition" -l allow-legacy-no-ait \
    -d 'Recover a trusted old archive without an integrity trailer'

complete -c zupt -n '__fish_zupt_using_command extract x' \
    -s o -l output -d 'Output directory' -r
complete -c zupt -n '__fish_zupt_using_command extract x' \
    -s t -l threads -d 'Decompression thread count' -x
complete -c zupt -n '__fish_zupt_using_command bench b' \
    -l compare -d 'Compare available external compressors'

complete -c zupt -f -n __fish_zupt_disk_needs_command \
    -a backup -d 'Create a disk-image archive'
complete -c zupt -f -n __fish_zupt_disk_needs_command \
    -a restore -d 'Restore a disk-image archive'
set -l disk_condition '__fish_zupt_using_command disk'
complete -c zupt -n "$disk_condition" -s l -l level \
    -d 'Compression level' -x -a '1 2 3 4 5 6 7 8 9'
complete -c zupt -n "$disk_condition" -s b -l block \
    -d 'Block size in bytes' -x
complete -c zupt -n "$disk_condition" -s s -l store \
    -d 'Store without compression'
complete -c zupt -n "$disk_condition" -l vv -l vaptvupt \
    -d 'Force VaptVupt LZ + ANS codec'
complete -c zupt -n "$disk_condition" -l lzhp \
    -d 'Force portable LZHP codec'
complete -c zupt -n "$disk_condition" -s p -l password \
    -d 'Password in process arguments' -x
complete -c zupt -n "$disk_condition" -l password-prompt \
    -d 'Read password interactively without echo'
complete -c zupt -n "$disk_condition" -l pass-file \
    -d 'Read password from first line of file' -r
complete -c zupt -n "$disk_condition" -l pass-fd \
    -d 'Read password from inherited file descriptor' -x
complete -c zupt -n "$disk_condition" -l kdf \
    -d 'Password KDF' -x -a 'pbkdf2 argon2id'
complete -c zupt -n "$disk_condition" -s c -l comment \
    -d 'Store an archive comment' -x
complete -c zupt -n "$disk_condition" -l comment-file \
    -d 'Read archive comment from file' -r
complete -c zupt -n "$disk_condition" -l pq \
    -d 'Native ML-KEM-768 + X25519 hybrid key' -r
complete -c zupt -n "$disk_condition" -l pq-only \
    -d 'Native ML-KEM-768-only key' -r
complete -c zupt -n "$disk_condition" -s D -l dedup \
    -d 'Enable block-level deduplication'
complete -c zupt -n "$disk_condition" -s v -l verbose \
    -d 'Additional progress or diagnostic output'
complete -c zupt -n "$disk_condition" -s t -l threads \
    -d 'Thread count' -x
complete -c zupt -n '__fish_zupt_disk_using_command restore' \
    -l allow-legacy-no-ait \
    -d 'Recover a trusted old disk archive without an integrity trailer'

set -l keygen_condition '__fish_zupt_using_command keygen'
complete -c zupt -n "$keygen_condition" -s o -l output \
    -d 'Output key file' -r
complete -c zupt -n "$keygen_condition" -l pub \
    -d 'Export a public key'
complete -c zupt -n "$keygen_condition" -s k -l key \
    -d 'Source private key' -r
complete -c zupt -n "$keygen_condition" -l pq-only -l pqonly \
    -d 'Native ML-KEM-768-only key format'
complete -c zupt -n "$keygen_condition" -l sdk -l pq-sdk \
    -d 'Optional system libvuptsdk key format'
complete -c zupt -n "$keygen_condition" -l box -l pq-box \
    -d 'Optional system libpqvaptvupt key format'
