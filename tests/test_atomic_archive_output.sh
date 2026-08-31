#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

bin=${1:-./zupt}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
case "$bin" in
    /*) ;;
    *) bin="$(pwd -P)/${bin#./}" ;;
esac
surgery="$repo_root/tests/archive_surgery.py"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-atomic-output.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

assert_no_temps() {
    if find "$tmp" -name '.zupt-archive-*' -print -quit | grep -q .; then
        fail 'private archive temporary was not removed'
    fi
}

printf 'archive payload\n' > "$tmp/input.txt"
printf 'victim must remain unchanged\n' > "$tmp/victim.txt"
cp "$tmp/victim.txt" "$tmp/victim.expected"

# Writers must never create an archive that their own extraction policy would
# reject. A parent component in the user-supplied input name fails before any
# output is published.
mkdir "$tmp/parent-input-work"
printf 'parent input\n' > "$tmp/parent-input.txt"
if (cd "$tmp/parent-input-work" &&
    MSYS2_ARG_CONV_EXCL='../parent-input.txt' \
        "$bin" compress -s parent-path.zupt ../parent-input.txt \
        >/dev/null 2>&1); then
    fail 'compression accepted an unsafe parent-component archive name'
fi
test ! -e "$tmp/parent-input-work/parent-path.zupt" ||
    fail 'unsafe parent-component input published an archive'

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) ;;
    *)
        mkdir -p "$tmp/collision/in/foo"
        printf 'literal backslash\n' > "$tmp/collision/in/foo\\bar"
        printf 'nested separator\n' > "$tmp/collision/in/foo/bar"
        if "$bin" compress -s "$tmp/collision.zupt" \
                "$tmp/collision/in" >/dev/null 2>&1; then
            fail 'compression accepted colliding slash/backslash destinations'
        fi
        test ! -e "$tmp/collision.zupt" ||
            fail 'colliding archive paths published an archive'
        mkdir "$tmp/case-collision"
        printf 'upper\n' > "$tmp/case-collision/Name.txt"
        printf 'lower\n' > "$tmp/case-collision/name.txt"
        if [[ $(find "$tmp/case-collision" -type f | wc -l) -eq 2 ]]; then
            if "$bin" compress -s "$tmp/case-collision.zupt" \
                    "$tmp/case-collision" >/dev/null 2>&1; then
                fail 'compression accepted ASCII case-colliding destinations'
            fi
            test ! -e "$tmp/case-collision.zupt" ||
                fail 'case-colliding archive paths published an archive'
        fi
        ;;
esac

# Normal compression must not publish an archive over any spelling or link
# alias of an input file. --force does not bypass this data-loss boundary.
mkdir "$tmp/self-input"
printf 'self input must survive\n' > "$tmp/self-input/self.zupt"
cp "$tmp/self-input/self.zupt" "$tmp/self-input.expected"
if "$bin" compress -s "$tmp/self-input/./self.zupt" \
        "$tmp/self-input/self.zupt" >/dev/null 2>&1; then
    fail 'compression accepted an alternate spelling of its input as output'
fi
if "$bin" compress --solid -s "$tmp/self-input/./self.zupt" \
        "$tmp/self-input/self.zupt" >/dev/null 2>&1; then
    fail 'solid compression accepted an alternate spelling of its input as output'
fi
cmp "$tmp/self-input.expected" "$tmp/self-input/self.zupt" ||
    fail 'alternate-spelling self compression changed its input'

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        # Native Windows publication uses handle-relative APIs and rejects
        # reparse-point ancestors. Exercise the portable guarantees here;
        # POSIX symlink, hardlink, ulimit and raw-device cases are reported as
        # skipped instead of imposing contradictory MSYS semantics on the PE.
        printf 'existing Windows output\n' > "$tmp/windows-output.zupt"
        "$bin" compress -s "$tmp/windows-output.zupt" "$tmp/input.txt" \
            >/dev/null 2>&1 || fail 'Windows archive replacement failed'
        "$bin" test "$tmp/windows-output.zupt" >/dev/null 2>&1 ||
            fail 'Windows atomically published archive is invalid'
        mkdir "$tmp/windows-directory.zupt"
        if "$bin" compress -s "$tmp/windows-directory.zupt" \
                "$tmp/input.txt" >/dev/null 2>&1; then
            fail 'Windows directory destination was replaced'
        fi
        dd if=/dev/urandom of="$tmp/windows-disk.img" bs=65536 count=2 \
            2>/dev/null
        "$bin" disk backup -s -b 65536 "$tmp/windows-disk.zupt" \
            "$tmp/windows-disk.img" >/dev/null 2>&1 ||
            fail 'Windows disk backup failed'
        "$bin" test "$tmp/windows-disk.zupt" >/dev/null 2>&1 ||
            fail 'Windows disk archive is invalid'
        mkdir "$tmp/windows-disk-extracted"
        "$bin" extract -o "$tmp/windows-disk-extracted" \
            "$tmp/windows-disk.zupt" >/dev/null 2>&1 ||
            fail 'Windows disk archive generic extraction failed'
        cmp "$tmp/windows-disk.img" \
            "$tmp/windows-disk-extracted/windows-disk.img" ||
            fail 'Windows disk archive generic extraction mismatch'
        "$bin" disk restore "$tmp/windows-disk.zupt" \
            "$tmp/windows-restored.img" >/dev/null 2>&1 ||
            fail 'Windows disk restore failed'
        cmp "$tmp/windows-disk.img" "$tmp/windows-restored.img" ||
            fail 'Windows disk restore mismatch'
        python3 "$surgery" flip-payload "$tmp/windows-disk.zupt" \
            "$tmp/windows-disk-corrupt.zupt" --kind data ||
            fail 'could not corrupt Windows disk archive fixture'
        printf 'Windows restore sentinel\n' > "$tmp/windows-restore-target"
        cp "$tmp/windows-restore-target" "$tmp/windows-restore.expected"
        if "$bin" disk restore "$tmp/windows-disk-corrupt.zupt" \
                "$tmp/windows-restore-target" >/dev/null 2>&1; then
            fail 'Windows disk restore accepted corrupt DATA'
        fi
        cmp "$tmp/windows-restore.expected" "$tmp/windows-restore-target" ||
            fail 'Windows corrupt disk restore changed its target'
        assert_no_temps
        printf 'SKIP: POSIX symlink, hardlink, ulimit and raw-device atomic cases\n'
        printf 'atomic archive output Windows subset: PASS\n'
        exit 0
        ;;
esac

printf 'hardlinked input must survive\n' > "$tmp/self-hard-input"
cp "$tmp/self-hard-input" "$tmp/self-hard.expected"
ln "$tmp/self-hard-input" "$tmp/self-hard-output.zupt"
if "$bin" compress -y -s "$tmp/self-hard-output.zupt" \
        "$tmp/self-hard-input" >/dev/null 2>&1; then
    fail 'compression accepted a hardlink alias of its input as output'
fi
if "$bin" compress --solid -y -s "$tmp/self-hard-output.zupt" \
        "$tmp/self-hard-input" >/dev/null 2>&1; then
    fail 'solid compression accepted a hardlink alias of its input as output'
fi
test "$tmp/self-hard-input" -ef "$tmp/self-hard-output.zupt" ||
    fail 'rejected compression hardlink alias was replaced'
cmp "$tmp/self-hard.expected" "$tmp/self-hard-input" ||
    fail 'hardlink-alias compression changed its input'

printf 'symlinked input must survive\n' > "$tmp/self-symlink-input"
cp "$tmp/self-symlink-input" "$tmp/self-symlink.expected"
ln -s self-symlink-input "$tmp/self-symlink-output.zupt"
if "$bin" compress -s "$tmp/self-symlink-output.zupt" \
        "$tmp/self-symlink-input" >/dev/null 2>&1; then
    fail 'compression accepted a symlink alias of its input as output'
fi
if "$bin" compress --solid -s "$tmp/self-symlink-output.zupt" \
        "$tmp/self-symlink-input" >/dev/null 2>&1; then
    fail 'solid compression accepted a symlink alias of its input as output'
fi
test -L "$tmp/self-symlink-output.zupt" ||
    fail 'rejected compression symlink alias was replaced'
cmp "$tmp/self-symlink.expected" "$tmp/self-symlink-input" ||
    fail 'symlink-alias compression changed its input'

# Replacing the output entry must not open or truncate its symlink target.
ln -s victim.txt "$tmp/symlink.zupt"
"$bin" compress -s "$tmp/symlink.zupt" "$tmp/input.txt" >/dev/null 2>&1
cmp "$tmp/victim.expected" "$tmp/victim.txt" || fail 'symlink target changed'
test ! -L "$tmp/symlink.zupt" || fail 'archive remained a symlink'
"$bin" test "$tmp/symlink.zupt" >/dev/null 2>&1 || fail 'published archive is invalid'
assert_no_temps

# The same directory-entry replacement rule protects another name linked to
# the old inode.  The victim keeps its bytes while the output gets a new inode.
printf 'hardlink victim\n' > "$tmp/hard-victim"
cp "$tmp/hard-victim" "$tmp/hard.expected"
ln "$tmp/hard-victim" "$tmp/hardlink.zupt"
"$bin" compress --solid -s "$tmp/hardlink.zupt" "$tmp/input.txt" >/dev/null 2>&1
cmp "$tmp/hard.expected" "$tmp/hard-victim" || fail 'hardlink peer changed'
if test "$tmp/hard-victim" -ef "$tmp/hardlink.zupt"; then
    fail 'archive reused victim inode'
fi
"$bin" test "$tmp/hardlink.zupt" >/dev/null 2>&1 || fail 'solid archive is invalid'
assert_no_temps

# A symlink explicitly present in the user-selected POSIX parent is resolved
# once, then the physical directory is pinned for the entire publication.
mkdir "$tmp/real-parent"
ln -s real-parent "$tmp/parent-link"
"$bin" compress -s "$tmp/parent-link/through-link.zupt" \
    "$tmp/input.txt" >/dev/null 2>&1 || fail 'symlinked parent was unusable'
"$bin" test "$tmp/real-parent/through-link.zupt" >/dev/null 2>&1 ||
    fail 'archive through resolved parent is invalid'
assert_no_temps

# A directory at the final name cannot be replaced.  The publication failure
# must remove the private temporary and leave the old directory untouched.
mkdir "$tmp/final-is-directory.zupt"
printf 'directory sentinel\n' > "$tmp/final-is-directory.zupt/sentinel"
if "$bin" compress -s "$tmp/final-is-directory.zupt" \
        "$tmp/input.txt" >/dev/null 2>&1; then
    fail 'directory destination was replaced'
fi
grep -qx 'directory sentinel' "$tmp/final-is-directory.zupt/sentinel" ||
    fail 'directory destination changed after failed publication'
assert_no_temps

# Force a write/fsync failure after the temporary has been opened.  A prior
# destination must survive byte-for-byte and no partial archive may appear.
head -c 16384 /dev/urandom > "$tmp/large-input.bin"
printf 'previous archive sentinel\n' > "$tmp/write-failure.zupt"
cp "$tmp/write-failure.zupt" "$tmp/write-failure.expected"
if (trap '' XFSZ; ulimit -f 1; "$bin" compress -s \
        "$tmp/write-failure.zupt" "$tmp/large-input.bin" \
        >/dev/null 2>&1); then
    fail 'forced write failure unexpectedly succeeded'
fi
cmp "$tmp/write-failure.expected" "$tmp/write-failure.zupt" ||
    fail 'prior archive changed after write failure'
assert_no_temps

# Two publishers may race for the same directory entry.  Each builds a private
# complete archive; whichever rename wins must leave a valid final archive.
"$bin" compress -s "$tmp/concurrent.zupt" "$tmp/input.txt" \
    >/dev/null 2>&1 &
first_pid=$!
"$bin" compress --solid -s "$tmp/concurrent.zupt" "$tmp/input.txt" \
    >/dev/null 2>&1 &
second_pid=$!
wait "$first_pid" || fail 'first concurrent publisher failed'
wait "$second_pid" || fail 'second concurrent publisher failed'
"$bin" test "$tmp/concurrent.zupt" >/dev/null 2>&1 ||
    fail 'concurrent final archive is invalid'
assert_no_temps

# Disk-image backup uses the same atomic publisher.
printf 'disk image bytes\n' > "$tmp/disk.img"

# A disk backup must never replace its only source name with the archive.  The
# identity check covers direct spelling, hardlink aliases, and symlink aliases.
cp "$tmp/disk.img" "$tmp/disk-same.img"
cp "$tmp/disk-same.img" "$tmp/disk-same.expected"
if "$bin" disk backup -s "$tmp/disk-same.img" "$tmp/disk-same.img" \
        >/dev/null 2>&1; then
    fail 'disk backup accepted the same source and output path'
fi
cmp "$tmp/disk-same.expected" "$tmp/disk-same.img" ||
    fail 'same-path disk backup changed its source'

cp "$tmp/disk.img" "$tmp/disk-hardlink-source"
cp "$tmp/disk-hardlink-source" "$tmp/disk-hardlink.expected"
ln "$tmp/disk-hardlink-source" "$tmp/disk-hardlink-output.zupt"
if "$bin" disk backup -s "$tmp/disk-hardlink-output.zupt" \
        "$tmp/disk-hardlink-source" >/dev/null 2>&1; then
    fail 'disk backup accepted a hardlink alias of its source'
fi
test "$tmp/disk-hardlink-source" -ef "$tmp/disk-hardlink-output.zupt" ||
    fail 'rejected disk hardlink alias was replaced'
cmp "$tmp/disk-hardlink.expected" "$tmp/disk-hardlink-source" ||
    fail 'hardlink-alias disk backup changed its source'

cp "$tmp/disk.img" "$tmp/disk-symlink-source"
cp "$tmp/disk-symlink-source" "$tmp/disk-symlink.expected"
ln -s disk-symlink-source "$tmp/disk-symlink-output.zupt"
if "$bin" disk backup -s "$tmp/disk-symlink-output.zupt" \
        "$tmp/disk-symlink-source" >/dev/null 2>&1; then
    fail 'disk backup accepted a symlink alias of its source'
fi
test -L "$tmp/disk-symlink-output.zupt" ||
    fail 'rejected disk symlink alias was replaced'
cmp "$tmp/disk-symlink.expected" "$tmp/disk-symlink-source" ||
    fail 'symlink-alias disk backup changed its source'
assert_no_temps

printf 'disk victim\n' > "$tmp/disk-victim"
cp "$tmp/disk-victim" "$tmp/disk.expected"
ln -s disk-victim "$tmp/disk.zupt"
"$bin" disk backup -s "$tmp/disk.zupt" "$tmp/disk.img" >/dev/null 2>&1
cmp "$tmp/disk.expected" "$tmp/disk-victim" || fail 'disk backup followed symlink'
test ! -L "$tmp/disk.zupt" || fail 'disk archive remained a symlink'
"$bin" disk restore "$tmp/disk.zupt" "$tmp/disk-restored.img" \
    >/dev/null 2>&1 || fail 'disk archive could not be restored'
cmp "$tmp/disk.img" "$tmp/disk-restored.img" || fail 'disk restore mismatch'
"$bin" test "$tmp/disk.zupt" >/dev/null 2>&1 || fail 'disk archive test failed'
"$bin" list "$tmp/disk.zupt" >/dev/null 2>&1 || fail 'disk archive list failed'
mkdir "$tmp/disk-extracted"
"$bin" extract -o "$tmp/disk-extracted" "$tmp/disk.zupt" \
    >/dev/null 2>&1 || fail 'absolute-source disk archive generic extraction failed'
cmp "$tmp/disk.img" "$tmp/disk-extracted/disk.img" ||
    fail 'absolute-source disk archive generic extraction mismatch'
assert_no_temps

# Restore must fail closed if it cannot create its private source snapshot;
# it may not fall back to validating and consuming a mutable pathname.
printf 'not a directory\n' > "$tmp/not-a-snapshot-directory"
printf 'snapshot failure target\n' > "$tmp/snapshot-failure-target"
cp "$tmp/snapshot-failure-target" "$tmp/snapshot-failure.expected"
if ZUPT_TMPDIR="$tmp/not-a-snapshot-directory" \
        "$bin" disk restore "$tmp/disk.zupt" \
        "$tmp/snapshot-failure-target" >/dev/null 2>&1; then
    fail 'disk restore continued without a private archive snapshot'
fi
cmp "$tmp/snapshot-failure.expected" "$tmp/snapshot-failure-target" ||
    fail 'snapshot creation failure changed the restore target'
assert_no_temps

# Restore targets are destructive by nature.  A final-component symlink must
# be rejected without following it or replacing it, and its external target
# must remain byte-for-byte unchanged.
printf 'external restore target\n' > "$tmp/restore-symlink-victim"
cp "$tmp/restore-symlink-victim" "$tmp/restore-symlink.expected"
ln -s restore-symlink-victim "$tmp/restore-symlink-target"
if "$bin" disk restore "$tmp/disk.zupt" "$tmp/restore-symlink-target" \
        >/dev/null 2>&1; then
    fail 'disk restore accepted a symlink target'
fi
test -L "$tmp/restore-symlink-target" ||
    fail 'disk restore replaced the rejected symlink'
cmp "$tmp/restore-symlink.expected" "$tmp/restore-symlink-victim" ||
    fail 'disk restore changed the symlink target'

# A regular target with st_nlink > 1 must also be rejected.  Both directory
# entries must still name the original inode and retain its original bytes.
printf 'multiply linked restore target\n' > "$tmp/restore-hardlink-peer"
cp "$tmp/restore-hardlink-peer" "$tmp/restore-hardlink.expected"
ln "$tmp/restore-hardlink-peer" "$tmp/restore-hardlink-target"
if "$bin" disk restore "$tmp/disk.zupt" "$tmp/restore-hardlink-target" \
        >/dev/null 2>&1; then
    fail 'disk restore accepted a multiply-linked target'
fi
test "$tmp/restore-hardlink-peer" -ef "$tmp/restore-hardlink-target" ||
    fail 'disk restore replaced the rejected hardlink entry'
cmp "$tmp/restore-hardlink.expected" "$tmp/restore-hardlink-peer" ||
    fail 'disk restore changed the hardlink peer'
cmp "$tmp/restore-hardlink.expected" "$tmp/restore-hardlink-target" ||
    fail 'disk restore changed the multiply-linked target'

# A target that is another hardlink to the archive itself is rejected before
# opening either inode for writing.  The archive must remain readable.
cp "$tmp/disk.zupt" "$tmp/same-inode.zupt"
ln "$tmp/same-inode.zupt" "$tmp/same-inode-target"
cp "$tmp/same-inode.zupt" "$tmp/same-inode.expected"
if "$bin" disk restore "$tmp/same-inode.zupt" "$tmp/same-inode-target" \
        >/dev/null 2>&1; then
    fail 'disk restore accepted its own archive inode as the target'
fi
cmp "$tmp/same-inode.expected" "$tmp/same-inode.zupt" ||
    fail 'same-inode restore attempt changed the archive'
test "$tmp/same-inode.zupt" -ef "$tmp/same-inode-target" ||
    fail 'same-inode restore attempt replaced one hardlink'
"$bin" test "$tmp/same-inode.zupt" >/dev/null 2>&1 ||
    fail 'same-inode restore attempt corrupted the archive'

# Removing the trailing archive-integrity field creates the structurally valid
# legacy framing used by the downgrade attack.  Disk restore must reject it by
# default and leave a preexisting regular target untouched.
python3 "$surgery" strip-ait "$tmp/disk.zupt" \
    "$tmp/disk-without-ait.zupt" || fail 'could not remove disk archive AIT'
printf 'existing no-AIT restore target\n' > "$tmp/no-ait-restore-target"
cp "$tmp/no-ait-restore-target" "$tmp/no-ait-restore.expected"
if "$bin" disk restore "$tmp/disk-without-ait.zupt" \
        "$tmp/no-ait-restore-target" >/dev/null 2>&1; then
    fail 'disk restore accepted a no-AIT archive by default'
fi
cmp "$tmp/no-ait-restore.expected" "$tmp/no-ait-restore-target" ||
    fail 'no-AIT disk archive changed the existing restore target'

# Late DATA corruption must be discovered before publishing over an existing
# regular target.  This specifically guards against open(O_TRUNC)-then-verify
# behavior and partial output left behind after a checksum/authentication
# failure.
python3 "$surgery" flip-payload "$tmp/disk.zupt" \
    "$tmp/corrupt-disk.zupt" --kind data ||
    fail 'could not construct corrupt disk archive'
printf 'existing regular restore target\n' > "$tmp/restore-existing"
cp "$tmp/restore-existing" "$tmp/restore-existing.expected"
if "$bin" disk restore "$tmp/corrupt-disk.zupt" "$tmp/restore-existing" \
        >/dev/null 2>&1; then
    fail 'disk restore accepted a corrupt DATA block'
fi
cmp "$tmp/restore-existing.expected" "$tmp/restore-existing" ||
    fail 'corrupt archive changed the existing restore target'
assert_no_temps

# Encrypted dedup references carry the original DATA frame AAD sequence and
# authenticate their own logical position; restore must reproduce the bytes.
dd if=/dev/urandom of="$tmp/repeated-block" bs=65536 count=1 2>/dev/null
cp "$tmp/repeated-block" "$tmp/dedup-disk.img"
dd if="$tmp/repeated-block" of="$tmp/dedup-disk.img" bs=65536 seek=1 \
    conv=notrunc 2>/dev/null
printf 'atomic-disk-test-password\n' > "$tmp/disk-password"
chmod 600 "$tmp/disk-password"
"$bin" disk backup --dedup -b 65536 --pass-file "$tmp/disk-password" -s \
    "$tmp/dedup-encrypted.zupt" "$tmp/dedup-disk.img" >/dev/null 2>&1 ||
    fail 'encrypted dedup disk backup failed'
"$bin" test --pass-file "$tmp/disk-password" "$tmp/dedup-encrypted.zupt" \
    >/dev/null 2>&1 || fail 'encrypted dedup disk archive test failed'
"$bin" disk restore --pass-file "$tmp/disk-password" \
    "$tmp/dedup-encrypted.zupt" "$tmp/dedup-restored.img" >/dev/null 2>&1 ||
    fail 'encrypted dedup disk restore failed'
cmp "$tmp/dedup-disk.img" "$tmp/dedup-restored.img" ||
    fail 'encrypted dedup disk restore mismatch'
assert_no_temps

printf 'atomic archive output: PASS\n'
