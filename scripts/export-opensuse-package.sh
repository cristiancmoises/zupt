#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

for command_name in awk basename bsdtar cat file find git grep mkdir mktemp mv rm sha256sum sort tar touch unzip xargs zip; do
    need_command "$command_name"
done

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) ||
    die 'run this script from the ZUPT Git repository'

cd "$repo_root"

remote_urls=$(git remote -v | awk '{print $2}' | sort -u)
grep -Eq '(^|[/:])cristiancmoises/zupt(\.git)?$' <<<"$remote_urls" ||
    die 'no configured remote identifies cristiancmoises/zupt'
grep -Eqi 'vaptvupt-web|zupt-web' <<<"$remote_urls" &&
    die 'a configured remote points to a web project'

version=$(awk -F'"' '/^#define ZUPT_VERSION_STRING / { print $2; exit }' include/zupt.h)
[[ -n "$version" ]] || die 'cannot determine version from include/zupt.h'
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "source version is not a stable semantic version: $version"

release_tag=${1:-v$version}
[[ "$release_tag" == "v$version" ]] ||
    die "tag $release_tag does not match source version v$version"

tag_ref="refs/tags/$release_tag"
git show-ref --verify --quiet "$tag_ref" || die "tag does not exist: $release_tag"
[[ $(git cat-file -t "$tag_ref") == tag ]] || die "tag is not annotated: $release_tag"

head_commit=$(git rev-parse HEAD)
tag_commit=$(git rev-parse "$tag_ref^{commit}")
[[ "$head_commit" == "$tag_commit" ]] ||
    die "HEAD $head_commit does not match $release_tag commit $tag_commit"

if ! git diff --quiet || ! git diff --cached --quiet; then
    die 'tracked working tree changes must be committed before export'
fi

scanner="$repo_root/scripts/check-source-only.sh"
[[ -f "$scanner" ]] || die 'missing scripts/check-source-only.sh'
bash "$scanner" --tag "$release_tag"

git check-ignore -q --no-index dist/ ||
    die 'dist/ must be ignored before creating the handoff'

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/zupt-opensuse-export.XXXXXX")
cleanup() {
    if [[ -n ${work_dir:-} && -d ${work_dir:-} ]]; then
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT

bundle_name="zupt-openSUSE-source-only-$release_tag"
bundle_root="$work_dir/$bundle_name"
mkdir -p "$bundle_root"

git archive "$release_tag" \
    packaging/opensuse \
    scripts/check-source-only.sh \
    scripts/test-installed-zupt.sh \
    LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-COMMERCIAL \
    LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 \
    NOTICE THIRD-PARTY-NOTICES.md |
    tar -xf - -C "$bundle_root"

handoff_legal_files=(
    LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-COMMERCIAL
    LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0
    NOTICE THIRD-PARTY-NOTICES.md
)
for legal_file in "${handoff_legal_files[@]}"; do
    [[ -s $bundle_root/$legal_file ]] || \
        die "handoff legal file is missing or empty: $legal_file"
done

cat >"$bundle_root/HANDOFF.md" <<EOF
# ZUPT openSUSE source-only handoff

- Version: $version
- Tag: $release_tag
- Commit: $tag_commit
- Source repository: https://github.com/cristiancmoises/zupt
- Package policy: source-only; no RPM, executable, object or library included
- Audit entry point: packaging/opensuse/source-audit.sh
- License payload: complete public license texts, NOTICE, and third-party record

Release summary and the validation matrix are recorded in
\`packaging/opensuse/zupt.changes\` and
\`packaging/opensuse/README.md\`. Run audit commands from this handoff's
top-level directory so the wrapper can find \`scripts/check-source-only.sh\`.
A result marked SKIP is not a PASS.
EOF

checksum_manifest="$work_dir/SHA256SUMS"
(
    cd "$bundle_root"
    find . -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum >"$checksum_manifest"
)
mv "$checksum_manifest" "$bundle_root/SHA256SUMS"
(
    cd "$bundle_root"
    sha256sum -c SHA256SUMS
)

mkdir -p "$repo_root/dist"
zip_path="$repo_root/dist/$bundle_name.zip"
checksum_path="$zip_path.sha256"
[[ ! -e "$zip_path" && ! -e "$checksum_path" ]] ||
    die "handoff already exists: $zip_path"

source_epoch=$(git show -s --format=%ct "$release_tag^{commit}")
[[ "$source_epoch" =~ ^[0-9]+$ ]] || die 'tag commit time is not numeric'
find "$bundle_root" -exec touch -d "@$source_epoch" {} +
(
    cd "$work_dir"
    find "$bundle_name" -print | LC_ALL=C sort | zip -X -q "$zip_path" -@
)

unzip -t "$zip_path"
bash "$scanner" --archive "$zip_path"

verify_dir="$work_dir/verified"
mkdir -p "$verify_dir"
unzip -q "$zip_path" -d "$verify_dir"
extracted_root="$verify_dir/$bundle_name"
[[ -d "$extracted_root" ]] || die 'validated ZIP did not contain the expected root'
(
    cd "$extracted_root"
    sha256sum -c SHA256SUMS
)
bash "$scanner" --tree "$extracted_root"

(
    cd "$repo_root/dist"
    sha256sum "$(basename "$zip_path")" >"$(basename "$checksum_path")"
    sha256sum -c "$(basename "$checksum_path")"
)

printf 'PASS: source-only openSUSE handoff created\n'
printf 'ZIP: %s\n' "$zip_path"
printf 'SHA-256: %s\n' "$checksum_path"
printf 'Tag: %s\nCommit: %s\n' "$release_tag" "$tag_commit"
