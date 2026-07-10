# openSUSE Build Service update for `home:cabelo:innovators/vaptvupt`

This directory contains the three files needed to build vaptvupt `4.2.0`
in OBS:

| File          | Purpose                                                                 |
|---------------|-------------------------------------------------------------------------|
| `_service`    | `revision` pinned to `v4.2.0`. Format unchanged (still `tar_scm`).      |
| `vaptvupt.spec`   | `Version: 4.2.0`. `License: AGPL-3.0-or-later`. `%check` calls `make check`. |
| `vaptvupt.changes`| Changelog for the 4.x series. Older history preserved verbatim.        |

## Spec notes

1. **License** — `AGPL-3.0-or-later` (dual-licensed AGPL-3.0-or-later
   + commercial).

2. **No BuildRequires beyond the toolchain** — the default build needs
   only `gcc gzip make` (plus `libm`/`pthread` from glibc). There are
   **no system library BuildRequires**. The repository is source-only:
   the previously vendored `libzuptsdk.so` and `libpqvaptvupt.so` have
   been removed from the tree, `%build` and `%install` run with
   `WITH_SDK=0`, and `%files` no longer lists any `.so`. The package
   installs no shared library. Do not add system crypto BuildRequires.

   The optional SDK modes (`--pq-sdk`, `--pq-box`) and the Argon2id KDF
   require an upstream `make WITH_SDK=1` build linked against the
   separately distributed `libzuptsdk`/`libpqvaptvupt` libraries. They
   are not part of this package.

3. **`%check` target** — the s390x branch falls back to `test-vectors`;
   other architectures run `make check`. This exercises the HMAC tamper
   detection, archive-integrity trailer, byte-level integrity preface
   AAD, default-KDF, auth-fail, and encrypted-comment suites, the
   NIST/RFC vectors (SHA-256, SHA-3, ML-KEM-768, AES-256-CTR, HMAC,
   X25519, PBKDF2), and the path-traversal, argument-order, and
   block-swap regressions.

   The default password KDF is **PBKDF2-SHA256** (600k iterations).
   Argon2id test vectors run only in a `WITH_SDK=1` build and are not
   checked here.

4. **URLs** — the `URL:` field points at the canonical project URL
   `https://git.securityops.co/cristiancmoises/vaptvupt`. The `_service`
   file still fetches from GitHub
   (`https://github.com/cristiancmoises/vaptvupt`), which is what the
   existing `tar_scm` configuration uses in OBS.

## How to apply

```sh
# 1. Check out the package
osc checkout home:cabelo:innovators vaptvupt
cd home:cabelo:innovators/vaptvupt

# 2. Drop the new files in (assuming this README is at
#    /path/to/vaptvupt-source/packaging/opensuse/README.md)
cp /path/to/vaptvupt-source/packaging/opensuse/_service     .
cp /path/to/vaptvupt-source/packaging/opensuse/vaptvupt.spec    .
cp /path/to/vaptvupt-source/packaging/opensuse/vaptvupt.changes .

# 3. Trigger the service locally to fetch v4.2.0 from GitHub
osc service runall
# Produces vaptvupt-4.2.0.tar.gz in the current directory.

# 4. (Optional) Local build to verify before committing
osc build openSUSE_Tumbleweed x86_64

# 5. Commit upstream
osc status   # confirm vaptvupt-4.2.0.tar.gz is staged alongside the
             # three text files
osc commit -m "Update to 4.2.0"
```

## Notes for future updates

* The `_service` `revision` is pinned to `v4.2.0`. To track a new
  release, edit that one line and re-run `osc service runall`.
* The spec's `Version:` field is hard-coded — when you bump `_service`
  `revision`, also bump `Version:` to match.
* `BuildRequires` is intentionally minimal (`gcc gzip make`). vaptvupt
  has no external library dependencies in the default build; do not add
  system crypto BuildRequires.

## Reporting issues

* Upstream bugs: https://git.securityops.co/cristiancmoises/vaptvupt
* openSUSE packaging bugs: https://bugs.opensuse.org/
* Cabelo's OBS project: https://build.opensuse.org/project/show/home:cabelo:innovators
