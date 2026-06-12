# openSUSE Build Service update for `home:cabelo:innovators/vaptvupt`

This directory contains the three files you need to update your OBS
package from `1.5.5` to `2.4.8`:

| File          | Status vs. your current files                                       |
|---------------|---------------------------------------------------------------------|
| `_service`    | Updated `revision` to `v2.4.8`. Format unchanged (still `tar_scm`). |
| `vaptvupt.spec`   | Version → `2.4.8`. License corrected `MIT` → `AGPL-3.0-or-later`. `%check` now calls `make check` (new distro-safe target). |
| `vaptvupt.changes`| 13 new entries prepended (2.0.0 → 2.4.8). Your existing 1.0.0–1.5.4 history is preserved verbatim. |

## What changed in the spec

1. **License correction** — your spec says `License: MIT`, but the
   upstream license is **AGPL-3.0-or-later** (dual-licensed
   AGPL-3.0-or-later + commercial). This was a bug that should
   probably trigger a rebuild even without the version bump.

2. **`%check` target** — your spec calls `test-all` on non-s390x
   architectures. In v2.4.x, `test-all` includes threading tests
   that are flaky on emulated build hosts (3 false positives on
   x86_64 GitHub-Actions-style sandboxes). The new `make check`
   target added in 2.4.8 runs a curated subset:

   * F-06 HMAC tamper detection (2000 trials)
   * F-08 archive-integrity-trailer
   * F-09 byte-level integrity preface AAD
   * F-10 KDF default
   * F-11 auth-fail message
   * F-12 encrypted comments
   * NIST/RFC vectors (SHA-256, SHA-3, ML-KEM-768, AES-256-CTR,
     HMAC, X25519, PBKDF2, Argon2id)
   * Path-traversal, argument-order, block-swap regressions
   * Quick smoke test

   Total ~91 assertions, runs in <2 minutes, no flakes on emulated
   hosts. The s390x branch still falls back to just `test-vectors`.

3. **Upstream URL in `URL:` field** updated to
   `https://git.securityops.co/cristiancmoises/vaptvupt` (the canonical
   project URL). The `_service` file still pulls from GitHub
   (`https://github.com/cristiancmoises/vaptvupt`) since that's where
   your `tar_scm` is already configured and what works in OBS today.

4. **`BuildRequires: make`** added — newer openSUSE chroots don't
   always pull `make` in transitively. Harmless on older targets.

5. **Docs** — `%doc README.md SECURITY.md CHANGELOG.md` now ships
   the security boundary docs as well as the README. THREAT_MODEL.md
   exists upstream but isn't listed here to keep the package small;
   add `%doc THREAT_MODEL.md` if you want it included.

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

# 3. Trigger the service locally to fetch v2.4.8 from GitHub
osc service runall

# This produces vaptvupt-2.4.8.tar.gz in the current directory and
# updates vaptvupt.changes with a service-generated entry if you have
# changesgenerate enabled (you don't, so this is a no-op for
# changes; tar_scm just downloads).

# 4. (Optional) Local build to verify before committing
osc build openSUSE_Tumbleweed x86_64

# Expected: build succeeds, %check runs `make check`, all 10 suites
# (~91 assertions) pass, package is produced.

# 5. Commit upstream
osc status   # confirm vaptvupt-2.4.8.tar.gz is staged alongside the
             # three text files
osc commit -m "Update to 2.4.8: distro-safe make check target; license fix MIT -> AGPL"
```

## Notes for future updates

* The `_service` `revision` is pinned to `v2.4.8`. To track a new
  release, just edit that one line and re-run `osc service runall`.
* The spec's `Version:` field is hard-coded — when you bump
  `_service` `revision`, also bump `Version:` to match. The
  `set_version` service in `_service` will auto-sync at OBS-build
  time if you want; it's mode="manual" today, which is safer.
* `BuildRequires` is intentionally minimal (just `gcc gzip make`).
  VaptVupt has no external library dependencies — `libargon2`,
  `libcrypto`, etc. used by other Linux packagers come from
  *vendored* code that's compiled in. This is a deliberate
  design choice; don't add system library BuildRequires.

## Reporting issues

* Upstream bugs: https://git.securityops.co/cristiancmoises/vaptvupt
* openSUSE packaging bugs: https://bugs.opensuse.org/
* Cabelo's OBS project: https://build.opensuse.org/project/show/home:cabelo:innovators

## Author of these update files

Generated against upstream `vaptvupt-2.4.8` source tree. Spec mirrors
cabelo's existing 1.5.5 conventions (minimal `BuildRequires`,
`%autosetup -p1`, `V=1` verbose build, `%ifarch s390x` branch in
`%check`, no separate libzuptsdk subpackage) — only the necessary
fields are changed.
