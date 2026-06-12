# Distributing VaptVupt

This document describes the upstream packaging recipes shipped under
`packaging/` and the path from "local source tree" to "package
installable on every major Linux distribution and macOS."

Recipes are upstream-maintained but distro-submission-ready. Real
submission to AUR / Debian / Fedora / Homebrew / NixOS is operational
work outside this repository.

## Producing a reproducible source tarball

Every packaging recipe expects an upstream tarball `vaptvupt-VERSION.tar.gz`
produced by the project's `make dist` target. The tarball is
**byte-reproducible**:

```sh
make dist
# → /tmp/vaptvupt-2.4.4.tar.gz
# → sha256: 407d20ef03e5bf857195b99e04843ef3b07357416a4115add1e8aaa2007a769f
# → bytes:  813113
```

Re-running `make dist` on the same source tree produces an identical
sha256 (verified by `tests/test_dist_reproducible.sh`, wired into
`make test`). This lets distros pin a stable hash in their recipes.

The reproducibility properties:

- Files sorted by name (deterministic order across filesystems)
- mtime fixed to `SOURCE_DATE_EPOCH` (default `1747699200`; override
  via env)
- uid/gid pinned to root (0/0) via `--owner=0 --group=0 --numeric-owner`
- gzip wrapped with `-9n` (no embedded timestamp or filename)
- Source-only — no `.o`, no built binaries, no `.git/` tree
- Includes the vendored `libzuptsdk.so.2.0.0` real file plus its two
  symlinks (`libzuptsdk.so`, `libzuptsdk.so.2`)

To force a specific epoch (for distro release-day pinning):

```sh
SOURCE_DATE_EPOCH=1727740800 make dist  # 2024-10-01 UTC
```

## Recipes shipped

| Distro / Platform | Path                            | Format         |
|-------------------|---------------------------------|----------------|
| Arch Linux        | `packaging/aur/PKGBUILD`        | AUR PKGBUILD   |
| Debian / Ubuntu   | `packaging/debian/`             | Source package (`3.0 (quilt)`) |
| Fedora / RHEL     | `packaging/rpm/vaptvupt.spec`       | RPM .spec      |
| macOS             | `packaging/homebrew/vaptvupt.rb`    | Homebrew formula |
| NixOS / Nix flake | `packaging/nix/flake.nix`       | Nix flake      |

All recipes:

- Install the binary to `$PREFIX/bin/vaptvupt` (default `/usr/bin/vaptvupt`)
- Install the vendored `libzuptsdk.so*` triple to `$PREFIX/lib/vaptvupt/`
  (the binary uses relative `rpath` so users don't need `LD_LIBRARY_PATH`)
- Install manpage to `$PREFIX/share/man/man1/vaptvupt.1.gz`
- Install docs (README, SECURITY, CHANGELOG, AUDIT) to
  `$PREFIX/share/doc/vaptvupt/`
- Run the full upstream regression suite (`make test`) during build
  when the distro's package guidelines allow check-phase execution

## Arch Linux (AUR)

Maintainer flow:

```sh
# 1. Produce the upstream tarball
make dist
# → /tmp/vaptvupt-2.4.4.tar.gz

# 2. Upload to a stable URL (e.g. git.securityops.co releases)

# 3. Update packaging/aur/PKGBUILD:
#    - Set pkgver=2.4.4
#    - Set sha256sums=("$(sha256sum /tmp/vaptvupt-2.4.4.tar.gz | awk '{print $1}')")

# 4. Generate .SRCINFO
cd packaging/aur && makepkg --printsrcinfo > .SRCINFO

# 5. Test locally
makepkg -s

# 6. Push to AUR
git clone ssh://aur@aur.archlinux.org/vaptvupt.git aur-vaptvupt
cp packaging/aur/PKGBUILD packaging/aur/.SRCINFO aur-vaptvupt/
cd aur-vaptvupt && git add -A && git commit -m "v2.4.4" && git push
```

User install:

```sh
yay -S vaptvupt          # or paru, pikaur, etc.
```

## Shell completions (v2.4.7+)

`make install` automatically installs Bash, zsh, and fish completion
files alongside the binary and manpage:

| Shell | Path |
|---|---|
| Bash | `$PREFIX/share/bash-completion/completions/vaptvupt` |
| zsh  | `$PREFIX/share/zsh/site-functions/_vaptvupt` |
| fish | `$PREFIX/share/fish/vendor_completions.d/vaptvupt.fish` |

The source files live under `completions/` in the project tree.
Distros that prefer a different install location should override
the relevant paths in their `make install` invocation; the
underlying recipe is straightforward.

For per-user installation without root:

```sh
# Bash
cp completions/vaptvupt.bash ~/.local/share/bash-completion/completions/vaptvupt

# zsh (somewhere in $fpath; add the directory to ~/.zshrc if needed)
cp completions/_vaptvupt ~/.zsh/completion/_vaptvupt

# fish
cp completions/vaptvupt.fish ~/.config/fish/completions/vaptvupt.fish
```

Completions cover every CLI flag the binary actually parses
(`--kdf`, `--comment`, `--comment-file`, `--pq-sdk`, `--dedup`,
etc.) and are validated on every CI run via
`tests/test_completions_manpage.sh`.

## Debian / Ubuntu

The `packaging/debian/` tree is a Debian source-package layout.
Maintainer flow:

```sh
# 1. Produce the upstream tarball with the standard Debian
#    orig.tar.gz naming convention:
make dist
cp /tmp/vaptvupt-2.4.4.tar.gz /tmp/vaptvupt_2.4.4.orig.tar.gz

# 2. Unpack and overlay the debian/ tree:
cd /tmp && tar xzf vaptvupt_2.4.4.orig.tar.gz && cd vaptvupt-2.4.4
cp -a /path/to/vaptvupt/packaging/debian ./debian

# 3. Build the source package:
dpkg-buildpackage -S -us -uc       # source-only
dpkg-buildpackage -b -us -uc       # binary

# 4. Lint:
lintian vaptvupt_2.4.4-1_*.deb

# 5. Submit via the standard Debian mentors process:
#    https://mentors.debian.net/intro-maintainers/
```

User install (after the package lands in Debian unstable / Ubuntu):

```sh
sudo apt install vaptvupt
```

## Fedora / RHEL / CentOS

```sh
# 1. Produce the tarball
make dist
cp /tmp/vaptvupt-2.4.4.tar.gz ~/rpmbuild/SOURCES/

# 2. Drop the .spec into the SPECS directory:
cp packaging/rpm/vaptvupt.spec ~/rpmbuild/SPECS/

# 3. Build source + binary RPMs:
cd ~/rpmbuild && rpmbuild -ba SPECS/vaptvupt.spec

# 4. Lint:
rpmlint RPMS/x86_64/vaptvupt-2.4.4-1.fc*.rpm

# 5. Submit via the Fedora new-package review process:
#    https://docs.fedoraproject.org/en-US/package-maintainers/Package_Review_Process/
#    EPEL automatically inherits Fedora packages.
```

User install (after the package lands in Fedora / EPEL):

```sh
sudo dnf install vaptvupt                 # Fedora
sudo dnf install epel-release vaptvupt    # RHEL/CentOS via EPEL
```

## macOS (Homebrew)

```sh
# 1. Produce the tarball and upload to a stable release URL.

# 2. Update packaging/homebrew/vaptvupt.rb:
#    - Set url to the release URL
#    - Set sha256 to the upstream tarball sha256

# 3. Test locally:
brew install --build-from-source ./packaging/homebrew/vaptvupt.rb
brew test vaptvupt
brew audit --strict --online vaptvupt

# 4. Submit to homebrew-core (preferred, requires popularity threshold):
#    https://docs.brew.sh/Adding-Software-to-Homebrew
#
#    OR host in your own tap:
#    https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap
```

User install (after submission lands):

```sh
brew install vaptvupt
# OR from a custom tap:
brew install cristiancmoises/tap/vaptvupt
```

## NixOS / Nix flake

```sh
# 1. Build directly from the flake (no central submission needed):
nix build github:cristiancmoises/vaptvupt#vaptvupt
nix run github:cristiancmoises/vaptvupt#vaptvupt -- version

# 2. To consume from another flake:
#    inputs.zupt.url = "github:cristiancmoises/vaptvupt?ref=v2.4.4";
#    packages.x86_64-linux.default = inputs.zupt.packages.x86_64-linux.zupt;

# 3. To submit to nixpkgs (https://github.com/NixOS/nixpkgs):
#    - Adapt packaging/nix/flake.nix's `vaptvupt` derivation into a
#      pkgs/by-name/zu/vaptvupt/package.nix using fetchurl and a hash.
#    - Follow the nixpkgs contribution guide:
#      https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md
```

## Submitting upstream — checklist

Before pushing any recipe to a distro repository:

- [ ] `make dist` produces a reproducible tarball (verified by
      `tests/test_dist_reproducible.sh` on every `make test`)
- [ ] The tarball is uploaded to a stable, immutable URL
- [ ] The recipe's checksum field is updated to match
      `sha256sum /tmp/vaptvupt-VERSION.tar.gz`
- [ ] The recipe builds and tests pass in a clean chroot/container
- [ ] The CHANGELOG mentions distro-relevant changes since the last release
- [ ] The license metadata is correct (AGPL-3.0-or-later for VaptVupt core;
      GPL-3.0-or-later for the vendored VaptVupt codec)

## Security posture for downstream

Every packaging recipe runs `make test` during build (`check()` for AUR,
`override_dh_auto_test` for Debian, `%check` for RPM, `checkPhase` for
Nix, `test` block for Homebrew). The suite includes:

- **F-06**: 2 000 HMAC tamper trials, 0 silent accepts required
- **F-08**: top-MAC header/footer integrity-trailer regression
- **F-09**: 1 827-position exhaustive byte sweep on PQ-SDK archive,
  0 silent accepts required
- **F-10..F-12**: KDF default, auth-fail message, encrypted comments
- **dist reproducibility**: `make dist` byte-identical across two runs

A build that doesn't pass `make test` will fail at distro check time —
the recipes don't paper over regressions.
