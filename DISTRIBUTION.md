# Distributing VaptVupt

This document describes the upstream packaging recipes shipped under `packaging/` and the path from a local source tree to an installable package.

Real submission to AUR / Debian / Fedora / Homebrew / NixOS / openSUSE is operational work outside this repository.

## Producing a reproducible source tarball

Every packaging recipe expects an upstream tarball `vaptvupt-VERSION.tar.gz` produced by the project's `make dist` target. The tarball is byte-reproducible:

```sh
make dist
# → /tmp/vaptvupt-5.0.0.tar.gz
```

Re-running `make dist` on the same source tree produces an identical sha256 (verified by `tests/test_dist_reproducible.sh`, wired into `make test`). This lets distros pin a stable hash in their recipes.

The reproducibility properties:

- Files sorted by name (deterministic order across filesystems)
- mtime fixed to `SOURCE_DATE_EPOCH` (default `1747699200`; override via env)
- uid/gid pinned to root (0/0) via `--owner=0 --group=0 --numeric-owner`
- gzip wrapped with `-9n` (no embedded timestamp or filename)
- Source-only — no `.o`, no built binaries, no `.git/` tree

The tree is source-only. The default `make` build needs only a C compiler, make, libm, and pthread — no external crypto library, and it installs no `.so`. The optional SDK-backed modes (`--pq-sdk`, `--pq-box`) and the Argon2id KDF are built only with `make WITH_SDK=1` against the separately distributed `libzuptsdk` / `libpqvaptvupt` libraries.

To force a specific epoch (for distro release-day pinning):

```sh
SOURCE_DATE_EPOCH=1727740800 make dist  # 2024-10-01 UTC
```

## Recipes shipped

| Distro / Platform | Path                            | Format         |
|-------------------|---------------------------------|----------------|
| Arch Linux        | `packaging/aur/PKGBUILD`        | AUR PKGBUILD   |
| Debian / Ubuntu   | `packaging/debian/`             | Source package (`3.0 (quilt)`) |
| Fedora / RHEL     | `packaging/rpm/vaptvupt.spec`   | RPM .spec      |
| openSUSE          | `packaging/opensuse/`           | RPM .spec (OBS) |
| macOS             | `packaging/homebrew/vaptvupt.rb`| Homebrew formula |
| NixOS / Nix flake | `packaging/nix/flake.nix`       | Nix flake      |

All recipes:

- Install the binary to `$PREFIX/bin/vaptvupt` (default `/usr/bin/vaptvupt`)
- Install manpage to `$PREFIX/share/man/man1/vaptvupt.1.gz`
- Install docs (README, SECURITY, CHANGELOG) to `$PREFIX/share/doc/vaptvupt/`
- Run the full upstream regression suite (`make test`) during build when the distro's package guidelines allow check-phase execution

## Arch Linux (AUR)

Maintainer flow:

```sh
# 1. Produce the upstream tarball
make dist
# → /tmp/vaptvupt-5.0.0.tar.gz

# 2. Upload to a stable URL (e.g. git.securityops.co releases)

# 3. Update packaging/aur/PKGBUILD:
#    - Set pkgver=5.0.0
#    - Set sha256sums=("$(sha256sum /tmp/vaptvupt-5.0.0.tar.gz | awk '{print $1}')")

# 4. Generate .SRCINFO
cd packaging/aur && makepkg --printsrcinfo > .SRCINFO

# 5. Test locally
makepkg -s

# 6. Push to AUR
git clone ssh://aur@aur.archlinux.org/vaptvupt.git aur-vaptvupt
cp packaging/aur/PKGBUILD packaging/aur/.SRCINFO aur-vaptvupt/
cd aur-vaptvupt && git add -A && git commit -m "v5.0.0" && git push
```

User install:

```sh
yay -S vaptvupt          # or paru, pikaur, etc.
```

## Shell completions

`make install` automatically installs Bash, zsh, and fish completion files alongside the binary and manpage:

| Shell | Path |
|---|---|
| Bash | `$PREFIX/share/bash-completion/completions/vaptvupt` |
| zsh  | `$PREFIX/share/zsh/site-functions/_vaptvupt` |
| fish | `$PREFIX/share/fish/vendor_completions.d/vaptvupt.fish` |

The source files live under `completions/` in the project tree. Distros that prefer a different install location should override the relevant paths in their `make install` invocation.

For per-user installation without root:

```sh
# Bash
cp completions/vaptvupt.bash ~/.local/share/bash-completion/completions/vaptvupt

# zsh (somewhere in $fpath; add the directory to ~/.zshrc if needed)
cp completions/_vaptvupt ~/.zsh/completion/_vaptvupt

# fish
cp completions/vaptvupt.fish ~/.config/fish/completions/vaptvupt.fish
```

Completions cover every CLI flag the binary actually parses (`--kdf`, `--comment`, `--comment-file`, `--pq`, `--dedup`, etc.) and are validated on every CI run via `tests/test_completions_manpage.sh`.

## Debian / Ubuntu

The `packaging/debian/` tree is a Debian source-package layout. Maintainer flow:

```sh
# 1. Produce the upstream tarball with the standard Debian
#    orig.tar.gz naming convention:
make dist
cp /tmp/vaptvupt-5.0.0.tar.gz /tmp/vaptvupt_5.0.0.orig.tar.gz

# 2. Unpack and overlay the debian/ tree:
cd /tmp && tar xzf vaptvupt_5.0.0.orig.tar.gz && cd vaptvupt-5.0.0
cp -a /path/to/vaptvupt/packaging/debian ./debian

# 3. Build the source package:
dpkg-buildpackage -S -us -uc       # source-only
dpkg-buildpackage -b -us -uc       # binary

# 4. Lint:
lintian vaptvupt_5.0.0-1_*.deb

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
cp /tmp/vaptvupt-5.0.0.tar.gz ~/rpmbuild/SOURCES/

# 2. Drop the .spec into the SPECS directory:
cp packaging/rpm/vaptvupt.spec ~/rpmbuild/SPECS/

# 3. Build source + binary RPMs:
cd ~/rpmbuild && rpmbuild -ba SPECS/vaptvupt.spec

# 4. Lint:
rpmlint RPMS/x86_64/vaptvupt-5.0.0-1.fc*.rpm

# 5. Submit via the Fedora new-package review process:
#    https://docs.fedoraproject.org/en-US/package-maintainers/Package_Review_Process/
#    EPEL automatically inherits Fedora packages.
```

User install (after the package lands in Fedora / EPEL):

```sh
sudo dnf install vaptvupt                 # Fedora
sudo dnf install epel-release vaptvupt    # RHEL/CentOS via EPEL
```

## openSUSE

The `packaging/opensuse/` tree carries an RPM `.spec` suited to the Open Build Service (OBS).

```sh
# 1. Produce the tarball
make dist

# 2. In an OBS package checkout (osc), stage the sources and spec:
cp /tmp/vaptvupt-5.0.0.tar.gz .
cp /path/to/vaptvupt/packaging/opensuse/vaptvupt.spec .

# 3. Build locally against a target repository:
osc build openSUSE_Tumbleweed x86_64

# 4. Commit to OBS once the build and check phase pass:
osc addremove && osc commit
```

User install (after the package lands in a distribution or OBS repository):

```sh
sudo zypper install vaptvupt
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
#    inputs.vaptvupt.url = "github:cristiancmoises/vaptvupt?ref=v5.0.0";
#    packages.x86_64-linux.default = inputs.vaptvupt.packages.x86_64-linux.vaptvupt;

# 3. To submit to nixpkgs (https://github.com/NixOS/nixpkgs):
#    - Adapt packaging/nix/flake.nix's `vaptvupt` derivation into a
#      pkgs/by-name/va/vaptvupt/package.nix using fetchurl and a hash.
#    - Follow the nixpkgs contribution guide:
#      https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md
```

## Submitting upstream — checklist

Before pushing any recipe to a distro repository:

- [ ] `make dist` produces a reproducible tarball (verified by `tests/test_dist_reproducible.sh` on every `make test`)
- [ ] The tarball is uploaded to a stable, immutable URL
- [ ] The recipe's checksum field is updated to match `sha256sum /tmp/vaptvupt-VERSION.tar.gz`
- [ ] The recipe builds and tests pass in a clean chroot/container
- [ ] The CHANGELOG mentions distro-relevant changes since the last release
- [ ] The license metadata is correct (AGPL-3.0-or-later for VaptVupt core; GPL-3.0-or-later for the vendored VaptVupt codec)

## Security posture for downstream

Every packaging recipe runs `make test` during build (`check()` for AUR, `override_dh_auto_test` for Debian, `%check` for RPM and openSUSE, `checkPhase` for Nix, `test` block for Homebrew). The test suite runs in each recipe's check phase, including the tamper/integrity regressions and the `make dist` byte-identical reproducibility check.

A build that doesn't pass `make test` will fail at distro check time — the recipes don't paper over regressions.
