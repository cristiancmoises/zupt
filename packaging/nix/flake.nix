# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Nix flake for zupt.
#
# Usage (with flakes enabled):
#   nix build .#zupt                    # build the package
#   nix run .#zupt -- version           # run zupt directly
#   nix develop                         # drop into a dev shell
#   nix flake check                     # lint the flake
#
# To consume from another flake:
#   inputs.zupt.url = "git+https://git.securityops.co/cristiancmoises/zupt?ref=v2.4.4";
#   ...packages.x86_64-linux.default = inputs.zupt.packages.x86_64-linux.zupt;
#
# Reproducibility:
#   * Nix already pins the source tree by hash.
#   * `make dist` is also reproducible (tests/test_dist_reproducible.sh).
#   * Together, two independent Nix evaluations of the same flake.lock
#     produce byte-identical /nix/store outputs.

{
  description = "Zupt — post-quantum backup compression utility (C11)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };

        zupt = pkgs.stdenv.mkDerivation {
          pname = "vaptvupt";
          version = "4.0.0";

          # When publishing, replace this with `fetchurl` against the
          # release tarball. For local development the flake assumes it
          # lives in the same directory as the source.
          src = ./.;

          nativeBuildInputs = with pkgs; [
            gcc
            gnumake
          ];

          # python3 is only used by the regression-test harness.
          checkInputs = [ pkgs.python3 ];

          # Build with the project's preferred warning set on top of Nix's
          # hardening flags. Don't override -O2 from stdenv.
          NIX_CFLAGS_COMPILE = "-Wall -Wextra -Wpedantic -std=c11";

          # `make` builds the binary using vendored libzuptsdk via rpath.
          buildPhase = ''
            runHook preBuild
            make -j$NIX_BUILD_CORES
            runHook postBuild
          '';

          # Run the full upstream regression suite. Disable per-package by
          # setting doCheck = false; on by default.
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            make test
            runHook postCheck
          '';

          installPhase = ''
            runHook preInstall
            make DESTDIR=$out PREFIX= install

            # Move libzuptsdk into $out/lib/zupt/. The binary's rpath is
            # $ORIGIN/../lib/zupt after autopatchelf rewrites it during
            # the fixup phase.
            mkdir -p $out/lib/zupt
            install -m 0755 vendor/zuptsdk/libzuptsdk.so.2.0.0 \
              $out/lib/zupt/libzuptsdk.so.2.0.0
            ln -sf libzuptsdk.so.2.0.0 $out/lib/zupt/libzuptsdk.so.2
            ln -sf libzuptsdk.so.2.0.0 $out/lib/zupt/libzuptsdk.so

            # Docs
            mkdir -p $out/share/doc/zupt
            cp README.md SECURITY.md CHANGELOG.md AUDIT.md $out/share/doc/zupt/
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Post-quantum backup compression utility (ML-KEM-768 + AES-256-CTR + HMAC-SHA256 + Argon2id)";
            homepage = "https://git.securityops.co/cristiancmoises/zupt";
            license = with licenses; [ agpl3Plus gpl3Plus ];
            maintainers = [ ];
            platforms = [ "x86_64-linux" "aarch64-linux" ];
            mainProgram = "zupt";
          };
        };
      in {
        packages = {
          zupt = zupt;
          default = zupt;
        };

        apps.default = {
          type = "app";
          program = "${zupt}/bin/zupt";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            gcc
            gnumake
            python3
            valgrind
            gdb
          ];
        };
      });
}
