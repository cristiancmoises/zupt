# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Nix flake for ZUPT.
#
# Usage (with flakes enabled):
#   nix build .#zupt                    # build the package
#   nix run .#zupt -- --version         # run ZUPT directly
#   nix develop                         # drop into a dev shell
#   nix flake check                     # lint the flake
#
# To consume from another flake:
#   inputs.zupt.url = "github:cristiancmoises/zupt/v5.2.4";
#   ...packages.x86_64-linux.default = inputs.zupt.packages.x86_64-linux.zupt;
#
# `make dist` has its own reproducibility gate. This development flake has no
# committed lock file and therefore makes no independent locked-output claim.

{
  description = "ZUPT — post-quantum backup compression utility (C11)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };

        zupt = pkgs.stdenv.mkDerivation {
          pname = "zupt";
          version = "5.2.4";

          # When publishing, replace this with `fetchurl` against the
          # release tarball. For local development the flake assumes it
          # lives in the same directory as the source.
          src = builtins.path { path = ../..; name = "zupt-source"; };

          nativeBuildInputs = with pkgs; [
            gcc
            git
            gnumake
            file
            gnutar
          ];

          # python3 is only used by the regression-test harness.
          checkInputs = [ pkgs.python3 ];

          # Build with the project's preferred warning set on top of Nix's
          # hardening flags. Don't override -O2 from stdenv.
          NIX_CFLAGS_COMPILE = "-Wall -Wextra -Wpedantic -std=c11";

          # Source-only build (WITH_SDK=0): native crypto, no vendored libraries.
          buildPhase = ''
            runHook preBuild
            make WITH_SDK=0 WITH_PQBOX=0 -j$NIX_BUILD_CORES
            runHook postBuild
          '';

          # Distro-safe regression subset. Disable with doCheck = false;.
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            make WITH_SDK=0 WITH_PQBOX=0 check
            runHook postCheck
          '';

          installPhase = ''
            runHook preInstall
            make PREFIX=$out WITH_SDK=0 WITH_PQBOX=0 \
              INSTALL_LEGACY_ALIAS=0 install

            # Docs
            mkdir -p $out/share/doc/zupt
            cp README.md SECURITY.md CHANGELOG.md $out/share/doc/zupt/
            test -f $out/share/licenses/zupt/LICENSE-BSD-3-Clause
            test -f $out/share/licenses/zupt/LICENSE-CC0-1.0
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Post-quantum backup compression utility (ML-KEM-768 + X25519 + AES-256-CTR + HMAC-SHA256)";
            homepage = "https://github.com/cristiancmoises/zupt";
            license = with licenses; [ agpl3Plus gpl3Plus bsd2 bsd3 cc0 ];
            maintainers = [ ];
            platforms = [ "x86_64-linux" ];
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
