# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Homebrew formula for zupt.
#
# To publish:
#   1. Run `make dist` upstream to produce zupt-VERSION.tar.gz (reproducible).
#   2. Upload to a stable release URL.
#   3. Update `url`, `version`, and `sha256` below.
#   4. Submit to homebrew-core via PR OR host in your own tap
#      (e.g. cristiancmoises/homebrew-tap).
#
# Local test:
#   brew install --build-from-source ./zupt.rb
#   brew test zupt
#   brew audit --strict --online zupt
#
# Notes for macOS:
#   * Jasmin assembly is disabled at build time on Darwin (no jasminc dep);
#     the C fallback for AES-256-CTR / HMAC compare paths is shipped.
#   * Source-only build: no vendored libraries; native crypto only.

class Vaptvupt < Formula
  desc "Post-quantum backup compression utility (ML-KEM-768 + AES-256-CTR + HMAC-SHA256)"
  homepage "https://git.securityops.co/cristiancmoises/vaptvupt"
  url "https://git.securityops.co/cristiancmoises/vaptvupt/releases/download/v5.0.0/vaptvupt-5.0.0.tar.gz"
  version "5.0.0"
  sha256 "REPLACE_WITH_SHA256_OF_RELEASE_TARBALL"
  license "AGPL-3.0-or-later"

  depends_on "python@3.12" => :test  # only for test-suite tamper harness

  def install
    # Source-only build (WITH_SDK=0): native crypto only, no vendored libraries.
    # macOS uses the C-fallback crypto paths (no Jasmin); the Makefile detects
    # this and falls back cleanly.
    ENV["CFLAGS"] = "#{ENV.cflags} -O2 -std=c11 -Wall -Wextra"

    system "make", "WITH_SDK=0", "-j#{ENV.make_jobs}"
    system "make", "DESTDIR=#{prefix}", "PREFIX=", "WITH_SDK=0", "install"

    # Docs (no vendored .so/.dylib in the source-only build).
    doc.install "README.md", "SECURITY.md", "CHANGELOG.md"
  end

  test do
    # End-to-end sanity check: build a real archive, extract it, byte-compare.
    (testpath/"input.txt").write("homebrew formula test payload\n")
    system bin/"zupt", "c", "-p", "test", "out.zupt", "input.txt"
    system bin/"zupt", "info", "out.zupt"
    mkdir "extracted"
    cd "extracted" do
      system bin/"zupt", "x", "-p", "test", "../out.zupt"
    end
    system "diff", "-q", "input.txt", "extracted/input.txt"
  end
end
