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
#   * libzuptsdk is vendored and installed alongside the binary; the binary
#     uses @loader_path rpath so users don't have to set DYLD paths.

class Vaptvupt < Formula
  desc "Post-quantum backup compression utility (ML-KEM-768 + AES-256-CTR + HMAC-SHA256)"
  homepage "https://git.securityops.co/cristiancmoises/zupt"
  url "https://git.securityops.co/cristiancmoises/zupt/releases/download/v4.1.0/vaptvupt-4.1.0.tar.gz"
  version "4.1.0"
  sha256 "REPLACE_WITH_SHA256_OF_RELEASE_TARBALL"
  license "AGPL-3.0-or-later"

  depends_on "python@3.12" => :test  # only for test-suite tamper harness

  def install
    # macOS build: no Jasmin, C-fallback crypto paths are used.
    # The Makefile auto-detects Jasmin availability and falls back cleanly.
    ENV["CFLAGS"] = "#{ENV.cflags} -O2 -std=c11 -Wall -Wextra"

    system "make", "-j#{ENV.make_jobs}"
    system "make", "DESTDIR=#{prefix}", "PREFIX=", "install"

    # Vendored libzuptsdk goes into lib/zupt/ with @loader_path rpath.
    # Note: Linux ships .so.2.0.0; macOS .dylib equivalent must be built
    # separately by the vendored makefile. For the initial Homebrew
    # submission this assumes the upstream tarball includes a .dylib build;
    # if not, build it here.
    lib_zupt = lib/"zupt"
    lib_zupt.mkpath
    if File.exist?("vendor/zuptsdk/libzuptsdk.dylib")
      cp "vendor/zuptsdk/libzuptsdk.dylib", lib_zupt
    elsif File.exist?("vendor/zuptsdk/libzuptsdk.so.2.0.0")
      # Fallback: link Linux-style .so on macOS (works for direct loads but
      # not for dlopen-on-Darwin scenarios). Upstream is tracking this.
      cp "vendor/zuptsdk/libzuptsdk.so.2.0.0", lib_zupt
    end

    # Docs
    doc.install "README.md", "SECURITY.md", "CHANGELOG.md", "AUDIT.md"
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
