# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Homebrew formula for ZUPT.
#
# To publish:
#   1. Run `make dist` upstream to produce zupt-VERSION.tar.gz.
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

class Zupt < Formula
  desc "Post-quantum backup compression utility (ML-KEM-768 + AES-256-CTR + HMAC-SHA256)"
  homepage "https://github.com/cristiancmoises/zupt"
  url "https://github.com/cristiancmoises/zupt/releases/download/v5.2.8/zupt-5.2.8.tar.gz"
  version "5.2.8"
  sha256 "4db1badbb9a62676176829326b6fd4bab5fe67be6631a7f6d341bdc6c7265c04"
  license all_of: ["AGPL-3.0-or-later", "GPL-3.0-or-later", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0"]

  depends_on "python@3.12" => :test  # only for test-suite tamper harness

  def install
    # Source-only build (WITH_SDK=0): native crypto only, no vendored libraries.
    # macOS uses the C-fallback crypto paths (no Jasmin); the Makefile detects
    # this and falls back cleanly.
    ENV["CFLAGS"] = "#{ENV.cflags} -O2 -std=c11 -Wall -Wextra"

    system "make", "WITH_SDK=0", "WITH_PQBOX=0", "-j#{ENV.make_jobs}"
    system "make", "PREFIX=#{prefix}", "WITH_SDK=0", "WITH_PQBOX=0",
                   "INSTALL_LEGACY_ALIAS=0", "install"

    # Docs (no vendored .so/.dylib in the source-only build). `make install`
    # also installs the complete project license/notice set.
    doc.install "README.md", "SECURITY.md", "CHANGELOG.md"
    %w[LICENSE-BSD-3-Clause LICENSE-CC0-1.0].each do |notice|
      odie "missing installed license #{notice}" unless \
        (share/"licenses/zupt"/notice).exist?
    end
  end

  test do
    # End-to-end sanity check: build a real archive, extract it, byte-compare.
    (testpath/"input.txt").write("homebrew formula test payload\n")
    system bin/"zupt", "c", "-p", "test", "out.zupt", "input.txt"
    system bin/"zupt", "t", "-p", "test", "out.zupt"
    mkdir "extracted"
    cd "extracted" do
      system bin/"zupt", "x", "-p", "test", "../out.zupt"
    end
    system "diff", "-q", "input.txt", "extracted/input.txt"
  end
end
