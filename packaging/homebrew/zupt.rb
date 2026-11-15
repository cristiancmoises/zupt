# SPDX-License-Identifier: AGPL-3.0-or-later
# Source: signed v5.2.10 at 0165fbd78faf78046d49e004622820ef79061f17.
# Pin the forge-generated source archive; portable release bundles use .zupt.
# Build and test with brew install --build-from-source ./zupt.rb and brew test zupt.

class Zupt < Formula
  desc "Post-quantum backup compression utility (ML-KEM-768 + AES-256-CTR + HMAC-SHA256)"
  homepage "https://github.com/cristiancmoises/zupt"
  url "https://github.com/cristiancmoises/zupt/archive/refs/tags/v5.2.10.tar.gz"
  version "5.2.10"
  sha256 "f755e7459df9d9e227f72fea0c0ba9015261f128af8e3c0276ea7e8f22a494a8"
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
    doc.install "README.md", "README.pt-BR.md", "DOCUMENTACAO.pt-BR.md",
                "SECURITY.md", "CHANGELOG.md"
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
