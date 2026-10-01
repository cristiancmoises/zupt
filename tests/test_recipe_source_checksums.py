#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Run the real CI recipe check without contacting a forge."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STEP = "Match downstream recipe checksums to the tagged source archive"
SHA = "ae4e26dcba3f466b5a839b72a4f04988962877bdd57724911945adffb59164d5"
BASE32 = "1mb4j6szzba5368j8xympmvji5l897qa8wlvhdd6niizpbf2ckmf"
URL = "https://github.com/cristiancmoises/zupt/archive/refs/tags/v5.2.10.tar.gz"


def workflow_command():
    lines = (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "- name: " + STEP)
    start = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "run: |") + 1
    command = []
    for line in lines[start:]:
        if line.strip() and not line.startswith("          "):
            break
        command.append(line[10:])
    return "\n".join(command)


class RecipeChecksums(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zupt-recipe-check-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("include", "packaging/aur", "packaging/homebrew",
                          "packaging/guix", "bin", "runner/release-source"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "include/zupt.h").write_text('#define ZUPT_VERSION_STRING "5.2.10"\n')
        (self.root / "packaging/aur/PKGBUILD").write_text(
            'pkgname=zupt\npkgver=5.2.10\n'
            'source=("${pkgname}-${pkgver}.tar.gz::https://github.com/cristiancmoises/zupt/archive/refs/tags/v${pkgver}.tar.gz")\n'
            f"sha256sums=('{SHA}')\n")
        (self.root / "packaging/homebrew/zupt.rb").write_text(
            f'  url "{URL}"\n  version "5.2.10"\n  sha256 "{SHA}"\n')
        (self.root / "packaging/guix/zupt.scm").write_text(
            '(define %zupt-version "5.2.10")\n'
            '(define %zupt-source (origin\n'
            '  (uri (string-append "https://github.com/cristiancmoises/zupt"\n'
            '                     "/archive/refs/tags/v" %zupt-version ".tar.gz"))\n'
            f'  (sha256 (base32 "{BASE32}"))))\n')
        (self.root / "download.tar.gz").write_bytes(b"tagged source bytes\n")
        # A make-dist archive is independent, and must not be used for recipe pins.
        (self.root / "runner/release-source/zupt-5.2.10.tar.gz").write_bytes(b"different make-dist bytes\n")
        curl = self.root / "bin/curl"
        curl.write_text('''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
pathlib.Path("curl-attempted").touch()
if os.environ.get("CURL_FAIL"):
    sys.exit(22)
url = "https://github.com/cristiancmoises/zupt/archive/refs/tags/v5.2.10.tar.gz"
if url not in args or "--output" not in args:
    sys.exit(64)
shutil.copyfile("download.tar.gz", args[args.index("--output") + 1])
''')
        curl.chmod(0o755)
        self.env = dict(os.environ, RUNNER_TEMP=str(self.root / "runner"),
                        PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"])

    def replace(self, path, old, new):
        file = self.root / path
        text = file.read_text()
        self.assertIn(old, text)
        file.write_text(text.replace(old, new))

    def run_check(self):
        return subprocess.run(["bash", "-e", "-c", workflow_command()],
                              cwd=self.root, env=self.env, capture_output=True,
                              text=True, timeout=15)

    def test_generated_archive_pins_pass_despite_different_make_dist(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_bad_checksum_is_rejected(self):
        for path, digest in (("packaging/aur/PKGBUILD", SHA),
                             ("packaging/homebrew/zupt.rb", SHA),
                             ("packaging/guix/zupt.scm", BASE32)):
            with self.subTest(path=path):
                self.replace(path, digest, "0" * len(digest))
                result = self.run_check()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.replace(path, "0" * len(digest), digest)

    def test_each_unexpected_source_url_is_rejected_before_download(self):
        for path in ("packaging/aur/PKGBUILD", "packaging/homebrew/zupt.rb",
                     "packaging/guix/zupt.scm"):
            with self.subTest(path=path):
                self.replace(path, "https://github.com/cristiancmoises/zupt",
                             "http://example.invalid/not-zupt")
                result = self.run_check()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / "curl-attempted").exists())
                self.replace(path, "http://example.invalid/not-zupt",
                             "https://github.com/cristiancmoises/zupt")

    def test_recipe_version_disagreement_is_rejected_before_download(self):
        self.replace("packaging/homebrew/zupt.rb", 'version "5.2.10"', 'version "5.2.9"')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "curl-attempted").exists())

    def test_agreeing_wrong_project_urls_are_rejected_before_download(self):
        for path in ("packaging/aur/PKGBUILD", "packaging/homebrew/zupt.rb",
                     "packaging/guix/zupt.scm"):
            self.replace(path, "https://github.com/cristiancmoises/zupt",
                         "https://example.invalid/not-zupt")
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "curl-attempted").exists())

    def test_equivalent_multiline_guix_version_passes(self):
        self.replace("packaging/guix/zupt.scm", '(define %zupt-version "5.2.10")',
                     '(define %zupt-version\n  "5.2.10")')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_download_failure_is_not_a_checksum_pass(self):
        self.env["CURL_FAIL"] = "1"
        # A stale matching file must not turn a failed fetch into success.
        (self.root / "runner/recipe-source.tar.gz").write_bytes(b"tagged source bytes\n")
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
