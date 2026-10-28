# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Exercise the real extracted-package documentation checker."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "scripts/check-installed-docs.py"
DOCUMENTS = {
    "docs/USER_GUIDE.md": b"English guide\n",
    "docs/GUIA_USUARIO.pt-BR.md": b"Guia em portugues\n",
    "SECURITY.md": b"Security policy\n",
    "DISTRIBUTION.md": b"Distribution policy\n",
}


@unittest.skipUnless(
    os.name == "posix" and sys.platform not in ("msys", "cygwin"),
    "DEB/RPM metadata tests require a POSIX package build host",
)
class InstalledDocsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="zupt docs test ")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = self.work / "source"
        self.extracted = self.work / "extracted"
        self.source.mkdir()
        self.extracted.mkdir()
        (self.source / "include").mkdir()
        self.header = self.source / "include/zupt.h"
        self.header.write_text('#define ZUPT_VERSION_STRING "5.2.10"\n')
        self.doc = self.extracted / "usr/share/doc/zupt"
        self.populate(self.doc)
        for name, content in DOCUMENTS.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def populate(self, directory):
        for name, content in DOCUMENTS.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o644)

    def run_checker(self, package="zupt", expected=0):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(CHECKER),
                str(self.source),
                str(self.extracted),
                package,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected:
            self.assertNotIn("PASS:", result.stdout)
            self.assertNotIn("Traceback", result.stderr)
            if expected == 1:
                self.assertTrue(
                    result.stderr.startswith("FAIL: installed documentation:"),
                    result.stderr,
                )
            else:
                self.assertIn("invalid choice", result.stderr)
        else:
            self.assertEqual(result.stdout.count("PASS:"), 1)
            self.assertEqual(result.stderr, "")

    def test_current_layout(self):
        self.run_checker()

    def test_gui_and_versioned_native_layouts(self):
        for directory, package in (
            ("usr/share/doc/zupt-gui", "zupt-gui"),
            ("usr/share/doc/zupt-5.2.10", "zupt"),
            ("usr/share/doc/packages/zupt", "zupt"),
            ("usr/share/doc/packages/zupt-gui-5.2.10", "zupt-gui"),
        ):
            with self.subTest(directory=directory):
                destination = self.extracted / directory
                destination.parent.mkdir(parents=True, exist_ok=True)
                self.doc.rename(destination)
                self.doc = destination
                self.run_checker(package)

    def test_missing_each_document_is_rejected(self):
        for name, content in DOCUMENTS.items():
            with self.subTest(document=name):
                path = self.doc / name
                path.unlink()
                self.run_checker(expected=1)
                path.write_bytes(content)
                path.chmod(0o644)

    def test_modified_bytes_with_same_size_are_rejected(self):
        target = self.doc / "docs/USER_GUIDE.md"
        target.write_bytes(b"english guide\n")
        source_stat = (self.source / "docs/USER_GUIDE.md").stat()
        os.utime(target, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        self.run_checker(expected=1)

    def test_wrong_mode_is_rejected(self):
        (self.doc / "SECURITY.md").chmod(0o600)
        self.run_checker(expected=1)

    def test_symlink_document_is_rejected(self):
        path = self.doc / "docs/USER_GUIDE.md"
        path.unlink()
        path.symlink_to(self.source / "docs/USER_GUIDE.md")
        self.run_checker(expected=1)

    def test_symlink_parent_is_rejected(self):
        (self.doc / "docs").rename(self.work / "outside")
        (self.doc / "docs").symlink_to(self.work / "outside", target_is_directory=True)
        self.run_checker(expected=1)

    def test_symlink_package_directory_is_rejected(self):
        self.doc.rename(self.work / "outside")
        self.doc.symlink_to(self.work / "outside", target_is_directory=True)
        self.run_checker(expected=1)

    def test_symlink_extract_root_is_rejected(self):
        self.extracted.rename(self.work / "outside")
        self.extracted.symlink_to(self.work / "outside", target_is_directory=True)
        self.run_checker(expected=1)

    def test_symlink_system_prefix_is_rejected(self):
        (self.extracted / "usr").rename(self.work / "outside")
        (self.extracted / "usr").symlink_to(
            self.work / "outside", target_is_directory=True
        )
        self.run_checker(expected=1)

    def test_duplicate_package_directories_are_rejected(self):
        self.populate(self.extracted / "usr/share/doc/packages/zupt")
        self.run_checker(expected=1)

    def test_missing_package_directory_is_rejected(self):
        self.doc.rename(self.doc.with_name("zupt-5.2.9"))
        self.run_checker(expected=1)

    def test_symlink_source_document_is_rejected(self):
        source = self.source / "DISTRIBUTION.md"
        source.rename(self.work / "source-policy")
        source.symlink_to(self.work / "source-policy")
        self.run_checker(expected=1)

    def test_malformed_or_duplicate_version_is_rejected(self):
        for header in ("no version\n", '#define ZUPT_VERSION_STRING "5.2.10"\n' * 2):
            with self.subTest(header=header):
                self.header.write_text(header)
                self.run_checker(expected=1)

    def test_fifo_is_rejected_without_opening_it(self):
        path = self.doc / "SECURITY.md"
        path.unlink()
        os.mkfifo(path)
        self.run_checker(expected=1)

    def test_unknown_package_is_usage_error(self):
        self.run_checker(package="../other", expected=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
