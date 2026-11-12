# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Exercise the real extracted-package documentation checker."""

import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

CHECKER = Path(__file__).resolve().parents[1] / "scripts/check-installed-docs.py"
DOCUMENTS = {
    "docs/USER_GUIDE.md": b"English guide\n",
    "docs/GUIA_USUARIO.pt-BR.md": b"Guia em portugues\n",
    "SECURITY.md": b"Security policy\n",
    "DISTRIBUTION.md": b"Distribution policy\n",
    "AUDIT.md": b"Audit guide\n",
    "INSTALL.md": b"Installation guide\n",
    "THREAT_MODEL.md": b"Threat model\n",
}


class InstalledDocsFixture(unittest.TestCase):
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


@unittest.skipUnless(
    os.name == "posix" and sys.platform not in ("msys", "cygwin"),
    "DEB/RPM metadata tests require a POSIX package build host",
)
class InstalledDocsTests(InstalledDocsFixture):
    def gui_installer(self, destination):
        root = CHECKER.parents[1]
        for name in (
            "gui/install.sh",
            "gui/src/zupt_gui.py",
            "gui/assets/zupt-icon.png",
            "gui/packaging/zupt-gui.desktop",
            "doc/zupt-gui.1",
            "LICENSE",
            "LICENSE-AGPL-3.0",
            "gui/LICENSE-GUI",
            "gui/assets/README.md",
        ):
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((root / name).read_bytes())
        environment = os.environ.copy()
        for name in ("BASH_ENV", "ENV", "BINDIR", "LIBEXECDIR", "DATADIR", "DESTDIR"):
            environment.pop(name, None)
        environment["TMPDIR"] = str(self.work)
        return subprocess.run(
            [
                "bash",
                str(self.source / "gui/install.sh"),
                "--destdir",
                str(destination),
                "--prefix",
                "/usr",
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_gui_installer_stages_navigation_pages(self):
        result = self.gui_installer(self.extracted)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        destination = self.extracted / "usr/share/doc/zupt-gui"
        for name, content in DOCUMENTS.items():
            with self.subTest(document=name):
                target = destination / name
                self.assertTrue(target.is_file(), name)
                self.assertEqual(target.read_bytes(), content)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.run_checker(package="zupt-gui")

    def test_gui_installer_rejects_missing_navigation_source_before_output(self):
        for index, (name, content) in enumerate(DOCUMENTS.items()):
            with self.subTest(document=name):
                source = self.source / name
                source.unlink()
                try:
                    destination = self.work / f"missing-source-{index}"
                    result = self.gui_installer(destination)
                    self.assertNotEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    self.assertIn("required source file is missing", result.stderr)
                    self.assertFalse(destination.exists())
                finally:
                    source.write_bytes(content)
                    source.chmod(0o644)

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


class NativeInstalledDocsTests(InstalledDocsFixture):
    """Exercise extracted Windows and mounted macOS layouts without native builds."""

    def layouts(self):
        # Dedicated macOS tests below report the native-NT mode limitation.
        profiles = ("windows", "macos") if os.name == "posix" else ("windows",)
        for profile in profiles:
            if profile == "windows":
                locations = [self.extracted / "zupt-5.2.10-windows-x86_64"]
            else:
                locations = [
                    self.extracted,
                    self.extracted / "ZUPT.app/Contents/Resources",
                ]
                self.write_plist()
            for location in locations:
                self.populate(location)
            yield profile, locations

    def write_plist(self, version: str | int = "5.2.10", short_version="5.2.10"):
        path = self.extracted / "ZUPT.app/Contents/Info.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            plistlib.dumps(
                {
                    "CFBundleVersion": version,
                    "CFBundleShortVersionString": short_version,
                }
            )
        )
        path.chmod(0o644)
        return path

    def symlink(self, target, path, *, directory=False):
        if sys.platform in ("msys", "cygwin"):
            # These runtimes choose copy-vs-native-link behavior at startup.
            environment = os.environ.copy()
            for name in ("MSYS", "CYGWIN"):
                options = [
                    option
                    for option in environment.get(name, "").split()
                    if option != "winsymlinks" and not option.startswith("winsymlinks:")
                ]
                environment[name] = " ".join([*options, "winsymlinks:nativestrict"])
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import os,sys; os.symlink(sys.argv[1], sys.argv[2], "
                        "target_is_directory=sys.argv[3] == '1')"
                    ),
                    str(target),
                    str(path),
                    "1" if directory else "0",
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            try:
                path.symlink_to(target, target_is_directory=directory)
            except OSError as error:
                if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                    self.skipTest(
                        "Windows symlink creation needs Developer Mode or privilege"
                    )
                raise
        self.assertTrue(path.is_symlink(), "fixture is not a symbolic link")
        observed = os.readlink(path)
        if os.name == "nt":
            self.assertTrue(Path(observed).is_absolute())
            self.assertTrue(Path(observed).samefile(target.resolve()))
        else:
            self.assertEqual(observed, str(target))

    def test_copied_symlink_fixture_is_setup_failure(self):
        target = self.source / "docs/USER_GUIDE.md"
        path = self.work / "copied guide"

        def copy(link, target, **_options):
            link.write_bytes(target.read_bytes())

        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(Path, "symlink_to", autospec=True, side_effect=copy),
            self.assertRaisesRegex(AssertionError, "fixture is not a symbolic link"),
        ):
            self.symlink(target, path)
        self.assertFalse(path.is_symlink())
        self.assertEqual(path.read_bytes(), target.read_bytes())

    @unittest.skipUnless(os.name == "posix", "modeled MSYS route uses a POSIX child")
    def test_msys_link_launcher_preserves_unrelated_options(self):
        target = self.source / "docs/USER_GUIDE.md"
        path = self.work / "native guide link"
        with (
            mock.patch.object(sys, "platform", "msys"),
            mock.patch.dict(
                os.environ,
                {"MSYS": "foo winsymlinks:deep bar", "CYGWIN": "winsymlinks baz"},
            ),
            mock.patch.object(subprocess, "run", wraps=subprocess.run) as run,
        ):
            self.symlink(target, path)
        self.assertEqual(run.call_count, 1)
        call = run.call_args
        assert call is not None
        self.assertEqual(call.kwargs["env"]["MSYS"], "foo bar winsymlinks:nativestrict")
        self.assertEqual(call.kwargs["env"]["CYGWIN"], "baz winsymlinks:nativestrict")
        self.assertEqual(call.kwargs["timeout"], 10)
        self.assertEqual(call.args[0][:3], [sys.executable, "-I", "-B"])
        self.assertTrue(path.is_symlink())
        self.assertEqual(os.readlink(path), str(target))

    def test_native_layouts(self):
        for profile, _locations in self.layouts():
            self.run_checker(profile)

    def test_each_native_document_is_required_in_each_location(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            for location in locations:
                for name, content in DOCUMENTS.items():
                    with self.subTest(
                        profile=profile, location=location, document=name
                    ):
                        path = location / name
                        path.unlink()
                        self.run_checker(profile, expected=1)
                        path.write_bytes(content)
                        path.chmod(0o644)

    def test_each_native_document_must_match_source_bytes(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            for location in locations:
                for name, content in DOCUMENTS.items():
                    with self.subTest(
                        profile=profile, location=location, document=name
                    ):
                        path = location / name
                        path.write_bytes(b"X" + content[1:])
                        self.run_checker(profile, expected=1)
                        path.write_bytes(content)

    def test_wrong_native_document_modes_are_rejected(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            for location in locations:
                for name in DOCUMENTS:
                    with self.subTest(
                        profile=profile, location=location, document=name
                    ):
                        path = location / name
                        try:
                            path.chmod(0o444)
                            self.assertEqual(
                                stat.S_IMODE(path.stat().st_mode),
                                0o444,
                                "read-only fixture mode did not materialize",
                            )
                            self.run_checker(profile, expected=1)
                        finally:
                            path.chmod(0o644)

    @unittest.skipUnless(os.name == "posix", "owner-only modes require POSIX")
    def test_owner_only_native_document_modes_are_rejected(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            for location in locations:
                for name in DOCUMENTS:
                    path = location / name
                    try:
                        path.chmod(0o600)
                        observed = stat.S_IMODE(path.stat().st_mode)
                        if observed != 0o600:
                            self.skipTest(
                                f"owner-only mode 0600 unavailable for {profile}/{name}: "
                                f"observed {observed:04o}"
                            )
                        self.run_checker(profile, expected=1)
                    finally:
                        path.chmod(0o644)

    def test_symlink_native_documents_are_rejected(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            for location in locations:
                for name, content in DOCUMENTS.items():
                    with self.subTest(
                        profile=profile, location=location, document=name
                    ):
                        path = location / name
                        path.unlink()
                        try:
                            self.symlink(self.source / name, path)
                            self.run_checker(profile, expected=1)
                        finally:
                            if path.is_symlink():
                                path.unlink()
                            path.write_bytes(content)
                            path.chmod(0o644)

    def test_symlink_native_ancestors_are_rejected(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            ancestors = [self.extracted, *(location / "docs" for location in locations)]
            if profile == "windows":
                ancestors.append(locations[0])
            else:
                ancestors.extend(
                    self.extracted / suffix
                    for suffix in (
                        "ZUPT.app",
                        "ZUPT.app/Contents",
                        "ZUPT.app/Contents/Resources",
                    )
                )
            for index, path in enumerate(ancestors):
                with self.subTest(profile=profile, ancestor=path):
                    outside = self.work / f"outside-{profile}-{index}"
                    path.rename(outside)
                    try:
                        self.symlink(outside, path, directory=True)
                        self.run_checker(profile, expected=1)
                    finally:
                        if path.is_symlink():
                            path.unlink()
                        outside.rename(path)

    def test_missing_native_directories_are_rejected(self):
        for profile, locations in self.layouts():
            self.run_checker(profile)
            for index, location in enumerate(locations):
                path = location / "docs"
                outside = self.work / f"missing-{profile}-{index}"
                path.rename(outside)
                self.run_checker(profile, expected=1)
                outside.rename(path)

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture requires native NT")
    def test_windows_junction_directory_is_rejected(self):
        target = self.work / "junction target"
        self.populate(target)
        path = self.extracted / "zupt-5.2.10-windows-x86_64"
        result = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(path), str(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode:
            self.skipTest(
                "native junction creation unavailable: " + result.stderr.strip()[:160]
            )
        try:
            self.assertTrue(
                getattr(path.lstat(), "st_file_attributes", 0)
                & vars(stat)["FILE_ATTRIBUTE_REPARSE_POINT"]
            )
            self.run_checker("windows", expected=1)
        finally:
            path.rmdir()

    def test_windows_directory_must_match_source_version(self):
        path = self.extracted / "zupt-5.2.9-windows-x86_64"
        self.populate(path)
        self.run_checker("windows", expected=1)
        self.header.write_text('#define ZUPT_VERSION_STRING "5.2.9"\n')
        self.run_checker("windows")

    @unittest.skipUnless(os.name == "posix", "macOS installed modes require POSIX")
    def test_macos_both_bundle_versions_must_match_source(self):
        self.populate(self.extracted)
        self.populate(self.extracted / "ZUPT.app/Contents/Resources")
        for version, short in (("5.2.9", "5.2.10"), ("5.2.10", "5.2.9"), (5, "5.2.10")):
            with self.subTest(version=version, short=short):
                self.write_plist(version, short)
                self.run_checker("macos", expected=1)
        self.write_plist()
        self.run_checker("macos")

    @unittest.skipUnless(os.name == "posix", "macOS installed modes require POSIX")
    def test_macos_missing_malformed_or_symlink_plist_is_rejected(self):
        self.populate(self.extracted)
        self.populate(self.extracted / "ZUPT.app/Contents/Resources")
        plist = self.write_plist()
        plist.unlink()
        self.run_checker("macos", expected=1)
        for content in (b"not a plist", b"<?xml version='1.0'?><plist><dict>"):
            plist.write_bytes(content)
            self.run_checker("macos", expected=1)
        plist.unlink()
        self.symlink(self.header, plist)
        self.run_checker("macos", expected=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
