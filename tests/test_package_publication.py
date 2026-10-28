#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
"""Exercise local package publication with real temporary files."""

import errno
import importlib.util
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/publish-package.py"
SPEC = importlib.util.spec_from_file_location("package_publisher", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="zupt-publication-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.fd = os.open(self.dist, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.source = self.root / "source"
        self.source.mkdir()
        self.package = self.source / "zupt.deb"
        self.package.write_bytes(b"package bytes\n")
        self.second = self.source / "zupt.src.rpm"
        self.second.write_bytes(b"source package\n")

    def publish(self, *artifacts):
        return PUBLISHER.publish(self.fd, self.dist, list(artifacts))

    def assert_no_staging(self, directory=None):
        target = directory or self.dist
        self.assertFalse(
            any(p.name.startswith(".zupt-publish-") for p in target.iterdir())
        )

    def test_publish_exact_bytes_hash_and_mode(self):
        self.package.chmod(0o600)
        result = self.publish(self.package)
        self.assertEqual(
            result,
            [
                (
                    "40fa264148fd4b9e9bea4447cc4504f68832044997ab4921af95356d05556031",
                    "zupt.deb",
                )
            ],
        )
        self.assertEqual((self.dist / "zupt.deb").read_bytes(), b"package bytes\n")
        self.assertEqual(stat.S_IMODE((self.dist / "zupt.deb").stat().st_mode), 0o644)
        self.assertEqual(self.package.read_bytes(), b"package bytes\n")
        self.assert_no_staging()

    def test_existing_entry_types_are_never_replaced(self):
        output = self.dist / "zupt.deb"
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"foreign bytes")
        for kind in ("regular", "symlink", "dangling", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "regular":
                    output.write_bytes(b"foreign output")
                elif kind == "symlink":
                    output.symlink_to(sentinel)
                elif kind == "dangling":
                    output.symlink_to(self.root / "missing")
                elif kind == "directory":
                    output.mkdir()
                else:
                    os.mkfifo(output)
                before = output.lstat()
                with self.assertRaises((OSError, ValueError)):
                    self.publish(self.package)
                self.assertEqual(
                    (output.lstat().st_dev, output.lstat().st_ino),
                    (before.st_dev, before.st_ino),
                )
                self.assertEqual(sentinel.read_bytes(), b"foreign bytes")
                if kind == "regular":
                    self.assertEqual(output.read_bytes(), b"foreign output")
                if kind == "dangling":
                    self.assertFalse((self.root / "missing").exists())
                if kind == "directory":
                    self.assertEqual(list(output.iterdir()), [])
                    output.rmdir()
                else:
                    output.unlink()
                self.assert_no_staging()

    def test_second_existing_output_prevents_first_publication(self):
        second = self.dist / "zupt.src.rpm"
        second.symlink_to(self.root / "missing")
        with self.assertRaises((OSError, ValueError)):
            self.publish(self.package, self.second)
        self.assertFalse((self.dist / "zupt.deb").exists())
        self.assertTrue(second.is_symlink())
        self.assertFalse((self.root / "missing").exists())
        self.assert_no_staging()

    def test_duplicate_basenames_fail_before_publication(self):
        with self.assertRaises(ValueError):
            self.publish(self.package, self.package)
        self.assertEqual(list(self.dist.iterdir()), [])

    def test_late_collision_does_not_clobber_foreign_file(self):
        original = os.link

        def collide(source, destination, **kwargs):
            (self.dist / destination).write_bytes(b"late foreign output")
            return original(source, destination, **kwargs)

        with (
            patch.object(PUBLISHER.os, "link", side_effect=collide) as replacement,
            patch.object(
                PUBLISHER.os, "supports_dir_fd", os.supports_dir_fd | {replacement}
            ),
            self.assertRaises(OSError),
        ):
            self.publish(self.package)
        self.assertEqual((self.dist / "zupt.deb").read_bytes(), b"late foreign output")
        self.assert_no_staging()

    def test_late_second_failure_retains_first_output(self):
        original = os.link

        def collide(source, destination, **kwargs):
            if destination == "zupt.src.rpm":
                (self.dist / destination).write_bytes(b"late second output")
            return original(source, destination, **kwargs)

        with (
            patch.object(PUBLISHER.os, "link", side_effect=collide) as replacement,
            patch.object(
                PUBLISHER.os, "supports_dir_fd", os.supports_dir_fd | {replacement}
            ),
            self.assertRaises(OSError),
        ):
            self.publish(self.package, self.second)
        self.assertEqual((self.dist / "zupt.deb").read_bytes(), b"package bytes\n")
        self.assertEqual(
            (self.dist / "zupt.src.rpm").read_bytes(), b"late second output"
        )
        self.assert_no_staging()

    def test_replaced_directory_is_rejected_before_staging(self):
        saved = self.root / "saved"
        self.dist.rename(saved)
        self.dist.mkdir()
        with self.assertRaises((OSError, ValueError)):
            self.publish(self.package)
        self.assertEqual(list(self.dist.iterdir()), [])
        self.assertEqual(list(saved.iterdir()), [])

    def test_replaced_directory_does_not_redirect_link(self):
        original = os.link
        saved = self.root / "saved"
        unrelated = self.root / "unrelated"
        unrelated.mkdir()

        def replace_parent(source, destination, **kwargs):
            self.dist.rename(saved)
            self.dist.symlink_to(unrelated, target_is_directory=True)
            return original(source, destination, **kwargs)

        with (
            patch.object(
                PUBLISHER.os, "link", side_effect=replace_parent
            ) as replacement,
            patch.object(
                PUBLISHER.os, "supports_dir_fd", os.supports_dir_fd | {replacement}
            ),
            self.assertRaises((OSError, ValueError)),
        ):
            self.publish(self.package)
        self.assertEqual(list(unrelated.iterdir()), [])
        self.assertEqual((saved / "zupt.deb").read_bytes(), b"package bytes\n")
        self.assert_no_staging(saved)

    def test_symlinked_directory_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.dist, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            PUBLISHER.check_directory(self.fd, alias)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses directory read permissions")
    def test_search_only_ancestor_does_not_require_read_access(self):
        ancestor = self.root / "search-only"
        ancestor.mkdir(mode=0o700)
        output = ancestor / "dist"
        output.mkdir(mode=0o700)
        held = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            ancestor.chmod(0o100)
            with self.assertRaises(PermissionError):
                os.listdir(ancestor)
            alias = self.root / "alias-parent"
            alias.symlink_to(ancestor, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                PUBLISHER.check_directory(held, alias / "dist")
            result = PUBLISHER.publish(held, output, [self.package])
            self.assertEqual(result[0][1], "zupt.deb")
            self.assertEqual((output / "zupt.deb").read_bytes(), b"package bytes\n")
            self.assert_no_staging(output)
        finally:
            ancestor.chmod(0o700)
            os.close(held)

    def test_shared_writable_directory_is_rejected(self):
        self.dist.chmod(0o777)
        with self.assertRaises((OSError, ValueError)):
            self.publish(self.package)
        self.assertEqual(list(self.dist.iterdir()), [])

    def test_replaced_staging_is_retained_without_checksum(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                output_dir = self.root / f"output-{populated}"
                output_dir.mkdir()
                held = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY)
                saved = self.root / f"saved-stage-{populated}"
                original = os.link
                replacement_stage = []

                def replace_stage(
                    source,
                    destination,
                    original=original,
                    output_dir=output_dir,
                    saved=saved,
                    populated=populated,
                    replacement_stage=replacement_stage,
                    **kwargs,
                ):
                    result = original(source, destination, **kwargs)
                    stage = next(
                        p
                        for p in output_dir.iterdir()
                        if p.name.startswith(".zupt-publish-")
                    )
                    stage.rename(saved)
                    stage.mkdir(mode=0o700)
                    if populated:
                        (stage / "zupt.deb").write_bytes(b"foreign staging bytes")
                    replacement_stage.append(stage)
                    return result

                stdout = io.StringIO()
                stderr = io.StringIO()
                try:
                    with (
                        patch.object(
                            PUBLISHER.os, "link", side_effect=replace_stage
                        ) as replacement,
                        patch.object(
                            PUBLISHER.os,
                            "supports_dir_fd",
                            os.supports_dir_fd | {replacement},
                        ),
                        patch.object(
                            PUBLISHER.sys,
                            "argv",
                            [
                                str(SCRIPT),
                                str(held),
                                str(output_dir),
                                str(self.package),
                            ],
                        ),
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                    ):
                        status = PUBLISHER.main()
                    self.assertNotEqual(status, 0)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("FAIL:", stderr.getvalue())
                    self.assertEqual(
                        (saved / "zupt.deb").read_bytes(), b"package bytes\n"
                    )
                    self.assertEqual(
                        (output_dir / "zupt.deb").read_bytes(), b"package bytes\n"
                    )
                    self.assertTrue(replacement_stage[0].is_dir())
                    if populated:
                        self.assertEqual(
                            (replacement_stage[0] / "zupt.deb").read_bytes(),
                            b"foreign staging bytes",
                        )
                    else:
                        self.assertEqual(list(replacement_stage[0].iterdir()), [])
                finally:
                    os.close(held)

    def test_invalid_directory_descriptors_fail(self):
        with self.assertRaises((OSError, ValueError)):
            PUBLISHER.check_directory(-1, self.dist)
        regular_fd = os.open(self.package, os.O_RDONLY)
        try:
            with self.assertRaises((OSError, ValueError)):
                PUBLISHER.check_directory(regular_fd, self.dist)
        finally:
            os.close(regular_fd)

    def test_special_or_missing_source_is_rejected(self):
        invalid = self.source / "invalid.rpm"
        for kind in ("missing", "symlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    invalid.symlink_to(self.package)
                elif kind == "directory":
                    invalid.mkdir()
                elif kind == "fifo":
                    os.mkfifo(invalid)
                with self.assertRaises((OSError, ValueError)):
                    self.publish(invalid)
                self.assertEqual(list(self.dist.iterdir()), [])
                if kind == "directory":
                    invalid.rmdir()
                elif kind != "missing":
                    invalid.unlink()

    def test_size_limit_failure_leaves_no_public_files(self):
        with (
            patch.object(PUBLISHER, "MAX_PACKAGE_BYTES", 4),
            self.assertRaises((OSError, ValueError)),
        ):
            self.publish(self.package)
        self.assertEqual(list(self.dist.iterdir()), [])

    def test_copy_failure_leaves_no_public_files(self):
        with (
            patch.object(
                PUBLISHER.os,
                "read",
                side_effect=OSError(errno.EIO, "injected read error"),
            ),
            self.assertRaises(OSError),
        ):
            self.publish(self.package)
        self.assertEqual(list(self.dist.iterdir()), [])

    def test_sync_failure_leaves_no_public_files(self):
        with (
            patch.object(
                PUBLISHER.os,
                "fsync",
                side_effect=OSError(errno.EIO, "injected sync error"),
            ),
            self.assertRaises(OSError),
        ):
            self.publish(self.package)
        self.assertEqual(list(self.dist.iterdir()), [])

    def test_partial_writes_are_completed(self):
        original = os.write

        def partial(fd, data):
            return original(fd, data[:3])

        with patch.object(PUBLISHER.os, "write", side_effect=partial):
            self.publish(self.package)
        self.assertEqual((self.dist / "zupt.deb").read_bytes(), b"package bytes\n")
        self.assert_no_staging()

    def test_cli_preserves_escaped_checksum_paths(self):
        directory = self.root / "odd\n\\dir"
        directory.mkdir()
        held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(held),
                    str(directory),
                    str(self.package),
                ],
                pass_fds=(held,),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        finally:
            os.close(held)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            f"\\40fa264148fd4b9e9bea4447cc4504f68832044997ab4921af95356d05556031  {self.root}/odd\\n\\\\dir/zupt.deb\n",
        )

    def test_publication_error_precedes_cleanup_error(self):
        original = os.link

        def collide(source, destination, **kwargs):
            (self.dist / destination).write_bytes(b"foreign output")
            return original(source, destination, **kwargs)

        stderr = io.StringIO()
        with (
            patch.object(PUBLISHER.os, "link", side_effect=collide) as replacement,
            patch.object(
                PUBLISHER.os, "supports_dir_fd", os.supports_dir_fd | {replacement}
            ),
            patch.object(
                PUBLISHER.os,
                "unlink",
                side_effect=OSError(errno.EIO, "injected cleanup failure"),
            ) as unlink,
            patch.object(
                PUBLISHER.os, "supports_dir_fd", os.supports_dir_fd | {unlink}
            ),
            redirect_stderr(stderr),
            self.assertRaises(OSError) as caught,
        ):
            self.publish(self.package)
        self.assertEqual(caught.exception.errno, errno.EEXIST)
        self.assertIn("staging cleanup failed", stderr.getvalue())
        self.assertEqual((self.dist / "zupt.deb").read_bytes(), b"foreign output")

    def test_cli_checksums_only_after_success(self):
        command = [
            sys.executable,
            str(SCRIPT),
            str(self.fd),
            str(self.dist),
            str(self.package),
        ]
        result = subprocess.run(
            command,
            pass_fds=(self.fd,),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            f"40fa264148fd4b9e9bea4447cc4504f68832044997ab4921af95356d05556031  {self.dist}/zupt.deb\n",
        )
        failed = subprocess.run(
            command,
            pass_fds=(self.fd,),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(failed.stdout, "")
        self.assertIn("FAIL:", failed.stderr)


if __name__ == "__main__":
    unittest.main()
