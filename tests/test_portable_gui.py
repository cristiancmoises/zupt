#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Test the portable package boundary with real Zupt containers, without Qt."""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def proxy_cli():
    """Forward real archive operations, injecting one named boundary fault."""
    args = sys.argv[1:]
    command = args[0]
    mode = os.environ["ZUPT_PORTABLE_PROXY_MODE"]
    real = os.environ["ZUPT_PORTABLE_REAL_CLI"]
    if (
        mode == "extracted-binary"
        and command == "extract"
        and os.environ.get("ZUPT_PORTABLE_NEGATIVE_CONTROL") == "1"
    ):
        print("PORTABLE-UNRELATED-EXTRACTION-FAILURE", file=sys.stderr)
        return 23
    if mode == f"fail-{command}":
        print(f"PORTABLE-FAULT: {mode}", file=sys.stderr)
        return 23
    if mode == "wrong-version" and command == "version":
        print("ZUPT 0.0.0 - fixture mismatched CLI")
        return 0
    if command == "compress":
        root = Path(args[-1])
        if mode == "extra-member":
            (root / "unexpected.txt").write_text("unexpected release payload\n")
        elif mode == "missing-member":
            (root / "assets/zupt.ico").unlink()
        elif mode == "missing-english-guide":
            (root / "docs/USER_GUIDE.md").unlink()
        elif mode == "missing-portuguese-guide":
            (root / "docs/GUIA_USUARIO.pt-BR.md").unlink()
        elif mode == "missing-security-policy":
            (root / "SECURITY.md").unlink()
        elif mode == "missing-distribution-policy":
            (root / "DISTRIBUTION.md").unlink()
        elif mode == "tampered-member":
            (root / "README.txt").write_text("changed after staging\n")
        elif mode == "wrong-codec":
            args[args.index("--vv")] = "--lzhp"
        elif mode == "wrong-level":
            args[args.index("9")] = "5"
        elif mode == "encrypted":
            args[1:1] = ["-p", "fixture-only-817"]
    result = subprocess.run([real, *args], capture_output=True, check=False)
    out = result.stdout
    if result.returncode == 0 and command == "list":
        if mode == "unsafe-member":
            out = out.replace(b"/zupt_gui.py", b"/../outside.py")
        elif mode == "duplicate-member":
            row = next(line for line in out.splitlines() if b"/zupt_gui.py" in line)
            out += row + b"\n"
    if result.returncode == 0 and command == "extract":
        root = Path(args[args.index("-o") + 1])
        package = next(root.iterdir())
        if mode == "extracted-extra":
            (package / "unexpected.txt").write_text("unexpected\n")
        elif mode == "extracted-tampered":
            (package / "README.txt").write_text("changed after extraction\n")
        elif mode == "extracted-binary":
            (package / "README.txt").write_bytes(b"\x7fELF" + bytes(128))
            print("PORTABLE-FAULT-REACHED: extracted-binary", file=sys.stderr)
        elif mode == "extracted-symlink":
            target = package / "README.txt"
            target.unlink()
            target.symlink_to(os.environ["ZUPT_PORTABLE_SYMLINK_TARGET"])
    sys.stdout.buffer.write(out)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if os.environ.get("ZUPT_PORTABLE_PROXY_CHILD") == "1":
    raise SystemExit(proxy_cli())


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = {
    "zupt_gui.py": "gui/src/zupt_gui.py",
    "zupt-gui.sh": "packaging/portable/zupt-gui.sh",
    "zupt-gui.command": "packaging/portable/zupt-gui.command",
    "zupt-gui.bat": "packaging/portable/zupt-gui.bat",
    "README.txt": "packaging/portable/README.txt",
    "assets/zupt-icon.png": "gui/assets/zupt-icon.png",
    "assets/zupt.ico": "gui/assets/zupt.ico",
    "LICENSE-AGPL-3.0": "LICENSE-AGPL-3.0",
    "LICENSE-GUI": "gui/LICENSE-GUI",
    "ASSET-PROVENANCE.md": "gui/assets/README.md",
    "CHANGELOG.md": "CHANGELOG.md",
    "README.pt-BR.md": "README.pt-BR.md",
    "DOCUMENTACAO.pt-BR.md": "DOCUMENTACAO.pt-BR.md",
    "docs/USER_GUIDE.md": "docs/USER_GUIDE.md",
    "docs/GUIA_USUARIO.pt-BR.md": "docs/GUIA_USUARIO.pt-BR.md",
    "SECURITY.md": "SECURITY.md",
    "DISTRIBUTION.md": "DISTRIBUTION.md",
}


class PortableGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = Path(os.environ.get("ZUPT_BIN", ROOT / "zupt")).resolve()
        if not cls.cli.is_file() or not os.access(cls.cli, os.X_OK):
            raise RuntimeError("Set ZUPT_BIN to a tested matching CLI")
        header = (ROOT / "include/zupt.h").read_text()
        match = re.search(
            r'^#define ZUPT_VERSION_STRING "([^"]+)"', header, re.MULTILINE
        )
        if match is None:
            raise RuntimeError("Source version is missing")
        cls.version = match.group(1)
        cls.name = f"zupt-gui-{cls.version}-portable"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zupt-portable-tests-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / "source with spaces"
        for relative in (
            *PAYLOAD.values(),
            "include/zupt.h",
            "scripts/check-source-only.sh",
        ):
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        helper = self.source / "packaging/build-portable-gui.sh"
        if (ROOT / "packaging/build-portable-gui.sh").exists():
            shutil.copyfile(ROOT / "packaging/build-portable-gui.sh", helper)
        self.dist = self.work / "release output"
        self.archive = self.dist / f"{self.name}.zupt"
        self.extracted = self.dist / f"{self.name}.extracted"
        self.proxy = self.work / "proxy-cli"
        shutil.copyfile(__file__, self.proxy)
        self.proxy.chmod(0o700)
        self.env = os.environ.copy()
        self.env.update(
            ZUPT_BIN=str(self.cli),
            PYTHON=sys.executable,
            DIST_DIR=str(self.dist),
            PYTHONDONTWRITEBYTECODE="1",
        )

    def build(self, mode=None):
        env = self.env.copy()
        if mode:
            env.update(
                ZUPT_BIN=str(self.proxy),
                ZUPT_PORTABLE_PROXY_CHILD="1",
                ZUPT_PORTABLE_PROXY_MODE=mode,
                ZUPT_PORTABLE_REAL_CLI=str(self.cli),
                ZUPT_PORTABLE_SYMLINK_TARGET=str(self.source / "LICENSE-AGPL-3.0"),
            )
        return subprocess.run(
            ["bash", str(self.source / "packaging/build-portable-gui.sh")],
            env=env,
            cwd=self.work,
            capture_output=True,
            text=True,
            timeout=40,
            check=False,
        )

    def rejected(self, mode, reason):
        result = self.build(mode)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.archive.exists(), result.stdout + result.stderr)
        self.assertFalse(self.extracted.exists(), result.stdout + result.stderr)
        self.assertFalse(Path(str(self.archive) + ".sha256").exists())
        self.assertNotIn("PASS: portable GUI", result.stdout)
        self.assertNotIn("No such file or directory", result.stderr)
        self.assertIn(reason, result.stdout + result.stderr)
        return result

    def test_make_routes_packaging_to_release_without_changing_core_check(self):
        make = os.environ.get("MAKE") or shutil.which("make")
        if not make:
            self.skipTest("GNU make unavailable for build-host routing")
        probe = self.work / "routing.mk"
        probe.write_text(
            ".PHONY: portable-routing-probe\nportable-routing-probe:\n\t@:\n"
        )
        result = subprocess.run(
            [
                make,
                "-p",
                "-f",
                str(ROOT / "Makefile"),
                "-f",
                str(probe),
                "WITH_SDK=0",
                "WITH_PQBOX=0",
                "portable-routing-probe",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        # Inspect GNU make's evaluated dependency database, without executing
        # the compilation, core tests, or formal release-check prerequisites.
        release = re.search(r"^release-check:(.*)$", result.stdout, re.MULTILINE)
        core = re.search(r"^check:(.*)$", result.stdout, re.MULTILINE)
        self.assertIsNotNone(release)
        self.assertIsNotNone(core)
        if release is None or core is None:
            self.fail("GNU make omitted the core or release target")
        self.assertIn("test-portable-gui", release.group(1).split())
        self.assertNotIn("test-portable-gui", core.group(1).split())

    def test_real_archive_contains_exact_source_bytes_and_no_execute_modes(self):
        # A PATH-selected CLI would fail; this package must use the explicit CLI.
        poison = self.work / "poison-path"
        poison.mkdir()
        (poison / "zupt").write_text("#!/bin/sh\nexit 98\n")
        (poison / "zupt").chmod(0o700)
        self.env["PATH"] = str(poison) + os.pathsep + self.env["PATH"]
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: portable GUI", result.stdout)
        self.assertEqual(self.archive.read_bytes()[:8], b"ZUPT\x1a\x00\x01\x06")
        checked = subprocess.run(
            [str(self.cli), "test", str(self.archive)], capture_output=True, check=False
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        metadata = subprocess.run(
            [str(self.cli), "info", str(self.archive)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertRegex(metadata, r"Encrypted:\s+no")
        bundle = self.extracted / self.name
        actual = {
            p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()
        }
        self.assertEqual(actual, set(PAYLOAD))
        for relative, source in PAYLOAD.items():
            self.assertEqual(
                (bundle / relative).read_bytes(), (self.source / source).read_bytes()
            )
        self.assertFalse(os.access(bundle / "zupt-gui.sh", os.X_OK))
        self.assertFalse(os.access(bundle / "zupt-gui.command", os.X_OK))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(
            Path(str(self.archive) + ".sha256").read_text(),
            f"{digest}  {self.archive.name}\n",
        )

    def test_cli_command_failures_do_not_publish_a_bundle(self):
        for command in ("version", "compress", "info", "list", "test", "extract"):
            with self.subTest(command=command):
                result = self.rejected(
                    f"fail-{command}", f"PORTABLE-FAULT: fail-{command}"
                )
                self.assertIn(f"PORTABLE-FAULT: fail-{command}", result.stderr)

    def test_different_cli_version_is_rejected(self):
        self.rejected("wrong-version", "does not match the source version")

    def test_wrong_codec_level_or_encryption_is_rejected(self):
        for mode in ("wrong-codec", "wrong-level", "encrypted"):
            with self.subTest(mode=mode):
                self.rejected(
                    mode,
                    "must be unencrypted"
                    if mode == "encrypted"
                    else "compression did not report VaptVupt level 9",
                )

    def test_extra_missing_unsafe_or_duplicate_members_are_rejected(self):
        for mode in (
            "extra-member",
            "missing-member",
            "missing-english-guide",
            "missing-portuguese-guide",
            "missing-security-policy",
            "missing-distribution-policy",
            "unsafe-member",
            "duplicate-member",
        ):
            with self.subTest(mode=mode):
                self.rejected(mode, "member allowlist mismatch")

    def test_archive_and_extracted_content_tampering_is_rejected(self):
        for mode in (
            "tampered-member",
            "extracted-extra",
            "extracted-tampered",
            "extracted-binary",
            "extracted-symlink",
        ):
            with self.subTest(mode=mode):
                reason = {
                    "tampered-member": "differs from source",
                    "extracted-extra": "member allowlist mismatch",
                    "extracted-tampered": "differs from source",
                    "extracted-binary": "FAIL source-only:",
                    "extracted-symlink": "symlink",
                }[mode]
                result = self.rejected(mode, reason)
                if mode == "extracted-binary":
                    self.assertIn(
                        "PORTABLE-FAULT-REACHED: extracted-binary", result.stderr
                    )
                    self.assertIn(
                        "README.txt (ELF executable or object)", result.stdout
                    )

    def test_source_symlinks_and_compiled_content_are_rejected(self):
        source = self.source / "gui/src/zupt_gui.py"
        source.unlink()
        source.symlink_to(ROOT / "gui/src/zupt_gui.py")
        self.rejected(None, "regular non-symlink file")
        source.unlink()
        source.write_bytes(b"\x7fELF" + bytes(128))
        result = self.rejected(None, "FAIL source-only:")
        self.assertIn("zupt_gui.py (ELF executable or object)", result.stdout)

    def test_missing_or_symlink_policy_sources_are_rejected(self):
        for name in ("SECURITY.md", "DISTRIBUTION.md"):
            with self.subTest(policy=name):
                source = self.source / name
                source.unlink()
                self.rejected(None, "regular non-symlink file")
                source.symlink_to(ROOT / name)
                self.rejected(None, "regular non-symlink file")
                source.unlink()
                shutil.copyfile(ROOT / name, source)

    def test_existing_output_files_directories_and_symlinks_are_preserved(self):
        self.dist.mkdir()
        sentinel = self.work / "sentinel"
        sentinel.write_bytes(b"existing user data")
        for kind in ("archive", "checksum", "extracted", "symlink"):
            with self.subTest(kind=kind):
                target = (
                    self.extracted
                    if kind == "extracted"
                    else Path(str(self.archive) + ".sha256")
                    if kind == "checksum"
                    else self.archive
                )
                if kind == "extracted":
                    target.mkdir()
                    (target / "sentinel").write_bytes(sentinel.read_bytes())
                elif kind == "symlink":
                    target.symlink_to(sentinel)
                else:
                    target.write_bytes(sentinel.read_bytes())
                try:
                    result = self.build()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("refusing to overwrite", result.stderr)
                    self.assertEqual(sentinel.read_bytes(), b"existing user data")
                    existing = target / "sentinel" if kind == "extracted" else target
                    self.assertEqual(existing.read_bytes(), sentinel.read_bytes())
                    self.assertNotIn("PASS: portable GUI", result.stdout)
                finally:
                    if kind == "extracted":
                        shutil.rmtree(target)
                    else:
                        target.unlink()

    def test_publication_collision_does_not_delete_a_replaced_user_directory(self):
        # Inject a filesystem race after the archive link succeeds. Archive
        # operations and both scans remain real; only final os.link is replaced.
        hooks = self.work / "publication-hook"
        hooks.mkdir()
        (hooks / "sitecustomize.py").write_text(
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "original_link = os.link\n"
            "def collision(source, destination, *args, **kwargs):\n"
            "    path = Path(os.environ['DIST_DIR']) / Path(destination).name\n"
            "    if path.name.endswith('.zupt.sha256'):\n"
            "        archive = path.with_name(path.name[:-7])\n"
            "        archive.unlink()\n"
            "        archive.mkdir()\n"
            "        (archive / 'user-data').write_bytes(b'concurrent user output')\n"
            "        print('PUBLICATION-RACE-INJECTED', file=sys.stderr)\n"
            "        raise FileExistsError('fixture publication collision')\n"
            "    return original_link(source, destination, *args, **kwargs)\n"
            "os.link = collision\n"
        )
        self.env["PYTHONPATH"] = str(hooks)
        result = self.build()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("PASS: portable GUI", result.stdout)
        self.assertIn("PUBLICATION-RACE-INJECTED", result.stderr)
        self.assertTrue(
            self.archive.is_dir(), "rollback deleted a replaced output directory"
        )
        self.assertEqual(
            (self.archive / "user-data").read_bytes(), b"concurrent user output"
        )

    def test_replaced_extracted_directory_cannot_redirect_publication(self):
        outside = self.work / "unrelated destination"
        outside.mkdir()
        (outside / "user-data").write_bytes(b"existing user data")
        hooks = self.work / "directory-hook"
        hooks.mkdir()
        (hooks / "sitecustomize.py").write_text(
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "original_mkdir = os.mkdir\n"
            "def replacement(path, *args, **kwargs):\n"
            "    result = original_mkdir(path, *args, **kwargs)\n"
            "    if Path(path).name.endswith('.extracted'):\n"
            "        target = Path(os.environ['DIST_DIR']) / Path(path).name\n"
            "        target.rmdir()\n"
            "        target.symlink_to(os.environ['ZUPT_PORTABLE_OUTSIDE'], target_is_directory=True)\n"
            "        print('EXTRACTED-DESTINATION-REPLACED', file=sys.stderr)\n"
            "    return result\n"
            "os.mkdir = replacement\n"
        )
        self.env.update(PYTHONPATH=str(hooks), ZUPT_PORTABLE_OUTSIDE=str(outside))
        result = self.build()
        self.assertIn("EXTRACTED-DESTINATION-REPLACED", result.stderr)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("PASS: portable GUI", result.stdout)
        self.assertEqual({p.name for p in outside.iterdir()}, {"user-data"})
        self.assertEqual((outside / "user-data").read_bytes(), b"existing user data")


if __name__ == "__main__":
    unittest.main(verbosity=2)
