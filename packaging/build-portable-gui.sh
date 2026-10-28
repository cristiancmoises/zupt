#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

# Assemble and verify frontend source only. ZUPT_BIN selects an independently
# tested matching CLI; Python/Qt remain external. The retained .extracted tree
# lets CI run the real GUI tests without assuming executable archive modes.
set -Eeuo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec "${PYTHON:-python3}" - "$repo_root" <<'PY'
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=120, check=False)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    require(result.returncode == 0,
            f"{Path(command[0]).name} {command[1]} exited {result.returncode}")
    return result.stdout + result.stderr


def main():
    os.umask(0o077)
    repo = Path(sys.argv[1])
    selected = os.environ.get("ZUPT_BIN", "")
    require(bool(selected), "set ZUPT_BIN to an independently tested matching CLI")
    cli = Path(selected).resolve(strict=True)
    require(cli.is_file() and os.access(cli, os.X_OK), "ZUPT_BIN is not executable")
    header = (repo / "include/zupt.h").read_text()
    match = re.search(r'^#define ZUPT_VERSION_STRING "([0-9]+\.[0-9]+\.[0-9]+)"$',
                      header, re.MULTILINE)
    require(match is not None, "source version is missing or invalid")
    version = match.group(1)
    banner = run([str(cli), "version"])
    require(re.match(r"\Azupt " + re.escape(version) + r"(?:\s|$)", banner) is not None,
            "selected CLI does not match the source version")
    name = f"zupt-gui-{version}-portable"
    requested = Path(os.environ.get("DIST_DIR", str(repo / "dist")))
    require(not requested.is_symlink(), "DIST_DIR must not be a symlink")
    requested.mkdir(parents=True, exist_ok=True)
    dist = requested.resolve(strict=True)
    archive_out = dist / f"{name}.zupt"
    checksum_out = dist / f"{name}.zupt.sha256"
    extracted_out = dist / f"{name}.extracted"
    for target in (archive_out, checksum_out, extracted_out):
        require(not target.exists() and not target.is_symlink(),
                f"refusing to overwrite existing output: {target}")

    payload = {
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
    with tempfile.TemporaryDirectory(prefix=".zupt-gui-", dir=dist) as temporary:
        work = Path(temporary)
        bundle = work / name
        for member, source_name in payload.items():
            source = repo / source_name
            require(source.is_file() and not source.is_symlink() and
                    source.resolve() == source,
                    f"payload source must be a regular non-symlink file: {source_name}")
            target = bundle / member
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        scanner = ["bash", str(repo / "scripts/check-source-only.sh"), "--tree"]
        run([*scanner, str(bundle)])

        archive = work / archive_out.name
        compressed = run([str(cli), "compress", "--vv", "-l", "9", "-t", "1",
                          str(archive), name], cwd=work)
        require(re.search(r"^\s*Codec:\s+VaptVupt \(level 9\)\s*$",
                          compressed, re.MULTILINE) is not None,
                "compression did not report VaptVupt level 9")
        with archive.open("rb") as stream:
            require(stream.read(8) == b"ZUPT\x1a\x00\x01\x06",
                    "output is not a genuine Zupt v1.6 container")
        metadata = run([str(cli), "info", str(archive)])
        require(re.findall(r"^\s*Encrypted:\s+(\S+)\s*$", metadata, re.MULTILINE) == ["no"],
                "portable GUI archive must be unencrypted")
        listing = run([str(cli), "list", str(archive)])
        members = []
        totals = []
        for line in listing.splitlines():
            row = line.strip()
            if not row or row.startswith(("ZUPT archive:", "Format:", "Path ", "TOTAL ")):
                continue
            if set(row) == {"-"}:
                continue
            count = re.fullmatch(r"([0-9]+) file\(s\)", row)
            if count:
                totals.append(int(count.group(1)))
                continue
            entry = re.fullmatch(
                r"(\S+)\s+[0-9.]+\s+[KMGT]?B\s+[0-9.]+\s+[KMGT]?B\s+[0-9.]+%", row)
            require(entry is not None, "unrecognized portable GUI member listing")
            members.append(entry.group(1))
        expected = {f"{name}/{member}" for member in payload}
        require(len(members) == 17 and len(set(members)) == 17 and
                set(members) == expected and totals == [17],
                "portable GUI member allowlist mismatch (expected 17 safe files)")
        run([str(cli), "test", str(archive)])
        extracted = work / "extracted"
        run([str(cli), "extract", "-o", str(extracted), str(archive)])
        run([*scanner, str(extracted)])
        actual = set()
        directories = {name, f"{name}/assets", f"{name}/docs"}
        for target in extracted.rglob("*"):
            relative = target.relative_to(extracted).as_posix()
            require(not target.is_symlink(), "symlink in extracted portable GUI")
            if target.is_dir():
                require(relative in directories, "unexpected extracted directory")
            else:
                require(target.is_file(), "special file in extracted portable GUI")
                actual.add(relative)
        require(actual == expected, "extracted portable GUI member allowlist mismatch")
        for member, source_name in payload.items():
            require((extracted / name / member).read_bytes() == (repo / source_name).read_bytes(),
                    f"extracted payload differs from source: {member}")

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = work / checksum_out.name
        checksum.write_text(f"{digest}  {archive_out.name}\n")
        require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
                "the build host must support safe directory descriptors")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        dist_fd = os.open(dist, directory_flags)
        extracted_fd = None
        try:
            # Hard links create new exact targets and fail on a concurrent collision.
            # Directory descriptors prevent a replaced parent symlink from
            # redirecting publication into an unrelated directory.
            os.link(archive, archive_out.name, dst_dir_fd=dist_fd, follow_symlinks=False)
            os.link(checksum, checksum_out.name, dst_dir_fd=dist_fd, follow_symlinks=False)
            os.mkdir(extracted_out.name, mode=0o700, dir_fd=dist_fd)
            extracted_fd = os.open(extracted_out.name, directory_flags, dir_fd=dist_fd)
            os.rename(extracted / name, name, dst_dir_fd=extracted_fd)
            require(os.path.samestat(os.fstat(extracted_fd),
                    os.stat(extracted_out.name, dir_fd=dist_fd, follow_symlinks=False)),
                    "extracted output directory changed; partial outputs retained")
            require(os.path.samestat(os.fstat(dist_fd),
                    os.stat(dist, follow_symlinks=False)),
                    "output parent directory changed; partial outputs retained")
        except OSError as error:
            # Another process may have replaced a newly created output. Never
            # delete final paths by name; retain partial outputs for inspection.
            raise ValueError("publication failed; partial outputs retained for inspection") from error
        finally:
            if extracted_fd is not None:
                os.close(extracted_fd)
            os.close(dist_fd)
    print(f"PASS: portable GUI {archive_out}")
    print(f"SHA256: {digest}")
    print(f"EXTRACTED_DIR: {extracted_out / name}")


try:
    main()
except (OSError, ValueError, subprocess.SubprocessError) as error:
    print(f"FAIL: portable GUI: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
