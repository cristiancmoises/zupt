# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Check documentation in a private, quiescent extracted or mounted package tree.

This reads files only. It does not extract archives, qualify a package manager
or defend a directory concurrently modified by another writer. Native Windows
checks normal read/write file mode (0666), not POSIX permissions or NT ACLs.
"""

import argparse
import filecmp
import os
import plistlib
import re
import stat
import sys
from pathlib import Path
from xml.parsers.expat import ExpatError

# The runtime also exposes this Windows constant on POSIX package-checking hosts.
FILE_ATTRIBUTE_REPARSE_POINT = vars(stat)["FILE_ATTRIBUTE_REPARSE_POINT"]


def directory(root: Path, relative: Path, windows: bool = False) -> bool:
    current = root
    for part in (".", *relative.parts):
        current = current / part
        try:
            info = current.lstat()
            mode = info.st_mode
        except FileNotFoundError:
            return False
        if (
            windows
            and getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError(f"reparse documentation directory: {current}")
        if not stat.S_ISDIR(mode):
            raise ValueError(f"not a non-symlink directory: {current}")
    return True


def document(
    root: Path, relative: str, installed: bool = False, windows: bool = False
) -> Path:
    path = Path(relative)
    if not directory(root, path.parent, windows=windows):
        raise ValueError(f"missing documentation directory: {path.parent}")
    target = root / path
    info = target.lstat()
    mode = info.st_mode
    if (
        windows
        and getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"reparse document: {relative}")
    if not stat.S_ISREG(mode):
        raise ValueError(f"not a regular non-symlink document: {relative}")
    expected_mode = 0o666 if windows and os.name == "nt" else 0o644
    if installed and stat.S_IMODE(mode) != expected_mode:
        raise ValueError(f"incorrect installed document mode: {relative}")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("extracted", type=Path)
    parser.add_argument("package", choices=("zupt", "zupt-gui", "windows", "macos"))
    args = parser.parse_args()
    windows = args.package == "windows"
    try:
        header = document(args.source, "include/zupt.h", windows=windows).read_text(
            encoding="utf-8"
        )
        versions = re.findall(
            r'^#define ZUPT_VERSION_STRING "([0-9]+\.[0-9]+\.[0-9]+)"$',
            header,
            re.MULTILINE,
        )
        if len(versions) != 1:
            raise ValueError("expected exactly one source version")
        if windows:
            matches = [Path(f"zupt-{versions[0]}-windows-x86_64")]
        elif args.package == "macos":
            matches = [Path("."), Path("ZUPT.app/Contents/Resources")]
            info = document(args.extracted, "ZUPT.app/Contents/Info.plist")
            metadata = plistlib.loads(info.read_bytes())
            if not isinstance(metadata, dict) or any(
                metadata.get(key) != versions[0]
                for key in ("CFBundleVersion", "CFBundleShortVersionString")
            ):
                raise ValueError("macOS bundle version differs from source")
        else:
            # Native RPM policies may use a versioned name or doc/packages.
            candidates = [
                Path(prefix) / name
                for prefix in ("usr/share/doc", "usr/share/doc/packages")
                for name in (args.package, f"{args.package}-{versions[0]}")
            ]
            matches = [path for path in candidates if directory(args.extracted, path)]
            if len(matches) != 1:
                raise ValueError(
                    f"expected one package documentation directory, found {len(matches)}"
                )
        for location in matches:
            for relative in (
                "docs/USER_GUIDE.md",
                "docs/GUIA_USUARIO.pt-BR.md",
                "SECURITY.md",
                "DISTRIBUTION.md",
                "AUDIT.md",
                "INSTALL.md",
                "THREAT_MODEL.md",
            ):
                source = document(args.source, relative, windows=windows)
                target = document(
                    args.extracted,
                    str(location / relative),
                    installed=True,
                    windows=windows,
                )
                if not filecmp.cmp(source, target, shallow=False):
                    raise ValueError(
                        f"installed document differs from source: {relative}"
                    )
    except (OSError, ValueError, ExpatError) as error:
        print(f"FAIL: installed documentation: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {args.package} installed bilingual documentation and policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
