# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Check documentation in a private, quiescent extracted DEB/RPM tree.

This reads files only. It does not extract archives, qualify a package manager
or defend a directory concurrently modified by another writer.
"""

import argparse
import filecmp
import re
import stat
import sys
from pathlib import Path


def directory(root: Path, relative: Path) -> bool:
    current = root
    for part in (".", *relative.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(mode):
            raise ValueError(f"not a non-symlink directory: {current}")
    return True


def document(root: Path, relative: str, installed: bool = False) -> Path:
    path = Path(relative)
    if not directory(root, path.parent):
        raise ValueError(f"missing documentation directory: {path.parent}")
    target = root / path
    mode = target.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"not a regular non-symlink document: {relative}")
    if installed and stat.S_IMODE(mode) != 0o644:
        raise ValueError(f"incorrect installed document mode: {relative}")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("extracted", type=Path)
    parser.add_argument("package", choices=("zupt", "zupt-gui"))
    args = parser.parse_args()
    try:
        header = document(args.source, "include/zupt.h").read_text(encoding="utf-8")
        versions = re.findall(
            r'^#define ZUPT_VERSION_STRING "([0-9]+\.[0-9]+\.[0-9]+)"$',
            header,
            re.MULTILINE,
        )
        if len(versions) != 1:
            raise ValueError("expected exactly one source version")
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
        for relative in (
            "docs/USER_GUIDE.md",
            "docs/GUIA_USUARIO.pt-BR.md",
            "SECURITY.md",
            "DISTRIBUTION.md",
        ):
            source = document(args.source, relative)
            target = document(
                args.extracted, str(matches[0] / relative), installed=True
            )
            if not filecmp.cmp(source, target, shallow=False):
                raise ValueError(f"installed document differs from source: {relative}")
    except (OSError, ValueError) as error:
        print(f"FAIL: installed documentation: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {args.package} installed bilingual documentation and policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
