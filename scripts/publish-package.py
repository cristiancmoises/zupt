#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
"""Publish validated native packages without replacing existing names.

The caller holds a read-only output-directory descriptor throughout its build.
Source files and their ancestors must be private and stable. The output
directory must be owned by the builder and not writable by group/others.
Ancestors and private staging bindings are trusted: this does not protect
against a malicious process with the same UID or root privileges. Directory
checks are namespace snapshots, not a lock against arbitrary concurrent renames.
Individual links are no-clobber; a batch is not an all-or-nothing transaction.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import os
import re
import secrets
import stat
import sys
from pathlib import Path

MAX_PACKAGE_BYTES = 1 << 30


def check_directory(directory_fd: int, directory: Path) -> None:
    if not all(hasattr(os, flag) for flag in ("O_PATH", "O_DIRECTORY", "O_NOFOLLOW")):
        raise ValueError("Linux path descriptors and no-follow opens are required")
    for operation in (os.open, os.stat, os.link, os.mkdir, os.unlink, os.rmdir):
        if operation not in os.supports_dir_fd:
            raise ValueError("directory-relative filesystem operations are required")
    if not directory.is_absolute() or directory == Path("/") or ".." in directory.parts:
        raise ValueError("output directory must be an absolute non-root path")
    held = os.fstat(directory_fd)
    if not stat.S_ISDIR(held.st_mode):
        raise ValueError("output descriptor is not a directory")
    if held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) & 0o022:
        raise ValueError(
            "output directory must be owned by the builder and not shared-writable"
        )
    # Traversing an ancestor needs search permission, not directory-list access.
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        for component in directory.parts[1:]:
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
        if not os.path.samestat(held, os.fstat(current)):
            raise ValueError("output directory changed since the build began")
    finally:
        os.close(current)


def copy_package(source: Path, stage_fd: int) -> str:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_PACKAGE_BYTES:
            raise ValueError("package source must be regular and at most 1 GiB")
        output_fd = os.open(
            source.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=stage_fd,
        )
        try:
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                block = os.read(source_fd, min(remaining, 1 << 20))
                if not block:
                    raise ValueError("package source was truncated during copying")
                remaining -= len(block)
                digest.update(block)
                pending = memoryview(block)
                while pending:
                    written = os.write(output_fd, pending)
                    if written <= 0:
                        raise OSError(
                            errno.EIO, "package staging write made no progress"
                        )
                    pending = pending[written:]
            if os.read(source_fd, 1):
                raise ValueError("package source grew during copying")
            after = os.fstat(source_fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError("package source changed during copying")
            os.fchmod(output_fd, 0o644)
            os.fsync(output_fd)
            return digest.hexdigest()
        finally:
            os.close(output_fd)
    finally:
        os.close(source_fd)


def check_staging(directory_fd: int, stage_fd: int, stage: str) -> None:
    held = os.fstat(stage_fd)
    named = os.stat(stage, dir_fd=directory_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(held.st_mode)
        or held.st_uid != os.geteuid()
        or stat.S_IMODE(held.st_mode) != 0o700
        or not os.path.samestat(held, named)
    ):
        raise OSError(
            errno.ESTALE, "private staging binding changed; staging retained", stage
        )


def remove_staging(
    directory_fd: int, stage_fd: int, stage: str, names: list[str]
) -> None:
    errors = []
    try:
        check_staging(directory_fd, stage_fd, stage)
    except OSError as error:
        errors.append(error)
    else:
        for name in names:
            try:
                os.unlink(name, dir_fd=stage_fd)
            except FileNotFoundError:
                pass
            except OSError as error:
                errors.append(error)
        try:
            os.rmdir(stage, dir_fd=directory_fd)
        except OSError as error:
            errors.append(error)
    finally:
        if stage_fd >= 0:
            try:
                os.close(stage_fd)
            except OSError as error:
                errors.append(error)
    if errors:
        raise errors[0]


def publish(
    directory_fd: int, directory: Path, artifacts: list[Path]
) -> list[tuple[str, str]]:
    check_directory(directory_fd, directory)
    if not 1 <= len(artifacts) <= 2:
        raise ValueError("expected one package or a binary/source RPM pair")
    names = [artifact.name for artifact in artifacts]
    if len(set(names)) != len(names):
        raise ValueError("duplicate output basenames")
    for artifact in artifacts:
        if (
            not artifact.is_absolute()
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", artifact.name) is None
        ):
            raise ValueError("package sources need absolute paths and safe basenames")
        try:
            os.stat(artifact.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise FileExistsError(
            errno.EEXIST, "refusing to overwrite existing output", artifact.name
        )
    for _ in range(16):
        stage = ".zupt-publish-" + secrets.token_hex(8)
        try:
            os.mkdir(stage, 0o700, dir_fd=directory_fd)
            break
        except FileExistsError:
            continue
    else:
        raise FileExistsError("could not create private package staging directory")
    stage_fd = -1
    failure: Exception | None = None
    results = []
    try:
        stage_fd = os.open(
            stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd
        )
        check_staging(directory_fd, stage_fd, stage)
        for artifact in artifacts:
            results.append((copy_package(artifact, stage_fd), artifact.name))
        check_directory(directory_fd, directory)
        for name in names:
            os.link(
                name,
                name,
                src_dir_fd=stage_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        check_directory(directory_fd, directory)
    except (OSError, ValueError) as error:
        failure = error
    finally:
        try:
            # Only private staging entries are removed. Published names may
            # have been replaced and must never be rolled back by pathname.
            remove_staging(directory_fd, stage_fd, stage, names)
        except OSError as error:
            if failure is None:
                failure = error
            else:
                print(
                    f"WARNING: package staging cleanup failed: {error}", file=sys.stderr
                )
    if failure is not None:
        raise failure
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-directory", action="store_true")
    parser.add_argument("directory_fd", type=int)
    parser.add_argument("directory", type=Path)
    parser.add_argument("artifacts", type=Path, nargs="*")
    args = parser.parse_args()
    try:
        if args.check_directory:
            if args.artifacts:
                raise ValueError("directory check does not accept artifacts")
            check_directory(args.directory_fd, args.directory)
        else:
            for digest, name in publish(
                args.directory_fd, args.directory, args.artifacts
            ):
                output = str(args.directory / name)
                escaped = "\\" in output or "\n" in output
                output = output.replace("\\", "\\\\").replace("\n", "\\n")
                prefix = "\\" if escaped else ""
                print(f"{prefix}{digest}  {output}")
    except (OSError, ValueError) as error:
        print(
            f"FAIL: package publication: {error}; any published outputs are retained for inspection",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
