"""Race-aware repository enumeration and nonblocking regular-file reads."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path, PurePosixPath

from .model import (
    HARD_GIT_TIMEOUT_SECONDS,
    Finding,
    ScanDataError,
    safe_policy_path,
)


def ensure_no_symlink_ancestry(repo_root: Path, relative: str) -> Path:
    if not safe_policy_path(relative):
        raise ScanDataError("SCN003_PATH_AMBIGUOUS")
    current = repo_root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
    try:
        resolved = current.resolve(strict=True)
        root_resolved = repo_root.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise ScanDataError("SCN003_PATH_AMBIGUOUS") from exc
    return current


def safe_read_file(repo_root: Path, relative: str, maximum: int) -> bytes:
    path = ensure_no_symlink_ancestry(repo_root, relative)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
    try:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
        if not stat.S_ISREG(info.st_mode):
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
        if info.st_size > maximum:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            try:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
            except OSError as exc:
                raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        return data
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def enumerate_repository_files(repo_root: Path) -> tuple[list[str], list[Finding]]:
    command = [
        "git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=HARD_GIT_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    if completed.returncode != 0:
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    try:
        values = completed.stdout.decode("utf-8").split("\x00")
    except UnicodeDecodeError:
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    files = sorted(value for value in values if value)
    if len(files) != len(set(files)) or any(
        not safe_policy_path(value) for value in files
    ):
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    return files, []
