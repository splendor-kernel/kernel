"""Descriptor-relative repository enumeration and race-closed file reads."""

from __future__ import annotations

import os
import re
import selectors
import stat
import subprocess
import time
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Protocol, runtime_checkable

from .model import (
    HARD_GIT_TIMEOUT_SECONDS,
    HARD_MAX_FILES,
    Finding,
    ScanDataError,
    safe_policy_path,
)


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _close(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


@runtime_checkable
class RepositoryReader(Protocol):
    """Minimal immutable-or-pinned repository view used by the scanner."""

    path: Path

    def assert_identity(self) -> None: ...

    def read_file(self, relative: str, maximum: int) -> bytes: ...


class PinnedRepository:
    """A canonical root held through a no-follow descriptor ancestry."""

    def __init__(self, repo_root: Path):
        try:
            canonical = repo_root.resolve(strict=True)
        except OSError as exc:
            raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
        if not canonical.is_absolute():
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
        self.path = canonical
        self._chain: list[tuple[int, str, int, tuple[int, int, int]]] = []
        self._descriptors: list[int] = []
        try:
            parent = os.open(os.sep, _directory_flags())
            self._descriptors.append(parent)
            parts = canonical.parts[1:]
            for part in parts:
                child = os.open(part, _directory_flags(), dir_fd=parent)
                self._descriptors.append(child)
                info = os.fstat(child)
                linked = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or _identity(info) != _identity(
                    linked
                ):
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
                self._chain.append((parent, part, child, _identity(info)))
                parent = child
            self.root_fd = parent
            self.assert_identity()
        except ScanDataError:
            self.close()
            raise
        except OSError as exc:
            self.close()
            raise ScanDataError("SCN003_PATH_AMBIGUOUS") from exc

    def __enter__(self) -> PinnedRepository:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        for descriptor in reversed(getattr(self, "_descriptors", [])):
            _close(descriptor)
        self._descriptors = []

    def assert_identity(self) -> None:
        try:
            for parent, part, child, expected in self._chain:
                linked = os.stat(part, dir_fd=parent, follow_symlinks=False)
                current = os.fstat(child)
                if _identity(linked) != expected or _identity(current) != expected:
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
        except ScanDataError:
            raise
        except OSError as exc:
            raise ScanDataError("SCN003_PATH_AMBIGUOUS") from exc

    def read_file(self, relative: str, maximum: int) -> bytes:
        if not safe_policy_path(relative):
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
        self.assert_identity()
        opened: list[tuple[int, str, int, tuple[int, int, int]]] = []
        descriptor = -1
        parent = self.root_fd
        parts = PurePosixPath(relative).parts
        try:
            for part in parts[:-1]:
                child = os.open(part, _directory_flags(), dir_fd=parent)
                info = os.fstat(child)
                linked = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or _identity(info) != _identity(
                    linked
                ):
                    _close(child)
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
                opened.append((parent, part, child, _identity(info)))
                parent = child

            final_name = parts[-1]
            linked_before = os.stat(final_name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(linked_before.st_mode):
                raise ScanDataError("SCN003_PATH_AMBIGUOUS")
            descriptor = os.open(final_name, _file_flags(), dir_fd=parent)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(
                linked_before
            ):
                raise ScanDataError("SCN003_PATH_AMBIGUOUS")
            if before.st_size < 0 or before.st_size > maximum:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")

            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > maximum:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")

            after = os.fstat(descriptor)
            linked_after = os.stat(final_name, dir_fd=parent, follow_symlinks=False)
            if (
                _file_identity(before) != _file_identity(after)
                or _identity(after) != _identity(linked_after)
                or len(data) != after.st_size
            ):
                raise ScanDataError("SCN003_PATH_AMBIGUOUS")
            for ancestor_parent, part, child, expected in opened:
                linked = os.stat(part, dir_fd=ancestor_parent, follow_symlinks=False)
                if (
                    _identity(linked) != expected
                    or _identity(os.fstat(child)) != expected
                ):
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
            self.assert_identity()
            return data
        except ScanDataError:
            raise
        except FileNotFoundError as exc:
            raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
        except OSError as exc:
            raise ScanDataError("SCN003_PATH_AMBIGUOUS") from exc
        finally:
            if descriptor >= 0:
                _close(descriptor)
            for _ancestor_parent, _part, child, _expected in reversed(opened):
                _close(child)


class GitObjectRepository:
    """Read one exact commit tree from immutable Git blob identities.

    Candidate self-tests never participate in this view.  Paths and blob object
    IDs are captured from one full commit before any blob is read, and symlinks,
    submodules, sparse worktree state, and untracked checkout bytes are excluded.
    """

    def __init__(self, repo_root: Path, revision: str):
        if re.fullmatch(r"[0-9a-f]{40,64}", revision) is None:
            raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
        self._repository = PinnedRepository(repo_root)
        self.path = self._repository.path
        self.revision = revision
        self._blobs: dict[str, tuple[str, int]] = {}
        try:
            resolved = (
                self._git_output(
                    ["rev-parse", "--verify", f"{revision}^{{commit}}"],
                    maximum=128,
                )
                .decode("ascii")
                .strip()
            )
            if resolved != revision:
                raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
            tree = self._git_output(
                ["ls-tree", "-r", "-z", "-l", "--full-tree", revision],
                maximum=4097 * (HARD_MAX_FILES + 1),
            )
            records = tree.split(b"\x00")
            if records[-1:] != [b""]:
                raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
            for record in records[:-1]:
                metadata, separator, raw_path = record.partition(b"\t")
                fields = metadata.split()
                if separator != b"\t" or len(fields) != 4:
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
                mode, object_type, raw_oid, raw_size = fields
                if mode not in {b"100644", b"100755"} or object_type != b"blob":
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
                try:
                    path = raw_path.decode("utf-8")
                    oid = raw_oid.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE") from exc
                if (
                    not safe_policy_path(path)
                    or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
                    or path in self._blobs
                    or len(self._blobs) >= HARD_MAX_FILES
                ):
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
                try:
                    size = int(raw_size.decode("ascii"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE") from exc
                if size < 0:
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
                self._blobs[path] = (oid, size)
            if not self._blobs:
                raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
            self.assert_identity()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> GitObjectRepository:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        repository = getattr(self, "_repository", None)
        if repository is not None:
            repository.close()

    def assert_identity(self) -> None:
        self._repository.assert_identity()

    def list_files(self, *, max_files: int) -> tuple[list[str], list[Finding]]:
        if max_files <= 0 or max_files > HARD_MAX_FILES or len(self._blobs) > max_files:
            return [], [Finding(".", 0, "SCN005_BUDGET_EXCEEDED")]
        self.assert_identity()
        return sorted(self._blobs), []

    def read_file(self, relative: str, maximum: int) -> bytes:
        if not safe_policy_path(relative):
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
        entry = self._blobs.get(relative)
        if entry is None:
            raise ScanDataError("SCN002_PATH_UNAVAILABLE")
        oid, size = entry
        if size > maximum:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        data = self._git_output(["cat-file", "blob", oid], maximum=maximum + 1)
        if len(data) != size or len(data) > maximum:
            raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
        self.assert_identity()
        return data

    def _git_output(self, arguments: list[str], *, maximum: int) -> bytes:
        if maximum < 0:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")

        def enter_pinned_root() -> None:
            os.fchdir(self._repository.root_fd)

        process: subprocess.Popen[bytes] | None = None
        try:
            self._repository.assert_identity()
            process = subprocess.Popen(
                ["git", *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(self._repository.root_fd,),
                preexec_fn=enter_pinned_root,
            )
            if process.stdout is None:
                raise OSError
            chunks: list[bytes] = []
            remaining = maximum + 1
            deadline = time.monotonic() + HARD_GIT_TIMEOUT_SECONDS
            while remaining > 0:
                if time.monotonic() > deadline:
                    raise subprocess.TimeoutExpired(arguments, HARD_GIT_TIMEOUT_SECONDS)
                chunk = process.stdout.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > maximum:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
            if process.returncode != 0:
                raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
            self._repository.assert_identity()
            return data
        except ScanDataError:
            raise
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE") from exc
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if process is not None and process.stdout is not None:
                process.stdout.close()


def safe_read_file(
    repo_root: Path | RepositoryReader, relative: str, maximum: int
) -> bytes:
    if isinstance(repo_root, RepositoryReader):
        return repo_root.read_file(relative, maximum)
    with PinnedRepository(repo_root) as repository:
        return repository.read_file(relative, maximum)


def _bounded_git_paths(
    repository: PinnedRepository, *, max_files: int
) -> tuple[list[str], list[Finding]]:
    if max_files <= 0 or max_files > HARD_MAX_FILES:
        return [], [Finding(".", 0, "SCN005_BUDGET_EXCEEDED")]
    command = [
        "git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    ]
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        repository.assert_identity()

        def enter_pinned_root() -> None:
            os.fchdir(repository.root_fd)

        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(repository.root_fd,),
            preexec_fn=enter_pinned_root,
        )
        if process.stdout is None:
            raise OSError
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + HARD_GIT_TIMEOUT_SECONDS
        pending = bytearray()
        paths: list[str] = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, HARD_GIT_TIMEOUT_SECONDS)
            events = selector.select(min(remaining, 0.1))
            if not events:
                continue
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if not chunk:
                break
            pending.extend(chunk)
            if len(pending) > 4097 * (max_files + 1):
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            while b"\x00" in pending:
                raw, _, rest = pending.partition(b"\x00")
                pending = bytearray(rest)
                if len(raw) > 4096 or len(paths) >= max_files:
                    raise ScanDataError("SCN005_BUDGET_EXCEEDED")
                try:
                    value = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE") from exc
                if not value or not safe_policy_path(value):
                    raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
                paths.append(value)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if process.returncode != 0 or pending:
            raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
        if len(paths) != len(set(paths)):
            raise ScanDataError("SCN010_REPOSITORY_UNAVAILABLE")
        repository.assert_identity()
        return sorted(paths), []
    except ScanDataError as exc:
        code = exc.code
        if code not in {"SCN005_BUDGET_EXCEEDED", "SCN010_REPOSITORY_UNAVAILABLE"}:
            code = "SCN010_REPOSITORY_UNAVAILABLE"
        return [], [Finding(".", 0, code)]
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process is not None and process.stdout is not None:
            process.stdout.close()


def enumerate_repository_files(
    repo_root: Path | RepositoryReader, *, max_files: int = HARD_MAX_FILES
) -> tuple[list[str], list[Finding]]:
    if isinstance(repo_root, GitObjectRepository):
        return repo_root.list_files(max_files=max_files)
    if isinstance(repo_root, PinnedRepository):
        return _bounded_git_paths(repo_root, max_files=max_files)
    if not isinstance(repo_root, Path):
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    try:
        with PinnedRepository(repo_root) as repository:
            return _bounded_git_paths(repository, max_files=max_files)
    except ScanDataError as exc:
        code = (
            exc.code
            if exc.code in {"SCN005_BUDGET_EXCEEDED", "SCN010_REPOSITORY_UNAVAILABLE"}
            else "SCN010_REPOSITORY_UNAVAILABLE"
        )
        return [], [Finding(".", 0, code)]
