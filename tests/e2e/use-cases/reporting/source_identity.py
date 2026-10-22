#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any


SOURCE_TREE_DIGEST_ALGORITHM = "splendor-e2e-source-tree-v1"
SOURCE_TREE_DIGEST_ENV = "SPLENDOR_E2E_SOURCE_TREE_DIGEST"
SOURCE_REVISION_ENV = "SPLENDOR_E2E_SOURCE_REV"
UNKNOWN_SOURCE_REVISION = "unknown-source-revision"
UNKNOWN_SOURCE_TREE_DIGEST = "unknown-source-tree-digest"
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "--literal-pathspecs", "-c", "core.quotePath=false", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _nul_paths(raw: bytes) -> list[bytes]:
    return sorted({path for path in raw.split(b"\0") if path})


def _hash_field(digest: Any, label: bytes, value: bytes) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _new_digest(head_revision: str) -> Any:
    digest = hashlib.sha256()
    _hash_field(digest, b"domain", SOURCE_TREE_DIGEST_ALGORITHM.encode("ascii"))
    _hash_field(digest, b"head", head_revision.encode("utf-8"))
    return digest


def _hash_entry(
    digest: Any,
    *,
    category: bytes,
    path: bytes,
    kind: bytes,
    mode: bytes,
    contents: bytes,
) -> None:
    _hash_field(digest, b"entry", category)
    _hash_field(digest, b"path", path)
    _hash_field(digest, b"kind", kind)
    _hash_field(digest, b"mode", mode)
    _hash_field(digest, b"contents", contents)


def clean_source_tree_digest(head_revision: str) -> str:
    return "sha256:" + _new_digest(head_revision).hexdigest()


def _hash_index_entry(digest: Any, root: Path, path: bytes) -> None:
    raw = _git(root, "ls-files", "--stage", "-z", "--", os.fsdecode(path))
    records = [record for record in raw.split(b"\0") if record]
    if not records:
        _hash_entry(
            digest,
            category=b"staged",
            path=path,
            kind=b"missing",
            mode=b"",
            contents=b"",
        )
        return
    if len(records) != 1 or b"\t" not in records[0]:
        raise ValueError("ambiguous index entry")
    metadata, recorded_path = records[0].split(b"\t", 1)
    parts = metadata.split()
    if len(parts) != 3 or parts[2] != b"0" or recorded_path != path:
        raise ValueError("unsupported index stage")
    mode, object_id, _ = parts
    object_type = _git(root, "cat-file", "-t", object_id.decode("ascii")).strip()
    if object_type == b"blob":
        contents = _git(root, "cat-file", "blob", object_id.decode("ascii"))
        kind = b"symlink" if mode == b"120000" else b"file"
    elif object_type == b"commit" and mode == b"160000":
        contents = object_id
        kind = b"gitlink"
    else:
        raise ValueError("unsupported index object")
    _hash_entry(
        digest,
        category=b"staged",
        path=path,
        kind=kind,
        mode=mode,
        contents=contents,
    )


def _worktree_entry(root: Path, path: bytes) -> tuple[bytes, bytes, bytes]:
    full_path = os.path.join(os.fsencode(root), path)
    try:
        metadata = os.lstat(full_path)
    except FileNotFoundError:
        return b"missing", b"", b""
    if stat.S_ISLNK(metadata.st_mode):
        return b"symlink", b"120000", os.readlink(full_path)
    if stat.S_ISREG(metadata.st_mode):
        mode = b"100755" if metadata.st_mode & 0o111 else b"100644"
        with open(full_path, "rb") as source:
            return b"file", mode, source.read()
    raise ValueError("unsupported worktree entry")


def _hash_worktree_entry(
    digest: Any,
    root: Path,
    path: bytes,
    category: bytes,
) -> None:
    kind, mode, contents = _worktree_entry(root, path)
    _hash_entry(
        digest,
        category=category,
        path=path,
        kind=kind,
        mode=mode,
        contents=contents,
    )


def _unknown_identity(reason: str) -> dict:
    return {
        "status": "unknown",
        "source": "unknown",
        "head_revision": None,
        "dirty": None,
        "digest": None,
        "digest_algorithm": SOURCE_TREE_DIGEST_ALGORITHM,
        "tracked_change_count": None,
        "staged_change_count": None,
        "unstaged_change_count": None,
        "untracked_file_count": None,
        "reason": reason,
    }


def _environment_identity() -> dict:
    revision = os.environ.get(SOURCE_REVISION_ENV, "").strip()
    digest = os.environ.get(SOURCE_TREE_DIGEST_ENV, "").strip()
    if not revision or revision == UNKNOWN_SOURCE_REVISION:
        return _unknown_identity("source_revision_unavailable")
    if not SHA256_DIGEST_RE.fullmatch(digest):
        reason = (
            "source_tree_digest_override_invalid"
            if digest
            else "source_tree_digest_unavailable"
        )
        return _unknown_identity(reason)
    return {
        "status": "known",
        "source": "environment_override",
        "head_revision": revision,
        "dirty": digest != clean_source_tree_digest(revision),
        "digest": digest,
        "digest_algorithm": SOURCE_TREE_DIGEST_ALGORITHM,
        "tracked_change_count": None,
        "staged_change_count": None,
        "unstaged_change_count": None,
        "untracked_file_count": None,
        "reason": "change_counts_unavailable_from_environment_override",
    }


def source_tree_identity(
    root: Path, *, allow_environment_override: bool = True
) -> dict:
    root = root.resolve()
    git_metadata_available = False
    try:
        top_level = Path(
            os.fsdecode(_git(root, "rev-parse", "--show-toplevel").strip())
        ).resolve()
        if top_level != root:
            raise ValueError("root is not repository top level")
        head_revision = (
            _git(root, "rev-parse", "--verify", "HEAD^{commit}")
            .decode("ascii")
            .strip()
        )
        git_metadata_available = True
        if _git(root, "ls-files", "--unmerged", "-z"):
            raise ValueError("unmerged index")
        staged_paths = _nul_paths(
            _git(
                root,
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "--no-renames",
                "HEAD",
                "--",
            )
        )
        unstaged_paths = _nul_paths(
            _git(root, "diff", "--name-only", "-z", "--no-renames", "--")
        )
        untracked_paths = _nul_paths(
            _git(root, "ls-files", "--others", "--exclude-standard", "-z", "--")
        )

        digest = _new_digest(head_revision)
        for path in staged_paths:
            _hash_index_entry(digest, root, path)
        for path in sorted(set(staged_paths) | set(unstaged_paths)):
            _hash_worktree_entry(digest, root, path, b"tracked-worktree")
        for path in untracked_paths:
            _hash_worktree_entry(digest, root, path, b"untracked")
        return {
            "status": "known",
            "source": "git",
            "head_revision": head_revision,
            "dirty": bool(staged_paths or unstaged_paths or untracked_paths),
            "digest": "sha256:" + digest.hexdigest(),
            "digest_algorithm": SOURCE_TREE_DIGEST_ALGORITHM,
            "tracked_change_count": len(set(staged_paths) | set(unstaged_paths)),
            "staged_change_count": len(staged_paths),
            "unstaged_change_count": len(unstaged_paths),
            "untracked_file_count": len(untracked_paths),
            "reason": None,
        }
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        if allow_environment_override and not git_metadata_available:
            return _environment_identity()
        reason = (
            "git_source_tree_unreadable"
            if git_metadata_available
            else "git_source_identity_unavailable"
        )
        return _unknown_identity(reason)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--digest-only", action="store_true")
    parser.add_argument("--shell-values", action="store_true")
    args = parser.parse_args()
    identity = source_tree_identity(
        Path(args.root), allow_environment_override=False
    )
    if args.shell_values:
        print(
            identity.get("head_revision") or UNKNOWN_SOURCE_REVISION,
            identity.get("digest") or UNKNOWN_SOURCE_TREE_DIGEST,
            sep="\t",
        )
    elif args.digest_only:
        print(identity.get("digest") or UNKNOWN_SOURCE_TREE_DIGEST)
    else:
        import json

        print(json.dumps(identity, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
