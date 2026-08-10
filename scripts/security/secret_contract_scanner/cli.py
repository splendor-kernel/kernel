"""Command-line boundary for the C03 repository scanner."""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Sequence

from .engine import scan_repository
from .io_utils import GitObjectRepository, PinnedRepository
from .model import DEFAULT_POLICY_PATH, Finding, ScanDataError
from .policy import load_policy
from .self_test import run_self_test


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check C03 contracts/fixtures and repository content for raw secret material."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
        help="Repository root (default: inferred from this script).",
    )
    parser.add_argument(
        "--git-tree",
        metavar="COMMIT_SHA",
        help="Scan immutable blobs from one exact full Git commit instead of checkout bytes.",
    )
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY_PATH,
        help=f"Repository-relative policy path (default: {DEFAULT_POLICY_PATH}).",
    )
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        help="Scan one repository-relative path instead of normal repository mode; repeatable.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run deterministic independent positive and negative tests.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.git_tree and args.paths:
        print(Finding(".", 0, "SCN003_PATH_AMBIGUOUS").render(), file=sys.stderr)
        return 1
    try:
        repository_context: GitObjectRepository | PinnedRepository
        repository_context = (
            GitObjectRepository(args.repo_root, args.git_tree)
            if args.git_tree
            else PinnedRepository(args.repo_root)
        )
        with repository_context as repository:
            policy, policy_findings = load_policy(
                repository,
                args.policy,
                today=dt.datetime.now(dt.timezone.utc).date(),
            )
            if policy is None:
                for finding in policy_findings:
                    print(finding.render(), file=sys.stderr)
                return 1
            findings, stats = scan_repository(
                repository, policy, explicit_paths=args.paths
            )
    except ScanDataError as exc:
        findings = [Finding(".", exc.line, exc.code)]
        stats = None
    except (
        OSError,
        ValueError,
        TypeError,
        UnicodeError,
        OverflowError,
        RecursionError,
    ):
        findings = [Finding(".", 0, "SCN003_PATH_AMBIGUOUS")]
        stats = None
    if findings:
        print(
            f"C03 secret contract scan: FAIL ({len(findings)} finding(s))",
            file=sys.stderr,
        )
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        return 1
    assert stats is not None
    print(
        "C03 secret contract scan: PASS "
        f"(governed_files={stats.governed_files}, content_files={stats.content_files}, "
        f"archive_members={stats.archive_members}, bytes_worked={stats.bytes_worked}, "
        f"parser_operations={stats.parser_operations}, "
        f"structural_exceptions={stats.structural_exceptions}, "
        f"content_allowlists={stats.content_allowlists})"
    )
    return 0
