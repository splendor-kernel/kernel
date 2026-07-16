#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import aggregate_report as ar


class SourceTreeIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is required")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.outside_temp_dir = tempfile.TemporaryDirectory()
        self.outside_git = Path(self.outside_temp_dir.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Splendor Test")
        self.git("config", "user.email", "splendor-test@example.invalid")
        (self.root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        (self.root / "tracked.txt").write_text("committed\n", encoding="utf-8")
        self.git("add", ".gitignore", "tracked.txt")
        self.git("commit", "-q", "-m", "initial")

    def tearDown(self) -> None:
        self.outside_temp_dir.cleanup()
        self.temp_dir.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.root, text=True
        ).strip()

    def test_clean_identity_is_deterministic(self) -> None:
        first = ar.source_tree_identity(self.root)
        second = ar.source_tree_identity(self.root)

        self.assertEqual(first, second)
        self.assertEqual("known", first["status"])
        self.assertEqual("git", first["source"])
        self.assertFalse(first["dirty"])
        self.assertEqual(0, first["tracked_change_count"])
        self.assertEqual(0, first["untracked_file_count"])
        self.assertEqual(
            ar.clean_source_tree_digest(first["head_revision"]), first["digest"]
        )

    def test_staged_and_unstaged_contents_both_affect_identity(self) -> None:
        clean = ar.source_tree_identity(self.root)
        (self.root / "tracked.txt").write_text("staged\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        staged = ar.source_tree_identity(self.root)

        (self.root / "tracked.txt").write_text("unstaged-after-stage\n", encoding="utf-8")
        staged_and_unstaged = ar.source_tree_identity(self.root)

        self.assertTrue(staged["dirty"])
        self.assertNotEqual(clean["digest"], staged["digest"])
        self.assertEqual(1, staged["staged_change_count"])
        self.assertEqual(0, staged["unstaged_change_count"])
        self.assertEqual(1, staged_and_unstaged["staged_change_count"])
        self.assertEqual(1, staged_and_unstaged["unstaged_change_count"])
        self.assertEqual(1, staged_and_unstaged["tracked_change_count"])
        self.assertNotEqual(staged["digest"], staged_and_unstaged["digest"])

    def test_untracked_path_and_contents_are_sensitive_but_ignored_files_are_not(
        self,
    ) -> None:
        (self.root / "untracked.txt").write_text("first\n", encoding="utf-8")
        first = ar.source_tree_identity(self.root)
        repeated = ar.source_tree_identity(self.root)

        (self.root / "ignored.txt").write_text("ignored-a\n", encoding="utf-8")
        ignored_changed = ar.source_tree_identity(self.root)
        (self.root / "ignored.txt").write_text("ignored-b\n", encoding="utf-8")
        ignored_changed_again = ar.source_tree_identity(self.root)

        (self.root / "untracked.txt").write_text("second\n", encoding="utf-8")
        content_changed = ar.source_tree_identity(self.root)
        (self.root / "untracked.txt").rename(self.root / "renamed.txt")
        path_changed = ar.source_tree_identity(self.root)

        self.assertEqual(first, repeated)
        self.assertEqual(first, ignored_changed)
        self.assertEqual(ignored_changed, ignored_changed_again)
        self.assertEqual(1, first["untracked_file_count"])
        self.assertNotEqual(first["digest"], content_changed["digest"])
        self.assertNotEqual(content_changed["digest"], path_changed["digest"])

    def test_missing_git_is_unknown_unless_both_container_overrides_exist(self) -> None:
        clean = ar.source_tree_identity(self.root)

        with mock.patch.dict(os.environ, {}, clear=True):
            unknown = ar.source_tree_identity(self.outside_git)
        self.assertEqual("unknown", unknown["status"])
        self.assertIsNone(unknown["dirty"])
        self.assertIsNone(unknown["digest"])

        with mock.patch.dict(
            os.environ,
            {
                "SPLENDOR_E2E_SOURCE_REV": clean["head_revision"],
                "SPLENDOR_E2E_SOURCE_TREE_DIGEST": clean["digest"],
            },
            clear=True,
        ):
            overridden = ar.source_tree_identity(self.outside_git)
        self.assertEqual("known", overridden["status"])
        self.assertEqual("environment_override", overridden["source"])
        self.assertFalse(overridden["dirty"])
        self.assertEqual(clean["digest"], overridden["digest"])


if __name__ == "__main__":
    unittest.main()
