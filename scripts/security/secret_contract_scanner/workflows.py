"""Closed self-protection checks for CI, build, and publication workflows."""

from __future__ import annotations

import hashlib
import re
from collections import Counter

SCANNER_COMMANDS = (
    "/usr/bin/python3 scripts/security/check-secret-contracts.py --self-test",
    "/usr/bin/python3 scripts/security/check-secret-contracts.py",
)
CHECKOUT_COMMANDS = (
    "git init .",
    'git remote add origin "https://github.com/${GITHUB_REPOSITORY}.git"',
    'git fetch --no-tags --depth=1 origin "${GITHUB_SHA}"',
    'git checkout --detach "${GITHUB_SHA}"',
    'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"',
    'git config --global --add safe.directory "${GITHUB_WORKSPACE}"',
)
REQUIRED_WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/docker-image.yml",
)
EXPECTED_WORKFLOW_SHA256 = {
    REQUIRED_WORKFLOWS[
        0
    ]: "71fec9c94125b3bc1da077fa3c40501117f174de669ca69de4621b9a2cded728",
    REQUIRED_WORKFLOWS[
        1
    ]: "c8884d0634eea70136d8c0c3173e8c0341fd26da3b0c472d863fb6d72cfc85c8",
}
EXPECTED_JOBS = {
    REQUIRED_WORKFLOWS[0]: {
        "secret-contracts": set(),
        "rust": {"secret-contracts"},
        "python": {"secret-contracts"},
        "typescript": {"secret-contracts"},
        "docker": {"secret-contracts"},
    },
    REQUIRED_WORKFLOWS[1]: {
        "secret-contracts": set(),
        "smoke": {"secret-contracts"},
        "publish-platform": {"secret-contracts", "smoke"},
        "publish-manifest": {"secret-contracts", "publish-platform"},
    },
}
EXPECTED_ACTIONS = {
    REQUIRED_WORKFLOWS[0]: Counter(
        {
            "actions/setup-node@v4": 1,
            "actions/setup-python@v5": 1,
        }
    ),
    REQUIRED_WORKFLOWS[1]: Counter(
        {
            "actions/download-artifact@v4": 1,
            "actions/upload-artifact@v4": 1,
            "docker/build-push-action@v6": 2,
            "docker/login-action@v3": 2,
            "docker/metadata-action@v5": 3,
            "docker/setup-buildx-action@v3": 3,
        }
    ),
}


def _top_level_section(text: str, name: str) -> str | None:
    lines = text.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line == f"{name}:"), None
    )
    if start is None:
        return None
    end = start + 1
    while end < len(lines) and (not lines[end] or lines[end].startswith(" ")):
        end += 1
    return "\n".join(lines[start:end]).rstrip()


def _job_blocks(text: str) -> dict[str, str] | None:
    lines = text.splitlines()
    jobs_index = next(
        (index for index, line in enumerate(lines) if line == "jobs:"), None
    )
    if jobs_index is None:
        return None
    starts: list[tuple[str, int]] = []
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        if not line.startswith("  ") or line.startswith("    ") or not line.strip():
            continue
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if match is None:
            return None
        starts.append((match.group(1), index))
    result: dict[str, str] = {}
    for position, (name, start) in enumerate(starts):
        if name in result:
            return None
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        result[name] = "\n".join(lines[start:end])
    return result


def _needs(block: str) -> set[str] | None:
    direct = re.search(r"(?m)^    needs:\s*([A-Za-z0-9_-]+)\s*$", block)
    if direct:
        return {direct.group(1)}
    inline = re.search(r"(?m)^    needs:\s*\[([^]]+)]\s*$", block)
    if inline:
        values = {
            token.strip().strip("'\"")
            for token in inline.group(1).split(",")
            if token.strip()
        }
        return (
            values
            if all(re.fullmatch(r"[A-Za-z0-9_-]+", value) for value in values)
            else None
        )
    list_match = re.search(r"(?ms)^    needs:\s*\n((?:      - [^\n]+\n?)+)", block)
    if list_match:
        values = {
            line.split("-", 1)[1].strip().strip("'\"")
            for line in list_match.group(1).splitlines()
        }
        return (
            values
            if all(re.fullmatch(r"[A-Za-z0-9_-]+", value) for value in values)
            else None
        )
    return set()


def _run_blocks(block: str) -> list[list[str]]:
    lines = block.splitlines()
    result: list[list[str]] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != "run: |":
            index += 1
            continue
        indent = len(lines[index]) - len(lines[index].lstrip(" "))
        index += 1
        commands: list[str] = []
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip(" ")) <= indent:
                break
            if line.strip():
                commands.append(line.strip())
            index += 1
        result.append(commands)
    return result


def _valid_triggers(path: str, text: str) -> bool:
    section = _top_level_section(text, "on")
    if section is None or re.search(
        r"(?m)^\s+(?:paths|paths-ignore|branches-ignore):", section
    ):
        return False
    if path == REQUIRED_WORKFLOWS[0]:
        return section == "on:\n  push:\n  pull_request:"
    if path != REQUIRED_WORKFLOWS[1]:
        return False
    return bool(
        re.search(r"(?m)^  push:$", section)
        and re.search(r"(?m)^  workflow_dispatch:$", section)
        and re.search(
            r"(?ms)^    branches:\n      - dev\n      - main(?:\n|$)", section
        )
        and re.search(r'(?ms)^    tags:\n      - "v\*"(?:\n|$)', section)
    )


def validate_workflow_text(path: str, text: str) -> bool:
    expected = EXPECTED_JOBS.get(path)
    if (
        expected is None
        or hashlib.sha256(text.encode("utf-8")).hexdigest()
        != EXPECTED_WORKFLOW_SHA256.get(path)
        or not _valid_triggers(path, text)
    ):
        return False
    if "\t" in text or "\r" in text:
        return False
    forbidden = (
        r"(?m)^defaults:",
        r"(?m)^\s+defaults:",
        r"(?m)^\s+shell:",
        r"(?m)^\s+continue-on-error:",
        r"(?m)^\s+PATH:",
        r"\$GITHUB_PATH\b",
        r"(?m)^\s+- uses:\s*actions/checkout@",
        r"\bGITHUB_REF\b",
        r"\bFETCH_HEAD\b",
        r"(?m)^\s*set\s+\+e\s*$",
        r"\|\|\s*true\b",
        r"(?m)^\s*exit\s+0\s*$",
        r"(?m)^\s+if:\s*.*\b(?:always|failure|cancelled)\s*\(",
    )
    if any(re.search(pattern, text) for pattern in forbidden):
        return False
    blocks = _job_blocks(text)
    if blocks is None or set(blocks) != set(expected):
        return False
    actions = Counter(
        match.group(1)
        for match in re.finditer(r"(?m)^\s+(?:-\s+)?uses:\s*([^\s#]+)\s*$", text)
    )
    if actions != EXPECTED_ACTIONS[path]:
        return False
    for job, block in blocks.items():
        dependencies = _needs(block)
        if dependencies is None or dependencies != expected[job]:
            return False
        if job != "secret-contracts" and "secret-contracts" not in dependencies:
            return False
        if re.search(r"(?m)^    if:", block):
            return False
        run_blocks = _run_blocks(block)
        if any(
            re.search(
                r"\|\||;\s*(?:true|exit\s+0)\s*$|^\s*set\s+\+e\s*$|^\s*trap\b.*\bERR\b",
                command,
            )
            for commands in run_blocks
            for command in commands
        ):
            return False
        if list(CHECKOUT_COMMANDS) not in run_blocks:
            return False
        if sum(commands == list(CHECKOUT_COMMANDS) for commands in run_blocks) != 1:
            return False
        if block.count('git fetch --no-tags --depth=1 origin "${GITHUB_SHA}"') != 1:
            return False
        if block.count('git checkout --detach "${GITHUB_SHA}"') != 1:
            return False
        if block.count('test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"') != 1:
            return False
    secret = blocks["secret-contracts"]
    if list(SCANNER_COMMANDS) not in _run_blocks(secret):
        return False
    if sum(commands == list(SCANNER_COMMANDS) for commands in _run_blocks(secret)) != 1:
        return False
    if re.search(r"(?m)^\s+(?:-\s+)?uses:", secret):
        return False
    timeout = re.search(r"(?m)^    timeout-minutes:\s*([0-9]+)\s*$", secret)
    return timeout is not None and int(timeout.group(1)) == 5
