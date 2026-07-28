"""Closed self-protection checks for CI, build, and publication workflows."""

from __future__ import annotations

import hashlib
import re
from collections import Counter

SCANNER_COMMANDS = (
    '/usr/bin/python3 -I scripts/security/check-secret-contracts.py --git-tree "${GITHUB_SHA}"',
    'sandbox="$(mktemp -d)"',
    "trap 'rm -rf \"${sandbox}\"' EXIT",
    'git archive "${GITHUB_SHA}" | tar -x -C "${sandbox}"',
    "(",
    'cd "${sandbox}"',
    'env -i HOME="${sandbox}" PATH="/usr/bin:/bin" /usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test',
    ")",
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
    ]: "c6f8e847ed014e8fecc69f0cbb876da075658ffc827a7b40eecb8dc88ea5c07b",
    REQUIRED_WORKFLOWS[
        1
    ]: "7b1de900391bebe8ca66e0588d33486718d6ab722dcf233ccc181ce3ee93fea4",
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
        "verify-smoke": {"secret-contracts", "smoke"},
        "publish-platform": {"secret-contracts", "smoke", "verify-smoke"},
        "publish-manifest": {"secret-contracts", "publish-platform"},
    },
}
EXPECTED_ACTIONS = {
    REQUIRED_WORKFLOWS[0]: Counter(
        {
            "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020": 1,
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065": 1,
        }
    ),
    REQUIRED_WORKFLOWS[1]: Counter(
        {
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093": 3,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02": 2,
            "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8": 1,
            "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9": 2,
            "docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051": 1,
            "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f": 2,
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
    if _top_level_section(text, "permissions") != "permissions:\n  contents: read":
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
    if any(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) is None for action in actions):
        return False
    if path == REQUIRED_WORKFLOWS[1] and (
        text.count("GITHUB_REF_PROTECTED") != 4
        or text.count("sha256sum --check") != 2
        or text.count("docker load --input image.tar") != 3
        or text.count("    environment: ghcr-release\n") != 2
        or text.count("outputs: type=docker,dest=") != 1
        or text.count("bash scripts/container-tests.sh") != 1
        or "published manifest children differ from tested digests" not in text
        or "docker/build-push-action@" in blocks["publish-platform"]
        or "bash scripts/container-tests.sh" in blocks["smoke"]
        or "bash scripts/container-tests.sh" not in blocks["verify-smoke"]
        or "actions/upload-artifact@" not in blocks["smoke"]
        or "actions/upload-artifact@" in blocks["verify-smoke"]
    ):
        return False
    for job, block in blocks.items():
        dependencies = _needs(block)
        if dependencies is None or dependencies != expected[job]:
            return False
        if job != "secret-contracts" and "secret-contracts" not in dependencies:
            return False
        if_lines = re.findall(r"(?m)^    if:\s*(.*?)\s*$", block)
        required_release_guard = path == REQUIRED_WORKFLOWS[1] and job in {
            "publish-platform",
            "publish-manifest",
        }
        if if_lines != (
            ["github.ref_protected == true"] if required_release_guard else []
        ):
            return False
        if required_release_guard and (
            "    environment: ghcr-release\n" not in block
            or "      packages: write\n" not in block
            or "GITHUB_REF_PROTECTED" not in block
        ):
            return False
        if not required_release_guard and "      packages: write\n" in block:
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
    if secret.index(SCANNER_COMMANDS[0]) > secret.index("--self-test"):
        return False
    timeout = re.search(r"(?m)^    timeout-minutes:\s*([0-9]+)\s*$", secret)
    return timeout is not None and int(timeout.group(1)) == 5
