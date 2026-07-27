"""Self-protection checks for CI and release scanner dependencies."""

from __future__ import annotations

import re

SCANNER_COMMANDS = (
    "python3 scripts/security/check-secret-contracts.py --self-test",
    "python3 scripts/security/check-secret-contracts.py",
)
REQUIRED_WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/docker-image.yml",
)


def _job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines()
    jobs_index = next(
        (index for index, line in enumerate(lines) if line.rstrip() == "jobs:"), None
    )
    if jobs_index is None:
        return {}
    starts: list[tuple[str, int]] = []
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if match:
            starts.append((match.group(1), index))
        elif line and not line.startswith(" "):
            break
    result: dict[str, str] = {}
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        result[name] = "\n".join(lines[start:end])
    return result


def _needs(block: str) -> set[str]:
    direct = re.search(r"(?m)^    needs:\s*([A-Za-z0-9_-]+)\s*$", block)
    if direct:
        return {direct.group(1)}
    inline = re.search(r"(?m)^    needs:\s*\[([^]]+)]\s*$", block)
    if inline:
        return {
            token.strip().strip("'\"")
            for token in inline.group(1).split(",")
            if token.strip()
        }
    list_match = re.search(r"(?ms)^    needs:\s*\n((?:      - [^\n]+\n?)+)", block)
    if list_match:
        return {
            line.split("-", 1)[1].strip().strip("'\"")
            for line in list_match.group(1).splitlines()
        }
    return set()


def _depends_on_secret(
    job: str, blocks: dict[str, str], visiting: set[str] | None = None
) -> bool:
    if job == "secret-contracts":
        return True
    visiting = set() if visiting is None else set(visiting)
    if job in visiting:
        return False
    visiting.add(job)
    dependencies = _needs(blocks.get(job, ""))
    return bool(dependencies) and all(
        dependency in blocks and _depends_on_secret(dependency, blocks, visiting)
        for dependency in dependencies
    )


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


def validate_workflow_text(path: str, text: str) -> bool:
    blocks = _job_blocks(text)
    secret = blocks.get("secret-contracts")
    if secret is None:
        return False
    if list(SCANNER_COMMANDS) not in _run_blocks(secret):
        return False
    if re.search(r"(?m)^\s+(?:continue-on-error|if):", secret):
        return False
    timeout = re.search(r"(?m)^    timeout-minutes:\s*([0-9]+)\s*$", secret)
    if timeout is None or int(timeout.group(1)) != 5:
        return False
    if path not in REQUIRED_WORKFLOWS:
        return False
    status_override = re.compile(r"(?im)^    if:.*\b(?:always|failure|cancelled)\s*\(")
    return all(
        _depends_on_secret(job, blocks)
        and (job == "secret-contracts" or not status_override.search(block))
        for job, block in blocks.items()
    )
