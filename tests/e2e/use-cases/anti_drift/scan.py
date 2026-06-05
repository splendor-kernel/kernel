#!/usr/bin/env python3
"""Static anti-drift scanner for use-case E2E scenarios.

The scanner is intentionally conservative. It fails closed on private helper
E2E claims, direct adapter execution, anonymous non-dev daemon calls, replay
claims without suppression evidence, undocumented endpoint strings, and allowed
low-level physical actions.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


FORBIDDEN_PHYSICAL = re.compile(
    r"\b(set_motor_pwm|raw actuator|disable_firmware_safety|bypass_collision_avoidance|modify_flight_controller|ignore_emergency_stop|hard_real_time)\b",
    re.IGNORECASE,
)
DIRECT_ADAPTER = re.compile(r"\b(adapter\.execute\(|execute_adapter\(|\.execute\(.*ActionRequest|Adapter::execute)\b", re.DOTALL)
PRIVATE_HELPER = re.compile(r"\b(use\s+splendor_(kernel|gateway|store)::|from\s+splendor\._|private_helper|crate::test_helpers)\b")
ANON_NON_DEV = re.compile(r"\b(non[-_ ]?dev|production|fleet|resident)\b[\s\S]{0,160}\b(anonymous|credential\s*[:=]\s*null|Authorization\s*[:=]\s*['\"]?['\"]?)", re.IGNORECASE)
REPLAY_CLAIM = re.compile(r"\breplay\b[\s\S]{0,120}\b(pass|success|completed|claim)", re.IGNORECASE)
SUPPRESSION = re.compile(r"\b(adapter_suppressed|side_effects_allowed\s*[:=]\s*false|inspect_only|side[-_ ]effect suppression)\b", re.IGNORECASE)
E2E_CLAIM = re.compile(r"\b(E2E|end[- ]to[- ]end|use[- ]case acceptance)\b", re.IGNORECASE)
ENDPOINT = re.compile(r"(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<path>/[A-Za-z0-9_{}:./-]+)")

DOCUMENTED_PATH_PREFIXES = (
    "/health",
    "/version",
    "/capabilities",
    "/runs",
    "/percepts",
    "/actions",
    "/state-head",
    "/state-snapshots",
    "/traces",
    "/replay",
    "/fleet",
    "/work-orders",
    "/messages",
    "/agents",
    "/message-schemas",
    "/policies",
    "/approvals",
    "/governance",
    "/devices",
    "/operator",
)


@dataclass
class Finding:
    rule_id: str
    path: str
    message: str
    severity: str = "blocking"

    def as_dict(self) -> dict[str, str]:
        return self.__dict__.copy()


def scan_file(path: Path, root: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = str(path.relative_to(root))
    findings: list[Finding] = []

    if E2E_CLAIM.search(text) and PRIVATE_HELPER.search(text):
        findings.append(Finding("private_helper_e2e_claim", rel, "E2E claim imports private runtime helper"))
    if DIRECT_ADAPTER.search(text):
        findings.append(Finding("direct_adapter_execution", rel, "Scenario code appears to execute an adapter directly"))
    if ANON_NON_DEV.search(text):
        findings.append(Finding("anonymous_non_dev_daemon_call", rel, "Non-dev/fleet call omits caller identity"))
    if REPLAY_CLAIM.search(text) and not SUPPRESSION.search(text):
        findings.append(Finding("missing_replay_suppression_evidence", rel, "Replay success claim lacks side-effect suppression evidence"))
    if FORBIDDEN_PHYSICAL.search(text) and re.search(r"\b(allowed|allowlist|allowed_physical_actions|capabilities|accepted)\b", text, re.IGNORECASE):
        findings.append(Finding("allowed_low_level_physical_action", rel, "Low-level physical action appears in an allowed list"))
    for match in ENDPOINT.finditer(text):
        path_str = match.group("path")
        if not path_str.startswith(DOCUMENTED_PATH_PREFIXES):
            findings.append(Finding("undocumented_endpoint", rel, f"Endpoint {match.group(0)} is outside documented prefixes"))
    return findings


def scan_paths(paths: list[Path], root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for base in paths:
        if not base.exists():
            continue
        if base.is_file():
            findings.extend(scan_file(base, root))
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".py", ".rs", ".ts", ".js", ".json", ".toml", ".md", ".yaml", ".yml", ".txt"}:
                findings.extend(scan_file(path, root))
    return findings


def run_self_test(root: Path) -> dict[str, object]:
    fixture_root = root / "tests/e2e/use-cases/anti_drift/fixtures"
    negative = sorted((fixture_root / "negative").glob("*"))
    positive = sorted((fixture_root / "positive").glob("*"))
    neg_findings = scan_paths(negative, root)
    pos_findings = scan_paths(positive, root)
    rules_hit = {f.rule_id for f in neg_findings}
    required_rules = {
        "private_helper_e2e_claim",
        "direct_adapter_execution",
        "anonymous_non_dev_daemon_call",
        "missing_replay_suppression_evidence",
        "allowed_low_level_physical_action",
    }
    failures = []
    if pos_findings:
        failures.append("positive anti-drift fixture produced blocking findings")
    missing = sorted(required_rules - rules_hit)
    if missing:
        failures.append(f"negative fixtures did not exercise rules: {', '.join(missing)}")
    return {
        "status": "passed" if not failures else "failed",
        "required_rules": sorted(required_rules),
        "rules_hit_by_negative_fixtures": sorted(rules_hit),
        "positive_fixture_findings": [f.as_dict() for f in pos_findings],
        "negative_fixture_findings": [f.as_dict() for f in neg_findings],
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    scan_targets = [root / "tests/e2e/use-cases/scenarios", root / "tests/e2e/use-cases/fixtures"]
    findings = scan_paths(scan_targets, root)
    self_test = run_self_test(root) if args.self_test else {"status": "not_run"}
    failures = []
    if findings:
        failures.append("scenario/fixture anti-drift findings present")
    if self_test.get("status") == "failed":
        failures.extend(self_test.get("failures", []))

    result = {
        "schema_version": "splendor.e2e.anti-drift-results.v1",
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "passed" if not failures else "failed",
        "scan_targets": [str(p.relative_to(root)) for p in scan_targets],
        "findings": [f.as_dict() for f in findings],
        "self_test": self_test,
        "failures": failures,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
