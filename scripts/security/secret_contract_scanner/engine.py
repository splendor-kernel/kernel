"""Repository traversal and deterministic composition of scanner concerns."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .archives import archive_members, detect_archive_kind
from .content import scan_content
from .io_utils import PinnedRepository, enumerate_repository_files
from .model import (
    ARCHIVE_SUFFIXES,
    SOURCE_SUFFIXES,
    ContentHit,
    Finding,
    ScanDataError,
    ScanStats,
    WorkBudget,
    path_under,
    safe_policy_path,
    suffix_for,
)
from .structured import (
    StructuredScan,
    document_schema,
    looks_like_yaml_document,
    markdown_outside_fences,
    parse_markdown_fences,
    parse_structured_data,
    parse_yaml_document,
    scan_python_source,
    scan_structured_value,
    scan_typescript_source,
    scan_yaml_comments,
)
from .workflows import REQUIRED_WORKFLOWS, validate_workflow_text

CONFIG_SUFFIXES = {
    ".bash",
    ".cfg",
    ".conf",
    ".env",
    ".envrc",
    ".ini",
    ".ksh",
    ".properties",
    ".sh",
    ".toml",
    ".zsh",
}
WORKFLOW_PATH_PATTERN = re.compile(r"^\.github/workflows/[^/]+\.(?:yml|yaml)$")
KNOWN_UNGOVERNED_PACKAGE_MANIFESTS = {
    "package.json",
    "python/bindings/pyproject.toml",
}
EXTERNAL_SOURCE_ROOT_NAMES = {"client", "clients", "sdk", "sdks"}


@dataclass
class BlobScan:
    hits: list[ContentHit]
    findings: list[Finding]


def governed_formats(
    policy: dict[str, Any], files: Sequence[str]
) -> tuple[dict[str, str], list[Finding]]:
    formats: dict[str, str] = {}
    findings: list[Finding] = []
    file_set = set(files)
    for root in policy["governed_roots"]:
        root_path = root["path"]
        candidates = [path for path in files if path_under(path, root_path)]
        if root_path in file_set:
            candidates = [root_path]
        if not candidates:
            findings.append(Finding(root_path, 0, "SCN002_PATH_UNAVAILABLE"))
            continue
        for path in candidates:
            kind = root["formats"].get(suffix_for(path))
            if kind is None:
                findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
                continue
            previous = formats.get(path)
            if previous is not None and previous != kind:
                findings.append(Finding(path, 0, "SCN001_POLICY_INVALID"))
            formats[path] = kind
    return formats, findings


def _unregistered_surface_findings(
    files: Sequence[str], formats: dict[str, str]
) -> list[Finding]:
    """Fail closed when repository discovery exposes a new authorizing root."""

    findings: list[Finding] = []
    allowed_python_roots = {"bindings", "splendor", "tests"}
    for path in files:
        python_match = re.fullmatch(r"python/([^/]+)(?:/.*)?\.py", path)
        if python_match and python_match.group(1) not in allowed_python_roots:
            findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
        if path.startswith("conformance/0.2/") and path not in formats:
            findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
        lowered_parts = tuple(part.lower() for part in path.split("/"))
        manifest_name = lowered_parts[-1] if lowered_parts else ""
        if (
            manifest_name in {"package.json", "pyproject.toml"}
            and path not in formats
            and path not in KNOWN_UNGOVERNED_PACKAGE_MANIFESTS
        ):
            findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
        if (
            suffix_for(path) in SOURCE_SUFFIXES
            and path not in formats
            and any(part in EXTERNAL_SOURCE_ROOT_NAMES for part in lowered_parts[:-1])
        ):
            findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
        if (
            re.fullmatch(
                r"(?i)(?:openapi|swagger)(?:[-_.][A-Za-z0-9_-]+)?\.(?:json|ya?ml)",
                manifest_name,
            )
            and path not in formats
        ):
            findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
    return sorted(set(findings))


def _decode_unambiguous(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if (
        "\ufeff" in text
        or "\x00" in text
        or any(
            unicodedata.category(char) in {"Cc", "Cf"}
            and char not in {"\n", "\r", "\t"}
            for char in text
        )
    ):
        raise ScanDataError("SCN003_PATH_AMBIGUOUS")
    return text


def _looks_like_json_text(text: str) -> bool:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return True
    if not stripped.startswith("["):
        return False
    remainder = stripped[1:].lstrip()
    if not remainder or remainder[0] in '[{"-0123456789]':
        return True
    for literal in ("true", "false", "null"):
        if remainder.startswith(literal) and (
            len(remainder) == len(literal)
            or remainder[len(literal)].isspace()
            or remainder[len(literal)] in ",]"
        ):
            return True
    return False


def _selected_kind(
    path: str,
    text: str,
    governed_kind: str | None,
    *,
    rich_surface: bool,
    prefer_structured_sniff: bool = False,
) -> str:
    if governed_kind:
        return governed_kind
    suffix = suffix_for(path)
    # INI/TOML table syntax may begin with ``[`` or ``[[``. Preserve the exact
    # config grammar before suffix-independent JSON sniffing so credential
    # section ancestry is evaluated rather than misclassified as malformed JSON.
    if suffix in CONFIG_SUFFIXES:
        return "config"
    if _looks_like_json_text(text):
        return "json"
    if prefer_structured_sniff and looks_like_yaml_document(text):
        return "yaml"
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if first_line.startswith("#!"):
        lowered = first_line.lower()
        if "python" in lowered:
            return "python_source"
        if any(runtime in lowered for runtime in ("node", "deno", "bun")):
            return "typescript_source"
        if any(shell in lowered for shell in ("/sh", "bash", "zsh", "ksh", "dash")):
            return "config"
    if suffix == ".py" and rich_surface:
        return "python_source"
    if suffix in SOURCE_SUFFIXES and rich_surface:
        return "typescript_source"
    if suffix == ".json":
        return "json"
    if suffix in {".yaml", ".yml"} and rich_surface:
        return "yaml"
    if suffix == ".md" and rich_surface:
        return "markdown"
    if not suffix and re.search(
        r"(?m)^\s*(?:async\s+)?(?:class|def|from|import)\s+", text
    ):
        return "python_source"
    if not suffix and re.search(
        r"(?m)^\s*(?:(?:export|declare|abstract)\s+)*(?:class|interface|type|function|const|let|var)\s+",
        text,
    ):
        return "typescript_source"
    if not suffix and re.search(
        r"(?m)^\s*(?:(?:export|set|setenv|declare\s+-[A-Za-z]+)\s+)?[^\s=:]{1,128}\s*[=:]",
        text,
    ):
        return "config"
    if not rich_surface:
        return "content"
    if looks_like_yaml_document(text):
        return "yaml"
    return "content"


def _content_allowlist_map(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in policy["content_allowlist"]}


def apply_content_allowlist(
    path: str,
    data: bytes,
    hits: list[ContentHit],
    allowlists: dict[str, dict[str, Any]],
    *,
    enforce_stale: bool,
) -> tuple[list[ContentHit], bool, list[Finding]]:
    entry = allowlists.get(path)
    if entry is None:
        return hits, False, []
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.code] = counts.get(hit.code, 0) + 1
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry["sha256"] or counts != entry["matches"]:
        if enforce_stale:
            return hits, False, [Finding(path, 0, "SCN009_STALE_ALLOWLIST")]
        return hits, False, []
    return [], True, []


def _scan_raw_text(
    text: str,
    *,
    budget: WorkBudget,
    maximum_hits: int,
    assignment_context: bool = False,
    colon_assignment_context: bool = False,
) -> list[ContentHit]:
    budget.charge_text(text)
    return scan_content(
        text,
        maximum_hits,
        assignment_context=assignment_context,
        colon_assignment_context=colon_assignment_context,
        budget=budget,
    )


def _exact_owner_status(
    path: str,
    data: bytes,
    value: Any,
    owner_documents: dict[str, dict[str, Any]],
    symbolic_fixtures: dict[str, dict[str, Any]],
    used_owner: set[str],
    used_symbolic: set[str],
) -> tuple[bool, list[Finding]]:
    owner = owner_documents.get(path)
    symbolic = symbolic_fixtures.get(path)
    if owner is None and symbolic is None:
        return False, []
    entry = owner or symbolic
    assert entry is not None
    if owner is not None:
        used_owner.add(path)
    else:
        used_symbolic.add(path)
    valid = hashlib.sha256(data).hexdigest() == entry["sha256"]
    if owner is not None:
        valid = valid and document_schema(value) == entry["schema_version"]
    return True, ([] if valid else [Finding(path, 0, "SCF003_INVALID_SAFE_RECORD")])


def _scan_structured_document(
    *,
    path: str,
    data: bytes,
    kind: str,
    policy: dict[str, Any],
    budget: WorkBudget,
    owner_documents: dict[str, dict[str, Any]],
    symbolic_fixtures: dict[str, dict[str, Any]],
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_owner: set[str],
    used_symbolic: set[str],
    used_exceptions: dict[tuple[str, str, str], int],
    unit_digests: dict[str, str],
    schema_hint: str | None = None,
    base_line: int = 1,
    structural_fields: bool = True,
) -> BlobScan:
    unit_digests[path] = hashlib.sha256(data).hexdigest()
    comments: list[tuple[int, str]] = []
    if kind == "yaml":
        value, comments = parse_yaml_document(data, policy["limits"], budget)
    else:
        value = parse_structured_data(kind, data, policy["limits"], budget)
    owner_exact, owner_findings = _exact_owner_status(
        path,
        data,
        value,
        owner_documents,
        symbolic_fixtures,
        used_owner,
        used_symbolic,
    )
    schema = document_schema(value) or schema_hint
    scanned = scan_structured_value(
        value,
        file_path=path,
        doc_schema=schema,
        exceptions=exceptions,
        used_exceptions=used_exceptions,
        budget=budget,
        maximum_hits=policy["limits"]["max_findings"] + 1,
        owner_exact=owner_exact,
        structural_fields_enabled=structural_fields,
        base_line=base_line,
    )
    comment_hits = scan_yaml_comments(
        comments,
        budget=budget,
        maximum_hits=policy["limits"]["max_findings"] + 1 - len(scanned.hits),
    )
    if base_line != 1:
        comment_hits = [
            ContentHit(
                base_line + hit.line - 1,
                hit.start,
                hit.end,
                hit.code,
            )
            for hit in comment_hits
        ]
    return BlobScan(
        scanned.hits + comment_hits,
        owner_findings + scanned.findings,
    )


def _merge_scans(scans: Iterable[StructuredScan | BlobScan]) -> BlobScan:
    hits: list[ContentHit] = []
    findings: list[Finding] = []
    for scan in scans:
        hits.extend(scan.hits)
        findings.extend(scan.findings)
    return BlobScan(hits, findings)


def _scan_text_blob(
    *,
    path: str,
    data: bytes,
    text: str,
    kind: str,
    policy: dict[str, Any],
    budget: WorkBudget,
    owner_documents: dict[str, dict[str, Any]],
    symbolic_fixtures: dict[str, dict[str, Any]],
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_owner: set[str],
    used_symbolic: set[str],
    used_exceptions: dict[tuple[str, str, str], int],
    unit_digests: dict[str, str],
    structural_fields: bool,
    safe_type_exports: dict[str, set[str]],
) -> BlobScan:
    unit_digests[path] = hashlib.sha256(data).hexdigest()
    maximum = policy["limits"]["max_findings"] + 1
    if kind in {"json", "yaml"}:
        return _scan_structured_document(
            path=path,
            data=data,
            kind=kind,
            policy=policy,
            budget=budget,
            owner_documents=owner_documents,
            symbolic_fixtures=symbolic_fixtures,
            exceptions=exceptions,
            used_owner=used_owner,
            used_symbolic=used_symbolic,
            used_exceptions=used_exceptions,
            unit_digests=unit_digests,
            structural_fields=structural_fields,
        )
    if kind == "markdown":
        fences = parse_markdown_fences(data, policy["limits"], budget)
        outside = markdown_outside_fences(text, fences)
        scans: list[BlobScan] = [
            BlobScan(
                _scan_raw_text(
                    outside,
                    budget=budget,
                    maximum_hits=maximum,
                    assignment_context=True,
                ),
                [],
            )
        ]
        for fence in fences:
            fence_path = f"{path}#fence-{fence.start_line}"
            if fence.kind in {"python_source", "typescript_source"}:
                fence_text = _decode_unambiguous(fence.data)
                if fence_text is None:
                    raise ScanDataError("SCN008_MALFORMED_MARKDOWN", fence.start_line)
                scans.append(
                    _scan_text_blob(
                        path=fence_path,
                        data=fence.data,
                        text=fence_text,
                        kind=fence.kind,
                        policy=policy,
                        budget=budget,
                        owner_documents=owner_documents,
                        symbolic_fixtures=symbolic_fixtures,
                        exceptions=exceptions,
                        used_owner=used_owner,
                        used_symbolic=used_symbolic,
                        used_exceptions=used_exceptions,
                        unit_digests=unit_digests,
                        structural_fields=structural_fields,
                        safe_type_exports=safe_type_exports,
                    )
                )
                continue
            scans.append(
                _scan_structured_document(
                    path=fence_path,
                    data=fence.data,
                    kind=fence.kind,
                    policy=policy,
                    budget=budget,
                    owner_documents=owner_documents,
                    symbolic_fixtures=symbolic_fixtures,
                    exceptions=exceptions,
                    used_owner=used_owner,
                    used_symbolic=used_symbolic,
                    used_exceptions=used_exceptions,
                    unit_digests=unit_digests,
                    schema_hint=f"markdown:{fence.kind}",
                    base_line=fence.start_line + 1,
                    structural_fields=structural_fields,
                )
            )
        return _merge_scans(scans)
    raw_hits = _scan_raw_text(
        text,
        budget=budget,
        maximum_hits=maximum,
        # Low-entropy assignment grammar is suffix-independent for every
        # unambiguous UTF-8 candidate. Source files use their stronger AST/token
        # grammar to avoid mistaking annotations for material assignments.
        assignment_context=kind not in {"python_source", "typescript_source"},
        colon_assignment_context=kind == "config",
    )
    if kind == "python_source":
        if not structural_fields:
            return BlobScan(raw_hits, [])
        source = scan_python_source(
            text,
            file_path=path,
            exceptions=exceptions,
            used_exceptions=used_exceptions,
            budget=budget,
            maximum_hits=maximum,
            safe_type_names=safe_type_exports.get("python", set()),
        )
        return BlobScan(_deduplicate_hits(raw_hits + source.hits), source.findings)
    if kind == "typescript_source":
        if not structural_fields:
            return BlobScan(raw_hits, [])
        source = scan_typescript_source(
            text,
            file_path=path,
            exceptions=exceptions,
            used_exceptions=used_exceptions,
            budget=budget,
            maximum_hits=maximum,
            safe_type_names=safe_type_exports.get("typescript", set()),
        )
        return BlobScan(_deduplicate_hits(raw_hits + source.hits), source.findings)
    if kind == "empty" and data:
        raise ScanDataError("SCN003_PATH_AMBIGUOUS")
    return BlobScan(raw_hits, [])


def _deduplicate_hits(hits: list[ContentHit]) -> list[ContentHit]:
    result: list[ContentHit] = []
    for hit in sorted(set(hits)):
        if any(
            hit.code == current.code
            and hit.line == current.line
            and hit.start < current.end
            and hit.end > current.start
            for current in result
        ):
            continue
        result.append(hit)
    return result


def _bounded_findings(findings: Iterable[Finding], maximum: int) -> list[Finding]:
    ordered = sorted(findings)
    if len(ordered) <= maximum:
        return ordered
    return ordered[:maximum] + [Finding(".", 0, "SCN005_BUDGET_EXCEEDED")]


def _scan_repository_pinned(
    repository: PinnedRepository,
    policy: dict[str, Any],
    *,
    explicit_paths: Sequence[str] | None = None,
) -> tuple[list[Finding], ScanStats]:
    findings: list[Finding] = []
    stats = ScanStats()
    limits = policy["limits"]
    budget = WorkBudget(limits)
    if explicit_paths:
        if len(explicit_paths) > limits["max_files"]:
            return [Finding(".", 0, "SCN005_BUDGET_EXCEEDED")], stats
        files = sorted(set(explicit_paths))
        if len(files) != len(explicit_paths) or any(
            not safe_policy_path(path) for path in files
        ):
            return [Finding(".", 0, "SCN003_PATH_AMBIGUOUS")], stats
        formats: dict[str, str] = {}
    else:
        files, enum_findings = enumerate_repository_files(
            repository, max_files=limits["max_files"]
        )
        findings.extend(enum_findings)
        if enum_findings:
            return findings, stats
        formats, format_findings = governed_formats(policy, files)
        findings.extend(format_findings)
        findings.extend(_unregistered_surface_findings(files, formats))

    owner_documents = {
        entry["path"]: entry for entry in policy["owner_schema_documents"]
    }
    symbolic_fixtures = {entry["path"]: entry for entry in policy["symbolic_fixtures"]}
    exceptions = {
        (entry["path"], entry["document_schema"], entry["field_path"]): entry
        for entry in policy["structural_exceptions"]
    }
    exception_files = {
        path.split("#fence-", 1)[0] for path, _schema, _field in exceptions
    }
    allowlists = _content_allowlist_map(policy)
    used_owner: set[str] = set()
    used_symbolic: set[str] = set()
    used_exceptions: dict[tuple[str, str, str], int] = {}
    unit_digests: dict[str, str] = {}
    used_allowlists: set[str] = set()
    workflow_text: dict[str, str] = {}
    safe_type_exports: dict[str, set[str]] = {}
    source_owner_digests: dict[str, str] = {}
    used_source_owner_files: set[str] = set()
    for entry in policy["source_owner_exports"]:
        entry_digests = {
            entry["path"]: entry["sha256"],
            entry["package_path"]: entry["package_sha256"],
        }
        source_owner_digests.update(entry_digests)
        valid_entry = True
        for owner_path, expected_digest in entry_digests.items():
            try:
                owner_data = repository.read_file(owner_path, limits["max_file_bytes"])
                budget.charge_work(len(owner_data))
                used_source_owner_files.add(owner_path)
                if hashlib.sha256(owner_data).hexdigest() != expected_digest:
                    valid_entry = False
                    findings.append(
                        Finding(owner_path, 0, "SCF003_INVALID_SAFE_RECORD")
                    )
            except ScanDataError:
                valid_entry = False
                findings.append(Finding(owner_path, 0, "SCF003_INVALID_SAFE_RECORD"))
        if valid_entry:
            safe_type_exports.setdefault(entry["language"], set()).update(
                entry["exports"]
            )

    def record_blob(path: str, data: bytes, scan: BlobScan) -> None:
        nonlocal findings
        findings.extend(scan.findings)
        hits, allowed, allow_findings = apply_content_allowlist(
            path,
            data,
            scan.hits,
            allowlists,
            enforce_stale=explicit_paths is None,
        )
        findings.extend(allow_findings)
        if allowed:
            used_allowlists.add(path)
            stats.content_allowlists += 1
        findings.extend(Finding(path, hit.line, hit.code) for hit in hits)

    for path in files:
        try:
            budget.charge_file()
            data = repository.read_file(path, limits["max_file_bytes"])
            budget.charge_work(len(data))
            expected_source_digest = source_owner_digests.get(path)
            if expected_source_digest is not None:
                used_source_owner_files.add(path)
                if hashlib.sha256(data).hexdigest() != expected_source_digest:
                    findings.append(Finding(path, 0, "SCF003_INVALID_SAFE_RECORD"))
            archive_kind = detect_archive_kind(data)
            archive_named = suffix_for(path) in ARCHIVE_SUFFIXES
            if archive_kind is not None or archive_named:
                if archive_kind is None:
                    raise ScanDataError("SCA001_ARCHIVE_INVALID")
                for member in archive_members(data, limits, budget):
                    stats.archive_members += 1
                    display = f"{path}!{member.name}"
                    if detect_archive_kind(member.data) is not None:
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    member_text = _decode_unambiguous(member.data)
                    if member_text is None:
                        continue
                    stats.content_files += 1
                    member_kind = _selected_kind(
                        display,
                        member_text,
                        None,
                        rich_surface=True,
                        prefer_structured_sniff=True,
                    )
                    member_scan = _scan_text_blob(
                        path=display,
                        data=member.data,
                        text=member_text,
                        kind=member_kind,
                        policy=policy,
                        budget=budget,
                        owner_documents=owner_documents,
                        symbolic_fixtures=symbolic_fixtures,
                        exceptions=exceptions,
                        used_owner=used_owner,
                        used_symbolic=used_symbolic,
                        used_exceptions=used_exceptions,
                        unit_digests=unit_digests,
                        structural_fields=True,
                        safe_type_exports=safe_type_exports,
                    )
                    record_blob(display, member.data, member_scan)
                    if len(findings) > limits["max_findings"]:
                        raise ScanDataError("SCN005_BUDGET_EXCEEDED")
                continue

            text = _decode_unambiguous(data)
            governed_kind = formats.get(path)
            if text is None:
                if WORKFLOW_PATH_PATTERN.fullmatch(path):
                    raise ScanDataError("SCN012_WORKFLOW_UNGATED")
                if governed_kind:
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
                continue
            stats.content_files += 1
            suffix = suffix_for(path)
            rich_surface = (
                governed_kind is not None
                or explicit_paths is not None
                or suffix in SOURCE_SUFFIXES
                or suffix in {".json", ".md", ".yaml", ".yml"}
            )
            structural_fields = (
                governed_kind is not None
                or explicit_paths is not None
                or path in exception_files
            )
            kind = _selected_kind(path, text, governed_kind, rich_surface=rich_surface)
            if governed_kind:
                stats.governed_files += 1
            blob_scan = _scan_text_blob(
                path=path,
                data=data,
                text=text,
                kind=kind,
                policy=policy,
                budget=budget,
                owner_documents=owner_documents,
                symbolic_fixtures=symbolic_fixtures,
                exceptions=exceptions,
                used_owner=used_owner,
                used_symbolic=used_symbolic,
                used_exceptions=used_exceptions,
                unit_digests=unit_digests,
                structural_fields=structural_fields,
                safe_type_exports=safe_type_exports,
            )
            record_blob(path, data, blob_scan)
            if WORKFLOW_PATH_PATTERN.fullmatch(path):
                workflow_text[path] = text
        except ScanDataError as exc:
            findings.append(Finding(path, exc.line, exc.code))
            if exc.code == "SCN005_BUDGET_EXCEEDED":
                break
        except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
            findings.append(Finding(path, 0, "SCN003_PATH_AMBIGUOUS"))
        if len(findings) > limits["max_findings"]:
            break

    workflow_paths = {
        path for path in files if WORKFLOW_PATH_PATTERN.fullmatch(path) is not None
    }
    if explicit_paths is None:
        workflow_paths.update(REQUIRED_WORKFLOWS)
    for path in sorted(workflow_paths):
        text = workflow_text.get(path)
        if (
            path not in REQUIRED_WORKFLOWS
            or text is None
            or not validate_workflow_text(path, text)
        ):
            findings.append(Finding(path, 0, "SCN012_WORKFLOW_UNGATED"))
    if explicit_paths is None:
        for path in sorted(set(owner_documents) - used_owner):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
        for path in sorted(set(symbolic_fixtures) - used_symbolic):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
        for identity in sorted(set(exceptions) - set(used_exceptions)):
            findings.append(Finding(identity[0], 0, "SCN009_STALE_ALLOWLIST"))
        for path in sorted(set(allowlists) - used_allowlists):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
        for path in sorted(set(source_owner_digests) - used_source_owner_files):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
    for identity, count in sorted(used_exceptions.items()):
        entry = exceptions[identity]
        if count != entry.get("occurrences") or unit_digests.get(
            identity[0]
        ) != entry.get("sha256"):
            findings.append(Finding(identity[0], 0, "SCF004_INVALID_EXCEPTION"))
    stats.structural_exceptions = sum(used_exceptions.values())
    stats.bytes_worked = budget.work_bytes
    stats.parser_operations = budget.parser_operations
    return _bounded_findings(findings, limits["max_findings"]), stats


def scan_repository(
    repo_root: Path | PinnedRepository,
    policy: dict[str, Any],
    *,
    explicit_paths: Sequence[str] | None = None,
) -> tuple[list[Finding], ScanStats]:
    if isinstance(repo_root, PinnedRepository):
        try:
            return _scan_repository_pinned(
                repo_root, policy, explicit_paths=explicit_paths
            )
        except ScanDataError as exc:
            return [Finding(".", exc.line, exc.code)], ScanStats()
    try:
        with PinnedRepository(repo_root) as repository:
            return _scan_repository_pinned(
                repository, policy, explicit_paths=explicit_paths
            )
    except ScanDataError as exc:
        return [Finding(".", exc.line, exc.code)], ScanStats()
