from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class SplendorDaemonClientError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, body: Any | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.body = body


@dataclass(frozen=True)
class SplendorDaemonClient:
    """Public HTTP client for the Splendor runtime daemon.

    The client is intentionally thin: it only calls daemon endpoints and never
    executes adapters or side effects directly. Mutating methods require caller
    credentials and audit attribution in the request body.
    """

    base_url: str
    token: str
    default_credential: dict[str, Any] | None = None
    default_audit_attribution: dict[str, Any] | None = None
    api_version: str = "0.1"

    def __post_init__(self) -> None:
        if not self.base_url.strip():
            raise ValueError("SplendorDaemonClient requires a daemon base_url")
        if not self.token.strip():
            raise ValueError("SplendorDaemonClient requires an authenticated caller token; anonymous fallback is not allowed")

    def get_health(self, *, credential: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", "/health", header_credential=credential or self.default_credential)

    def get_version(self, *, credential: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", "/version", header_credential=credential or self.default_credential)

    def get_capabilities(self, *, credential: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", "/capabilities", header_credential=credential or self.default_credential)

    def create_run(self, request: dict[str, Any]) -> dict[str, Any]:
        self._require_mutating_body(request)
        if not request.get("work_order"):
            raise ValueError("create_run requires a signed scoped work_order")
        return self._request("POST", "/runs", body=request)

    def append_percept(self, run_id: str, percept: dict[str, Any], *, credential: dict[str, Any] | None = None, audit_attribution: dict[str, Any] | None = None) -> dict[str, Any]:
        body = {"credential": self._credential(credential), "audit_attribution": self._audit(audit_attribution), "percept": percept}
        self._require_mutating_body(body)
        return self._request("POST", f"/runs/{_quote(run_id)}/percepts", body=body)

    def start_run(self, run_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return self._lifecycle(run_id, "start", request)

    def stop_run(self, run_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return self._lifecycle(run_id, "stop", request)

    def cancel_run(self, run_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return self._lifecycle(run_id, "cancel", request)

    def inspect_run(self, run_id: str, *, credential: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", f"/runs/{_quote(run_id)}", header_credential=credential or self.default_credential)

    def get_state_head(self, run_id: str, *, credential: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", f"/runs/{_quote(run_id)}/state-head", header_credential=credential or self.default_credential)

    def read_traces(self, run_id: str, *, redaction_policy: str, credential: dict[str, Any] | None = None) -> dict[str, Any]:
        if not redaction_policy.strip():
            raise ValueError("read_traces requires an explicit redaction_policy")
        return self._request("GET", f"/runs/{_quote(run_id)}/traces?redaction_policy={_quote(redaction_policy)}", header_credential=credential or self.default_credential)

    def export_traces(self, run_id: str, *, redaction_policy: str, credential: dict[str, Any] | None = None, audit_attribution: dict[str, Any] | None = None) -> dict[str, Any]:
        if not redaction_policy.strip():
            raise ValueError("export_traces requires an explicit redaction_policy")
        body = {"credential": self._credential(credential), "audit_attribution": self._audit(audit_attribution), "redaction_policy": redaction_policy, "start": None, "end": None}
        self._require_mutating_body(body)
        return self._request("POST", f"/runs/{_quote(run_id)}/traces/export", body=body)

    def request_replay(self, run_id: str, *, credential: dict[str, Any] | None = None, audit_attribution: dict[str, Any] | None = None) -> dict[str, Any]:
        body = {"credential": self._credential(credential), "audit_attribution": self._audit(audit_attribution), "mode": "inspect_only", "side_effects_allowed": False}
        self._require_mutating_body(body)
        return self._request("POST", f"/runs/{_quote(run_id)}/replay", body=body)

    def submit_action(self, request: dict[str, Any]) -> dict[str, Any]:
        if not request.get("causal_trace_id"):
            raise ValueError("submit_action requires causal_trace_id trace linkage")
        body = {**request, "credential": request.get("credential") or self.default_credential, "audit_attribution": request.get("audit_attribution") or self._audit(None)}
        self._require_mutating_body(body)
        return self._request("POST", "/actions", body=body)

    def _lifecycle(self, run_id: str, action: str, request: dict[str, Any]) -> dict[str, Any]:
        body = {**request, "credential": request.get("credential") or self.default_credential, "audit_attribution": request.get("audit_attribution") or self._audit(None)}
        self._require_mutating_body(body)
        return self._request("POST", f"/runs/{_quote(run_id)}/{action}", body=body)

    def _audit(self, audit_attribution: dict[str, Any] | None) -> dict[str, Any]:
        audit = audit_attribution or self.default_audit_attribution
        if not audit:
            raise ValueError("mutating daemon calls require audit attribution")
        return audit

    def _credential(self, credential: dict[str, Any] | None) -> dict[str, Any]:
        resolved = credential or self.default_credential
        if not resolved:
            raise ValueError("mutating daemon calls require caller credential")
        return resolved

    @staticmethod
    def _require_mutating_body(body: dict[str, Any]) -> None:
        if not body.get("credential"):
            raise ValueError("mutating daemon calls require caller credential")
        if not body.get("audit_attribution"):
            raise ValueError("mutating daemon calls require audit attribution")

    def _request(self, method: str, path: str, *, body: dict[str, Any] | None = None, header_credential: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.base_url.rstrip("/") + path
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.token}", "X-Splendor-API-Version": self.api_version, "X-Splendor-Client": "python/splendor.daemon_client"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, sort_keys=True).encode("utf-8")
        if header_credential is not None:
            headers["X-Splendor-Caller-Credential"] = json.dumps(header_credential, sort_keys=True, separators=(",", ":"))
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            raise SplendorDaemonClientError(exc.code, str(parsed.get("code", f"http_{exc.code}")), str(parsed.get("message", exc.reason)), parsed) from exc


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")
