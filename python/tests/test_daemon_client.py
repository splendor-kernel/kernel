import io
import urllib.error

import pytest

from splendor.daemon_client import SplendorDaemonClient, SplendorDaemonClientError


def credential():
    return {"credential_id": "cred", "scopes": ["replay_create"], "principal": {"client_principal_id": "client"}}


def audit():
    return {"credential_id": "cred", "principal": {"client_principal_id": "client"}, "requested_at": "2026-06-05T00:00:00Z"}


def create_run_body(**overrides):
    body = {
        "request_id": "req_python_create_run",
        "idempotency_key": "idem_python_create_run",
        "credential": credential(),
        "audit_attribution": audit(),
        "work_order": {"signature": "sig"},
    }
    body.update(overrides)
    return body


class Response:
    def __init__(self, body=b'{"ok":true}'):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return self.body


def capture_requests(monkeypatch, body=b'{"ok":true}'):
    captured = []

    def fake_urlopen(request, timeout):
        captured.append(request)
        assert timeout == 10
        return Response(body)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return captured


def test_refuses_anonymous_fallback():
    with pytest.raises(ValueError, match="authenticated caller token"):
        SplendorDaemonClient("http://127.0.0.1:8077", "  ")
    client = SplendorDaemonClient("http://127.0.0.1:8077", "token")
    with pytest.raises(ValueError, match="caller credential"):
        client.create_run({"request_id": "req", "idempotency_key": "idem", "work_order": {"signature": {}}, "audit_attribution": audit()})


def test_replay_request_shape_suppresses_side_effects(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["method"] = request.get_method()
        captured["body"] = request.data.decode("utf-8")
        return Response(b'{"mode":"inspect_only"}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = SplendorDaemonClient("http://127.0.0.1:8077", "token", default_credential=credential(), default_audit_attribution=audit())
    assert client.request_replay("run_1") == {"mode": "inspect_only"}
    assert captured["method"] == "POST"
    assert '"audit_attribution"' in captured["body"]
    assert '"mode": "inspect_only"' in captured["body"]
    assert '"side_effects_allowed": false' in captured["body"]


def test_export_and_replay_require_credential_and_audit():
    client = SplendorDaemonClient("http://127.0.0.1:8077", "token")
    with pytest.raises(ValueError, match="caller credential"):
        client.append_percept("run_1", {"schema": "splendor.percept.test.v1"}, audit_attribution=audit())
    with pytest.raises(ValueError, match="audit attribution"):
        client.append_percept("run_1", {"schema": "splendor.percept.test.v1"}, credential=credential())
    with pytest.raises(ValueError, match="audit attribution"):
        client.request_replay("run_1", credential=credential())
    with pytest.raises(ValueError, match="caller credential"):
        client.request_replay("run_1", audit_attribution=audit())
    with pytest.raises(ValueError, match="audit attribution"):
        client.export_traces("run_1", redaction_policy="tenant-default", credential=credential())
    with pytest.raises(ValueError, match="caller credential"):
        client.export_traces("run_1", redaction_policy="tenant-default", audit_attribution=audit())


def test_read_only_methods_send_header_credentials(monkeypatch):
    captured = capture_requests(monkeypatch, b'{"status":"ok"}')
    client = SplendorDaemonClient("http://127.0.0.1:8077/", "token", default_credential=credential())

    assert client.get_health() == {"status": "ok"}
    client.get_version(credential={"credential_id": "override"})
    client.get_capabilities()
    client.inspect_run("run/with space")
    client.get_state_head("run_1")
    client.read_traces("run_1", redaction_policy="tenant default")

    assert captured[0].get_method() == "GET"
    assert captured[0].headers["Authorization"] == "Bearer token"
    assert "x-splendor-caller-credential" in {key.lower() for key in captured[0].headers}
    assert captured[3].full_url.endswith("/runs/run%2Fwith%20space")
    assert captured[5].full_url.endswith("redaction_policy=tenant%20default")


def test_mutating_methods_include_credentials_and_audit(monkeypatch):
    captured = capture_requests(monkeypatch)
    client = SplendorDaemonClient(
        "http://127.0.0.1:8077",
        "token",
        default_credential=credential(),
        default_audit_attribution=audit(),
    )

    client.create_run(create_run_body())
    client.append_percept("run_1", {"schema": "splendor.percept.test.v1"})
    client.start_run("run_1", {})
    client.stop_run("run_1", {})
    client.cancel_run("run_1", {})
    client.export_traces("run_1", redaction_policy="tenant-default")
    client.submit_action({"causal_trace_id": "trace_1", "action": {"name": "noop"}})

    urls = [request.full_url for request in captured]
    assert urls[0].endswith("/runs")
    assert urls[1].endswith("/runs/run_1/percepts")
    assert urls[2].endswith("/runs/run_1/start")
    assert urls[3].endswith("/runs/run_1/stop")
    assert urls[4].endswith("/runs/run_1/cancel")
    assert urls[5].endswith("/runs/run_1/traces/export")
    assert urls[6].endswith("/actions")
    for request in captured:
        body = request.data.decode("utf-8")
        assert '"credential"' in body
        assert '"audit_attribution"' in body
    create_body = captured[0].data.decode("utf-8")
    assert '"request_id": "req_python_create_run"' in create_body
    assert '"idempotency_key": "idem_python_create_run"' in create_body


def test_mutating_validation_and_redaction_policy():
    client = SplendorDaemonClient(
        "http://127.0.0.1:8077",
        "token",
        default_credential=credential(),
        default_audit_attribution=audit(),
    )
    with pytest.raises(ValueError, match="request_id"):
        client.create_run(create_run_body(request_id=" "))
    with pytest.raises(ValueError, match="idempotency_key"):
        client.create_run(create_run_body(idempotency_key="\t"))
    with pytest.raises(ValueError, match="signed scoped work_order"):
        client.create_run(create_run_body(work_order=None))
    with pytest.raises(ValueError, match="causal_trace_id"):
        client.submit_action({"action": {"name": "noop"}})
    with pytest.raises(ValueError, match="redaction_policy"):
        client.read_traces("run_1", redaction_policy=" ")
    with pytest.raises(ValueError, match="redaction_policy"):
        client.export_traces("run_1", redaction_policy=" ")
    with pytest.raises(ValueError, match="base_url"):
        SplendorDaemonClient(" ", "token")


def test_http_error_preserves_structured_body(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"code":"scope_denied","message":"wrong endpoint scope"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = SplendorDaemonClient("http://127.0.0.1:8077", "token")

    with pytest.raises(SplendorDaemonClientError) as exc:
        client.get_health()
    assert exc.value.status == 403
    assert exc.value.code == "scope_denied"
    assert exc.value.body == {"code": "scope_denied", "message": "wrong endpoint scope"}


def test_http_error_with_non_json_body(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 500, "Boom", hdrs=None, fp=io.BytesIO(b"not json"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = SplendorDaemonClient("http://127.0.0.1:8077", "token")

    with pytest.raises(SplendorDaemonClientError) as exc:
        client.get_health()
    assert exc.value.status == 500
    assert exc.value.code == "http_500"
    assert exc.value.body == {"raw": "not json"}
