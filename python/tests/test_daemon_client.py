import pytest

from splendor.daemon_client import SplendorDaemonClient


def credential():
    return {"credential_id": "cred", "scopes": ["replay_create"], "principal": {"client_principal_id": "client"}}


def audit():
    return {"credential_id": "cred", "principal": {"client_principal_id": "client"}, "requested_at": "2026-06-05T00:00:00Z"}


def test_refuses_anonymous_fallback():
    with pytest.raises(ValueError, match="authenticated caller token"):
        SplendorDaemonClient("http://127.0.0.1:8077", "  ")
    client = SplendorDaemonClient("http://127.0.0.1:8077", "token")
    with pytest.raises(ValueError, match="caller credential"):
        client.create_run({"work_order": {"signature": {}}, "audit_attribution": audit()})


def test_replay_request_shape_suppresses_side_effects(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b'{"mode":"inspect_only"}'

    def fake_urlopen(request, timeout):
        captured["method"] = request.get_method()
        captured["body"] = request.data.decode("utf-8")
        return Response()

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
