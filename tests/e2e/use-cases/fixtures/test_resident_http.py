#!/usr/bin/env python3
from __future__ import annotations

import copy
import http.server
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from resident_http import project_retained_approval_evidence, request_json_no_redirect


def authority_receipt(receipt_id: str) -> dict[str, object]:
    return {
        "schema_version": "splendor.authority.obligation_receipt.v1",
        "receipt_id": receipt_id,
        "approval_id": "approval-1",
        "audience": "splendor.daemon.approval_receipt.v2:instance:i-1:run:r-1",
        "authority_decision_id": "decision-1",
        "obligation_id": "obligation-1",
        "canonical_request_digest": "blake3:request",
        "evidence_digest": "blake3:evidence",
        "approval_trace_event_id": "trace-1",
        "evidence_ref": "approval-trace:trace-1",
        "validation": {
            "algorithm": "ed25519",
            "digest": "blake3:receipt",
            "key_id": "approval-key-1",
            "validation_kind": "detached_signature",
            "signature": "raw-receipt-signature",
        },
    }


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    requests: list[dict[str, str | None]] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(
            {"path": self.path, "authorization": self.headers.get("Authorization")}
        )
        body = json.dumps({"captured": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        return


def redirect_handler(location: str) -> type[http.server.BaseHTTPRequestHandler]:
    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("location", location)
            self.end_headers()

        def log_message(self, *_: object) -> None:
            return

    return RedirectHandler


class RunningServer:
    def __init__(self, handler: type[http.server.BaseHTTPRequestHandler]) -> None:
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class ResidentHttpRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        CaptureHandler.requests = []

    def test_cross_origin_and_https_downgrade_redirects_do_not_receive_bearer(self) -> None:
        self.assertIsNotNone(
            shutil.which("openssl"),
            "openssl is required for the verified-TLS redirect fixture",
        )
        capture = RunningServer(CaptureHandler)
        capture.start()
        cross_origin = RunningServer(
            redirect_handler(f"http://127.0.0.1:{capture.port}/cross-origin-capture")
        )
        cross_origin.start()
        https_redirect: RunningServer | None = None
        try:
            headers = {"authorization": "Bearer acceptance-test-value"}
            status, _ = request_json_no_redirect(
                "GET", f"http://127.0.0.1:{cross_origin.port}/redirect", headers=headers
            )
            self.assertEqual(302, status)
            self.assertEqual([], CaptureHandler.requests)

            with tempfile.TemporaryDirectory(prefix="resident-http-redirect-") as temp:
                cert = Path(temp) / "server.pem"
                key = Path(temp) / "server-key.pem"
                subprocess.run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-keyout",
                        str(key),
                        "-out",
                        str(cert),
                        "-days",
                        "1",
                        "-subj",
                        "/CN=localhost",
                        "-addext",
                        "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    ],
                    check=True,
                    capture_output=True,
                )
                https_redirect = RunningServer(
                    redirect_handler(
                        f"http://127.0.0.1:{capture.port}/downgrade-capture"
                    )
                )
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(certfile=cert, keyfile=key)
                https_redirect.server.socket = tls.wrap_socket(
                    https_redirect.server.socket, server_side=True
                )
                https_redirect.start()
                trusted_context = ssl.create_default_context(cafile=str(cert))
                self.assertEqual(ssl.CERT_REQUIRED, trusted_context.verify_mode)
                self.assertTrue(trusted_context.check_hostname)
                status, _ = request_json_no_redirect(
                    "GET",
                    f"https://localhost:{https_redirect.port}/redirect",
                    headers=headers,
                    context=trusted_context,
                )
                self.assertEqual(302, status)
                self.assertEqual([], CaptureHandler.requests)
        finally:
            if https_redirect is not None:
                https_redirect.stop()
            cross_origin.stop()
            capture.stop()


class RetainedApprovalEvidenceProjectionTests(unittest.TestCase):
    def test_projection_omits_receipt_signature_without_mutating_source(self) -> None:
        source = authority_receipt("receipt-source")
        original = copy.deepcopy(source)

        projected = project_retained_approval_evidence(source)

        self.assertEqual(original, source)
        self.assertIsNot(projected, source)
        self.assertNotIn("signature", projected["validation"])
        self.assertEqual(
            {
                "algorithm": "ed25519",
                "digest": "blake3:receipt",
                "key_id": "approval-key-1",
                "validation_kind": "detached_signature",
            },
            projected["validation"],
        )
        for field in [
            "receipt_id",
            "approval_id",
            "audience",
            "authority_decision_id",
            "obligation_id",
            "canonical_request_digest",
            "evidence_digest",
            "approval_trace_event_id",
            "evidence_ref",
        ]:
            self.assertEqual(source[field], projected[field])

    def test_projection_finds_nested_request_response_and_list_receipts(self) -> None:
        source = {
            "request": {
                "authority_obligation_receipts": [authority_receipt("receipt-request")],
                "signature": "unrelated-work-order-signature",
            },
            "response": {
                "grant": {
                    "authority_obligation_receipt": authority_receipt("receipt-response")
                }
            },
            "artifacts": [
                {"retained_receipt": authority_receipt("receipt-artifact")}
            ],
        }

        projected = project_retained_approval_evidence(source)

        receipts = [
            projected["request"]["authority_obligation_receipts"][0],
            projected["response"]["grant"]["authority_obligation_receipt"],
            projected["artifacts"][0]["retained_receipt"],
        ]
        self.assertEqual(
            ["receipt-request", "receipt-response", "receipt-artifact"],
            [receipt["receipt_id"] for receipt in receipts],
        )
        self.assertTrue(
            all("signature" not in receipt["validation"] for receipt in receipts)
        )
        self.assertEqual(
            "unrelated-work-order-signature", projected["request"]["signature"]
        )


if __name__ == "__main__":
    unittest.main()
