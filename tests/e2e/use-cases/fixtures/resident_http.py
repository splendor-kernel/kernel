#!/usr/bin/env python3
"""Secret-safe HTTP helper for credentialed resident acceptance calls."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any


REDIRECT_POLICY = "disabled"


def project_retained_approval_evidence(value: Any) -> Any:
    """Copy evidence while omitting authority receipt validation signatures."""

    if isinstance(value, dict):
        projected = {
            key: project_retained_approval_evidence(item)
            for key, item in value.items()
        }
        is_authority_receipt = (
            value.get("schema_version")
            == "splendor.authority.obligation_receipt.v1"
            or bool(value.get("receipt_id") and isinstance(value.get("validation"), dict))
        )
        validation = projected.get("validation")
        if is_authority_receipt and isinstance(validation, dict):
            validation.pop("signature", None)
        return projected
    if isinstance(value, list):
        return [project_retained_approval_evidence(item) for item in value]
    return value


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirects to the caller instead of issuing a second request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


def request_json_no_redirect(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    context: ssl.SSLContext | None = None,
    *,
    timeout: float = 20,
) -> tuple[int, dict[str, Any]]:
    """Issue one JSON request with CA-backed TLS and redirects disabled."""

    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method=method)
    if payload is not None:
        request.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)

    handlers: list[urllib.request.BaseHandler] = [NoRedirectHandler()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8")
        try:
            return error.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return error.code, {"raw": raw}
    except urllib.error.URLError:
        return 599, {"code": "transport_unavailable"}
