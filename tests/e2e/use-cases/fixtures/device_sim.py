#!/usr/bin/env python3
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any


STATE: dict[str, Any] = {"total": 0, "by_action": {}, "actions": []}
LOCK = Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path != "/counters":
            self._json(404, {"error": "not_found"})
            return
        with LOCK:
            self._json(200, json.loads(json.dumps(STATE)))

    def do_POST(self) -> None:
        if self.path != "/actions":
            self._json(404, {"error": "not_found"})
            return
        length = int(self.headers.get("content-length", "0"))
        try:
            request = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad_json"})
            return
        action_name = str(request.get("action_name", ""))
        if not action_name:
            self._json(400, {"error": "missing_action_name"})
            return
        with LOCK:
            STATE["total"] += 1
            STATE["by_action"][action_name] = STATE["by_action"].get(action_name, 0) + 1
            entry = {
                "sequence": STATE["total"],
                "action_id": request.get("action_id"),
                "action_name": action_name,
                "adapter_execution": request.get("adapter_execution"),
                "run_id": request.get("run_id"),
                "tenant_id": request.get("tenant_id"),
                "agent_id": request.get("agent_id"),
            }
            STATE["actions"].append(entry)
            self._json(200, {"accepted": True, "counter": STATE["total"], "entry": entry})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8086), Handler).serve_forever()
