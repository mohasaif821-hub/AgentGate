# AgentGate. Copyright 2026 Mohammed Jadulhaqq.
# SPDX-License-Identifier: Apache-2.0
"""AgentGate approval service: a local page where a human approves or rejects.

Run it in its OWN terminal, apart from the agent:

    agentgate approver --queue <folder> --private-key-file approver_key.hex

It prints a one-time login code in that terminal. Only someone who can see the
terminal can log in.

Protections (agreed design):
  * listens on 127.0.0.1 only, never 0.0.0.0
  * random login code per run (no password in the code); 5 wrong codes and the
    service stops
  * session cookie: random, HttpOnly, SameSite=Strict
  * every POST needs the session's CSRF token, a matching Origin, and a Host
    of 127.0.0.1/localhost on this port (also blocks DNS rebinding)
  * a decision is accepted only from a logged-in session; an HTTP request on
    its own approves nothing
  * the page shows the request's details and RECOMPUTES its fingerprint; a
    request whose details don't match its fingerprint can't be approved
  * everything shown is HTML-escaped (the arguments come from the agent) and a
    strict Content-Security-Policy forbids scripts and framing
  * the approval private key lives only in this process; AgentGate gets the
    public key

Honest limit: on a single Windows account, a process running as you (for
example an agent with a terminal tool) could read this terminal's code or the
key file. Real separation needs another OS account or another device. This is
practical protection within our model, not full isolation.
"""

from __future__ import annotations

import hmac
import html
import json
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from .approval import (APPROVE, REJECT, REQUEST_FORMAT, request_hash,
                       sign_decision, valid_approval_id, write_json_atomic)

MAX_FAILED_LOGINS = 5
SESSION_SECONDS = 8 * 3600
_SENSITIVE = ("password", "passwd", "secret", "token", "apikey", "api_key",
              "authorization", "credential", "private")

CSP = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")


def mask_sensitive(value: Any) -> Any:
    """Hide values under secret-looking keys when DISPLAYING a request."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k).lower().replace("-", "_")
            out[k] = "***" if any(s in key for s in _SENSITIVE) else mask_sensitive(v)
        return out
    if isinstance(value, list):
        return [mask_sensitive(v) for v in value]
    return value


class ApproverService:
    def __init__(self, queue_dir: str | Path, signer, *, approver_id: str = "operator",
                 port: int = 8765) -> None:
        self.queue = Path(queue_dir)
        self.pending_dir = self.queue / "pending"
        self.decision_dir = self.queue / "decisions"
        self.signer = signer
        self.approver_id = approver_id
        self.login_code = secrets.token_urlsafe(24)
        self._sessions: dict[str, tuple[str, float]] = {}   # session id -> (csrf, expiry)
        self._failed = 0
        self._lock = threading.Lock()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(self))
        self.port = self.httpd.server_address[1]

    # ---- auth --------------------------------------------------------------
    def login(self, code: str) -> str | None:
        with self._lock:
            if self._failed >= MAX_FAILED_LOGINS:
                return None
            if not hmac.compare_digest(code.encode(), self.login_code.encode()):
                self._failed += 1
                if self._failed >= MAX_FAILED_LOGINS:
                    print("too many wrong login codes: stopping the approval service",
                          file=sys.stderr)
                    threading.Thread(target=self.httpd.shutdown, daemon=True).start()
                return None
            sid = secrets.token_urlsafe(32)
            self._sessions[sid] = (secrets.token_urlsafe(32), time.time() + SESSION_SECONDS)
            return sid

    def session(self, sid: str | None) -> str | None:
        """CSRF token of a live session, or None."""
        if not sid:
            return None
        with self._lock:
            entry = self._sessions.get(sid)
            if entry is None or entry[1] < time.time():
                self._sessions.pop(sid, None)
                return None
            return entry[0]

    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    def allowed_origins(self) -> set[str]:
        return {f"http://{h}" for h in self.allowed_hosts()}

    # ---- requests ----------------------------------------------------------
    def pending(self) -> list[dict[str, Any]]:
        out = []
        for path in sorted(self.pending_dir.glob("*.json")):
            item = self._load(path.stem)
            if item is not None:
                out.append(item)
        return out

    def _load(self, approval_id: str) -> dict[str, Any] | None:
        if not valid_approval_id(approval_id):
            return None
        try:
            doc = json.loads((self.pending_dir / f"{approval_id}.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(doc, dict) or doc.get("format") != REQUEST_FORMAT \
                or doc.get("approval_id") != approval_id:
            return None
        try:
            recomputed = request_hash(
                agent_id=doc["agent_id"], token_id=doc["token_id"], tool=doc["tool"],
                arguments=doc["arguments"], policy_name=doc["policy_name"],
                policy_version=doc["policy_version"])
        except (KeyError, TypeError):
            return None
        doc["_consistent"] = hmac.compare_digest(recomputed, str(doc.get("request_hash")))
        doc["_decided"] = (self.decision_dir / f"{approval_id}.json").exists()
        return doc

    def decide(self, approval_id: str, verdict: str) -> str:
        if verdict not in (APPROVE, REJECT):
            return "unknown decision"
        doc = self._load(approval_id)
        if doc is None:
            return "request not found (already handled or expired)"
        if not doc["_consistent"]:
            return "request details do not match its fingerprint: not signed"
        if doc["_decided"]:
            return "already decided"
        expires = doc.get("expires_at")
        if not isinstance(expires, (int, float)) or time.time() >= expires:
            return "request expired"
        signed = sign_decision(self.signer, approval_id=approval_id,
                               req_hash=doc["request_hash"], decision=verdict,
                               approver_id=self.approver_id)
        write_json_atomic(self.decision_dir / f"{approval_id}.json", signed)
        return "approved" if verdict == APPROVE else "rejected"

    def serve_forever(self) -> None:
        self.httpd.serve_forever()


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _page(body: str) -> bytes:
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>AgentGate approvals</title><style>"
            "body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:24px auto;"
            "padding:0 16px;background:#f6f7f9;color:#111}"
            ".card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:14px;"
            "margin:12px 0}pre{background:#f0f2f5;padding:10px;border-radius:6px;"
            "overflow:auto;white-space:pre-wrap;word-break:break-word}"
            "button{font-size:15px;padding:6px 14px;margin-right:8px;border-radius:6px;"
            "border:1px solid #888;cursor:pointer}.ok{background:#1f7a3a;color:#fff}"
            ".no{background:#a32020;color:#fff}.warn{color:#a32020;font-weight:600}"
            "</style></head><body>" + body + "</body></html>").encode("utf-8")


def _make_handler(svc: ApproverService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentGateApprover"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep the terminal for the login code
            pass

        def _send(self, status: int, body: bytes, extra: dict[str, str] | None = None):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            # "same-origin", NOT "no-referrer": with no-referrer, browsers send
            # "Origin: null" on form POSTs and the Origin check would refuse
            # every login (found with a real browser).
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in svc.allowed_hosts()

        def _sid(self) -> str | None:
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == "agsession":
                    return value
            return None

        def _form(self) -> dict[str, str]:
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n < 0 or n > 10_000:
                return {}
            data = self.rfile.read(n).decode("utf-8", errors="replace")
            return {k: v[0] for k, v in parse_qs(data).items()}

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, _page("<p>Forbidden host.</p>"))
            if self.path not in ("/", "/?"):
                return self._send(404, _page("<p>Not found.</p>"))
            csrf = svc.session(self._sid())
            if csrf is None:
                return self._send(200, _page(
                    "<h1>AgentGate approvals</h1><p>Enter the login code shown in the "
                    "approval service's terminal.</p><form method='post' action='/login'>"
                    "<input name='code' type='password' autocomplete='off' size='40' autofocus> "
                    "<button>Log in</button></form>"))
            cards = []
            for item in svc.pending():
                left = int(item.get("expires_at", 0) - time.time())
                shown = json.dumps(mask_sensitive(item.get("arguments")), indent=2,
                                   ensure_ascii=False)
                head = (f"<p><b>Agent:</b> {_esc(item.get('agent_id'))} "
                        f"(roles: {_esc(', '.join(map(str, item.get('roles') or [])))})<br>"
                        f"<b>Tool:</b> {_esc(item.get('tool'))}<br>"
                        f"<b>Rule:</b> {_esc(item.get('rule_id'))}<br>"
                        f"<b>Time left:</b> {max(left, 0)} s</p>"
                        f"<pre>{_esc(shown)}</pre>")
                if not item["_consistent"]:
                    action = "<p class='warn'>Details do not match the fingerprint: can't be approved.</p>"
                elif item["_decided"]:
                    action = "<p>Decided. Waiting for AgentGate.</p>"
                elif left <= 0:
                    action = "<p>Expired.</p>"
                else:
                    hidden = (f"<input type='hidden' name='csrf' value='{_esc(csrf)}'>"
                              f"<input type='hidden' name='id' value='{_esc(item['approval_id'])}'>")
                    action = (f"<form method='post' action='/decide'>{hidden}"
                              "<button class='ok' name='decision' value='approve'>Approve</button>"
                              "<button class='no' name='decision' value='reject'>Reject</button></form>")
                cards.append(f"<div class='card'>{head}{action}</div>")
            body = ("<h1>AgentGate approvals</h1><p>Each approval runs this exact request "
                    "once. It does not change the agent's permissions.</p>"
                    "<p><a href='/'>Refresh</a></p>" + ("".join(cards) or "<p>No pending requests.</p>"))
            self._send(200, _page(body))

        def do_POST(self):
            # Read the (size-capped) body first, even for requests about to be
            # refused: closing a socket with unread data makes Windows reset
            # the connection, so the client never sees the 403. Nothing in the
            # form is acted on before the checks below.
            form = self._form()
            if not self._host_ok():
                return self._send(403, _page("<p>Forbidden host.</p>"))
            if self.headers.get("Origin", "") not in svc.allowed_origins():
                return self._send(403, _page("<p>Forbidden origin.</p>"))
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None and site not in ("same-origin", "none"):
                return self._send(403, _page("<p>Forbidden.</p>"))
            if self.path == "/login":
                sid = svc.login(form.get("code", ""))
                if sid is None:
                    return self._send(403, _page("<p>Wrong code.</p><p><a href='/'>Back</a></p>"))
                return self._send(303, b"", {
                    "Location": "/",
                    "Set-Cookie": f"agsession={sid}; HttpOnly; SameSite=Strict; Path=/"})
            if self.path == "/decide":
                csrf = svc.session(self._sid())
                if csrf is None or not hmac.compare_digest(form.get("csrf", ""), csrf):
                    return self._send(403, _page("<p>Not logged in.</p><p><a href='/'>Back</a></p>"))
                result = svc.decide(form.get("id", ""), form.get("decision", ""))
                return self._send(200, _page(f"<p>{_esc(result)}</p><p><a href='/'>Back</a></p>"))
            return self._send(404, _page("<p>Not found.</p>"))

    return Handler
