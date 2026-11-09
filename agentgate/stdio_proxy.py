# Modified for AgentGate by Mohammed Jadulhaqq, 2026.
# Based on mcp-gate (https://github.com/rsh1k/mcp-gate), Copyright 2026 The mcp-gate Authors.
# AgentGate changes in this file:
#   Refuses to start without a valid identity; re-checks identity and
#   revocation on every request; filters the tool list per role; holds calls
#   for approval on worker threads; audits identity refusals.
# SPDX-License-Identifier: Apache-2.0
"""Stdio proxy: gate an MCP server that speaks over stdin/stdout.

Architecture (stdio transport):

    MCP client (agent host)
        | stdin/stdout  (talks to AgentGate as if it were the server)
        v
    AgentGate stdio proxy   <-- this module
        | stdin/stdout  (spawns the REAL server as a subprocess)
        v
    upstream MCP server

Per the MCP spec, stdio transport has no client<->server auth and the server is
launched as a subprocess configured by environment variables — which is exactly
why a proxy slots in cleanly here: we become the subprocess the client launches,
and we launch the real server ourselves.

MCP messages are newline-delimited JSON-RPC 2.0 objects. We read a line from the
client, parse it, run it through the Gate, and either forward it to the upstream
subprocess or answer the client directly with a denial. Responses from upstream
are streamed back unchanged.

# HARDENING:
#  - This reference proxy reads identity from the AGENTGATE_AGENT_TOKEN env var,
#    set when the client launches the proxy. For stdio that is the natural
#    channel (the spec uses env for stdio config). Validate token freshness.
#  - A truly robust proxy must handle: partial lines, huge messages (cap line
#    size), upstream crash/restart, and backpressure. The threading model below
#    is intentionally simple and readable; review it for your load profile.
#  - Notifications (no `id`) and batches need care; tools/call always has an id.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from typing import Any

from .decision import Decision, Effect
from .enforce import blocked_response
from .gate import Gate
from .identity import (
    AgentIdentity, IdentityError, IdentityVerifier, HmacVerifier,
)

log = logging.getLogger("agentgate.stdio")


class StdioProxy:
    def __init__(self, gate: Gate, upstream_cmd: list[str], *,
                 identity_secret: bytes | None = None,
                 verifier: IdentityVerifier | None = None,
                 session_id: str = "stdio-session",
                 max_age_seconds: float | None = 3600.0,
                 revocation: Any = None) -> None:
        self.gate = gate
        self.upstream_cmd = upstream_cmd
        # A verifier (HMAC, Ed25519, or custom) takes precedence; otherwise fall
        # back to building an HMAC verifier from a raw secret for convenience.
        if verifier is None and identity_secret is not None:
            verifier = HmacVerifier(identity_secret)
        self.verifier = verifier
        self.session_id = session_id
        self.max_age_seconds = max_age_seconds
        # AgentGate: optional RevocationChecker, consulted on every request.
        self.revocation = revocation
        self._token: str | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._identity: AgentIdentity = AgentIdentity.anonymous()
        # ids of tools/list requests sent upstream whose responses must be filtered
        self._pending_lists: set[Any] = set()
        self._pending_lock = threading.Lock()
        # client stdout is written from two threads; keep each message whole
        self._write_lock = threading.Lock()
        # upstream stdin is written by the main thread and by approval holds
        self._upstream_lock = threading.Lock()

    def _resolve_identity(self) -> AgentIdentity:
        """Who is this agent?

        No verifier configured: there is no identity system, so the agent is
        'anonymous' and the policy decides what anonymous may do.

        Verifier configured (AgentGate): the agent MUST present a valid, fresh
        token. A missing, forged or expired token raises IdentityError and the
        proxy refuses to start, instead of silently running with unknown
        privileges.
        """
        if self.verifier is None:
            return AgentIdentity.anonymous()
        token = os.environ.get("AGENTGATE_AGENT_TOKEN")
        if not token:
            raise IdentityError("identity is required but AGENTGATE_AGENT_TOKEN is not set")
        self._token = token
        return self._verify_token()

    def _verify_token(self) -> AgentIdentity:
        """Signature, times and revocation of the session's token. Raises."""
        if self._token is None:
            raise IdentityError("no identity token")
        identity = self.verifier.verify(self._token, self.max_age_seconds)
        if self.revocation is not None:
            self.revocation.check(identity.token_id)
        return identity

    def identity_still_valid(self) -> bool:
        """AgentGate: re-checked before EVERY request, not just at start.

        A token that expires or is revoked during a session stops working on
        the next request. Any error while checking counts as invalid.
        """
        return self._identity_problem() is None

    def _identity_problem(self) -> str | None:
        """None if the identity is still valid, else why not (operator-only)."""
        if self.verifier is None:
            return None
        try:
            self._verify_token()
            return None
        except Exception as exc:  # fail closed on anything unexpected
            log.warning("request refused: agent identity is no longer valid: %s", exc)
            return str(exc) or type(exc).__name__

    def _audit_identity_refusal(self, message: dict[str, Any], problem: str) -> None:
        """Tool calls refused for identity reasons go in the audit log too."""
        params = message.get("params") or {}
        tool = params.get("name", "") if isinstance(params, dict) else ""
        args = params.get("arguments") or {} if isinstance(params, dict) else {}
        try:
            self.gate.audit.record(
                session_id=self.session_id, identity=self._identity,
                tool=str(tool), args=args if isinstance(args, dict) else {},
                decision=Decision(effect=Effect.DENY, rule_id="__identity__",
                                  reason=f"agent identity no longer valid: {problem}"),
                policy_name=self.gate.engine.policy.name,
                policy_version=self.gate.engine.policy.version,
                mode="enforce",  # identity is enforced even in monitor mode
            )
        except Exception:
            log.exception("could not write the identity refusal to the audit log")

    def run(self) -> int:
        try:
            identity = self._resolve_identity()
        except IdentityError as exc:
            log.error("refusing to start: agent identity check failed: %s", exc)
            return 3
        log.info("agent identity: %s (roles: %s)", identity.agent_id,
                 ", ".join(sorted(identity.roles)) or "none")
        if self.verifier is not None and self.revocation is None:
            log.warning("no revocation list configured: a stolen token keeps "
                        "working until it expires")
        self._identity = identity
        self._proc = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface upstream errors to the operator
        )
        assert self._proc.stdin and self._proc.stdout

        # Pump upstream -> client on a background thread.
        pump = threading.Thread(target=self._pump_upstream_to_client, daemon=True)
        pump.start()

        client_in = sys.stdin.buffer
        upstream_out = self._proc.stdin
        try:
            for raw in client_in:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                self._handle_client_line(line, identity, upstream_out)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                upstream_out.close()
            except Exception:
                pass
            self._proc.wait(timeout=5)
        return self._proc.returncode or 0

    def _handle_client_line(self, line: str, identity: AgentIdentity,
                            upstream_out: Any) -> None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            log.error("dropping non-JSON line from client")
            return

        problem = self._identity_problem()
        if problem is not None:
            # Requests get the same generic denial as a policy block; anything
            # else (notifications, responses) is dropped. Nothing is forwarded.
            # Enforced in monitor mode too: identity is not a policy decision.
            if isinstance(message, dict) and message.get("method") == "tools/call":
                self._audit_identity_refusal(message, problem)
            if isinstance(message, dict) and "method" in message \
                    and message.get("id") is not None:
                self._write_client(blocked_response(message["id"]))
            return

        outcome = self.gate.handle_request(message, identity, self.session_id)

        if outcome.hold is not None:
            # Held for human approval: wait on a worker thread so other
            # requests keep flowing. Nothing is sent until there is a decision.
            threading.Thread(target=self._finish_hold, args=(outcome.hold, upstream_out),
                             daemon=True).start()
            return

        if outcome.response_to_agent is not None:
            # Denied/approval-rejected/fail-closed: answer the client directly.
            self._write_client(outcome.response_to_agent)

        if outcome.forward_message is not None:
            if (isinstance(message, dict) and message.get("method") == "tools/list"
                    and message.get("id") is not None):
                with self._pending_lock:
                    self._pending_lists.add(_id_key(message["id"]))
            self._write_upstream(outcome.forward_message, upstream_out)

    def _write_upstream(self, msg: dict[str, Any], upstream_out: Any) -> None:
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode()
        with self._upstream_lock:
            upstream_out.write(data)
            upstream_out.flush()

    def _finish_hold(self, hold: Any, upstream_out: Any) -> None:
        """AgentGate: wait for the human, then run the frozen copy or answer."""
        from .approval import APPROVE
        from .enforce import approval_pending_response
        mgr = self.gate.approvals
        request_id = hold.message.get("id")
        try:
            verdict, approver = mgr.wait_for_decision(hold, self._identity)
            # identity, expiry and revocation are checked again right before running
            problem = self._identity_problem() if verdict == APPROVE else None
            if problem is not None:
                self._audit_identity_refusal(hold.message, problem)
            res = mgr.resolve_hold(hold, self._identity, verdict, approver, problem)
        except Exception:
            log.exception("approval hold failed; refusing the call")
            hold.hold_done.set()
            self._write_client(blocked_response(request_id))
            return
        if res.forward is not None:
            self._write_upstream(res.forward, upstream_out)
        elif res.respond == "pending":
            self._write_client(approval_pending_response(request_id))
        else:
            self._write_client(blocked_response(request_id))

    def _pump_upstream_to_client(self) -> None:
        assert self._proc and self._proc.stdout
        for raw in self._proc.stdout:
            out = self.process_upstream_line(raw)
            with self._write_lock:
                sys.stdout.buffer.write(out)
                sys.stdout.buffer.flush()

    def process_upstream_line(self, raw: bytes) -> bytes:
        """Return what to send the client for one line from upstream.

        Only responses to tracked tools/list requests are changed; every other
        line passes through byte for byte.
        """
        with self._pending_lock:
            if not self._pending_lists:
                return raw
        try:
            msg = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw  # not JSON: the client cannot read a tool list from it
        if not isinstance(msg, dict) or "id" not in msg:
            return raw
        key = _id_key(msg["id"])
        with self._pending_lock:
            if key not in self._pending_lists:
                return raw
            self._pending_lists.discard(key)
        if "result" not in msg:
            return raw  # an error response carries no tools
        if self.gate.mode == "monitor":
            # Monitor mode changes nothing: report what WOULD be hidden.
            try:
                _, hidden = self.filter_tools_list(msg)
                if hidden:
                    log.warning("MONITOR (not enforced): would have hidden %s",
                                ", ".join(hidden))
            except Exception:
                log.warning("MONITOR (not enforced): tools/list could not be "
                            "checked; in enforce mode the agent would get an error")
            return raw
        try:
            filtered, hidden = self.filter_tools_list(msg)
        except Exception:
            log.exception("could not filter tools/list response; sending an error instead")
            return _line(blocked_response(msg["id"]))
        if hidden:
            log.info("hid %d tool(s) from the agent: %s", len(hidden), ", ".join(hidden))
        return _line(filtered)

    def filter_tools_list(self, msg: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        """Remove tools this agent can never use. Raises on anything malformed."""
        result = msg["result"]
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise ValueError("tools/list result has no tools list")
        kept: list[Any] = []
        hidden: list[str] = []
        for tool in result["tools"]:
            name = tool.get("name") if isinstance(tool, dict) else None
            if not isinstance(name, str) or not name:
                raise ValueError("tool entry without a name")
            if self.gate.engine.tool_visible(name, self._identity):
                kept.append(tool)
            else:
                hidden.append(name)
        new_result = dict(result)
        new_result["tools"] = kept
        new_msg = dict(msg)
        new_msg["result"] = new_result
        return new_msg, hidden

    def _write_client(self, obj: dict[str, Any]) -> None:
        with self._write_lock:
            sys.stdout.buffer.write(_line(obj))
            sys.stdout.buffer.flush()


def _line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()


def _id_key(request_id: Any) -> Any:
    """Hashable key for a JSON-RPC id (ints and strings are kept distinct)."""
    return (type(request_id).__name__, json.dumps(request_id, sort_keys=True))
