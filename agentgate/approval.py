"""AgentGate: human approval bound to one exact request.

Design (agreed before any code was written):

  * An approval covers ONE request: the agent, its token id, the tool, the
    exact arguments and the policy version are hashed together. Any change,
    however small, is a different request that needs its own approval.
  * An approval never changes the agent's privileges. It is used at most once
    and then it is gone.
  * Nothing runs before a valid, signed approval arrives. The decision is
    signed by a separate approval service with ITS OWN key; AgentGate holds
    only that service's public key, and that key must differ from the token
    key.
  * AgentGate first HOLDS the call (default 45 s, below the 60 s after which
    linked Claude sessions were measured to give up, without telling the
    server). If the human decides in time, the held copy runs. If not, the
    agent is told the request needs approval and the approval stays pending
    for a limited time (default 10 min, never renewed). When approved, the
    agent's IDENTICAL retry runs exactly once, using the frozen copy of the
    arguments.
  * Before anything runs: identity, revocation and policy are checked again.
  * At most N (default 3) undecided approvals per agent, so a flood of
    requests can't wear the human down into approving without reading.
  * AgentGate and the approval service only share a folder. AgentGate opens
    no network port. A forged decision file fails the signature check; the
    worst a local attacker can do to the folder is delete things, which can
    only cause refusals.
  * Pending approvals live in AgentGate's memory. A restart voids them all.

Folder layout:
    <queue>/pending/<approval_id>.json     written by AgentGate
    <queue>/decisions/<approval_id>.json   written by the approval service
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .decision import Decision, Effect
from .identity import CLOCK_SKEW_SECONDS, IdentityError

log = logging.getLogger("agentgate")

REQUEST_FORMAT = "agentgate-approval-request"
DECISION_FORMAT = "agentgate-approval-decision"
_DECISION_PREFIX = b"agentgate-approval-v1\n"
APPROVE, REJECT = "approve", "reject"
_ID_RE = re.compile(r"^[0-9a-f]{32}$")

DEFAULT_HOLD_SECONDS = 45.0
DEFAULT_TTL_SECONDS = 600.0
DEFAULT_MAX_PENDING = 3


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


def request_hash(*, agent_id: str, token_id: str, tool: str,
                 arguments: dict[str, Any], policy_name: str,
                 policy_version: str) -> str:
    """Fingerprint of the exact request a human approves.

    The approval service recomputes it from the request it displays, so a
    request whose displayed details were altered can't be approved.
    """
    return hashlib.sha256(_canonical({
        "agent_id": agent_id, "token_id": token_id, "tool": tool,
        "arguments": arguments, "policy_name": policy_name,
        "policy_version": policy_version,
    })).hexdigest()


def valid_approval_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def decision_bytes(doc: dict[str, Any]) -> bytes:
    return _DECISION_PREFIX + _canonical({
        k: doc.get(k) for k in
        ("approval_id", "request_hash", "decision", "approver_id", "decided_at")})


def sign_decision(signer, *, approval_id: str, req_hash: str, decision: str,
                  approver_id: str, decided_at: float | None = None) -> dict[str, Any]:
    """Build a signed decision (the approval service holds the private key)."""
    if decision not in (APPROVE, REJECT):
        raise ValueError("decision must be approve or reject")
    doc = {"format": DECISION_FORMAT, "scheme": signer.scheme,
           "approval_id": approval_id, "request_hash": req_hash,
           "decision": decision, "approver_id": approver_id,
           "decided_at": time.time() if decided_at is None else decided_at}
    doc["signature"] = signer.sign_bytes(decision_bytes(doc))
    return doc


def write_json_atomic(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    # Windows refuses to replace a file another process has open for a moment
    # (AgentGate reads these often), so retry briefly before giving up.
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


@dataclass
class Pending:
    approval_id: str
    req_hash: str
    agent_id: str
    tool: str
    arguments: dict[str, Any]       # frozen copy: this is what will run
    message: dict[str, Any]         # frozen copy of the original JSON-RPC call
    decision: Decision              # the policy decision that asked for approval
    session_id: str
    identity: Any                   # who asked (audited on every event)
    created_at: float
    expires_at: float
    outcome: str | None = None      # set once: executed / rejected / expired / ...
    hold_done: threading.Event = field(default_factory=threading.Event)


@dataclass
class ApprovalResult:
    """What the proxy should do with a call that needs approval."""
    forward: dict[str, Any] | None = None   # run this (frozen) message
    respond: str | None = None              # "blocked" or "pending"
    hold: Pending | None = None             # wait for a decision, then call resolve_hold


class ApprovalManager:
    def __init__(self, queue_dir: str | Path, approver_verifier, *, audit, engine,
                 hold_seconds: float = DEFAULT_HOLD_SECONDS,
                 ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_pending: int = DEFAULT_MAX_PENDING,
                 poll_seconds: float = 0.25) -> None:
        if not (0 < hold_seconds <= ttl_seconds):
            raise ValueError("need 0 < hold_seconds <= ttl_seconds")
        if max_pending < 1:
            raise ValueError("max_pending must be >= 1")
        self.queue = Path(queue_dir)
        self.pending_dir = self.queue / "pending"
        self.decision_dir = self.queue / "decisions"
        self.verifier = approver_verifier
        self.audit = audit
        self.engine = engine
        self.hold_seconds = hold_seconds
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self.poll_seconds = poll_seconds
        self._lock = threading.RLock()
        self._by_id: dict[str, Pending] = {}
        self._by_hash: dict[str, str] = {}
        # Anything left from an earlier run is void: approvals are in memory.
        for d in (self.pending_dir, self.decision_dir):
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True, exist_ok=True)

    # ---- audit -------------------------------------------------------------
    def _audit(self, p: Pending, event: str, effect: Effect,
               approver_id: str = "") -> None:
        obligations = {"approval_id": p.approval_id, "approval_event": event,
                       "request_hash": p.req_hash}
        if approver_id:
            obligations["approver_id"] = approver_id
        try:
            self.audit.record(
                session_id=p.session_id, identity=p.identity, tool=p.tool,
                args=p.arguments,
                decision=Decision(effect=effect, rule_id=p.decision.rule_id,
                                  reason=f"approval {event}", obligations=obligations),
                policy_name=self.engine.policy.name,
                policy_version=self.engine.policy.version, mode="enforce")
        except Exception:
            log.exception("could not write approval event %s to the audit log", event)

    # ---- request side (called by the gate) ---------------------------------
    def on_request(self, message: dict[str, Any], tool: str, arguments: dict[str, Any],
                   identity, decision: Decision, session_id: str) -> ApprovalResult:
        h = request_hash(agent_id=identity.agent_id,
                         token_id=getattr(identity, "token_id", ""), tool=tool,
                         arguments=arguments, policy_name=self.engine.policy.name,
                         policy_version=self.engine.policy.version)
        with self._lock:
            self._expire()
            existing = self._by_hash.get(h)
            if existing is not None:
                p = self._by_id[existing]
                if not p.hold_done.is_set():
                    return ApprovalResult(respond="pending")   # still being held
                verdict, approver = self._read_decision(p)
                if verdict == APPROVE:
                    return self._execute(p, approver, new_id=message.get("id"))
                if verdict == REJECT:
                    self._close(p, "rejected", Effect.DENY, approver)
                    return ApprovalResult(respond="blocked")
                self._audit(p, "still_pending", Effect.REQUIRE_APPROVAL)
                return ApprovalResult(respond="pending")

            open_for_agent = sum(1 for q in self._by_id.values()
                                 if q.agent_id == identity.agent_id and q.outcome is None)
            now = time.time()
            p = Pending(approval_id=secrets.token_hex(16), req_hash=h,
                        agent_id=identity.agent_id, tool=tool,
                        arguments=copy.deepcopy(arguments), message=copy.deepcopy(message),
                        decision=decision, session_id=session_id, identity=identity,
                        created_at=now, expires_at=now + self.ttl_seconds)
            if open_for_agent >= self.max_pending:
                self._audit(p, "too_many_pending", Effect.DENY)
                return ApprovalResult(respond="blocked")
            try:
                write_json_atomic(self.pending_dir / f"{p.approval_id}.json",
                                  self._request_doc(p, identity))
            except OSError:
                log.exception("could not write the approval request")
                return ApprovalResult(respond="blocked")
            self._by_id[p.approval_id] = p
            self._by_hash[h] = p.approval_id
            self._audit(p, "requested", Effect.REQUIRE_APPROVAL)
            return ApprovalResult(hold=p)

    def _request_doc(self, p: Pending, identity) -> dict[str, Any]:
        return {"format": REQUEST_FORMAT, "approval_id": p.approval_id,
                "request_hash": p.req_hash, "agent_id": identity.agent_id,
                "token_id": getattr(identity, "token_id", ""),
                "roles": sorted(identity.roles), "tool": p.tool,
                "arguments": p.arguments, "rule_id": p.decision.rule_id,
                "policy_name": self.engine.policy.name,
                "policy_version": self.engine.policy.version,
                "created_at": p.created_at, "expires_at": p.expires_at}

    # ---- hold side (called by the proxy on a worker thread) ----------------
    def wait_for_decision(self, p: Pending, identity) -> tuple[str | None, str]:
        """Poll for a decision until the hold ends. Returns (verdict, approver)."""
        deadline = time.monotonic() + self.hold_seconds
        while time.monotonic() < deadline:
            with self._lock:
                if p.outcome is not None:
                    return None, ""
                verdict, approver = self._read_decision(p)
            if verdict is not None:
                return verdict, approver
            time.sleep(self.poll_seconds)
        return None, ""

    def resolve_hold(self, p: Pending, identity, verdict: str | None,
                     approver: str, identity_problem: str | None) -> ApprovalResult:
        """After the hold: run the frozen copy, refuse, or leave it pending."""
        with self._lock:
            try:
                if p.outcome is not None:
                    return ApprovalResult(respond="blocked")
                if identity_problem is not None:
                    self._close(p, "identity_invalid", Effect.DENY, approver)
                    return ApprovalResult(respond="blocked")
                if verdict == APPROVE:
                    return self._execute(p, approver, new_id=p.message.get("id"))
                if verdict == REJECT:
                    self._close(p, "rejected", Effect.DENY, approver)
                    return ApprovalResult(respond="blocked")
                self._audit(p, "hold_timeout", Effect.REQUIRE_APPROVAL)
                return ApprovalResult(respond="pending")
            finally:
                p.hold_done.set()

    # ---- internals ---------------------------------------------------------
    def _execute(self, p: Pending, approver: str, new_id) -> ApprovalResult:
        """Run the FROZEN copy once, after re-checking the policy."""
        if time.time() >= p.expires_at:
            self._close(p, "expired", Effect.DENY, approver)
            return ApprovalResult(respond="blocked")
        try:
            again = self.engine.evaluate(p.tool, copy.deepcopy(p.arguments), p.identity,
                                         p.session_id)
        except Exception:
            log.exception("policy re-check failed; refusing the approved call")
            again = None
        if again is None or again.effect not in (Effect.REQUIRE_APPROVAL, Effect.ALLOW):
            self._close(p, "policy_changed", Effect.DENY, approver)
            return ApprovalResult(respond="blocked")
        self._close(p, "approved_executed", Effect.ALLOW, approver)
        try:
            self.engine.commit_budget(p.tool, p.arguments, p.decision, p.session_id)
        except Exception:
            log.exception("could not record budget for an approved call")
        msg = copy.deepcopy(p.message)
        msg["id"] = new_id
        msg.setdefault("params", {})["arguments"] = copy.deepcopy(p.arguments)
        return ApprovalResult(forward=msg)

    def _close(self, p: Pending, outcome: str, effect: Effect,
               approver: str = "") -> None:
        p.outcome = outcome
        self._by_id.pop(p.approval_id, None)
        if self._by_hash.get(p.req_hash) == p.approval_id:
            self._by_hash.pop(p.req_hash, None)
        for path in (self.pending_dir / f"{p.approval_id}.json",
                     self.decision_dir / f"{p.approval_id}.json"):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                log.warning("could not remove %s", path)
        self._audit(p, outcome, effect, approver)

    def _expire(self) -> None:
        now = time.time()
        for p in list(self._by_id.values()):
            if p.outcome is None and now >= p.expires_at and p.hold_done.is_set():
                self._close(p, "expired", Effect.DENY)

    def _read_decision(self, p: Pending) -> tuple[str | None, str]:
        path = self.decision_dir / f"{p.approval_id}.json"
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None, ""
        except OSError:
            return None, ""
        try:
            doc = json.loads(text)
            if not isinstance(doc, dict) or doc.get("format") != DECISION_FORMAT \
                    or doc.get("scheme") != self.verifier.scheme:
                raise IdentityError("not a decision")
            self.verifier.verify_bytes(decision_bytes(doc), doc.get("signature"))
            decided_at = doc.get("decided_at")
            if doc.get("approval_id") != p.approval_id or doc.get("request_hash") != p.req_hash \
                    or doc.get("decision") not in (APPROVE, REJECT) \
                    or not isinstance(doc.get("approver_id"), str) \
                    or isinstance(decided_at, bool) or not isinstance(decided_at, (int, float)) \
                    or not (p.created_at - CLOCK_SKEW_SECONDS <= decided_at
                            <= min(p.expires_at, time.time() + CLOCK_SKEW_SECONDS)):
                raise IdentityError("decision does not match this request")
        except (json.JSONDecodeError, IdentityError) as exc:
            # A forged or mismatched decision is ignored, removed and audited.
            log.warning("ignoring an invalid approval decision for %s: %s",
                        p.approval_id, exc)
            try:
                path.unlink()
            except OSError:
                pass
            self._audit(p, "invalid_decision_ignored", Effect.DENY)
            return None, ""
        return doc["decision"], doc["approver_id"]
