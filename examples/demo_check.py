"""Self-check for the AgentGate demo, without Claude Desktop.

Run after demo_setup.py:

    python examples/demo_check.py

It starts AgentGate with EXACTLY the command, arguments and environment that
demo_setup.py gave Claude Desktop, then talks to it the way an MCP client does:
initialize -> initialized -> tools/list -> tools/call. It checks that allowed
calls work, that blocked calls are refused by AgentGate, that blocked calls
never reach the tool server (using the server's own evidence log), that the
always-denied delete_file tool is hidden from the agent's tool list, and that
the agent only ever sees a generic denial while the audit log keeps the rule
that fired. Finally it verifies the audit log's hash chain.

Least privilege by identity: it runs as reader-agent (Claude Desktop's token),
then as admin-agent (from keys/tokens.json), and checks that AgentGate refuses
to start with no token, a forged, expired, too-long-lived or old-format token.

Tokens during a session: a token that expires, or is revoked, stops working on
the very next request. A tampered, rolled-back or missing revocation list makes
AgentGate refuse to start. Every change to the demo folder is put back.

Human approval: reading workspace/confidential needs approval. The check plays
the human by signing decisions with the demo's approval key, and shows that an
approval runs one exact request once; that a rejection, a forged decision, a
changed request or a too-late retry runs nothing; and that at most 3 approvals
can wait per agent. (The approval page itself is covered by the unit tests.)

If every line says PASS, the same setup should work from Claude Desktop.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # for agentgate

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


class Client:
    def __init__(self, cfg: dict) -> None:
        env = dict(os.environ)
        env.update(cfg.get("env", {}))
        self.proc = subprocess.Popen(
            [cfg["command"], *cfg["args"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env)
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0

    def _read(self) -> None:
        for raw in self.proc.stdout:
            self.lines.put(raw.decode("utf-8", errors="replace"))

    def send(self, msg: dict) -> None:
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        while True:
            try:
                reply = json.loads(self.lines.get(timeout=15))
            except queue.Empty:
                raise RuntimeError(f"no reply to {method} within 15s")
            if reply.get("id") == self.next_id:
                return reply

    def call(self, tool: str, path: str) -> dict:
        return self.request("tools/call", {"name": tool, "arguments": {"path": path}})

    def close(self) -> str:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        return self.proc.stderr.read().decode("utf-8", errors="replace")


BLOCKED = {"code": -31901, "message": "AgentGate: request blocked by policy"}


def denied_by_agentgate(reply: dict) -> bool:
    """Blocked, and the agent learns nothing else (no rule name, no reason)."""
    return reply.get("error") == BLOCKED and "result" not in reply


def tool_ok(reply: dict) -> bool:
    res = reply.get("result") or {}
    return "error" not in reply and res.get("isError") is False


def text_of(reply: dict) -> str:
    content = (reply.get("result") or {}).get("content") or [{}]
    return content[0].get("text", "")


def read_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentGate demo self-check")
    ap.add_argument("--root", default=str(Path.home() / "AgentGateDemo"))
    args = ap.parse_args()
    root = Path(args.root).resolve()
    snippet = root / "claude_desktop_config_snippet.json"
    if not snippet.exists():
        print(f"Run demo_setup.py first (missing {snippet})")
        return 1
    cfg = json.loads(snippet.read_text(encoding="utf-8"))["mcpServers"]["agentgate-demo"]
    tokens_file = root / "keys" / "tokens.json"
    if "AGENTGATE_AGENT_TOKEN" not in cfg.get("env", {}) or not tokens_file.exists() \
            or "--revocation-list" not in cfg["args"] or "--approval-queue" not in cfg["args"]:
        print("This demo folder is from an older version: run demo_setup.py again.")
        return 1
    tokens = json.loads(tokens_file.read_text(encoding="utf-8"))

    ws = root / "workspace"
    secret = root / "outside" / "secret.txt"
    report = ws / "report.txt"
    trashed = root / ".trash" / "report.txt"
    server_log = root / "server_received.log"
    audit_log = root / "audit.jsonl"
    seen_before = len(read_log(server_log))
    audited_before = len(read_log(audit_log))
    stderr = ""

    # ---- 1. reader-agent: the identity Claude Desktop uses --------------------
    client = Client(cfg)
    try:
        init = client.request("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "agentgate-demo-check", "version": "1"},
        })
        info = (init.get("result") or {}).get("serverInfo") or {}
        check("handshake passes through AgentGate", info.get("name") == "agentgate-demo-server",
              json.dumps(init)[:200])
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        names = list_tools(client)
        check("reader: tool list reaches the agent", "read_file" in names and "list_files" in names,
              str(names))
        check("reader: delete_file is hidden (readers cannot delete)", "delete_file" not in names,
              str(names))

        r = client.call("list_files", str(ws))
        check("reader ALLOW: list the workspace", tool_ok(r) and "notes.txt" in text_of(r), json.dumps(r)[:200])

        r = client.call("read_file", str(ws / "notes.txt"))
        check("reader ALLOW: read a workspace file", tool_ok(r) and "Team notes" in text_of(r), json.dumps(r)[:200])

        sneaky = str(ws) + os.sep + ".." + os.sep + "outside" + os.sep + "secret.txt"
        r = client.call("read_file", sneaky)
        check("reader DENY: ../ trick to read the secret", denied_by_agentgate(r), json.dumps(r)[:200])

        r = client.call("read_file", str(secret))
        check("reader DENY: read the secret directly", denied_by_agentgate(r), json.dumps(r)[:200])

        r = client.call("delete_file", str(report))
        check("reader DENY: calling the hidden delete_file anyway", denied_by_agentgate(r), json.dumps(r)[:200])
        check("denial tells the agent no rule name or reason",
              "admin" not in json.dumps(r) and "workspace" not in json.dumps(r), json.dumps(r))
        check("report.txt still exists after the reader's delete attempt", report.exists())
    finally:
        stderr = client.close()

    # ---- 2. admin-agent: same AgentGate, more privilege -----------------------
    admin_cfg = with_token(cfg, tokens["admin-agent"])
    client = Client(admin_cfg)
    try:
        handshake(client)
        names = list_tools(client)
        check("admin: delete_file is visible (admins may delete)", "delete_file" in names, str(names))

        r = client.call("delete_file", str(report))
        check("admin ALLOW: delete inside the workspace",
              tool_ok(r) and trashed.exists() and not report.exists(), json.dumps(r)[:200])

        r = client.call("delete_file", str(secret))
        check("admin DENY: delete outside the workspace", denied_by_agentgate(r) and secret.exists(),
              json.dumps(r)[:200])
    finally:
        stderr += client.close()
        # Put the demo folder back the way it was, whatever happened above.
        if trashed.exists() and not report.exists():
            shutil.move(str(trashed), str(report))
    check("report.txt is back in the workspace", report.exists())

    # ---- 3. no valid identity: AgentGate must not start -----------------------
    no_token = dict(cfg, env={k: v for k, v in cfg["env"].items() if k != "AGENTGATE_AGENT_TOKEN"})
    check("no token: AgentGate refuses to start", refuses_to_start(no_token))
    check("forged token: AgentGate refuses to start", refuses_to_start(with_token(cfg, forged_token())))
    signer = demo_signer(root)
    expired = signer.sign("reader-agent", ["reader"], issued_at=time.time() - 7200,
                          ttl_seconds=3600)
    check("expired token: AgentGate refuses to start", refuses_to_start(with_token(cfg, expired)))
    too_long = signer.sign("admin-agent", ["reader", "admin"], ttl_seconds=365 * 86400)
    check("token living longer than the allowed maximum: refuses to start",
          refuses_to_start(with_token(cfg, too_long)))
    check("old-format token without expiry/id: refuses to start",
          refuses_to_start(with_token(cfg, old_format_token(signer))))

    # ---- 4. tokens re-checked on EVERY request ---------------------------------
    notes = str(ws / "notes.txt")
    client = Client(with_token(cfg, signer.sign("reader-agent", ["reader"], ttl_seconds=4)))
    try:
        handshake(client)
        r = client.call("read_file", notes)
        check("short token: allowed while valid", tool_ok(r), json.dumps(r)[:200])
        time.sleep(5)
        r = client.call("read_file", notes)
        check("short token: refused on the next request after it expires",
              denied_by_agentgate(r), json.dumps(r)[:200])
    finally:
        stderr += client.close()

    rev_list = Path(option(cfg, "--revocation-list"))
    list_before = rev_list.read_text(encoding="utf-8")
    temp_token = signer.sign("reader-agent", ["reader"])
    client = Client(with_token(cfg, temp_token))
    try:
        handshake(client)
        r = client.call("read_file", notes)
        check("revocation: allowed before revoking", tool_ok(r), json.dumps(r)[:200])
        rv = subprocess.run([cfg["command"], "-m", "agentgate.cli", "revoke",
                             "--list", str(rev_list),
                             "--private-key-file", str(root / "keys" / "agentgate_private_key.hex"),
                             "--token", temp_token],
                            capture_output=True, text=True, env={**os.environ, **cfg["env"]})
        check("revoke command signs a new list version", rv.returncode == 0, rv.stdout + rv.stderr)
        r = client.call("read_file", notes)
        check("revocation: refused on the next request in the SAME session",
              denied_by_agentgate(r), json.dumps(r)[:200])
    finally:
        stderr += client.close()
    client = Client(cfg)
    try:
        handshake(client)
        r = client.call("read_file", notes)
        check("revoking one token leaves Claude Desktop's token working", tool_ok(r),
              json.dumps(r)[:200])
    finally:
        stderr += client.close()

    # ---- 5. the revocation list itself must be trustworthy ---------------------
    list_now = rev_list.read_text(encoding="utf-8")
    try:
        doc = json.loads(list_now)
        doc["revoked"] = []  # "un-revoke" the stolen token, keeping the signature
        rev_list.write_text(json.dumps(doc), encoding="utf-8")
        check("edited revocation list (signature broken): refuses to start",
              refuses_to_start(cfg))
        rev_list.write_text(list_before, encoding="utf-8")
        check("older signed list put back (rollback): refuses to start",
              refuses_to_start(cfg))
        rev_list.unlink()
        check("missing revocation list: refuses to start", refuses_to_start(cfg))
    finally:
        rev_list.write_text(list_now, encoding="utf-8")

    # ---- 6. evidence -----------------------------------------------------------
    reached = read_log(server_log)[seen_before:]
    reached_desc = [(e["tool"], Path(e["path"]).name) for e in reached]
    check("only allowed calls reached the tool server", reached_desc == [
        ("list_files", "workspace"), ("read_file", "notes.txt"), ("delete_file", "report.txt"),
        ("read_file", "notes.txt"), ("read_file", "notes.txt"), ("read_file", "notes.txt"),
    ], str(reached_desc))

    audited = [(e["agent_id"], e["tool"], e["decision"]["effect"], e["decision"]["rule_id"])
               for e in read_log(audit_log)[audited_before:]]
    check("audit log records who asked and the rule behind every decision", audited == [
        ("reader-agent", "list_files", "allow", "read-workspace"),
        ("reader-agent", "read_file", "allow", "read-workspace"),
        ("reader-agent", "read_file", "deny", "__default__"),
        ("reader-agent", "read_file", "deny", "__default__"),
        ("reader-agent", "delete_file", "deny", "__default__"),
        ("admin-agent", "delete_file", "allow", "admin-delete-workspace"),
        ("admin-agent", "delete_file", "deny", "__default__"),
        ("reader-agent", "read_file", "allow", "read-workspace"),
        ("reader-agent", "read_file", "deny", "__identity__"),     # expired
        ("reader-agent", "read_file", "allow", "read-workspace"),
        ("reader-agent", "read_file", "deny", "__identity__"),     # revoked
        ("reader-agent", "read_file", "allow", "read-workspace"),
    ], str(audited))

    stderr += approval_checks(root, cfg)

    verify = subprocess.run(
        [cfg["command"], "-m", "agentgate.cli", "verify", "--audit", str(audit_log)],
        capture_output=True, text=True, env={**os.environ, **cfg.get("env", {})})
    check("audit log hash chain verifies", verify.returncode == 0, verify.stdout + verify.stderr)

    print()
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nAgentGate stderr (for troubleshooting):\n" + stderr[-2000:])
    return 1 if FAILED else 0


PENDING = {"code": -31902, "message": "AgentGate: request requires human approval. "
                                     "Retry the same request after it is approved."}


class Human(threading.Thread):
    """Plays the person at the approval page: signs the next new request."""

    def __init__(self, root: Path, verdict: str, key_hex: str | None = None,
                 skip: set[str] | None = None) -> None:
        super().__init__(daemon=True)
        from agentgate.approval import sign_decision
        from agentgate.identity import Ed25519Signer
        key = key_hex or (root / "keys" / "approver_private_key.hex").read_text(encoding="utf-8").strip()
        self.signer, self.sign = Ed25519Signer(bytes.fromhex(key)), sign_decision
        self.queue, self.verdict, self.skip = root / "approvals", verdict, set(skip or ())
        self.done = threading.Event()
        self.start()

    def run(self) -> None:
        from agentgate.approval import write_json_atomic
        end = time.time() + 20
        while time.time() < end:
            for f in sorted((self.queue / "pending").glob("*.json")):
                if f.stem in self.skip:
                    continue
                try:
                    req = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                write_json_atomic(self.queue / "decisions" / f.name, self.sign(
                    self.signer, approval_id=req["approval_id"], req_hash=req["request_hash"],
                    decision=self.verdict, approver_id="demo-check"))
                self.done.set()
                return
            time.sleep(0.1)


def pending_ids(root: Path) -> set[str]:
    return {f.stem for f in (root / "approvals" / "pending").glob("*.json")}


def approval_checks(root: Path, cfg: dict) -> str:
    ws = root / "workspace"
    salaries = str(ws / "confidential" / "salaries.txt")
    server_log, audit_log = root / "server_received.log", root / "audit.jsonl"
    seen_before, audited_before = len(read_log(server_log)), len(read_log(audit_log))
    short = with_option(with_option(cfg, "--approval-hold", "3"), "--approval-ttl", "30")
    err = ""

    client = Client(short)
    try:
        handshake(client)
        Human(root, "approve")
        r = client.call("read_file", salaries)
        check("approval: approved during the hold, the held request runs",
              tool_ok(r) and "FAKE CONFIDENTIAL" in text_of(r), json.dumps(r)[:200])
        Human(root, "reject")
        r = client.call("read_file", salaries)
        check("approval: rejected request is refused", denied_by_agentgate(r), json.dumps(r)[:200])

        r = client.call("read_file", salaries)          # nobody answers in time
        check("approval: no answer in time -> agent told to retry, nothing ran",
              r.get("error") == PENDING, json.dumps(r)[:200])
        Human(root, "approve").done.wait(5)
        r = client.call("read_file", salaries)
        check("approval: approved later, the IDENTICAL retry runs",
              tool_ok(r) and "FAKE CONFIDENTIAL" in text_of(r), json.dumps(r)[:200])
        r = client.call("read_file", salaries)
        check("approval: used once (the same request again needs a new approval)",
              r.get("error") == PENDING, json.dumps(r)[:200])

        Human(root, "approve").done.wait(5)             # approves that waiting request
        # Same file, different text: pathlib would drop the "." so build it by hand.
        changed = str(ws / "confidential") + os.sep + "." + os.sep + "salaries.txt"
        assert changed != salaries
        r = client.call("read_file", changed)
        check("approval: a changed request does not use the approval",
              r.get("error") == PENDING, json.dumps(r)[:200])
    finally:
        err += client.close()

    from agentgate.identity import Ed25519Signer
    other_key = Ed25519Signer.generate()
    client = Client(short)
    try:
        handshake(client)
        Human(root, "approve", key_hex=_hex(other_key))
        r = client.call("read_file", salaries)
        check("approval: decision signed with another key runs nothing",
              r.get("error") == PENDING, json.dumps(r)[:200])
    finally:
        err += client.close()

    client = Client(with_option(short, "--approval-hold", "1"))
    try:
        handshake(client)
        answers = [client.call("read_file", str(ws / "confidential" / f"f{i}.txt")) for i in range(4)]
        check("approval: at most 3 requests can wait per agent",
              [a.get("error") == PENDING for a in answers[:3]] == [True] * 3
              and denied_by_agentgate(answers[3]), json.dumps(answers[3])[:200])
    finally:
        err += client.close()

    reached = [(e["tool"], Path(e["path"]).name) for e in read_log(server_log)[seen_before:]]
    check("approval: only the two approved reads reached the tool server",
          reached == [("read_file", "salaries.txt")] * 2, str(reached))
    events = [e["decision"]["obligations"].get("approval_event")
              for e in read_log(audit_log)[audited_before:]
              if "approval_event" in e["decision"].get("obligations", {})]
    check("approval: every step is in the audit log", events == [
        "requested", "approved_executed",
        "requested", "rejected",
        "requested", "hold_timeout", "approved_executed",
        "requested", "hold_timeout",
        "requested", "hold_timeout",
        "requested", "invalid_decision_ignored", "hold_timeout",
        "requested", "hold_timeout", "requested", "hold_timeout",
        "requested", "hold_timeout", "too_many_pending",
    ], str(events))
    return err


def _hex(signer) -> str:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from demo_setup import _private_hex
    return _private_hex(signer)


def handshake(client: Client) -> None:
    client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "agentgate-demo-check", "version": "1"}})
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})


def list_tools(client: Client) -> list[str]:
    tools = client.request("tools/list")
    return sorted(t["name"] for t in (tools.get("result") or {}).get("tools", []))


def with_token(cfg: dict, token: str) -> dict:
    return dict(cfg, env=dict(cfg["env"], AGENTGATE_AGENT_TOKEN=token))


def with_option(cfg: dict, name: str, value: str) -> dict:
    args = list(cfg["args"])
    if name in args:
        args[args.index(name) + 1] = value
    else:
        args.insert(args.index("run") + 1, value)
        args.insert(args.index("run") + 1, name)
    return dict(cfg, args=args)


def option(cfg: dict, name: str) -> str:
    args = cfg["args"]
    return args[args.index(name) + 1]


def demo_signer(root: Path):
    from agentgate.identity import Ed25519Signer
    key = (root / "keys" / "agentgate_private_key.hex").read_text(encoding="utf-8").strip()
    return Ed25519Signer(bytes.fromhex(key))


def old_format_token(signer) -> str:
    """A token in the pre-AgentGate format: correctly signed, but no exp/jti."""
    raw = json.dumps({"agent_id": "admin-agent", "roles": ["admin", "reader"],
                      "issued_at": time.time(), "claims": {}},
                     separators=(",", ":"), sort_keys=True).encode()
    return f"{raw.hex()}.ed25519.{signer.sign_bytes(raw)}"


def forged_token() -> str:
    """A token for an 'admin' signed with a DIFFERENT key than AgentGate trusts."""
    from agentgate.identity import Ed25519Signer
    return Ed25519Signer.generate().sign("admin-agent", ["reader", "admin"])


def refuses_to_start(cfg: dict) -> bool:
    env = {**os.environ, **cfg.get("env", {})}
    if "AGENTGATE_AGENT_TOKEN" not in cfg.get("env", {}):
        env.pop("AGENTGATE_AGENT_TOKEN", None)
    r = subprocess.run([cfg["command"], *cfg["args"]], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=30)
    return r.returncode != 0 and "refusing to start" in r.stderr


if __name__ == "__main__":
    raise SystemExit(main())
