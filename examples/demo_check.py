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

If every line says PASS, the same setup should work from Claude Desktop.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

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


BLOCKED = {"code": -32001, "message": "AgentGate: request blocked by policy"}


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

    ws = root / "workspace"
    secret = root / "outside" / "secret.txt"
    server_log = root / "server_received.log"
    audit_log = root / "audit.jsonl"
    seen_before = len(read_log(server_log))
    audited_before = len(read_log(audit_log))

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

        tools = client.request("tools/list")
        names = sorted(t["name"] for t in (tools.get("result") or {}).get("tools", []))
        check("tool list reaches the agent", "read_file" in names and "list_files" in names,
              str(names))
        check("delete_file is hidden from the agent", "delete_file" not in names, str(names))

        r = client.call("list_files", str(ws))
        check("ALLOW: list the workspace", tool_ok(r) and "notes.txt" in text_of(r), json.dumps(r)[:200])

        r = client.call("read_file", str(ws / "notes.txt"))
        check("ALLOW: read a workspace file", tool_ok(r) and "Team notes" in text_of(r), json.dumps(r)[:200])

        sneaky = str(ws) + os.sep + ".." + os.sep + "outside" + os.sep + "secret.txt"
        r = client.call("read_file", sneaky)
        check("DENY: ../ trick to read the secret", denied_by_agentgate(r), json.dumps(r)[:200])

        r = client.call("read_file", str(secret))
        check("DENY: read the secret directly", denied_by_agentgate(r), json.dumps(r)[:200])

        r = client.call("delete_file", str(ws / "report.txt"))
        check("DENY: calling the hidden delete_file anyway", denied_by_agentgate(r), json.dumps(r)[:200])
        check("denial tells the agent no rule name or reason",
              "deny-delete" not in json.dumps(r) and "undone" not in json.dumps(r), json.dumps(r))
        check("report.txt still exists after the delete attempt", (ws / "report.txt").exists())
    finally:
        stderr = client.close()

    reached = read_log(server_log)[seen_before:]
    reached_desc = [(e["tool"], Path(e["path"]).name) for e in reached]
    check("only the 2 allowed calls reached the tool server",
          reached_desc == [("list_files", "workspace"), ("read_file", "notes.txt")],
          str(reached_desc))

    audited = [(e["tool"], e["decision"]["effect"], e["decision"]["rule_id"])
               for e in read_log(audit_log)[audited_before:]]
    check("audit log records the rule behind every decision", audited == [
        ("list_files", "allow", "read-workspace"),
        ("read_file", "allow", "read-workspace"),
        ("read_file", "deny", "__default__"),
        ("read_file", "deny", "__default__"),
        ("delete_file", "deny", "deny-delete"),
    ], str(audited))

    verify = subprocess.run(
        [cfg["command"], "-m", "mcpgate.cli", "verify", "--audit", str(root / "audit.jsonl")],
        capture_output=True, text=True, env={**os.environ, **cfg.get("env", {})})
    check("audit log hash chain verifies", verify.returncode == 0, verify.stdout + verify.stderr)

    print()
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nAgentGate stderr (for troubleshooting):\n" + stderr[-2000:])
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
