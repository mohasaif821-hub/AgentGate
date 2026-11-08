"""Self-check for AgentGate MONITOR mode, without Claude Desktop.

Run after demo_setup.py (it does NOT touch your Claude Desktop config):

    python examples/demo_monitor_check.py

It starts AgentGate with the same command Claude Desktop uses, plus
--mode monitor, for about a minute, and shows that:

  * monitor mode refuses to start without the confirmation flag;
  * when confirmed, it prints the warning, blocks NOTHING and hides NOTHING;
  * the audit log still records what WOULD have been blocked, marked "monitor".

Damage is contained by design: the demo tool server never touches anything
outside the demo folder, "delete" only moves a file into the demo's .trash
folder, and the "secret" is fake. This check moves report.txt back where it
was before it finishes, even if a step fails.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import demo_check as dc  # noqa: E402  (reuses its MCP test client and checks)

CONFIRM = "--i-understand-this-disables-protection"


def with_mode(cfg: dict, *extra: str) -> dict:
    """Same command as Claude Desktop's, with options added right after 'run'."""
    args = list(cfg["args"])
    i = args.index("run") + 1
    return {**cfg, "args": args[:i] + list(extra) + args[i:]}


def main() -> int:
    root = Path(os.environ.get("AGENTGATE_DEMO_ROOT", Path.home() / "AgentGateDemo")).resolve()
    if len(sys.argv) > 2 and sys.argv[1] == "--root":
        root = Path(sys.argv[2]).resolve()
    snippet = root / "claude_desktop_config_snippet.json"
    if not snippet.exists():
        print(f"Run demo_setup.py first (missing {snippet})")
        return 1
    cfg = json.loads(snippet.read_text(encoding="utf-8"))["mcpServers"]["agentgate-demo"]
    ws = root / "workspace"
    report = ws / "report.txt"
    trashed = root / ".trash" / "report.txt"
    secret = root / "outside" / "secret.txt"
    audit_log = root / "audit.jsonl"
    env = {**os.environ, **cfg.get("env", {})}

    # 1. Without the confirmation flag it must refuse to start.
    unconfirmed = with_mode(cfg, "--mode", "monitor")
    r = subprocess.run([unconfirmed["command"], *unconfirmed["args"]], env=env,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    dc.check("refuses to start without the confirmation flag",
             r.returncode != 0 and "refusing to start" in r.stderr, r.stderr[-300:])

    audited_before = len(dc.read_log(audit_log))
    client = dc.Client(with_mode(cfg, "--mode", "monitor", CONFIRM))
    try:
        client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "agentgate-monitor-check", "version": "1"}})
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        tools = client.request("tools/list")
        names = sorted(t["name"] for t in (tools.get("result") or {}).get("tools", []))
        dc.check("monitor hides nothing (delete_file is listed)", "delete_file" in names, str(names))

        rr = client.call("read_file", str(secret))
        dc.check("monitor blocks nothing: the fake secret was read",
                 dc.tool_ok(rr) and "FAKE SECRET" in dc.text_of(rr), json.dumps(rr)[:200])

        rd = client.call("delete_file", str(report))
        dc.check("monitor blocks nothing: report.txt was moved to .trash",
                 dc.tool_ok(rd) and trashed.exists() and not report.exists(), json.dumps(rd)[:200])
    finally:
        stderr = client.close()
        # Put the demo folder back the way it was, whatever happened above.
        if trashed.exists() and not report.exists():
            shutil.move(str(trashed), str(report))

    dc.check("report.txt is back in the workspace", report.exists())
    dc.check("the MONITOR warning was printed at start",
             "AgentGate is in MONITOR mode" in stderr, stderr[-300:])

    audited = [(e["tool"], e["decision"]["effect"], e["decision"]["rule_id"], e.get("mode"))
               for e in dc.read_log(audit_log)[audited_before:]]
    dc.check("audit records what WOULD have been blocked, marked monitor", audited == [
        ("read_file", "deny", "__default__", "monitor"),
        ("delete_file", "deny", "deny-delete", "monitor"),
    ], str(audited))

    verify = subprocess.run([cfg["command"], "-m", "mcpgate.cli", "verify", "--audit", str(audit_log)],
                            capture_output=True, text=True, env=env)
    dc.check("audit log hash chain verifies", verify.returncode == 0, verify.stdout + verify.stderr)

    print()
    print(f"{len(dc.PASSED)} passed, {len(dc.FAILED)} failed")
    print("Claude Desktop was not changed: it still runs AgentGate in enforce mode.")
    return 1 if dc.FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
