"""Measure how long Claude Desktop waits for a slow tool (AgentGate design aid).

Human approval means AgentGate holds a tool call while a person decides. This
probe answers two questions before that is designed:

  1. How long does Claude Desktop wait for a tool reply before giving up?
  2. When it gives up, does it tell the server (notifications/cancelled)?

It is a tiny MCP server with ONE tool, wait_seconds, that only sleeps. It
reads and writes no files except its own log. It is NOT part of AgentGate and
does not go through it.

    python examples/timeout_probe.py --install-claude-config   # add it (backup first)
    python examples/timeout_probe.py --remove-claude-config    # take it out again
    python examples/timeout_probe.py --show-log                # what happened

Quit Claude Desktop before installing or removing.
Log: <home>/AgentGateDemo/timeout_probe.log
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import sys
import threading
import time
from pathlib import Path

NAME = "timeout-probe"
MAX_WAIT = 900  # seconds
DEFAULT_LOG = Path.home() / "AgentGateDemo" / "timeout_probe.log"

TOOL = {
    "name": "wait_seconds",
    "description": "Test tool: waits the given number of seconds, then replies. "
                   "Touches nothing.",
    "inputSchema": {
        "type": "object",
        "properties": {"seconds": {"type": "number", "description": f"1 to {MAX_WAIT}"}},
        "required": ["seconds"],
    },
}


class Probe:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._out = threading.Lock()
        self._started: dict[str, float] = {}

    def log(self, event: str, **fields) -> None:
        line = {"time": _dt.datetime.now().isoformat(timespec="milliseconds"),
                "event": event, **fields}
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")

    def send(self, msg: dict) -> None:
        with self._out:
            sys.stdout.buffer.write((json.dumps(msg) + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()

    def _slow_reply(self, msg_id, seconds: float) -> None:
        time.sleep(seconds)
        waited = time.monotonic() - self._started.pop(json.dumps(msg_id), time.monotonic())
        self.send({"jsonrpc": "2.0", "id": msg_id, "result": {
            "content": [{"type": "text", "text": f"Waited {seconds:g} seconds."}],
            "isError": False}})
        self.log("replied", id=msg_id, seconds=seconds, waited=round(waited, 1))

    def handle(self, msg: dict) -> None:
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            # notifications, including notifications/cancelled
            self.log("notification", method=method, params=msg.get("params"))
            return
        if method == "initialize":
            self.send({"jsonrpc": "2.0", "id": msg_id, "result": {
                "protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": NAME, "version": "1"}}})
        elif method == "tools/list":
            self.send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [TOOL]}})
        elif method == "tools/call":
            args = (msg.get("params") or {}).get("arguments") or {}
            try:
                seconds = float(args.get("seconds"))
            except (TypeError, ValueError):
                seconds = -1
            if not 1 <= seconds <= MAX_WAIT:
                self.send({"jsonrpc": "2.0", "id": msg_id, "result": {
                    "content": [{"type": "text", "text": f"seconds must be 1 to {MAX_WAIT}"}],
                    "isError": True}})
                return
            self._started[json.dumps(msg_id)] = time.monotonic()
            self.log("call received", id=msg_id, seconds=seconds)
            threading.Thread(target=self._slow_reply, args=(msg_id, seconds),
                             daemon=True).start()
        elif method == "ping":
            self.send({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        else:
            self.send({"jsonrpc": "2.0", "id": msg_id,
                       "error": {"code": -32601, "message": f"method not found: {method}"}})

    def serve(self) -> None:
        self.log("server started")
        for raw in sys.stdin.buffer:
            try:
                msg = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict):
                self.handle(msg)
        self.log("client closed the connection")


def claude_config_path() -> Path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from demo_setup import claude_config_path as path  # same logic as the demo
    return path()


def edit_claude_config(add: bool, log_path: Path) -> int:
    path = claude_config_path()
    if not path.exists():
        print(f"Claude Desktop config not found: {path}")
        return 1
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Not touching {path}: it could not be read as JSON ({exc}).")
        return 1
    if not isinstance(config, dict):
        print(f"Not touching {path}: unexpected content.")
        return 1
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    if not add and NAME not in servers:
        print("The timeout probe is not in Claude Desktop's config. Nothing changed.")
        return 0
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"claude_desktop_config.backup-{stamp}.json")
    shutil.copy2(path, backup)
    if add:
        servers[NAME] = {"command": sys.executable,
                         "args": [str(Path(__file__).resolve()), "--log", str(log_path)]}
    else:
        servers.pop(NAME)
    config["mcpServers"] = servers
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"{'Added' if add else 'Removed'} '{NAME}' in {path}")
    print(f"Backup of the previous config: {backup}")
    print("Start Claude Desktop again to load the change.")
    return 0


def show_log(log_path: Path) -> int:
    if not log_path.exists():
        print(f"No log yet: {log_path}")
        return 1
    for line in log_path.read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        extra = {k: v for k, v in e.items() if k not in ("time", "event")}
        print(e["time"][11:23], e["event"], json.dumps(extra) if extra else "")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", default=str(DEFAULT_LOG))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--install-claude-config", action="store_true")
    g.add_argument("--remove-claude-config", action="store_true")
    g.add_argument("--show-log", action="store_true")
    args = ap.parse_args()
    log_path = Path(args.log).resolve()
    if args.install_claude_config:
        return edit_claude_config(True, log_path)
    if args.remove_claude_config:
        return edit_claude_config(False, log_path)
    if args.show_log:
        return show_log(log_path)
    Probe(log_path).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
