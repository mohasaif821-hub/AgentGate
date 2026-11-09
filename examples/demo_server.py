# AgentGate. Copyright 2026 Mohammed Jadulhaqq.
# SPDX-License-Identifier: Apache-2.0
"""AgentGate demo tool server (MCP over stdio, Python standard library only).

This is the "real tool" that sits BEHIND AgentGate in the Claude Desktop demo.
It offers three file tools:

    list_files(path)    list a folder
    read_file(path)     read a text file
    delete_file(path)   "delete" a file (moved to the demo's .trash folder)

Two things make it useful for proving AgentGate works:

1. Evidence log. Every tool call that REACHES this server is appended to
   <root>/server_received.log. If AgentGate blocks a call, it never shows up
   here. That log is the proof that a denied call did not reach the tool.

2. Safety net. This server never touches anything outside the demo folder
   (--root), even if AgentGate is misconfigured or switched off. A call aimed
   outside the folder is logged as REACHED and refused here, so your real files
   are never at risk. Deletes are moves into <root>/.trash, so nothing is lost.

Paths must be absolute. AgentGate checks the real path of what the agent sends,
and requiring absolute paths keeps AgentGate and this server talking about the
same file. (Relative paths would resolve against two different folders.)

Run (normally Claude Desktop starts it through AgentGate, see demo_setup.py):
    python demo_server.py --root C:/Users/you/AgentGateDemo
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import sys

PROTOCOL_FALLBACK = "2025-06-18"

TOOLS = [
    {
        "name": "list_files",
        "description": "List the files in a folder. Use an absolute path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute folder path"}},
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a text file. Use an absolute path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute file path"}},
            "required": ["path"],
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file. Use an absolute path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute file path"}},
            "required": ["path"],
        },
    },
]


class DemoServer:
    def __init__(self, root: str) -> None:
        self.root = os.path.normcase(os.path.realpath(root))
        self.trash = os.path.join(self.root, ".trash")
        self.log_path = os.path.join(self.root, "server_received.log")

    # ---- evidence log -------------------------------------------------------
    def _log(self, tool: str, args: dict, outcome: str) -> None:
        line = {
            "time": _dt.datetime.now().isoformat(timespec="seconds"),
            "tool": tool,
            "path": args.get("path"),
            "outcome": outcome,
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")

    # ---- safety net ---------------------------------------------------------
    def _inside_root(self, path: str) -> str | None:
        """Real path if it is inside the demo folder, else None."""
        if not isinstance(path, str) or not path or not os.path.isabs(path):
            return None
        try:
            real = os.path.normcase(os.path.realpath(path))
            if os.path.commonpath([real, self.root]) == self.root:
                return real
        except (OSError, ValueError):
            return None
        return None

    # ---- tools --------------------------------------------------------------
    def call_tool(self, name: str, args: dict) -> tuple[str, bool]:
        path = args.get("path")
        if not isinstance(path, str) or not os.path.isabs(path):
            self._log(name, args, "refused: path must be absolute")
            return "Error: path must be an absolute path.", True
        real = self._inside_root(path)
        if real is None:
            self._log(name, args, "REACHED SERVER but outside demo folder: not touched")
            return ("Demo safety net: this path is outside the demo folder, so the "
                    "demo server did not touch it. (AgentGate should have blocked "
                    "this call before it got here.)"), True

        if name == "list_files":
            if not os.path.isdir(real):
                self._log(name, args, "error: not a folder")
                return "Error: not a folder.", True
            names = sorted(n for n in os.listdir(real) if n != ".trash")
            self._log(name, args, f"listed {len(names)} entries")
            full = [os.path.join(path, n) for n in names]
            return "\n".join(full) if full else "(empty folder)", False

        if name == "read_file":
            if not os.path.isfile(real):
                self._log(name, args, "error: not a file")
                return "Error: not a file.", True
            with open(real, encoding="utf-8", errors="replace") as f:
                text = f.read(20000)
            self._log(name, args, "read")
            return text, False

        if name == "delete_file":
            if not os.path.isfile(real):
                self._log(name, args, "error: not a file")
                return "Error: not a file.", True
            os.makedirs(self.trash, exist_ok=True)
            target = os.path.join(self.trash, os.path.basename(real))
            shutil.move(real, target)
            self._log(name, args, "moved to .trash")
            return f"Deleted (moved to {target}).", False

        self._log(name, args, "error: unknown tool")
        return f"Error: unknown tool {name}.", True

    # ---- MCP / JSON-RPC -----------------------------------------------------
    def handle(self, msg: dict) -> dict | None:
        method = msg.get("method")
        msg_id = msg.get("id")
        if msg_id is None:
            return None  # notification (e.g. notifications/initialized): no reply

        if method == "initialize":
            requested = (msg.get("params") or {}).get("protocolVersion")
            return _result(msg_id, {
                "protocolVersion": requested or PROTOCOL_FALLBACK,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentgate-demo-server", "version": "0.1.0"},
            })
        if method == "ping":
            return _result(msg_id, {})
        if method == "tools/list":
            return _result(msg_id, {"tools": TOOLS})
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name", "")
            args = params.get("arguments") or {}
            text, is_error = self.call_tool(name, args)
            return _result(msg_id, {"content": [{"type": "text", "text": text}],
                                    "isError": is_error})
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": f"method not found: {method}"}}

    def serve(self) -> None:
        for raw in sys.stdin.buffer:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            reply = self.handle(msg)
            if reply is not None:
                sys.stdout.buffer.write((json.dumps(reply) + "\n").encode("utf-8"))
                sys.stdout.buffer.flush()


def _result(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentGate demo tool server")
    ap.add_argument("--root", required=True, help="demo folder (created by demo_setup.py)")
    args = ap.parse_args()
    if not os.path.isdir(args.root):
        print(f"demo folder not found: {args.root}", file=sys.stderr)
        return 1
    DemoServer(args.root).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
