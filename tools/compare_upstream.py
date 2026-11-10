# AgentGate. Copyright 2026 Mohammed Jadulhaqq.
# SPDX-License-Identifier: Apache-2.0
"""Measure how much AgentGate's Python code differs from its mcp-gate baseline.

This is the tool behind the "Built on mcp-gate" numbers in docs/REPORT.md.
It is a measuring aid, not part of AgentGate, and it is not counted itself.

    git clone https://github.com/rsh1k/mcp-gate upstream
    git -C upstream checkout ae0e045
    python tools/compare_upstream.py upstream

What it counts (non-blank lines of Python only):
  * mcp-gate side: every .py file except scripts/ (a publishing helper that
    AgentGate dropped; its copy is kept in docs/upstream-archive/).
  * AgentGate side: every .py file except tools/ and docs/upstream-archive/.
  * The licence-notice lines AgentGate added at the top of files are left out,
    so they don't inflate the numbers.
  * agentgate/ is compared with mcpgate/ (the same package, renamed).
  * A changed line counts once as removed and once as added (git diff --numstat).
  * "rename only": a file whose only change is the package rename.

Needs git on PATH (for git diff --no-index). Reads files, writes nothing except
a temporary folder that is removed at the end.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASELINE = "ae0e045"
HEADER = ("# Modified for AgentGate", "# Based on mcp-gate", "# AgentGate changes in this file",
          "#   ", "# SPDX-License-Identifier", "# AgentGate. Copyright")


def strip_header(text: str) -> str:
    """Drop the licence-notice block AgentGate put at the top of a file."""
    out, in_head = [], True
    for i, line in enumerate(text.split("\n")):
        if in_head and i == 0 and line.startswith("#!"):
            out.append(line)
            continue
        if in_head and line.startswith(HEADER):
            continue
        in_head = False
        out.append(line)
    return "\n".join(out)


def nonblank(text: str) -> int:
    return sum(1 for line in text.split("\n") if line.strip())


def numstat(old: str, new: str, tmp: Path) -> tuple[int, int]:
    a, b = tmp / "a.py", tmp / "b.py"
    a.write_text(old, encoding="utf-8")
    b.write_text(new, encoding="utf-8")
    out = subprocess.run(["git", "diff", "--no-index", "--numstat", "--ignore-blank-lines",
                          str(a), str(b)], capture_output=True, text=True).stdout.split()
    return (int(out[0]), int(out[1])) if out else (0, 0)


def python_files(root: Path, skip: tuple[str, ...]) -> dict[str, Path]:
    files = {}
    for p in root.rglob("*.py"):
        rel = p.relative_to(root).as_posix()
        parts = p.relative_to(root).parts
        if ".git" in parts or "__pycache__" in parts or rel.startswith(skip):
            continue
        files[rel] = p
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("upstream", help=f"a checkout of mcp-gate at commit {BASELINE}")
    ap.add_argument("--agentgate", default=str(Path(__file__).resolve().parent.parent),
                    help="AgentGate folder (default: this repository)")
    args = ap.parse_args()
    up_root, ag_root = Path(args.upstream).resolve(), Path(args.agentgate).resolve()

    head = subprocess.run(["git", "-C", str(up_root), "rev-parse", "--short=7", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    if head != BASELINE:
        print(f"warning: upstream is at {head or 'unknown'}, the report uses {BASELINE}",
              file=sys.stderr)

    up = python_files(up_root, ("scripts/",))
    ag = {rel.replace("agentgate/", "mcpgate/", 1): p
          for rel, p in python_files(ag_root, ("tools/", "docs/upstream-archive/")).items()}

    read = lambda p: p.read_text(encoding="utf-8")
    total_up = sum(nonblank(read(p)) for p in up.values())
    total_ag = sum(nonblank(strip_header(read(p))) for p in ag.values())
    new = sorted(set(ag) - set(up))
    common = sorted(set(ag) & set(up))
    new_lines = sum(nonblank(strip_header(read(ag[f]))) for f in new)

    added = removed = modified = unchanged = rename_only = 0
    tmp = Path(tempfile.mkdtemp())
    try:
        for f in common:
            old, cur = read(up[f]), strip_header(read(ag[f]))
            x, y = numstat(old, cur, tmp)
            added += x
            removed += y
            if not (x or y):
                unchanged += 1
                continue
            modified += 1
            # rename only = identical once the project name is spelled one way
            same = lambda t: t.lower().replace("mcp-gate", "agentgate").replace("mcpgate", "agentgate")
            if numstat(same(old), same(cur), tmp) == (0, 0):
                rename_only += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ours = new_lines + added
    print(f"baseline: mcp-gate {BASELINE}")
    print(f"mcp-gate  python files {len(up)}, non-blank lines {total_up:,}")
    print(f"AgentGate python files {len(ag)}, non-blank lines {total_ag:,} "
          f"({total_ag / total_up:.2f}x)")
    print(f"new files {len(new)}, lines {new_lines:,}")
    print(f"original files changed {modified} of {len(common)} "
          f"(rename only: {rename_only}), unchanged {unchanged}")
    print(f"lines added in original files {added:,}, removed {removed:,}")
    print(f"added or changed lines {ours:,} = {100 * ours / total_ag:.1f}% of current code")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
