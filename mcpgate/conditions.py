"""Conditions: a small, SAFE predicate language over tool-call arguments.

Policies need to say things like "amount under 500" or "path starts with /tmp".
The unsafe way to do that is eval() on a string — which would hand arbitrary
code execution to whoever writes policy, defeating the entire purpose. Instead
this module defines a tiny declarative condition tree built from plain
dicts/lists in the policy file. There is NO code execution anywhere here.

Condition forms (as they appear under a rule's `when:` key):

  {"field": "amount", "op": "lt", "value": 500}
  {"field": "path", "op": "startswith", "value": "/etc"}
  {"all": [ {...}, {...} ]}          # logical AND
  {"any": [ {...}, {...} ]}          # logical OR
  {"not": {...}}                     # negation

`field` is a dotted path into the call arguments, e.g. "filters.region".
Supported ops: eq ne lt le gt ge in not_in contains startswith endswith
               regex exists within not_within

AgentGate path ops (use these for file paths, not startswith):

  {"field": "path", "op": "within", "value": "./workspace"}
  {"field": "path", "op": "not_within", "value": ["/etc", "/var/secrets"]}

`within` resolves the REAL path first: "..", "." and symlinks are followed,
then the result is compared with the real path of each base folder. So
"./workspace/../../etc/passwd" is NOT within ./workspace, and a symlink inside
the workspace that points outside it is NOT within it either. `startswith`
only compares text and is fooled by both tricks.

Fail-safe: a value that is not a string, or a path that cannot be resolved,
counts as NOT within. So `within` fails (an allow rule does not match) and
`not_within` succeeds (a deny rule does match).

Limits (stated, not hidden):
  * Relative paths resolve against AgentGate's working directory. Run AgentGate
    from the same folder the tool server uses, or use absolute paths.
  * The check happens at decision time. If the file or a symlink changes
    between the check and the tool server running the call (TOCTOU), the
    server may touch a different file. See the AgentGate threat model.

# HARDENING: the regex op compiles user-supplied patterns. A pathological
# pattern can cause ReDoS. Before production, compile with a timeout (e.g. the
# `regex` module's timeout arg) or restrict regex to an allowlist of patterns.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from .errors import PolicyError  # noqa: F401


class _ConditionError(Exception):
    pass


def _resolve(path: str, args: dict[str, Any]) -> tuple[bool, Any]:
    """Resolve a dotted path. Returns (found, value)."""
    cur: Any = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


class Condition:
    """Base condition. Subclasses implement evaluate()."""

    def evaluate(self, args: dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError


@dataclass(frozen=True)
class AlwaysTrue(Condition):
    def evaluate(self, args: dict[str, Any]) -> bool:
        return True


@dataclass(frozen=True)
class Comparison(Condition):
    field: str
    op: str
    value: Any = None

    def evaluate(self, args: dict[str, Any]) -> bool:
        found, actual = _resolve(self.field, args)

        if self.op == "exists":
            return found
        if not found:
            # A missing field can never satisfy a value comparison. This is a
            # deliberate fail-safe: absent data does not accidentally match.
            return False

        op = self.op
        v = self.value
        try:
            if op == "eq":
                return actual == v
            if op == "ne":
                return actual != v
            if op == "lt":
                return _num(actual) < _num(v)
            if op == "le":
                return _num(actual) <= _num(v)
            if op == "gt":
                return _num(actual) > _num(v)
            if op == "ge":
                return _num(actual) >= _num(v)
            if op == "in":
                return actual in v
            if op == "not_in":
                return actual not in v
            if op == "contains":
                return v in actual
            if op == "startswith":
                return str(actual).startswith(str(v))
            if op == "endswith":
                return str(actual).endswith(str(v))
            if op == "regex":
                return re.search(str(v), str(actual)) is not None
            if op == "within":
                return _is_within(actual, v) is True
            if op == "not_within":
                return _is_within(actual, v) is not True
        except (TypeError, ValueError):
            # Type mismatch (e.g. lt on a string) => condition simply fails.
            # It does NOT crash the proxy. Failing the condition is safer than
            # failing the request open.
            return False

        raise _ConditionError(f"unknown op: {op}")


def _real(path: str) -> str:
    """Absolute, symlink-resolved, case-normalized path (case-insensitive on Windows)."""
    return os.path.normcase(os.path.realpath(path))


def _is_within(candidate: Any, bases: Any) -> bool | None:
    """True if candidate's real path is inside one of the base folders.

    Returns None when the answer cannot be trusted (not a string, bad path);
    callers treat None as "not within".
    """
    if not isinstance(candidate, str) or not candidate:
        return None
    if isinstance(bases, str):
        bases = [bases]
    if not isinstance(bases, (list, tuple)) or not bases:
        return None
    try:
        real = _real(candidate)
        for base in bases:
            root = _real(str(base))
            try:
                if os.path.commonpath([real, root]) == root:
                    return True
            except ValueError:
                # Different drives on Windows: cannot be inside this base.
                continue
        return False
    except (OSError, ValueError):
        # e.g. an embedded NUL byte: refuse to guess.
        return None


def _num(x: Any) -> float:
    if isinstance(x, bool):  # bool is a subclass of int; reject to avoid surprises
        raise ValueError("bool not comparable as number")
    return float(x)


@dataclass(frozen=True)
class And(Condition):
    parts: tuple[Condition, ...]

    def evaluate(self, args: dict[str, Any]) -> bool:
        return all(p.evaluate(args) for p in self.parts)


@dataclass(frozen=True)
class Or(Condition):
    parts: tuple[Condition, ...]

    def evaluate(self, args: dict[str, Any]) -> bool:
        return any(p.evaluate(args) for p in self.parts)


@dataclass(frozen=True)
class Not(Condition):
    inner: Condition

    def evaluate(self, args: dict[str, Any]) -> bool:
        return not self.inner.evaluate(args)


_VALID_OPS = {
    "eq", "ne", "lt", "le", "gt", "ge", "in", "not_in",
    "contains", "startswith", "endswith", "regex", "exists",
    "within", "not_within",
}


def parse_condition(raw: Any) -> Condition:
    """Build a Condition tree from plain data. Raises PolicyError on bad input."""
    from .errors import PolicyError as PE

    if raw is None:
        return AlwaysTrue()
    if not isinstance(raw, dict):
        raise PE(f"condition must be a mapping, got {type(raw).__name__}")

    if "all" in raw:
        return And(tuple(parse_condition(p) for p in raw["all"]))
    if "any" in raw:
        return Or(tuple(parse_condition(p) for p in raw["any"]))
    if "not" in raw:
        return Not(parse_condition(raw["not"]))

    if "field" in raw and "op" in raw:
        op = raw["op"]
        if op not in _VALID_OPS:
            raise PE(f"unknown condition op {op!r}; valid: {sorted(_VALID_OPS)}")
        return Comparison(field=str(raw["field"]), op=op, value=raw.get("value"))

    raise PE(f"unrecognized condition shape: {raw!r}")
