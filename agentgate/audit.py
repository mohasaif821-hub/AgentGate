# Modified for AgentGate by Mohammed Jadulhaqq, 2026.
# Based on mcp-gate (https://github.com/rsh1k/mcp-gate), Copyright 2026 The mcp-gate Authors.
# AgentGate changes in this file:
#   Records the mode (enforce/monitor) and the token id of each decision.
#   Safe with several AgentGate processes on one log (file lock, continues
#   from the file's real last record) and refuses to write when the log was
#   replaced, emptied or removed under a running process (AuditLogError).
# SPDX-License-Identifier: Apache-2.0
"""Audit log: tamper-evident, append-only, and compliance-shaped.

Every decision — allow, deny, approval, redact — is written here. Two design
choices make this more than a log file:

1. Hash chaining. Each record includes the SHA-256 of the previous record. Any
   edit or deletion of a past record breaks the chain and is detectable by
   verify(). This gives you tamper-EVIDENCE (not tamper-proofing; for that you
   anchor the chain head externally — see HARDENING note).

2. Compliance-shaped fields. Each record captures who (agent identity), what
   (tool + arguments hash), when, under which policy version, what decision, and
   why. That maps directly onto the audit-trail and decision-explainability
   obligations enterprises are scrambling to meet before the EU AI Act's
   high-risk provisions take effect (August 2026). The same enforcement stream
   becomes your evidence generator.

# HARDENING:
#  - Argument VALUES are hashed, not stored, by default, to avoid persisting PII
#    in the audit log. If you need full payloads for forensics, store them in a
#    separate, access-controlled, encrypted sink — never the same file.
#  - For true tamper-proofing, periodically publish the latest chain head hash
#    to an external write-once medium (e.g. a transparency log, object storage
#    with object-lock, or a notary service). The chain proves internal
#    consistency; the external anchor proves nothing was truncated.
#  - AgentGate: several processes may write the same file. Each write takes
#    a lock on <log>.lock and continues from the file's real last record. If
#    the file was replaced (renamed away, deleted, emptied, or cut back) while
#    a process was running, that process refuses to write (AuditLogError)
#    instead of breaking the chain, and the call is refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .decision import Decision
from .identity import AgentIdentity

GENESIS = "0" * 64
LOCK_TIMEOUT = 10.0  # seconds to wait for another process holding the log


class AuditLogError(RuntimeError):
    """AgentGate: the audit log can't be written safely. Callers refuse the call."""


@contextmanager
def _file_lock(lock_path: Path, timeout: float = LOCK_TIMEOUT):
    """AgentGate: exclusive lock between processes, on a separate lock file."""
    deadline = time.monotonic() + timeout
    fh = open(lock_path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AuditLogError("audit log is locked by another process")
                    time.sleep(0.02)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AuditLogError("audit log is locked by another process")
                    time.sleep(0.02)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def _last_line(path: Path) -> str | None:
    """AgentGate: the last non-empty line, read from the end of the file."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        chunk = 4096
        while True:
            start = max(0, end - chunk)
            fh.seek(start)
            data = fh.read(end - start).rstrip(b"\r\n \t")
            if not data:
                return None
            nl = data.rfind(b"\n")
            if nl != -1 or start == 0:
                return data[nl + 1:].decode("utf-8").strip() or None
            chunk *= 2


def _file_id(st: os.stat_result) -> tuple[int, int] | None:
    # st_ino can be 0 on some file systems; then only the record check applies.
    return (st.st_dev, st.st_ino) if st.st_ino else None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_args(args: dict[str, Any]) -> str:
    """Stable hash of arguments without storing their (possibly sensitive) values."""
    canonical = json.dumps(args or {}, separators=(",", ":"), sort_keys=True,
                           default=str).encode()
    return _sha256_hex(canonical)


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    timestamp: float
    session_id: str
    agent_id: str
    agent_roles: list[str]
    tool: str
    args_hash: str
    decision: dict[str, Any]
    policy_name: str
    policy_version: str
    prev_hash: str
    # AgentGate: "enforce" or "monitor". In monitor mode the decision was
    # recorded but NOT applied, so an auditor must be able to tell them apart.
    mode: str = "enforce"
    # AgentGate: id of the token the agent used, so a misused token can be
    # found in the log and revoked. Empty for anonymous agents.
    token_id: str = ""

    def body(self) -> dict[str, Any]:
        # Everything EXCEPT this record's own hash. The hash is computed over
        # this body, so it can't include itself.
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "agent_roles": self.agent_roles,
            "tool": self.tool,
            "args_hash": self.args_hash,
            "decision": self.decision,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "prev_hash": self.prev_hash,
            "mode": self.mode,
            "token_id": self.token_id,
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(self.body(), separators=(",", ":"),
                               sort_keys=True).encode()
        return _sha256_hex(canonical)


class AuditLog:
    """Append-only JSONL audit log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._seq, self._last_hash = self._recover_state()
        # AgentGate: which file this process is writing, once it exists.
        self._file = _file_id(self.path.stat()) if self.path.exists() else None

    def _recover_state(self) -> tuple[int, str]:
        """On startup, read the tail to continue the chain across restarts."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last_line = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return 0, GENESIS
        rec = json.loads(last_line)
        return int(rec["seq"]) + 1, str(rec["hash"])

    def _sync_with_file(self) -> None:
        """AgentGate: continue from the file's real last record, or refuse.

        Called with the file lock held, right before each write. Another
        AgentGate process may have appended since our last write; that is fine
        and the chain simply continues from its record. But if the file we were
        writing was renamed away, deleted, emptied or cut back, writing would
        break the chain, so we refuse instead.
        """
        known = self._file is not None or self._seq > 0
        if not self.path.exists():
            if known:
                raise AuditLogError("audit log file is missing; restart AgentGate")
            return
        fid = _file_id(self.path.stat())
        if self._file is not None and fid is not None and fid != self._file:
            raise AuditLogError("audit log file was replaced; restart AgentGate")
        line = _last_line(self.path)
        if line is None:
            if self._seq > 0:
                raise AuditLogError("audit log file was emptied; restart AgentGate")
            return
        try:
            rec = json.loads(line)
            stored = rec.pop("hash")
            ok = _sha256_hex(json.dumps(rec, separators=(",", ":"),
                                        sort_keys=True).encode()) == stored
            tail_seq = int(rec["seq"])
        except Exception as exc:
            raise AuditLogError(f"last audit record is unreadable: {exc}") from None
        if not ok:
            raise AuditLogError("last audit record does not verify")
        if tail_seq < self._seq - 1 or (tail_seq == self._seq - 1
                                        and stored != self._last_hash):
            raise AuditLogError("audit log no longer continues this process's "
                                "chain; restart AgentGate")
        self._seq, self._last_hash = tail_seq + 1, stored

    def record(self, *, session_id: str, identity: AgentIdentity, tool: str,
               args: dict[str, Any], decision: Decision,
               policy_name: str, policy_version: str,
               mode: str = "enforce") -> AuditRecord:
        with self._lock, _file_lock(self._lock_path):
            self._sync_with_file()
            rec = AuditRecord(
                seq=self._seq,
                timestamp=time.time(),
                session_id=session_id,
                agent_id=identity.agent_id,
                agent_roles=sorted(identity.roles),
                tool=tool,
                args_hash=_hash_args(args),
                decision=decision.to_audit_dict(),
                policy_name=policy_name,
                policy_version=policy_version,
                prev_hash=self._last_hash,
                mode=mode,
                token_id=getattr(identity, "token_id", ""),
            )
            rec_hash = rec.compute_hash()
            line = json.dumps({**rec.body(), "hash": rec_hash},
                              separators=(",", ":"), sort_keys=True)
            # Append + fsync so a crash can't lose an acknowledged decision.
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._file = _file_id(self.path.stat())
            self._seq += 1
            self._last_hash = rec_hash
            return rec

    def verify(self) -> tuple[bool, str]:
        """Re-walk the whole chain. Returns (ok, message).

        Detects: edited records, reordering, deletions, and a broken prev_hash
        link. This is what you run to PROVE the log wasn't tampered with.
        AgentGate note: records cut from the END leave a valid, shorter chain;
        only an externally kept copy of the last hash can show that.
        """
        if not self.path.exists():
            return True, "empty log"
        prev = GENESIS
        expected_seq = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                stored_hash = rec.pop("hash")
                if int(rec["seq"]) != expected_seq:
                    return False, f"seq gap at line {lineno}: {rec['seq']} != {expected_seq}"
                if rec["prev_hash"] != prev:
                    return False, f"chain break at line {lineno} (seq {rec['seq']})"
                recomputed = _sha256_hex(
                    json.dumps(rec, separators=(",", ":"), sort_keys=True).encode()
                )
                if recomputed != stored_hash:
                    return False, f"hash mismatch at line {lineno} (seq {rec['seq']})"
                prev = stored_hash
                expected_seq += 1
        return True, f"chain valid: {expected_seq} records"

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
