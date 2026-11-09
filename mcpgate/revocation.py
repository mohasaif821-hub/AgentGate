"""AgentGate: signed token revocation list, checked on every request.

A stolen token stays usable until it expires, unless it can be revoked. The
revocation list names revoked tokens by their id (jti), never by agent, so
revoking one token leaves the agent's other tokens working.

File format (JSON):

    {
      "format": "agentgate-revocation-list",
      "scheme": "ed25519",
      "version": 3,
      "revoked": ["9f2c...", "a71b..."],
      "signature": "<hex>"
    }

The signature covers a fixed prefix plus the canonical {"revoked", "version"},
using the same key that signs identity tokens. The prefix keeps a list
signature and a token signature from ever being swapped for one another.

What this protects against, and what it does not:

  * Editing the list (for example removing a stolen token's id) breaks the
    signature: every request is then refused.
  * A missing, unreadable or badly signed list: every request is refused.
  * Putting back an OLDER signed list (rollback): AgentGate keeps the highest
    version it has trusted in a separate state file and in memory, and refuses
    any list older than that.
  * NOT covered: someone with the rights of the account or machine running
    AgentGate can change the state file and the list together, or the clock.
    On a single Windows account this stops unsigned changes, not an attacker
    who already owns that account.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .identity import IdentityError

FORMAT = "agentgate-revocation-list"
_PREFIX = b"agentgate-revocation-list-v1\n"


def _signed_bytes(version: int, revoked: list[str]) -> bytes:
    body = json.dumps({"revoked": sorted(revoked), "version": version},
                      separators=(",", ":"), sort_keys=True).encode()
    return _PREFIX + body


def _valid_version(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def build_list(signer, version: int, revoked: list[str]) -> dict[str, Any]:
    """Create a signed revocation list document (signer holds the PRIVATE key)."""
    if not _valid_version(version):
        raise ValueError("version must be an integer >= 1")
    ids = sorted(set(revoked))
    return {
        "format": FORMAT,
        "scheme": signer.scheme,
        "version": version,
        "revoked": ids,
        "signature": signer.sign_bytes(_signed_bytes(version, ids)),
    }


def parse_list(text: str, verifier) -> tuple[int, frozenset[str]]:
    """Verify a revocation list. Returns (version, revoked ids) or raises."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IdentityError("revocation list is not valid JSON") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise IdentityError("not an AgentGate revocation list")
    if doc.get("scheme") != verifier.scheme:
        raise IdentityError("revocation list uses the wrong signature scheme")
    version, revoked = doc.get("version"), doc.get("revoked")
    if not _valid_version(version) or not isinstance(revoked, list) \
            or not all(isinstance(x, str) and x for x in revoked):
        raise IdentityError("revocation list is malformed")
    verifier.verify_bytes(_signed_bytes(version, revoked), doc.get("signature"))
    return version, frozenset(revoked)


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class RevocationChecker:
    """Checks a token id against the signed list, refusing rollbacks.

    Raises IdentityError at construction if the list or state is unusable, so
    AgentGate refuses to start; `check()` raises on every later problem, so the
    request is refused.
    """

    def __init__(self, list_path: str | Path, state_path: str | Path, verifier) -> None:
        self.list_path = Path(list_path)
        self.state_path = Path(state_path)
        self.verifier = verifier
        self._lock = threading.Lock()
        trusted = self._read_state()
        version, _ = self._load()
        if trusted is not None and version < trusted:
            raise IdentityError("revocation list is older than the last trusted "
                                "version (rollback refused)")
        self._highest = version if trusted is None else max(version, trusted)
        if trusted is None or version > trusted:
            self._save_state(self._highest)

    def _read_state(self) -> int | None:
        if not self.state_path.exists():
            return None  # first start: trust the list as it is now
        try:
            v = json.loads(self.state_path.read_text(encoding="utf-8")).get("trusted_version")
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            raise IdentityError("revocation state file is unreadable") from exc
        if not _valid_version(v):
            raise IdentityError("revocation state file is malformed")
        return v

    def _save_state(self, version: int) -> None:
        try:
            write_atomic(self.state_path,
                         json.dumps({"trusted_version": version}) + "\n")
        except OSError as exc:
            raise IdentityError("could not save revocation state") from exc

    def _load(self) -> tuple[int, frozenset[str]]:
        try:
            text = self.list_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise IdentityError("revocation list is missing or unreadable") from exc
        return parse_list(text, self.verifier)

    def check(self, token_id: str) -> None:
        """Raise IdentityError if the token is revoked or the list can't be trusted."""
        with self._lock:
            version, revoked = self._load()
            if version < self._highest:
                raise IdentityError("revocation list is older than the last "
                                    "trusted version (rollback refused)")
            if version > self._highest:
                self._save_state(version)
                self._highest = version
        if not token_id or token_id in revoked:
            raise IdentityError("identity token has been revoked")
