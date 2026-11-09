"""Agent identity: agents as first-class security principals.

The research is blunt about this: most orgs run agents on shared service
accounts or borrowed human credentials, which destroys accountability. AgentGate
assigns each agent a distinct principal so every decision in the audit log is
attributable to a specific agent, not a human standing in for it.

Identity verification is PLUGGABLE via the `IdentityVerifier` interface. Two
verifiers ship in the box:

  HmacVerifier      stdlib-only, symmetric (shared secret). Fine for a single-
                    tenant self-host and for dev/test. Does NOT give
                    non-repudiation: anyone who can verify can also forge,
                    because the same secret signs and checks.

  Ed25519Verifier   asymmetric. The signer holds a private key; AgentGate holds
                    only the PUBLIC key, so the proxy can verify but cannot
                    forge. This is the production-appropriate choice and the
                    direction NIST's NCCoE agent-identity work points at (JWT-
                    SVID / SPIFFE use asymmetric signatures). Requires the
                    optional `cryptography` dependency: `pip install agentgate[crypto]`.

Token format (both verifiers): "<payload_hex>.<scheme>.<signature_hex>" where
scheme is "hmac-sha256" or "ed25519". Embedding the scheme lets a deployment
reject a downgrade (e.g. refuse hmac tokens when it expects ed25519).

# HARDENING:
#  - HmacVerifier is symmetric; for multi-tenant or zero-trust, use
#    Ed25519Verifier (or integrate a real SPIFFE/SPIRE workload API and verify
#    x509-SVID / JWT-SVID).
#  - Bind tokens to the transport to stop replay/relay (cf. MCP SEP-1932 DPoP /
#    SEP-1933 Workload Identity Federation). This module verifies the token's
#    authenticity and freshness, not its channel binding.
#  - Rotate keys; keep token lifetimes and `max_age_seconds` short.
#  - AgentGate: tokens carry signed iat/exp/jti; revocation by jti lives in
#    revocation.py and is checked on every request by the proxy.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Protocol


class IdentityError(Exception):
    pass


@dataclass(frozen=True)
class AgentIdentity:
    """A verified agent principal.

    `agent_id`  stable unique id for this agent (used in policy matching)
    `roles`     roles granted to the agent (e.g. "support-agent")
    `issued_at` unix seconds; used for staleness checks
    `claims`    any additional verified attributes
    """

    agent_id: str
    roles: frozenset[str]
    issued_at: float
    claims: dict[str, str]
    # AgentGate: signed expiry time and unique token id (used for revocation).
    expires_at: float = 0.0
    token_id: str = ""

    @staticmethod
    def anonymous() -> "AgentIdentity":
        """Fallback principal for unauthenticated calls.

        Policies can (and in a locked-down deployment, should) deny anything
        attributed to 'anonymous'. Failing closed on identity is a policy choice,
        not a hardcoded one, so the engine stays flexible.
        """
        return AgentIdentity(
            agent_id="anonymous",
            roles=frozenset(),
            issued_at=time.time(),
            claims={},
        )

    def has_role(self, role: str) -> bool:
        return role in self.roles


# --------------------------------------------------------------------------
# Token (de)serialization shared by all verifiers
# --------------------------------------------------------------------------

# AgentGate token payload (v2). Every field is inside the signed bytes, so no
# one can extend a token's life, change its roles, or swap its id without
# signing a new token.
DEFAULT_TOKEN_TTL_SECONDS = 3600.0
# Tolerated clock difference between the token issuer and AgentGate.
CLOCK_SKEW_SECONDS = 60.0
_MAX_TOKEN_ID_LEN = 128


def _encode_payload(agent_id: str, roles: list[str],
                    claims: dict[str, str] | None, *,
                    ttl_seconds: float = DEFAULT_TOKEN_TTL_SECONDS,
                    issued_at: float | None = None,
                    token_id: str | None = None) -> bytes:
    iat = time.time() if issued_at is None else float(issued_at)
    payload = {
        "v": 2,
        "agent_id": agent_id,
        "roles": sorted(roles),
        "iat": iat,
        "exp": iat + float(ttl_seconds),
        "jti": token_id or secrets.token_hex(16),
        "claims": claims or {},
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def _split_token(token: str) -> tuple[bytes, str, str]:
    """Return (raw_payload_bytes, scheme, signature_hex)."""
    try:
        raw_hex, scheme, sig = token.split(".", 2)
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise IdentityError("malformed identity token") from exc
    return raw, scheme, sig


def _number(payload: dict, key: str) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value):
        raise IdentityError("invalid identity token")
    return float(value)


def check_token_times(iat: float, exp: float, max_age_seconds: float | None,
                      now: float | None = None) -> None:
    """AgentGate: the token's own times must be consistent AND within limits.

    The issuer chooses iat/exp, so they are not trusted blindly:
      * issued in the future (beyond clock skew)  -> rejected
      * expires at or before it was issued         -> rejected
      * lifetime (exp - iat) above the maximum     -> rejected, so an issuer
        cannot exceed AgentGate's limit by picking a far-away exp or an
        odd iat
      * already expired                            -> rejected
    """
    now = time.time() if now is None else now
    if iat > now + CLOCK_SKEW_SECONDS:
        raise IdentityError("identity token is issued in the future")
    if exp <= iat:
        raise IdentityError("identity token has inconsistent times")
    if max_age_seconds is not None and exp - iat > max_age_seconds:
        raise IdentityError("identity token lifetime exceeds the allowed maximum")
    if now >= exp:
        raise IdentityError("identity token expired")


def _payload_to_identity(raw: bytes, max_age_seconds: float | None) -> AgentIdentity:
    """Parse a SIGNED payload. Anything unexpected is an IdentityError."""
    try:
        payload = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityError("invalid identity token") from exc
    if not isinstance(payload, dict) or payload.get("v") != 2:
        # Tokens from before AgentGate v2 have no exp/jti: refused.
        raise IdentityError("unsupported identity token format (issue a new token)")
    agent_id = payload.get("agent_id")
    roles = payload.get("roles", [])
    jti = payload.get("jti")
    claims = payload.get("claims", {})
    if not isinstance(agent_id, str) or not agent_id \
            or not isinstance(roles, list) or not all(isinstance(r, str) for r in roles) \
            or not isinstance(jti, str) or not 0 < len(jti) <= _MAX_TOKEN_ID_LEN \
            or not isinstance(claims, dict):
        raise IdentityError("invalid identity token")
    iat = _number(payload, "iat")
    exp = _number(payload, "exp")
    check_token_times(iat, exp, max_age_seconds)
    return AgentIdentity(
        agent_id=agent_id,
        roles=frozenset(roles),
        issued_at=iat,
        claims={str(k): str(v) for k, v in claims.items()},
        expires_at=exp,
        token_id=jti,
    )


# --------------------------------------------------------------------------
# Verifier interface + implementations
# --------------------------------------------------------------------------

class IdentityVerifier(Protocol):
    scheme: str
    def verify(self, token: str,
               max_age_seconds: float | None = None) -> AgentIdentity: ...


class HmacVerifier:
    """Symmetric HMAC-SHA256 verifier. stdlib-only. Dev / single-tenant."""

    scheme = "hmac-sha256"

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise IdentityError("HMAC secret must be non-empty")
        self._secret = secret

    def sign(self, agent_id: str, roles: list[str],
             claims: dict[str, str] | None = None, **times) -> str:
        raw = _encode_payload(agent_id, roles, claims, **times)
        sig = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
        return f"{raw.hex()}.{self.scheme}.{sig}"

    def sign_bytes(self, data: bytes) -> str:
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def verify_bytes(self, data: bytes, sig_hex: str) -> None:
        if not isinstance(sig_hex, str) or not hmac.compare_digest(
                self.sign_bytes(data), sig_hex):
            raise IdentityError("signature mismatch")

    def verify(self, token: str,
               max_age_seconds: float | None = None) -> AgentIdentity:
        raw, scheme, sig = _split_token(token)
        if scheme != self.scheme:
            raise IdentityError(
                f"expected scheme {self.scheme}, got {scheme} (downgrade refused)")
        expected = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):  # constant-time
            raise IdentityError("identity token signature mismatch")
        return _payload_to_identity(raw, max_age_seconds)


class Ed25519Verifier:
    """Asymmetric Ed25519 verifier. Proxy holds only the PUBLIC key.

    Requires the optional `cryptography` dependency. Construct from a 32-byte
    raw public key, or use `from_public_pem` / `from_public_hex`.
    """

    scheme = "ed25519"

    def __init__(self, public_key_bytes: bytes) -> None:
        pub = self._load_public(public_key_bytes)
        self._pub = pub

    @staticmethod
    def _crypto():
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.exceptions import InvalidSignature
            return ed25519, InvalidSignature
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise IdentityError(
                "Ed25519 identity requires the 'cryptography' package; "
                "install with: pip install agentgate[crypto]") from exc

    @classmethod
    def _load_public(cls, raw: bytes):
        ed25519, _ = cls._crypto()
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)

    @classmethod
    def from_public_hex(cls, hex_str: str) -> "Ed25519Verifier":
        return cls(bytes.fromhex(hex_str))

    def verify(self, token: str,
               max_age_seconds: float | None = None) -> AgentIdentity:
        _, InvalidSignature = self._crypto()
        raw, scheme, sig = _split_token(token)
        if scheme != self.scheme:
            raise IdentityError(
                f"expected scheme {self.scheme}, got {scheme} (downgrade refused)")
        try:
            self._pub.verify(bytes.fromhex(sig), raw)
        except (InvalidSignature, ValueError) as exc:
            raise IdentityError("ed25519 signature verification failed") from exc
        return _payload_to_identity(raw, max_age_seconds)

    def verify_bytes(self, data: bytes, sig_hex: str) -> None:
        _, InvalidSignature = self._crypto()
        try:
            self._pub.verify(bytes.fromhex(sig_hex), data)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise IdentityError("ed25519 signature verification failed") from exc


class Ed25519Signer:
    """Holds a PRIVATE key to mint tokens. Lives with the agent, NOT the proxy.

    Provided so you can issue tokens and run the asymmetric path end-to-end.
    Keep private keys off the AgentGate host.
    """

    scheme = "ed25519"

    def __init__(self, private_key_bytes: bytes) -> None:
        ed25519, _ = Ed25519Verifier._crypto()
        self._priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        ed25519, _ = Ed25519Verifier._crypto()
        from cryptography.hazmat.primitives import serialization
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cls(raw)

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization
        pub = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub.hex()

    def sign(self, agent_id: str, roles: list[str],
             claims: dict[str, str] | None = None, **times) -> str:
        raw = _encode_payload(agent_id, roles, claims, **times)
        sig = self._priv.sign(raw).hex()
        return f"{raw.hex()}.{self.scheme}.{sig}"

    def sign_bytes(self, data: bytes) -> str:
        return self._priv.sign(data).hex()

    def verifier(self) -> "Ed25519Verifier":
        return Ed25519Verifier.from_public_hex(self.public_key_hex())


# --------------------------------------------------------------------------
# Backward-compatible convenience functions (HMAC), used by CLI/tests
# --------------------------------------------------------------------------

def issue_token(secret: bytes, agent_id: str, roles: list[str],
                claims: dict[str, str] | None = None, **times) -> str:
    """Mint an HMAC-signed identity token. Convenience wrapper."""
    return HmacVerifier(secret).sign(agent_id, roles, claims, **times)


def token_id_of(token: str) -> str:
    """Read a token's id WITHOUT verifying it (for building revocation lists)."""
    raw, _, _ = _split_token(token)
    try:
        jti = json.loads(raw.decode()).get("jti")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise IdentityError("invalid identity token") from exc
    if not isinstance(jti, str) or not jti:
        raise IdentityError("token has no id (issue a new token)")
    return jti


def verify_token(secret: bytes, token: str,
                 max_age_seconds: float | None = None) -> AgentIdentity:
    """Verify an HMAC-signed token. Convenience wrapper."""
    return HmacVerifier(secret).verify(token, max_age_seconds)
