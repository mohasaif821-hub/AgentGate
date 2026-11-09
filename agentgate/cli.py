"""Command-line interface for AgentGate.

Subcommands:
  run       launch the stdio proxy in front of an upstream MCP server
  check     validate a policy file (catches errors before deploy)
  verify    verify the integrity of an audit log's hash chain
  token     mint an agent identity token (dev/testing convenience)

Example (wrapping a filesystem MCP server):
  agentgate run --policy policy.yaml --audit audit.jsonl --fail closed \\
      -- npx @modelcontextprotocol/server-filesystem /data
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .audit import AuditLog
from .enforce import FailMode
from .engine import PolicyEngine
from .errors import PolicyError
from .gate import Gate
from .identity import issue_token
from .policy import load_policy
from .stdio_proxy import StdioProxy

log = logging.getLogger("agentgate")


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    if policy.default_effect.value == "allow":
        print("WARNING: default_effect is 'allow' — this fails OPEN on unmatched "
              "calls. Prefer 'deny' for a locked-down posture.", file=sys.stderr)
    for warning in least_privilege_warnings(policy):
        print(f"WARNING: {warning}", file=sys.stderr)
    print(f"OK: '{policy.name}' v{policy.version}, {len(policy.rules)} rules, "
          f"default={policy.default_effect.value}")
    return 0


def least_privilege_warnings(policy) -> list[str]:
    """AgentGate: flag rules that grant something to EVERY agent.

    Least privilege means each agent gets only what its role needs. A rule that
    lets any agent (agents "*" and no required role) through, even with
    conditions, is a broad grant worth a second look. Deny rules are fine.
    """
    out = []
    for rule in policy.rules:
        if rule.effect.value == "deny":
            continue
        if "*" in rule.agents and not rule.require_roles:
            out.append(f"rule '{rule.id}' ({rule.effect.value}) applies to every "
                       "agent: least privilege suggests limiting it with "
                       "'agents' or 'require_roles'")
    return out


def _cmd_verify(args: argparse.Namespace) -> int:
    ok, msg = AuditLog(args.audit).verify()
    print(("OK: " if ok else "TAMPER DETECTED: ") + msg,
          file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 2


def _cmd_report(args: argparse.Namespace) -> int:
    from .report import generate_report
    md = generate_report(args.audit)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"wrote compliance report to {args.out}")
    else:
        print(md)
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    """AgentGate: static HTML dashboard built from the audit log."""
    from pathlib import Path
    from .dashboard import generate_dashboard
    Path(args.out).write_text(generate_dashboard(args.audit, args.lang), encoding="utf-8")
    print(f"wrote dashboard to {args.out} (open it in a browser; run again to refresh)")
    return 0


def _cmd_controls(args: argparse.Namespace) -> int:
    from .regulatory import render_markdown, render_text
    fw = None if args.framework == "all" else args.framework
    if args.format == "markdown":
        if args.out:  # write UTF-8 directly (PowerShell's ">" would write UTF-16)
            from pathlib import Path
            Path(args.out).write_text(render_markdown(fw) + "\n", encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(render_markdown(fw))
        return 0
    if fw is None:
        from .compliance import render_markdown_table, coverage_summary
        print("NIST / NCCoE / OWASP map inherited from mcp-gate (not re-verified by AgentGate):")
        print(render_markdown_table())
        cov = coverage_summary()
        print("\nOWASP ASI addressed:", ", ".join(cov["owasp_asi_addressed"]))
        print("NCCoE pillars addressed:", ", ".join(cov["nccoe_pillars_addressed"]))
        print("\nAgentGate regulatory mapping (NCA / SAMA / OWASP), checked against official sources:")
    print(render_text(fw))
    print("\nAgentGate SUPPORTS these controls; it does not make an organisation compliant.")
    return 0


def _cmd_token(args: argparse.Namespace) -> int:
    if args.scheme == "ed25519":
        from .identity import Ed25519Signer
        key_hex = _private_key_hex(args)
        if not key_hex:
            print("ed25519 tokens require --private-key-file or --private-key (hex)",
                  file=sys.stderr)
            return 1
        signer = Ed25519Signer(bytes.fromhex(key_hex))
        print(signer.sign(args.agent_id, args.role or [], None, ttl_seconds=args.ttl))
    else:
        if not args.secret:
            print("hmac tokens require --secret", file=sys.stderr)
            return 1
        print(issue_token(args.secret.encode(), args.agent_id, args.role or [], None,
                          ttl_seconds=args.ttl))
    return 0


def _private_key_hex(args: argparse.Namespace) -> str | None:
    """--private-key-file keeps the key off the command line (process list)."""
    path = getattr(args, "private_key_file", None)
    if path:
        from pathlib import Path
        return Path(path).read_text(encoding="utf-8").strip()
    return args.private_key


def _signer_from_args(args: argparse.Namespace):
    if args.scheme == "ed25519":
        from .identity import Ed25519Signer
        key_hex = _private_key_hex(args)
        if not key_hex:
            raise ValueError("ed25519 needs --private-key-file or --private-key (hex)")
        signer = Ed25519Signer(bytes.fromhex(key_hex))
        return signer, signer.verifier()
    from .identity import HmacVerifier
    if not args.secret:
        raise ValueError("hmac needs --secret")
    signer = HmacVerifier(args.secret.encode())
    return signer, signer


def _cmd_revoke(args: argparse.Namespace) -> int:
    """AgentGate: create or extend the signed revocation list."""
    from pathlib import Path
    from .identity import IdentityError, token_id_of
    from .revocation import build_list, parse_list, write_atomic
    try:
        signer, verifier = _signer_from_args(args)
        ids = list(args.token_id or [])
        ids += [token_id_of(t) for t in (args.token or [])]
    except (OSError, ValueError, IdentityError) as exc:
        print(f"revoke failed: {exc}", file=sys.stderr)
        return 1
    path = Path(args.list)
    if path.exists():
        if args.init:
            print(f"revoke failed: {path} already exists (drop --init)", file=sys.stderr)
            return 1
        try:
            version, revoked = parse_list(path.read_text(encoding="utf-8"), verifier)
        except (OSError, IdentityError) as exc:
            print(f"revoke failed: current list can't be trusted: {exc}", file=sys.stderr)
            return 1
        version += 1
    elif args.init:
        version, revoked = 1, frozenset()
    else:
        print(f"revoke failed: {path} not found (use --init to create it)", file=sys.stderr)
        return 1
    doc = build_list(signer, version, sorted(revoked | set(ids)))
    write_atomic(path, json.dumps(doc, indent=2) + "\n")
    print(f"revocation list {path}: version {version}, {len(doc['revoked'])} revoked token(s)")
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 keypair. Private key signs (lives with the agent);
    public key verifies (lives with AgentGate)."""
    from .identity import Ed25519Signer
    try:
        signer = Ed25519Signer.generate()
    except Exception as exc:  # cryptography not installed
        print(f"keygen failed: {exc}", file=sys.stderr)
        return 1
    # Re-derive the private hex from a fresh generate is awkward; expose via API.
    from cryptography.hazmat.primitives import serialization
    priv_hex = signer._priv.private_bytes(  # noqa: SLF001 - intentional, CLI only
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    print(f"private_key_hex (keep secret, give to the agent): {priv_hex}")
    print(f"public_key_hex  (give to agentgate --pubkey):       {signer.public_key_hex()}")
    return 0


def _cmd_approver(args: argparse.Namespace) -> int:
    """AgentGate: run the local approval page (in its own terminal)."""
    from .approver import ApproverService
    from .identity import Ed25519Signer
    try:
        key_hex = _private_key_hex(args)
        if not key_hex:
            raise ValueError("needs --private-key-file")
        signer = Ed25519Signer(bytes.fromhex(key_hex))
    except (OSError, ValueError) as exc:
        print(f"approver failed: {exc}", file=sys.stderr)
        return 1
    try:
        svc = ApproverService(args.queue, signer, approver_id=args.approver_id,
                              port=args.port)
    except OSError as exc:
        print(f"approver failed: could not listen on 127.0.0.1:{args.port} ({exc})",
              file=sys.stderr)
        return 1
    print("AgentGate approval service")
    print(f"  open:        http://127.0.0.1:{svc.port}/")
    print(f"  login code:  {svc.login_code}")
    print(f"  approver id: {args.approver_id}")
    print("Keep this window to yourself. Press Ctrl+C to stop.", flush=True)
    try:
        svc.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


MONITOR_WARNING = (
    "WARNING: AgentGate is in MONITOR mode. NO calls are blocked or changed.\n"
    "Use only in an isolated test environment with dummy data."
)
MONITOR_CONFIRM_FLAG = "--i-understand-this-disables-protection"


def _cmd_run(args: argparse.Namespace) -> int:
    if args.mode == "monitor":
        if not args.i_understand_this_disables_protection:
            print("refusing to start: monitor mode disables all protection. "
                  f"Add {MONITOR_CONFIRM_FLAG} to confirm, and use it only in an "
                  "isolated test environment with dummy data.", file=sys.stderr)
            return 2
        banner = "!" * 72
        print(f"{banner}\n{MONITOR_WARNING}\n{banner}", file=sys.stderr)
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"refusing to start: invalid policy: {exc}", file=sys.stderr)
        return 1

    engine = PolicyEngine(policy)
    audit = AuditLog(args.audit)
    gate = Gate(engine, audit, fail_mode=FailMode(args.fail), mode=args.mode)

    verifier = None
    secret = None
    if args.pubkey:
        from .identity import Ed25519Verifier
        try:
            verifier = Ed25519Verifier.from_public_hex(args.pubkey)
        except Exception as exc:
            print(f"refusing to start: bad ed25519 pubkey: {exc}", file=sys.stderr)
            return 1
    elif args.secret:
        secret = args.secret.encode()
        from .identity import HmacVerifier
        verifier = HmacVerifier(secret)

    if args.token_max_age < 0:
        print("refusing to start: --token-max-age must be >= 0", file=sys.stderr)
        return 1

    revocation = None
    if args.revocation_list or args.revocation_state:
        if not (args.revocation_list and args.revocation_state):
            print("refusing to start: --revocation-list and --revocation-state "
                  "must be given together", file=sys.stderr)
            return 1
        if verifier is None:
            print("refusing to start: a revocation list needs --pubkey or --secret",
                  file=sys.stderr)
            return 1
        from .identity import IdentityError
        from .revocation import RevocationChecker
        try:
            revocation = RevocationChecker(args.revocation_list, args.revocation_state,
                                           verifier)
        except IdentityError as exc:
            print(f"refusing to start: revocation list check failed: {exc}",
                  file=sys.stderr)
            return 3

    if args.approval_queue or args.approver_pubkey:
        if not (args.approval_queue and args.approver_pubkey):
            print("refusing to start: --approval-queue and --approver-pubkey must be "
                  "given together", file=sys.stderr)
            return 1
        if args.pubkey and args.approver_pubkey.strip().lower() == args.pubkey.strip().lower():
            print("refusing to start: the approval key must differ from the token key",
                  file=sys.stderr)
            return 1
        if args.approval_hold >= 55:
            log.warning("--approval-hold %.0fs: linked Claude sessions were measured to "
                        "give up after 60 s", args.approval_hold)
        from .approval import ApprovalManager
        from .identity import Ed25519Verifier
        try:
            approvals = ApprovalManager(
                args.approval_queue, Ed25519Verifier.from_public_hex(args.approver_pubkey),
                audit=audit, engine=engine, hold_seconds=args.approval_hold,
                ttl_seconds=args.approval_ttl, max_pending=args.max_pending)
        except Exception as exc:
            print(f"refusing to start: approval setup failed: {exc}", file=sys.stderr)
            return 1
        gate.approvals = approvals

    proxy = StdioProxy(gate, args.upstream, verifier=verifier,
                       session_id=args.session,
                       max_age_seconds=args.token_max_age,
                       revocation=revocation)
    return proxy.run()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentgate",
                                description="Runtime policy proxy for MCP tool calls")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("check", help="validate a policy file")
    pc.add_argument("--policy", required=True)
    pc.set_defaults(func=_cmd_check)

    pv = sub.add_parser("verify", help="verify audit log integrity")
    pv.add_argument("--audit", required=True)
    pv.set_defaults(func=_cmd_verify)

    prep = sub.add_parser("report", help="generate a compliance evidence report")
    prep.add_argument("--audit", required=True)
    prep.add_argument("--out", help="write Markdown here (default: stdout)")
    prep.set_defaults(func=_cmd_report)

    pdb = sub.add_parser("dashboard", help="AgentGate: static HTML dashboard from the audit log")
    pdb.add_argument("--audit", required=True)
    pdb.add_argument("--out", default="agentgate-dashboard.html")
    pdb.add_argument("--lang", choices=["en", "ar"], default="en")
    pdb.set_defaults(func=_cmd_dashboard)

    pctl = sub.add_parser("controls", help="print the control mappings (NIST/OWASP, and "
                          "AgentGate's NCA/SAMA/OWASP mapping)")
    pctl.add_argument("--framework", choices=["all", "NCA", "SAMA", "OWASP"], default="all")
    pctl.add_argument("--format", choices=["text", "markdown"], default="text")
    pctl.add_argument("--out", help="with --format markdown: write to this file (UTF-8)")
    pctl.set_defaults(func=_cmd_controls)

    pt = sub.add_parser("token", help="mint an agent identity token")
    pt.add_argument("--scheme", choices=["hmac", "ed25519"], default="hmac")
    pt.add_argument("--secret", help="HMAC secret (for --scheme hmac)")
    pt.add_argument("--private-key", help="Ed25519 private key hex (for --scheme ed25519)")
    pt.add_argument("--private-key-file", help="file holding the Ed25519 private key hex "
                    "(safer than --private-key)")
    pt.add_argument("--agent-id", required=True)
    pt.add_argument("--role", action="append", help="repeatable")
    pt.add_argument("--ttl", type=float, default=3600.0,
                    help="token lifetime in seconds (default 3600); signed into the token")
    pt.set_defaults(func=_cmd_token)

    prv = sub.add_parser("revoke", help="AgentGate: add tokens to the signed revocation list")
    prv.add_argument("--list", required=True, help="revocation list file")
    prv.add_argument("--scheme", choices=["hmac", "ed25519"], default="ed25519")
    prv.add_argument("--secret", help="HMAC secret (for --scheme hmac)")
    prv.add_argument("--private-key", help="Ed25519 private key hex (the token signing key)")
    prv.add_argument("--private-key-file", help="file holding the Ed25519 private key hex "
                     "(safer than --private-key)")
    prv.add_argument("--token", action="append", help="a token to revoke (repeatable)")
    prv.add_argument("--token-id", action="append", help="a token id (jti) to revoke (repeatable)")
    prv.add_argument("--init", action="store_true", help="create a new, empty list (version 1)")
    prv.set_defaults(func=_cmd_revoke)

    pa = sub.add_parser("approver", help="AgentGate: run the local approval page")
    pa.add_argument("--queue", required=True, help="folder shared with AgentGate")
    pa.add_argument("--private-key-file", help="approval private key hex file")
    pa.add_argument("--private-key", help=argparse.SUPPRESS)
    pa.add_argument("--approver-id", default="operator")
    pa.add_argument("--port", type=int, default=8765)
    pa.set_defaults(func=_cmd_approver)

    pk = sub.add_parser("keygen", help="generate an Ed25519 keypair (needs [crypto])")
    pk.set_defaults(func=_cmd_keygen)

    pr = sub.add_parser("run", help="run the stdio proxy",
                        epilog="Monitor mode: " + MONITOR_WARNING)
    pr.add_argument("--policy", required=True)
    pr.add_argument("--audit", required=True)
    pr.add_argument("--fail", choices=["open", "closed"], default="closed")
    pr.add_argument("--secret", help="identity HMAC secret (symmetric; dev)")
    pr.add_argument("--pubkey", help="Ed25519 public key hex (asymmetric; recommended)")
    pr.add_argument("--session", default="stdio-session")
    pr.add_argument("--token-max-age", type=float, default=3600.0,
                    help="longest token lifetime accepted, in seconds (default 3600). "
                         "Tokens are re-checked on every request; a missing, forged, "
                         "expired, revoked or too-long-lived token is refused")
    pr.add_argument("--revocation-list", help="AgentGate: signed revocation list, "
                    "checked on every request")
    pr.add_argument("--revocation-state", help="AgentGate: file that remembers the last "
                    "trusted list version (refuses rollback); keep it apart from the list")
    pr.add_argument("--approval-queue", help="AgentGate: folder shared with the approval "
                    "service (enables human approval)")
    pr.add_argument("--approver-pubkey", help="AgentGate: the approval service's Ed25519 "
                    "public key (must differ from --pubkey)")
    pr.add_argument("--approval-hold", type=float, default=45.0,
                    help="seconds to hold a call waiting for a decision (default 45)")
    pr.add_argument("--approval-ttl", type=float, default=600.0,
                    help="seconds an undecided approval stays open (default 600)")
    pr.add_argument("--max-pending", type=int, default=3,
                    help="undecided approvals allowed per agent (default 3)")
    pr.add_argument("--mode", choices=["enforce", "monitor"], default="enforce",
                    help="enforce (default) blocks per policy; monitor only records "
                         "what WOULD happen and blocks NOTHING (test environments only)")
    pr.add_argument(MONITOR_CONFIRM_FLAG, action="store_true",
                    help="required with --mode monitor: confirms you accept that "
                         "no call is blocked or changed")
    pr.add_argument("upstream", nargs=argparse.REMAINDER,
                    help="-- then the upstream server command")
    pr.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    # Strip a leading "--" from REMAINDER for the run command.
    if getattr(args, "upstream", None) and args.upstream and args.upstream[0] == "--":
        args.upstream = args.upstream[1:]
    if getattr(args, "command", None) == "run" and not args.upstream:
        parser.error("run requires an upstream command after --")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
