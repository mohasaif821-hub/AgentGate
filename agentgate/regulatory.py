# AgentGate. Copyright 2026 Mohammed Jadulhaqq.
# SPDX-License-Identifier: Apache-2.0
"""AgentGate: where AgentGate's controls meet NCA, SAMA and OWASP.

This is the ONE source of truth for the regulatory mapping. The `controls`
command and docs/regulatory-mapping.md are both generated from it, and a test
fails if the document drifts from this data, or if any test, scenario or file
named as evidence does not exist.

Rules we hold ourselves to:
  * "Supports", never "complies". Compliance is organisational (policies,
    processes, people); AgentGate is one technical control, and it only sees
    tool calls that pass through it.
  * Each framework is kept separate. NCA and SAMA are regulatory control
    sets; OWASP is a list of risks, not a compliance standard.
  * Control numbers and texts are copied from the official documents as
    written (ECC-2:2024 writes controls with hyphens, e.g. 2-2-3, and their
    sub-controls with dots, e.g. 2.2.3.3).
  * Evidence is listed only when it proves the exact function claimed.

Support status:
  Supported            a function and test evidence cover the control
  Partially Supported  only part of the control is covered
  Not Supported        no function or evidence
  Not Verified         the control text was not checked in the official source

Evidence verification:
  Verified  the named tests/scenarios exist and prove the claim
  Pending   evidence not reviewed yet
  Missing   no evidence supports the claim
"""

from __future__ import annotations

from dataclasses import dataclass, field

SUPPORT = ("Supported", "Partially Supported", "Not Supported", "Not Verified")
VERIFICATION = ("Verified", "Pending", "Missing")
CHECKED_ON = "2026-11-09"

SOURCES = {
    "NCA": {
        "framework": "NCA Essential Cybersecurity Controls",
        "document": "Essential Cybersecurity Controls (ECC – 2 : 2024)",
        "issuer": "National Cybersecurity Authority (NCA), Saudi Arabia",
        "version": "ECC-2:2024 (English edition; Arabic edition is authoritative)",
        "url": "https://cdn.nca.gov.sa/api/files/public/upload/86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf",
        "note": "Checked against the official English PDF (SHA-256 "
                "146505199e5374d99302fc3d7e1fdc73b6e2f3292fefd535d5dd891294a81db1). "
                "Page numbers are the printed page numbers.",
        "kind": "Regulatory control set",
    },
    "SAMA": {
        "framework": "SAMA Cyber Security Framework",
        "document": "Cyber Security Framework",
        "issuer": "Saudi Central Bank (SAMA)",
        "version": "1.0, 24 May 2017 (In-Force in the SAMA Rulebook)",
        "url": "https://rulebook.sama.gov.sa/node/3932",
        "note": "Checked in the official SAMA Rulebook pages for 3.3.5 and 3.3.14.",
        "kind": "Regulatory control set (financial sector)",
    },
    "OWASP": {
        "framework": "OWASP Top 10 for Agentic Applications",
        "document": "OWASP Top 10 for Agentic Applications for 2026",
        "issuer": "OWASP Gen AI Security Project",
        "version": "2026, published 9 December 2025",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "note": "Risk names checked on the official announcement page; the full "
                "PDF was not read, so risk descriptions are not quoted.",
        "kind": "Risk list (not a compliance standard)",
    },
}


@dataclass(frozen=True)
class Mapping:
    framework: str
    control: str
    title: str
    text: str                       # official text (short, as written)
    location: str                   # section / page in the official source
    status: str
    agentgate: str                  # what in AgentGate supports it
    limits: str                     # what it does NOT cover
    verification: str
    tests: tuple[str, ...] = ()     # tests/test_core.py function names
    scenarios: tuple[str, ...] = () # evaluation/scenarios.py ids
    files: tuple[str, ...] = field(default_factory=tuple)
    url: str = ""                   # overrides the framework URL when set


_SCOPE = "Only tool calls that pass through AgentGate are covered."

MAPPINGS: tuple[Mapping, ...] = (
    # ------------------------------------------------------------------ NCA
    Mapping("NCA", "2.2.3.3", "Identity and access control principles",
            "User authorization based on identity and access control principles (Need-to-Know "
            "and Need-to-Use principle, Least Privilege principle, and Segregation of Duties principle).",
            "2-2-3, p. 20", "Partially Supported",
            "Role-scoped rules with default deny; path scoping by real path; tools a role can never "
            "use are hidden and still refused if called; `check` warns about grants to every agent; "
            "approvals are signed by a separate service with its own key.",
            "Segregation of duties is only partial (approver vs agent, on one OS account). " + _SCOPE,
            "Verified",
            tests=("test_roles_grant_only_what_each_role_needs", "test_tool_list_follows_the_role",
                   "test_hidden_tool_called_anyway_is_still_denied",
                   "test_least_privilege_check_flags_grants_to_every_agent",
                   "test_cli_refuses_same_key_for_tokens_and_approvals"),
            scenarios=("C01", "C02", "C03", "C08", "C09", "A01"),
            files=("agentgate/engine.py", "agentgate/conditions.py", "agentgate/stdio_proxy.py")),
    Mapping("NCA", "2.2.3.4", "Privileged access management",
            "Privileged access management.", "2-2-3, p. 20", "Partially Supported",
            "The admin role is limited to the workspace; its tokens can be revoked by id and are "
            "re-checked on every request.",
            "Not a PAM system: no credential vaulting, session recording or MFA. " + _SCOPE,
            "Verified",
            tests=("test_roles_grant_only_what_each_role_needs",
                   "test_revocation_by_token_id_checked_each_time"),
            scenarios=("B10", "C08", "C19"),
            files=("agentgate/engine.py", "agentgate/revocation.py")),
    Mapping("NCA", "2.2.3.5", "Periodic review of identities and access rights",
            "Periodic review of identities and access rights.", "2-2-3, p. 20", "Partially Supported",
            "The dashboard shows activity per agent and per rule, and `check` flags broad grants, "
            "which supports a review.",
            "AgentGate shows information; it does not run or schedule a periodic review.",
            "Verified",
            tests=("test_dashboard_counts_and_escapes",
                   "test_least_privilege_check_flags_grants_to_every_agent"),
            files=("agentgate/dashboard.py", "agentgate/cli.py")),
    Mapping("NCA", "2.2.3.2", "Multi-factor authentication",
            "Multi-factor authentication, and defining the suitable authentication factors and their "
            "numbers ... for remote access and for privileged accounts.",
            "2-2-3, p. 20", "Not Supported", "None.",
            "A signed agent token is a single factor. Human approval is not MFA.", "Missing"),
    Mapping("NCA", "2.12.3.1", "Event logs for critical information assets",
            "Activation of cybersecurity event logs for critical information assets within the entity.",
            "2-12-3, p. 26", "Partially Supported",
            "Every decision on a tool call, including identity refusals and approval steps, is "
            "written to the hash-chained audit log.",
            "Covers AgentGate's decisions only, not all critical assets of the entity.", "Verified",
            tests=("test_audit_log_keeps_rule_and_reason", "test_identity_is_rechecked_on_every_request"),
            scenarios=("B02", "C03", "C19"),
            files=("agentgate/audit.py", "evaluation/run_eval.py")),
    Mapping("NCA", "2.12.3.2", "Event logs for privileged accounts",
            "Activation of cybersecurity event logs for critical and privileged accounts accessing "
            "information assets as well as for remote access events within the entity.",
            "2-12-3, p. 26", "Partially Supported",
            "Each record carries the agent id, its roles and the token id, so actions of the admin "
            "role are attributable.",
            "Does not cover privileged accounts outside AgentGate, or remote access events.", "Verified",
            tests=("test_audit_records_token_id",),
            scenarios=("B10", "C08"),
            files=("agentgate/audit.py",)),
    Mapping("NCA", "2.12.3.3", "SIEM techniques for log collection",
            "Identification of Security Information and Event Management (SIEM) techniques required "
            "for cybersecurity event logs collection.", "2-12-3, p. 26", "Partially Supported",
            "The audit log is one JSON record per line, a format SIEM tools can ingest.",
            "No SIEM integration is built or tested.", "Verified",
            files=("agentgate/audit.py", "evaluation/run_eval.py")),
    Mapping("NCA", "2.12.3.4", "Continuous monitoring of event logs",
            "Continuous monitoring of cybersecurity event logs.", "2-12-3, p. 26", "Partially Supported",
            "The dashboard summarises the log and flags a broken chain.",
            "The dashboard is a static file regenerated on demand: no continuous monitoring or alerting.",
            "Verified",
            tests=("test_dashboard_counts_and_escapes", "test_dashboard_flags_tampering_and_arabic"),
            files=("agentgate/dashboard.py",)),
    Mapping("NCA", "2.12.3.5", "Log retention of at least 12 months",
            "Retention period of cybersecurity event logs (shall be at least 12 months).",
            "2-12-3, p. 26", "Not Supported", "None.",
            "AgentGate appends to a file and never deletes, but retention is up to the operator.",
            "Missing"),
    Mapping("NCA", "2-7", "Data and information protection",
            "(Sub-controls not reviewed.)", "2-7, p. 23", "Not Verified",
            "Not assessed.", "The sub-controls of 2-7 have not been read in full yet.", "Pending"),

    # ----------------------------------------------------------------- SAMA
    Mapping("SAMA", "3.3.5 (4.a)", "Business requirements for access control",
            "business requirements for access control (i.e., need-to-have and need-to-know);",
            "3.3.5 Identity and Access Management", "Partially Supported",
            "Access for agents is written as reviewable policy-as-code: roles, tools and paths, "
            "default deny.",
            "AgentGate rules do not prove the institution has approved business requirements. " + _SCOPE,
            "Verified",
            tests=("test_roles_grant_only_what_each_role_needs",),
            scenarios=("B01", "C03", "C09"),
            files=("agentgate/engine.py", "examples/demo_setup.py")),
    Mapping("SAMA", "3.3.5 (4.b.4)", "Formal approval of access requests",
            "user access requests are formally approved in accordance with business and compliance "
            "requirements",
            "3.3.5 Identity and Access Management", "Partially Supported",
            "A human approves one specific sensitive tool call (signed, single use).",
            "Approving one operation is NOT approving a user access request; AgentGate does not "
            "manage the granting of access rights.", "Verified",
            tests=("test_approval_during_hold_runs_frozen_copy_once", "test_approval_rejected_or_timed_out"),
            scenarios=("B13", "C21", "C22"),
            files=("agentgate/approval.py", "agentgate/approver.py")),
    Mapping("SAMA", "3.3.5 (4.b.6)", "Periodic review of access rights",
            "periodically user access rights and profiles should be reviewed;",
            "3.3.5 Identity and Access Management", "Partially Supported",
            "The dashboard shows who did what under which rule, supporting a review.",
            "It does not perform or schedule the review.", "Verified",
            tests=("test_dashboard_counts_and_escapes",),
            files=("agentgate/dashboard.py",)),
    Mapping("SAMA", "3.3.5 (4.b.7)", "Audit trail of access and revocation requests",
            "an audit trail of submitted, approved and processed user access requests and revocation "
            "requests should be established;",
            "3.3.5 Identity and Access Management", "Partially Supported",
            "Decisions and every approval step (requested, approved, rejected, expired) are audited.",
            "The full lifecycle of granting/revoking user access is not recorded; token revocations "
            "are versioned in the signed list, not in the audit log.", "Verified",
            tests=("test_approval_during_hold_runs_frozen_copy_once", "test_approval_expires_and_is_not_renewed"),
            scenarios=("C22", "C26"),
            files=("agentgate/approval.py", "agentgate/audit.py")),
    Mapping("SAMA", "3.3.5 (4.e)", "Multi-factor authentication",
            "multi-factor authentication for sensitive and critical systems and profiles;",
            "3.3.5 Identity and Access Management", "Not Supported", "None.",
            "Agent tokens are single factor.", "Missing"),
    Mapping("SAMA", "3.3.5 (4.f.1)", "Restricted use of privileged access",
            "the allocation and restricted use of privileged and remote access",
            "3.3.5 Identity and Access Management", "Partially Supported",
            "The admin role is limited in tools and paths; tools are hidden from roles that can never "
            "use them.",
            "No MFA for privileged access; remote access is out of scope.", "Verified",
            tests=("test_roles_grant_only_what_each_role_needs", "test_tool_list_follows_the_role"),
            scenarios=("C01", "C08", "B12"),
            files=("agentgate/engine.py", "agentgate/stdio_proxy.py")),
    Mapping("SAMA", "3.3.5 (4.f.3)", "Individual accountability",
            "individual accountability;", "3.3.5 Identity and Access Management", "Partially Supported",
            "Each agent has its own signed identity; every audited action names the agent, its roles "
            "and token id; forged or edited identities are refused.",
            "An agent identity is not proof of the responsible person, and a token can be copied "
            "until it expires or is revoked.", "Verified",
            tests=("test_audit_records_token_id", "test_tampered_token_rejected"),
            scenarios=("C13", "C14"),
            files=("agentgate/identity.py", "agentgate/audit.py")),
    Mapping("SAMA", "3.3.14 (4.h)", "Adequately protected logs",
            "adequately protected logs;", "3.3.14 Cyber Security Event Management", "Partially Supported",
            "Hash-chained audit log; `verify` and the dashboard detect edits, deletions and reordering.",
            "Tamper-evident, not tamper-proof: someone who can rewrite the whole file can rebuild "
            "the chain.", "Verified",
            tests=("test_audit_chain_valid_then_detects_tamper", "test_dashboard_flags_tampering_and_arabic"),
            files=("agentgate/audit.py",),
            url="https://rulebook.sama.gov.sa/en/node/3955"),
    Mapping("SAMA", "3.3.14 (4.j)", "Centralised analysis and correlation (SIEM)",
            "automated and centralized analysis of security loggings and correlation of event or "
            "patterns (i.e., Security Information and Event Management (SIEM));",
            "3.3.14 Cyber Security Event Management", "Not Supported", "None.",
            "No central analysis or correlation.", "Missing",
            url="https://rulebook.sama.gov.sa/en/node/3955"),

    # ---------------------------------------------------------------- OWASP
    Mapping("OWASP", "ASI02", "Tool Misuse", "(risk; description not quoted)",
            "OWASP Top 10 for Agentic Applications 2026", "Partially Supported",
            "Every tool call is decided by policy before it runs; least privilege per role; "
            "sensitive calls need a signed, single-use human approval.",
            "Cannot detect misuse inside an allowed tool, and does not detect prompt injection "
            "itself (scenario A11 only shows the resulting calls are still checked).", "Verified",
            tests=("test_roles_grant_only_what_each_role_needs",
                   "test_hidden_tool_called_anyway_is_still_denied",
                   "test_approval_during_hold_runs_frozen_copy_once"),
            scenarios=("C02", "C03", "C21", "A11"),
            files=("agentgate/gate.py", "agentgate/engine.py", "agentgate/approval.py")),
    Mapping("OWASP", "ASI03", "Identity & Privilege Abuse", "(risk; description not quoted)",
            "OWASP Top 10 for Agentic Applications 2026", "Partially Supported",
            "Signed identities with signed expiry and id; forged, edited, expired or revoked "
            "tokens are refused, and expiry and revocation are re-checked on EVERY request "
            "(not only at start); privileges are per role.",
            "A token can be copied until it expires or is revoked; access paths outside AgentGate "
            "are not covered; a hard link placed in the workspace bypasses the path check (A09).",
            "Verified",
            tests=("test_identity_is_rechecked_on_every_request",
                   "test_revoked_mid_session_blocks_next_request",
                   "test_token_times_must_be_consistent_and_within_cap"),
            scenarios=("C13", "C14", "C15", "C19", "C20"),
            files=("agentgate/identity.py", "agentgate/revocation.py", "agentgate/stdio_proxy.py")),
)


def by_framework(name: str | None = None) -> list[Mapping]:
    return [m for m in MAPPINGS if name is None or m.framework == name]


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(framework: str | None = None) -> str:
    """The document (docs/regulatory-mapping.md) is exactly this output."""
    out = ["# AgentGate regulatory mapping", "",
           "Generated from `agentgate/regulatory.py` (`agentgate controls --format markdown`). "
           "Do not edit by hand.", "",
           "AgentGate **supports** these controls; it does not make an organisation "
           "compliant. Compliance also needs policies, processes and people, and AgentGate "
           "only sees tool calls that pass through it.", "",
           f"Last checked against the official sources: {CHECKED_ON}.", "",
           "Support: " + ", ".join(SUPPORT) + ". Evidence: " + ", ".join(VERIFICATION) + ".", ""]
    for fw in ("NCA", "SAMA", "OWASP"):
        if framework and fw != framework:
            continue
        src = SOURCES[fw]
        out += [f"## {src['framework']} ({src['kind']})", "",
                f"- Document: {src['document']}", f"- Issuer: {src['issuer']}",
                f"- Version: {src['version']}", f"- Source: {src['url']}",
                f"- Note: {src['note']}", "",
                "| Control | Official text | Where | Support | AgentGate | Evidence | Evidence status | Limits |",
                "|---|---|---|---|---|---|---|---|"]
        for m in by_framework(fw):
            ev = "; ".join(filter(None, [
                ", ".join(f"`{t}`" for t in m.tests),
                ("scenarios " + ", ".join(m.scenarios)) if m.scenarios else "",
                ", ".join(f"`{f}`" for f in m.files)])) or "-"
            where = m.location + (f" ({m.url})" if m.url else "")
            out.append(f"| **{_cell(m.control)}** {_cell(m.title)} | {_cell(m.text)} | {_cell(where)} | "
                       f"{m.status} | {_cell(m.agentgate)} | {_cell(ev)} | {m.verification} | {_cell(m.limits)} |")
        out.append("")
    counts = {s: sum(1 for m in MAPPINGS if m.status == s and (not framework or m.framework == framework))
              for s in SUPPORT}
    out += ["## Summary", ""] + [f"- {s}: {n}" for s, n in counts.items()] + [""]
    return "\n".join(out)


def render_text(framework: str | None = None) -> str:
    lines = []
    for m in by_framework(framework):
        lines.append(f"[{m.framework}] {m.control} {m.title}: {m.status} (evidence {m.verification})")
        lines.append(f"    supports: {m.agentgate}")
        lines.append(f"    limits:   {m.limits}")
    return "\n".join(lines)
