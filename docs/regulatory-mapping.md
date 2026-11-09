# AgentGate regulatory mapping

Generated from `agentgate/regulatory.py` (`agentgate controls --format markdown`). Do not edit by hand.

AgentGate **supports** these controls; it does not make an organisation compliant. Compliance also needs policies, processes and people, and AgentGate only sees tool calls that pass through it.

Last checked against the official sources: 2026-11-09.

Support: Supported, Partially Supported, Not Supported, Not Verified. Evidence: Verified, Pending, Missing.

## NCA Essential Cybersecurity Controls (Regulatory control set)

- Document: Essential Cybersecurity Controls (ECC – 2 : 2024)
- Issuer: National Cybersecurity Authority (NCA), Saudi Arabia
- Version: ECC-2:2024 (English edition; Arabic edition is authoritative)
- Source: https://cdn.nca.gov.sa/api/files/public/upload/86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf
- Note: Checked against the official English PDF (SHA-256 146505199e5374d99302fc3d7e1fdc73b6e2f3292fefd535d5dd891294a81db1). Page numbers are the printed page numbers.

| Control | Official text | Where | Support | AgentGate | Evidence | Evidence status | Limits |
|---|---|---|---|---|---|---|---|
| **2.2.3.3** Identity and access control principles | User authorization based on identity and access control principles (Need-to-Know and Need-to-Use principle, Least Privilege principle, and Segregation of Duties principle). | 2-2-3, p. 20 | Partially Supported | Role-scoped rules with default deny; path scoping by real path; tools a role can never use are hidden and still refused if called; `check` warns about grants to every agent; approvals are signed by a separate service with its own key. | `test_roles_grant_only_what_each_role_needs`, `test_tool_list_follows_the_role`, `test_hidden_tool_called_anyway_is_still_denied`, `test_least_privilege_check_flags_grants_to_every_agent`, `test_cli_refuses_same_key_for_tokens_and_approvals`; scenarios C01, C02, C03, C08, C09, A01; `agentgate/engine.py`, `agentgate/conditions.py`, `agentgate/stdio_proxy.py` | Verified | Segregation of duties is only partial (approver vs agent, on one OS account). Only tool calls that pass through AgentGate are covered. |
| **2.2.3.4** Privileged access management | Privileged access management. | 2-2-3, p. 20 | Partially Supported | The admin role is limited to the workspace; its tokens can be revoked by id and are re-checked on every request. | `test_roles_grant_only_what_each_role_needs`, `test_revocation_by_token_id_checked_each_time`; scenarios B10, C08, C19; `agentgate/engine.py`, `agentgate/revocation.py` | Verified | Not a PAM system: no credential vaulting, session recording or MFA. Only tool calls that pass through AgentGate are covered. |
| **2.2.3.5** Periodic review of identities and access rights | Periodic review of identities and access rights. | 2-2-3, p. 20 | Partially Supported | The dashboard shows activity per agent and per rule, and `check` flags broad grants, which supports a review. | `test_dashboard_counts_and_escapes`, `test_least_privilege_check_flags_grants_to_every_agent`; `agentgate/dashboard.py`, `agentgate/cli.py` | Verified | AgentGate shows information; it does not run or schedule a periodic review. |
| **2.2.3.2** Multi-factor authentication | Multi-factor authentication, and defining the suitable authentication factors and their numbers ... for remote access and for privileged accounts. | 2-2-3, p. 20 | Not Supported | None. | - | Missing | A signed agent token is a single factor. Human approval is not MFA. |
| **2.12.3.1** Event logs for critical information assets | Activation of cybersecurity event logs for critical information assets within the entity. | 2-12-3, p. 26 | Partially Supported | Every decision on a tool call, including identity refusals and approval steps, is written to the hash-chained audit log. | `test_audit_log_keeps_rule_and_reason`, `test_identity_is_rechecked_on_every_request`; scenarios B02, C03, C19; `agentgate/audit.py`, `evaluation/run_eval.py` | Verified | Covers AgentGate's decisions only, not all critical assets of the entity. |
| **2.12.3.2** Event logs for privileged accounts | Activation of cybersecurity event logs for critical and privileged accounts accessing information assets as well as for remote access events within the entity. | 2-12-3, p. 26 | Partially Supported | Each record carries the agent id, its roles and the token id, so actions of the admin role are attributable. | `test_audit_records_token_id`; scenarios B10, C08; `agentgate/audit.py` | Verified | Does not cover privileged accounts outside AgentGate, or remote access events. |
| **2.12.3.3** SIEM techniques for log collection | Identification of Security Information and Event Management (SIEM) techniques required for cybersecurity event logs collection. | 2-12-3, p. 26 | Partially Supported | The audit log is one JSON record per line, a format SIEM tools can ingest. | `agentgate/audit.py`, `evaluation/run_eval.py` | Verified | No SIEM integration is built or tested. |
| **2.12.3.4** Continuous monitoring of event logs | Continuous monitoring of cybersecurity event logs. | 2-12-3, p. 26 | Partially Supported | The dashboard summarises the log and flags a broken chain. | `test_dashboard_counts_and_escapes`, `test_dashboard_flags_tampering_and_arabic`; `agentgate/dashboard.py` | Verified | The dashboard is a static file regenerated on demand: no continuous monitoring or alerting. |
| **2.12.3.5** Log retention of at least 12 months | Retention period of cybersecurity event logs (shall be at least 12 months). | 2-12-3, p. 26 | Not Supported | None. | - | Missing | AgentGate appends to a file and never deletes, but retention is up to the operator. |
| **2-7** Data and information protection | (Sub-controls not reviewed.) | 2-7, p. 23 | Not Verified | Not assessed. | - | Pending | The sub-controls of 2-7 have not been read in full yet. |

## SAMA Cyber Security Framework (Regulatory control set (financial sector))

- Document: Cyber Security Framework
- Issuer: Saudi Central Bank (SAMA)
- Version: 1.0, 24 May 2017 (In-Force in the SAMA Rulebook)
- Source: https://rulebook.sama.gov.sa/node/3932
- Note: Checked in the official SAMA Rulebook pages for 3.3.5 and 3.3.14.

| Control | Official text | Where | Support | AgentGate | Evidence | Evidence status | Limits |
|---|---|---|---|---|---|---|---|
| **3.3.5 (4.a)** Business requirements for access control | business requirements for access control (i.e., need-to-have and need-to-know); | 3.3.5 Identity and Access Management | Partially Supported | Access for agents is written as reviewable policy-as-code: roles, tools and paths, default deny. | `test_roles_grant_only_what_each_role_needs`; scenarios B01, C03, C09; `agentgate/engine.py`, `examples/demo_setup.py` | Verified | AgentGate rules do not prove the institution has approved business requirements. Only tool calls that pass through AgentGate are covered. |
| **3.3.5 (4.b.4)** Formal approval of access requests | user access requests are formally approved in accordance with business and compliance requirements | 3.3.5 Identity and Access Management | Partially Supported | A human approves one specific sensitive tool call (signed, single use). | `test_approval_during_hold_runs_frozen_copy_once`, `test_approval_rejected_or_timed_out`; scenarios B13, C21, C22; `agentgate/approval.py`, `agentgate/approver.py` | Verified | Approving one operation is NOT approving a user access request; AgentGate does not manage the granting of access rights. |
| **3.3.5 (4.b.6)** Periodic review of access rights | periodically user access rights and profiles should be reviewed; | 3.3.5 Identity and Access Management | Partially Supported | The dashboard shows who did what under which rule, supporting a review. | `test_dashboard_counts_and_escapes`; `agentgate/dashboard.py` | Verified | It does not perform or schedule the review. |
| **3.3.5 (4.b.7)** Audit trail of access and revocation requests | an audit trail of submitted, approved and processed user access requests and revocation requests should be established; | 3.3.5 Identity and Access Management | Partially Supported | Decisions and every approval step (requested, approved, rejected, expired) are audited. | `test_approval_during_hold_runs_frozen_copy_once`, `test_approval_expires_and_is_not_renewed`; scenarios C22, C26; `agentgate/approval.py`, `agentgate/audit.py` | Verified | The full lifecycle of granting/revoking user access is not recorded; token revocations are versioned in the signed list, not in the audit log. |
| **3.3.5 (4.e)** Multi-factor authentication | multi-factor authentication for sensitive and critical systems and profiles; | 3.3.5 Identity and Access Management | Not Supported | None. | - | Missing | Agent tokens are single factor. |
| **3.3.5 (4.f.1)** Restricted use of privileged access | the allocation and restricted use of privileged and remote access | 3.3.5 Identity and Access Management | Partially Supported | The admin role is limited in tools and paths; tools are hidden from roles that can never use them. | `test_roles_grant_only_what_each_role_needs`, `test_tool_list_follows_the_role`; scenarios C01, C08, B12; `agentgate/engine.py`, `agentgate/stdio_proxy.py` | Verified | No MFA for privileged access; remote access is out of scope. |
| **3.3.5 (4.f.3)** Individual accountability | individual accountability; | 3.3.5 Identity and Access Management | Partially Supported | Each agent has its own signed identity; every audited action names the agent, its roles and token id; forged or edited identities are refused. | `test_audit_records_token_id`, `test_tampered_token_rejected`; scenarios C13, C14; `agentgate/identity.py`, `agentgate/audit.py` | Verified | An agent identity is not proof of the responsible person, and a token can be copied until it expires or is revoked. |
| **3.3.14 (4.h)** Adequately protected logs | adequately protected logs; | 3.3.14 Cyber Security Event Management (https://rulebook.sama.gov.sa/en/node/3955) | Partially Supported | Hash-chained audit log; `verify` and the dashboard detect edits, deletions and reordering. | `test_audit_chain_valid_then_detects_tamper`, `test_dashboard_flags_tampering_and_arabic`; `agentgate/audit.py` | Verified | Tamper-evident, not tamper-proof: someone who can rewrite the whole file can rebuild the chain. |
| **3.3.14 (4.j)** Centralised analysis and correlation (SIEM) | automated and centralized analysis of security loggings and correlation of event or patterns (i.e., Security Information and Event Management (SIEM)); | 3.3.14 Cyber Security Event Management (https://rulebook.sama.gov.sa/en/node/3955) | Not Supported | None. | - | Missing | No central analysis or correlation. |

## OWASP Top 10 for Agentic Applications (Risk list (not a compliance standard))

- Document: OWASP Top 10 for Agentic Applications for 2026
- Issuer: OWASP Gen AI Security Project
- Version: 2026, published 9 December 2025
- Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Note: Risk names checked on the official announcement page; the full PDF was not read, so risk descriptions are not quoted.

| Control | Official text | Where | Support | AgentGate | Evidence | Evidence status | Limits |
|---|---|---|---|---|---|---|---|
| **ASI02** Tool Misuse | (risk; description not quoted) | OWASP Top 10 for Agentic Applications 2026 | Partially Supported | Every tool call is decided by policy before it runs; least privilege per role; sensitive calls need a signed, single-use human approval. | `test_roles_grant_only_what_each_role_needs`, `test_hidden_tool_called_anyway_is_still_denied`, `test_approval_during_hold_runs_frozen_copy_once`; scenarios C02, C03, C21, A11; `agentgate/gate.py`, `agentgate/engine.py`, `agentgate/approval.py` | Verified | Cannot detect misuse inside an allowed tool, and does not detect prompt injection itself (scenario A11 only shows the resulting calls are still checked). |
| **ASI03** Identity & Privilege Abuse | (risk; description not quoted) | OWASP Top 10 for Agentic Applications 2026 | Partially Supported | Signed identities with signed expiry and id; forged, edited, expired or revoked tokens are refused, and expiry and revocation are re-checked on EVERY request (not only at start); privileges are per role. | `test_identity_is_rechecked_on_every_request`, `test_revoked_mid_session_blocks_next_request`, `test_token_times_must_be_consistent_and_within_cap`; scenarios C13, C14, C15, C19, C20; `agentgate/identity.py`, `agentgate/revocation.py`, `agentgate/stdio_proxy.py` | Verified | A token can be copied until it expires or is revoked; access paths outside AgentGate are not covered; a hard link placed in the workspace bypasses the path check (A09). |

## Summary

- Supported: 0
- Partially Supported: 16
- Not Supported: 4
- Not Verified: 1

