# Changelog

AgentGate changes. The history of the original mcp-gate project is kept,
unchanged, in `docs/upstream-archive/CHANGELOG.md`.

## Unreleased

### Added
- Least privilege by identity: role-scoped rules, tool lists filtered per role.
- Signed agent tokens with signed expiry and token id; lifetime cap and
  timestamp consistency checks; identity re-checked on every request.
- Signed revocation list by token id, with rollback protection.
- Human approval bound to one exact request: signed decisions from a separate
  approval service and key, single use, hold-then-pending flow, pending cap,
  local approval page with CSRF/Origin/Host checks.
- Monitor mode behind a mandatory confirmation flag.
- Static HTML dashboard built from the audit log (English and Arabic).
- Evaluation: 68 frozen scenarios checked against the reply, the tool's own
  evidence log and the audit log; run in CI with the project's targets.
- Regulatory mapping to NCA ECC-2:2024, SAMA CSF and OWASP Agentic Top 10
  2026, generated from one data file and guarded by tests.

### Changed
- Deny-overrides rule precedence; real-path `within` / `not_within` checks.
- Generic agent-facing denial and approval messages (details stay in the audit).
- AgentGate error codes `-31901` / `-31902`, outside the JSON-RPC reserved range.
- Project, package and command renamed to `agentgate`.

### Fixed
- Container licence label said MIT (stale in mcp-gate); now Apache-2.0.

### Known limitations
- A hard link placed inside the workspace bypasses the path check (scenario A09).
- Approver, keys and agent on one OS account are not fully separated.
