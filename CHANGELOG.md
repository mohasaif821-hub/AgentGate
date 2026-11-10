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
- Final README, report (`docs/REPORT.md`) and operator guide (`docs/USAGE.md`).

### Fixed
- Container licence label said MIT (stale in mcp-gate); now Apache-2.0.
- Audit log with several writers: each write now takes a file lock and
  continues from the file's real last record. A process whose log was renamed,
  deleted, emptied or cut back while it ran refuses to write, and the call is
  refused, instead of breaking the hash chain. A call (or an approved call)
  that can't be audited no longer runs, in monitor mode too. Found when an
  archived log was renamed while Claude Desktop's AgentGate was still running.
- Approval page: a refused POST now reads its (size-capped) body before
  answering, so on Windows the client gets the 403 instead of a reset
  connection. Found by running the unit tests on Windows.
- Dashboard no longer says "no deletions": the hash chain cannot show records
  cut from the end of the log. The banner now says what the chain proves.

### Added (tools)
- `tools/compare_upstream.py`: reproduces the "built on mcp-gate" size
  numbers in the report. Not part of AgentGate and not counted itself.

### Known limitations
- A hard link placed inside the workspace bypasses the path check (scenario A09).
- Approver, keys and agent on one OS account are not fully separated.
