# Security policy

AgentGate sits on the path between AI agents and their tools. Please report
vulnerabilities privately.

## Reporting
Use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Do not open a public issue.
Include what you found, how to reproduce it, the commit, and the impact.

## Scope
In scope: anything that lets a tool call run that the policy, identity,
revocation or approval checks should have stopped, or that hides or alters
audit records without detection.

Known and documented, so not new findings: a hard link inside the workspace
(evaluation scenario A09), the single-OS-account limits of the approval page
and keys, tool access paths that do not go through AgentGate, the
time-of-check to time-of-use gap between the path check and the tool, and
audit-log lines cut from the end (the chain is tamper-evident, not
tamper-proof). AgentGate does not detect prompt injection by itself. See the
limits in `docs/REPORT.md` and the evaluation reports.
