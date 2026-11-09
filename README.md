# mcp-gate

> A runtime policy-enforcement proxy for the Model Context Protocol (MCP) — a **firewall for AI-agent tool calls**, with tamper-evident audit logging, heuristic threat scanning, and a control mapping to the NIST AI RMF and OWASP Agentic Top 10.

<p>
<a href="#license"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
<img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
<img alt="Dependencies: none" src="https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg">
<img alt="Tests" src="https://img.shields.io/badge/tests-37%20unit%20%2B%2020%20samples-success.svg">
</p>

mcp-gate sits on the tool-call path between an AI agent and its tools. Every
`tools/call` is intercepted, evaluated against a declarative policy, and then
**allowed, denied, held for human approval, or forwarded with arguments
redacted** — and every decision is written to a hash-chained, tamper-evident
audit log that doubles as compliance evidence.

It governs the one layer most enterprises leave open today: the **execution
layer**, where an agent's reasoning becomes real API calls, database writes, and
transactions. Because it works at the MCP protocol level, it is **framework-
agnostic** — anything that speaks MCP (Claude Code, Gemini CLI, CrewAI,
LangGraph, custom agents) is governed without per-framework integration.

---

## Honest scope — read this first

This is a **working foundation**, published openly so it can be read, run, and
extended. It does **not** claim to be a finished, certified, or
"zero-false-positive" product, because:

- A policy engine's false-positive rate is a property of **the policies you
  write**, not the engine. A flawless engine still blocks a legitimate call if a
  rule is too broad. The right goal is an engine you can reason about, test
  exhaustively, and audit — which is what this is.
- The **threat scanner is a heuristic**, not a calibrated classifier. It is
  meant to feed *human approval*, not silent denial, so a false hit costs a
  review click rather than a broken workflow.
- The compliance mapping is a **self-assessment aid**, not a certification. NIST
  AI RMF is voluntary; the NCCoE agent-identity guidance is a draft.

Every place that needs production hardening is marked in the source with a
`# HARDENING:` comment. Search for it before deploying.

### Monitor mode — no protection

> **WARNING: in monitor mode NO calls are blocked or changed.**
> Use it only in an isolated test environment with dummy data.

`run --mode monitor` evaluates and audits every call exactly as enforce mode
would, then forwards it **untouched**: nothing is denied, redacted, held for
approval or hidden from the tool list. Its only purpose is to try a policy and
see what it *would* block before turning it on.

- It will not start without the explicit flag
  `--i-understand-this-disables-protection`.
- It prints a warning when it starts, and every audit record carries
  `"mode": "monitor"`, so a monitored period can never pass for a protected one
  (the `report` command flags it too).
- AgentGate cannot tell whether an environment is isolated or the data is real.
  That responsibility stays with whoever runs it. The software is provided
  "AS IS", without warranty, under the Apache 2.0 license.

---

## Why this exists

Agent adoption has badly outrun control. Across 2026 industry reporting, most
teams are running agents in production while a small minority have full security
sign-off, and security incidents involving agents are widespread. The model
layer is reasonably well secured; the **tool-call layer is trusted by default** —
no per-call policy, no risk scoring, no audit trail.

mcp-gate is grounded in current, published guidance:

- **NIST AI RMF 1.0** (NIST AI 100-1) — the Govern / Map / Measure / Manage
  functions. mcp-gate is a *Manage*-and-*Measure* control: it enforces and
  records risk decisions at runtime.
- **NIST NCCoE concept paper**, *Accelerating the Adoption of Software and AI
  Agent Identity and Authorization* (Feb 2026) — its four operational concerns
  are **identification, authorization, auditing & non-repudiation, and
  prompt-injection mitigation**. mcp-gate implements a control for each, and the
  paper itself references OAuth 2.0, SPIFFE/SPIRE, and MCP.
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10). mcp-gate
  directly addresses Tool Misuse (ASI02), Identity & Privilege Abuse (ASI03),
  Cascading Failures (ASI08), and Human-Agent Trust Exploitation (ASI09), and
  contributes to Goal Hijack (ASI01) and Memory/Context Poisoning (ASI06).

See the full control mapping with `mcp-gate controls`.

---

## Features

| | Feature | What it does |
|---|---|---|
| 🧱 | **Policy decision engine** | Pure, synchronous, exhaustively testable. First-match-wins ruleset like a firewall. |
| 🎯 | **Argument-aware + stateful policy** | Rules condition on argument values *and* on cumulative session budgets ("≤ $2000 of refunds per session"). No `eval`, no code execution. |
| 🚦 | **Four enforcement effects** | `allow` · `deny` · `require_approval` (human in the loop) · `redact` (mask fields before forwarding). |
| 🪪 | **Per-agent identity** | Agents are first-class cryptographic principals, not shared service accounts — so every action is attributable. |
| 🔗 | **Tamper-evident audit log** | Append-only, fsync'd, SHA-256 hash-chained. `verify()` detects any edit, reorder, or deletion. |
| 🛡️ | **Heuristic threat scanner** | Flags prompt injection, command injection, secret exfiltration, path traversal, and suspicious URLs in tool arguments. Explainable hits feed approval. |
| 📋 | **Compliance evidence reports** | Turns the audit log into a NIST/OWASP-mapped Markdown report: integrity attestation, per-agent activity, threat rollup. |
| ⚙️ | **Fail-open / fail-closed** | Operator-selectable posture for what happens if the engine itself errors. |
| 🔌 | **stdio MCP proxy + CLI** | Wraps any stdio MCP server. Zero runtime dependencies. |

---

## Install

From PyPI:

```bash
pip install mcp-gate-policy              # core, zero runtime deps
pip install "mcp-gate-policy[yaml]"      # + YAML policy support (JSON works without)
pip install "mcp-gate-policy[crypto]"    # + Ed25519 asymmetric agent identity
pip install "mcp-gate-policy[yaml,crypto]"   # both extras
```

Or with [uv](https://docs.astral.sh/uv/): `uv pip install mcp-gate-policy`.

Either way the CLI is available as `mcp-gate`:

```bash
mcp-gate --help
```

From source (for development or to run the tests):

```bash
git clone https://github.com/rsh1k/mcp-gate.git
cd mcp-gate
pip install -e ".[dev]"     # installs test deps too
python tests/test_core.py   # 40 unit tests
python tests/test_samples.py  # 20 end-to-end samples
```

## Quickstart

```bash
# 1. Validate a policy before deploying it
mcp-gate check --policy examples/policy.yaml

# 2. Run the proxy in front of any stdio MCP server
mcp-gate run \
    --policy examples/policy.yaml \
    --audit audit.jsonl \
    --fail closed \
    -- python examples/fake_server.py

# 3. Prove the audit log wasn't tampered with
mcp-gate verify --audit audit.jsonl

# 4. Generate a NIST/OWASP-mapped compliance report
mcp-gate report --audit audit.jsonl --out compliance.md

# 5. See exactly which controls map to which frameworks
mcp-gate controls
```

In production you point the `--` command at your real server, e.g.
`-- npx @modelcontextprotocol/server-filesystem /data`, and configure your MCP
client to launch `mcp-gate run …` instead of the server directly.

### Docker

```bash
docker build -t mcp-gate:latest .

# stdio transport needs -i and no TTY so the JSON-RPC stream stays clean
docker run --rm -i \
  -v "$PWD/policy.yaml:/etc/mcp-gate/policy.yaml:ro" \
  -v "mcp-gate-audit:/var/lib/mcp-gate" \
  mcp-gate:latest run \
    --policy /etc/mcp-gate/policy.yaml \
    --audit  /var/lib/mcp-gate/audit.jsonl \
    --fail closed \
    -- <your upstream MCP server command>
```

The image runs as a non-root user and exposes `/var/lib/mcp-gate` as a volume so
your audit log (the evidence trail) survives container recreation. Published
images: `ghcr.io/rsh1k/mcp-gate`.

---

## Policy at a glance

Policies are plain YAML/JSON, reviewed in a pull request like Terraform. Rules
evaluate top-to-bottom; **first match wins**; unmatched calls hit
`default_effect` (keep it `deny`).

```yaml
name: support-agent-policy
version: "1"
default_effect: deny

rules:
  # Hold ANY call for a human if its arguments trip the threat scanner.
  - id: threat-scan-hold
    effect: require_approval
    min_threat_score: 4
    reason: "arguments tripped the threat scanner"

  # Support agents may refund <$500 each, capped at $2000 per session.
  - id: refund-small-capped
    effect: allow
    tools: ["billing.refund"]
    require_roles: ["support-agent"]
    when: {field: amount, op: lt, value: 500}          # argument-aware
    budget: {key: refund_total, field: amount, limit: 2000}  # stateful

  # Anything else hitting billing.refund needs a human.
  - id: refund-large-approval
    effect: require_approval
    tools: ["billing.refund"]

  # Strip bcc before forwarding outbound email.
  - id: email-redact-bcc
    effect: redact
    tools: ["email.send"]
    redact_fields: ["bcc"]
```

Conditions support `eq ne lt le gt ge in not_in contains startswith endswith
regex exists`, plus boolean trees with `all` / `any` / `not`, dotted field paths
(`filters.region`), tool/agent globs, and role requirements.

### Threat scanner: what it is, and what it isn't

The built-in scanner (`min_threat_score` in policy) is a **heuristic that feeds
human approval — not a detector that makes a verdict.** This framing is
deliberate and load-bearing for the tool's credibility:

- It is pattern matching: a cheap, deterministic, network-free first pass that
  cannot itself be prompt-injected. It catches *known shapes* of prompt
  injection, secret exfiltration, command injection, and path traversal.
- It has false positives and false negatives by nature. So the recommended wiring
  is `effect: require_approval`, **not** `deny`: a hit costs a human a review
  click, and a miss is backstopped by your other rules — neither outcome silently
  trusts or silently breaks.
- It is **not** a security boundary on its own and must not be sold or relied on
  as one. The `ThreatScanner` interface exists so you can place a real
  classifier (an LLM guard or trained model) behind it; the heuristic is the
  floor, not the ceiling.

If you ever find yourself wiring the scanner straight to `deny` and trusting it
as detection, stop — that is the failure mode this section exists to prevent.

### Agent identity: HMAC vs Ed25519

Two verifiers ship in the box:

- **HMAC** (`--secret`, stdlib-only): symmetric. Fine for dev and single-tenant
  self-hosting, but the same secret signs and verifies, so it gives no
  non-repudiation.
- **Ed25519** (`--pubkey`, needs `pip install mcp-gate-policy[crypto]`): asymmetric. The
  agent holds the private key; **mcp-gate holds only the public key**, so the
  proxy can verify identity but cannot forge it. This is the production-
  appropriate choice and the direction NIST's NCCoE agent-identity work points at
  (JWT-SVID / SPIFFE use asymmetric signatures).

```bash
# generate a keypair (needs the [crypto] extra)
mcp-gate keygen
# agent mints a token with its PRIVATE key
mcp-gate token --scheme ed25519 --private-key <PRIV_HEX> --agent-id support-1 --role support-agent
# mcp-gate runs holding only the PUBLIC key
mcp-gate run --policy policy.yaml --audit audit.jsonl --pubkey <PUB_HEX> -- <server>
```

The token embeds its scheme, and each verifier refuses a mismatched scheme, so an
attacker cannot downgrade an Ed25519 deployment to HMAC.

### Least privilege by identity (AgentGate)

Each agent gets only the tools and paths its role needs; everything else is
denied by default and hidden from that agent's tool list.

- **No valid identity, no start.** When `--pubkey` or `--secret` is set, the
  proxy refuses to start if `MCPGATE_AGENT_TOKEN` is missing, forged or
  expired (exit code 3). It never falls back to running as "anonymous".
- **Signed expiry and id.** Each token carries `iat`, `exp` and a unique `jti`
  inside the signed bytes, so its life can't be extended or its id changed
  without a new signature. Tokens without them (older format) are refused.
- **Times must make sense.** A token issued in the future (beyond 60 s of
  clock skew), one that expires before it was issued, or one whose lifetime
  (`exp - iat`) is longer than `--token-max-age SECONDS` (default 3600) is
  refused, so the issuer can't get past the limit with odd timestamps.
- **Checked on every request**, not just at start: signature, expiry and
  revocation. A token that expires or is revoked mid-session is refused on the
  next request, and the refusal is audited with rule `__identity__`. Identity
  is enforced in monitor mode too.
- **Revocation by token id:** `--revocation-list FILE --revocation-state FILE`.
  The list is signed with the token signing key and names revoked `jti`s, so
  revoking one token leaves the agent's other tokens working. A missing,
  unreadable, edited or wrongly signed list means every request is refused.
  Rotating the key stays the emergency option, not the daily one.

  ```bash
  mcp-gate revoke --list revoked.json --private-key-file key.hex --init
  mcp-gate revoke --list revoked.json --private-key-file key.hex --token <TOKEN>
  ```
- **Rollback refused.** The version number in the list alone can't stop someone
  putting back an older signed list, so the last trusted version is also kept
  in the separate `--revocation-state` file (and in memory) and any older list
  is refused.
- **`check` warns about broad grants:** any non-deny rule that applies to every
  agent (`agents: ["*"]` with no `require_roles`) is printed as a
  `WARNING`. It is a warning, not an error: the exit code stays 0.

The demo (`examples/demo_setup.py`) uses two identities:

| Agent | Roles | May do |
|---|---|---|
| reader-agent | reader | list + read inside the workspace |
| admin-agent | reader, admin | the same, plus delete inside the workspace |

Claude Desktop is given the **reader** token, so the agent used every day holds
the least privilege. `examples/demo_check.py` tests both identities and the
missing, forged and expired token cases.

**Limits.** The proxy holds only the public key, so editing Claude Desktop's
config cannot *mint* a token with more roles. But a token is a bearer token:
anyone who can read an existing token (for example the admin token in the demo's
`keys/` folder) can *copy* it until it expires or is revoked. Keep tokens and
the private key readable only by the user who needs them, and keep
`--token-max-age` short.

The signed list stops **unsigned** changes. It does not resist an attacker who
already has the rights of the account or machine running AgentGate: on a
single Windows account, such an attacker can change the state file and the
list together, change the clock, or read the private key. Real separation
needs a different OS account or another machine.


### Human approval bound to one request (AgentGate)

A rule with `effect: require_approval` holds the call until a person decides.

- **One exact request.** The approval covers a fingerprint of the agent, its
  token id, the tool, the exact arguments and the policy version. Any change
  (one character, another token) is a different request.
- **Used once, no new permissions.** An approval runs that request once and is
  gone. It never changes what the agent may do.
- **Nothing runs before a valid, signed approval.** The decision is signed by
  a separate approval service with its own key. AgentGate holds only that
  public key (`--approver-pubkey`), which must differ from the token key.
- **Hold, then pending.** AgentGate holds the call (`--approval-hold`, default
  45 s). We measured that linked Claude sessions give up after 60 s *without
  telling the server*, so the hold stays below that. If no one decides in time,
  the agent gets `-31902 ... Retry the same request after it is approved.` and
  the approval stays open for `--approval-ttl` (default 600 s, never renewed).
  The identical retry then runs the frozen copy of the arguments, once.
- **Checked again right before running:** identity, expiry, revocation, policy.
- **At most `--max-pending` (default 3) waiting approvals per agent**, so a
  flood of requests can't wear the person down.
- **No network port in AgentGate.** It shares only a folder with the approval
  service (`--approval-queue`). A forged decision fails its signature and is
  audited; deleting files can only cause refusals. A restart voids all
  pending approvals.
- **Every step is audited** (`requested`, `approved_executed`, `rejected`,
  `hold_timeout`, `expired`, `too_many_pending`, `invalid_decision_ignored`,
  ...), with the request fingerprint and the approver id, never the secrets.

The approval page (`mcp-gate approver --queue DIR --private-key-file KEY`)
listens on `127.0.0.1` only, prints a one-time login code in its own terminal
(5 wrong codes stop it), uses an HttpOnly SameSite=Strict session, checks the
CSRF token, `Origin` and `Host` on every POST, escapes everything it shows,
masks secret-looking argument values, forbids scripts and framing with a strict
CSP, and recomputes each request's fingerprint so a request whose shown details
were altered can't be approved.

**Error codes.** AgentGate answers with its own codes, outside the JSON-RPC
reserved range (`-32768..-32000`) as MCP asks for application errors:
`-31901` blocked, `-31902` needs approval. (mcp-gate used `-32001`/`-32002`;
`-32002` means "resource not found" in MCP.)

**Waiting.** The hold is a short wait, not a long one: linked Claude sessions
were measured to wait 45 s and 55 s but give up at 120 s, without telling the
server. Anything longer works only through the identical retry within
`--approval-ttl`. Long synchronous waits are not supported.

**Limits.** On a single Windows account, a process running as you (an agent
with a terminal tool, say) could read the login code or the approval key file,
or open the page. This is practical protection within our model, not full
separation: that needs the approval service on another OS account or device.
Masked values (passwords and the like) are not shown to the approver.


### Evaluation (AgentGate)

`python evaluation/run_eval.py` plays 68 scenarios (32 clear violations, 19
ambiguous tricks, 17 legitimate requests; some are Windows-only) against the
real AgentGate in a throw-away folder. Expected outcomes were written and
frozen (SHA-256 in the report) before the first run and are not adjusted
afterwards. A scenario passes only if AgentGate's reply, the tool server's
evidence log (did the tool run?) and the audit log all match.

Reports: `evaluation/results/report-posix.md`, `report-windows.md`.
CI runs it with `--gate` (fails below clear >= 98%, ambiguous >= 80%).

Known finding: a **hard link** placed inside the workspace that points to a
file outside it is allowed (scenario A09). Real-path checks resolve symbolic
links and junctions but cannot see hard links. Creating one needs write access
to the workspace, which the demo agent does not have.

---

## Verification

```bash
python tests/test_core.py      # 37 unit tests
python tests/test_samples.py   # 20 labeled end-to-end samples
```

The 20-sample harness runs realistic tool calls (reads, refunds, redactions,
sensitive-path denials, budget accumulation, and injection/exfil attempts)
through the full gate and checks each against an expected decision, then
verifies the audit chain over all 20 records. Current result: **20/20 pass,
chain intact.**

---

## How it works

```
client ──stdin/stdout──▶  mcp-gate  ──stdin/stdout──▶  upstream MCP server
                            │
        ┌───────────────────┼───────────────────┬───────────────┐
        ▼                   ▼                   ▼               ▼
   PolicyEngine        ThreatScanner         AuditLog        Enforce
  (decision point)   (injection/exfil)    (hash chain)   (redact/errors)
```

- `engine.py` — Policy Decision Point: pure, no I/O, fully testable.
- `gate.py` — Policy Enforcement Point: applies decisions, handles fail modes.
- `threats.py` — heuristic argument scanner (deterministic, no network).
- `audit.py` — append-only, fsync'd, SHA-256 chained log with `verify()`.
- `compliance.py` / `report.py` — control mapping + evidence reports.
- `identity.py` — signed agent principals.
- `stdio_proxy.py` — stdio transport plumbing.

---

## Roadmap

1. **HTTP / streamable transport** + MCP OAuth 2.1 / JWT-SVID identity — design
   sketched in [`docs/milestone-http-transport.md`](docs/milestone-http-transport.md)
   (this core is stdio-only; the engine is already transport-agnostic).
2. **Durable, shared session store** (Redis) for multi-replica budget enforcement.
3. **Approval workflow** integrations (Slack / web) behind the existing hook.
4. **Policy simulation / dry-run** against recorded traffic — the honest way to
   tune out false positives *before* enforcing.
5. Optional **ML/LLM threat classifier** behind the `ThreatScanner` interface.
6. **Review dashboard** (deferred on purpose; CLI + config-as-code first).

**Done since 0.1:** asymmetric Ed25519 agent identity (proxy holds public key
only), heuristic threat scanner, NIST/OWASP control mapping + evidence reports,
Docker image, and PyPI packaging.

Contributions welcome — see `CONTRIBUTING.md`.

---

## A note on trust

This is security-critical software. Before running it on a production tool-call
path: read it, run the tests, add your own, get it independently reviewed, and
threat-model your deployment. Do not treat any tool — including this one — as
correct because someone said so.


## Relationship to revoco

[`revoco`](https://github.com/rsh1k/revoco) merges this package with
[`veritrail`](https://github.com/rsh1k/veritrail) and
[`mnemosyne`](https://github.com/rsh1k/mnemosyne), and adds a reversal layer none of
them had — planning an undo *before* an action runs, then rolling back a compromised
grant's whole subtree in one call.

**What moved into revoco:** the policy decision point — allow / deny /
require_approval / redact, argument-aware conditions, and stateful session budgets.

**What did not: the stdio MCP proxy.** revoco exposes a `ControlPlane` API and has no
MCP integration at all, so it cannot be put in front of Claude Code, Cursor or any
other MCP client the way this package can. If you want a policy firewall you drop
into an MCP config and nothing else changes, that is still exactly this.

Both are Apache-2.0 and both are maintained.

## License

[Apache-2.0](LICENSE).
