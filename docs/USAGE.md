# Using AgentGate

Operator reference: what each protection does and the options behind it. For
the overview see the [README](../README.md); for the evaluation, findings and
limits see the [report](REPORT.md).

## Monitor mode — no protection

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


## Least privilege by identity

Each agent gets only the tools and paths its role needs; everything else is
denied by default and hidden from that agent's tool list.

- **No valid identity, no start.** When `--pubkey` or `--secret` is set, the
  proxy refuses to start if `AGENTGATE_AGENT_TOKEN` is missing, forged or
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
  agentgate revoke --list revoked.json --private-key-file key.hex --init
  agentgate revoke --list revoked.json --private-key-file key.hex --token <TOKEN>
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


## Human approval bound to one request

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
  45 s). Linked Claude sessions were measured to wait 45 s and 55 s but give up
  at 120 s *without telling the server*, so the hold stays at the low end. If no one decides in time,
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

The approval page (`agentgate approver --queue DIR --private-key-file KEY`)
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


## Regulatory mapping: NCA, SAMA, OWASP

`docs/regulatory-mapping.md` maps AgentGate to NCA ECC-2:2024, the SAMA Cyber
Security Framework and the OWASP Top 10 for Agentic Applications 2026, each
kept separate. Every row gives the official control number and text, where it
is in the official source, a support status (Supported / Partially Supported /
Not Supported / Not Verified), the evidence (tests, evaluation scenarios,
files), whether that evidence was verified, and what AgentGate does NOT cover.

AgentGate **supports** these controls; it does not make an organisation
compliant. Most rows are "Partially Supported" on purpose: AgentGate only sees
tool calls that pass through it.

```bash
agentgate controls --framework NCA                     # read it in the terminal
agentgate controls --format markdown --out docs/regulatory-mapping.md   # regenerate the doc
```

The document is generated from `agentgate/regulatory.py`; a test fails if the
two differ, if a status contradicts its evidence, or if any named test,
scenario or file does not exist.

## Audit log

```bash
agentgate verify --audit audit.jsonl
```

Every decision is one JSON line, linked to the hash of the line before.
`verify` re-walks the chain: an edited line, a line removed from the middle or
a changed order breaks it. Lines cut from the **end** leave a valid, shorter
chain; only a copy of the last hash kept somewhere else can show that.

- **Several writers are fine.** Claude Desktop's AgentGate and, say, the demo
  check can write the same log: each write takes a lock on `<log>.lock` and
  continues from the file's real last line.
- **Archiving: quit every AgentGate process first** (for Claude Desktop, quit
  the app fully, not just its window), then rename the log. A process that
  finds its log renamed, deleted, emptied or cut back while it runs refuses to
  write, and refuses the calls, until it is restarted.
- **A call that can't be logged doesn't run,** in monitor mode too, and
  neither does an approved call.
- Argument values are hashed, not stored.

## Dashboard

```bash
agentgate dashboard --audit audit.jsonl --out dashboard.html          # English
agentgate dashboard --audit audit.jsonl --out dashboard-ar.html --lang ar   # Arabic
```

One static HTML page built from the audit log: audit-chain integrity (and a
warning if it was edited), allowed / denied / needed-approval counts, identity
refusals, records made in monitor mode, breakdowns by agent, tool and rule,
the human-approval funnel, and the latest 50 decisions.

It is a file, not a server, so it opens no port; run the command again to
refresh it. On purpose it never shows token ids, approval ids, argument or
chain hashes, rule reason texts or file paths. Rule ids are shown so the
operator can see *why* a call was decided; keep the file on the machine.
Everything from the log is HTML-escaped and a strict Content-Security-Policy
allows no scripts and no external requests.

## Evaluation

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
