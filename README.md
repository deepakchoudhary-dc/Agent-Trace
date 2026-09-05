# AgentTrace — Local Causal Auditor for AI Coding Agents

![CI](https://github.com/deepakchoudhary-dc/Agent-Trace/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

AgentTrace is a **local-first** service that records, reconstructs, and explains
how AI coding assistants behave in a developer's workspace — including mixed
use of Codex CLI, Claude Code, Copilot, and local LLM tools. It answers the
question *"what did the agent actually do, and was it safe?"* with
tamper-evident evidence instead of guesswork.

Everything runs on your machine. There are no accounts, no cloud, and no
telemetry.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Dashboard (Optional)](#dashboard-optional)
- [Architecture](#architecture)
- [Security & Privacy Model](#security--privacy-model)
- [Platform Support](#platform-support)
- [Development & Testing](#development--testing)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Features

- **Hash-Chained Event Ledger** — append-only SQLite store where every event's
  SHA-256 hash includes the previous event's hash. Payloads are encrypted with
  AES-256-GCM; indexed columns are separately bound so plaintext-column edits
  cannot hide behind a valid chain. `agenttrace verify` recomputes the whole
  chain on demand.
- **Context Graph Engine** — temporal, evidence-backed graph connecting task
  intent, repository baseline snapshots, tool calls, process trees, file
  mutations, network destinations, and test results.
- **Causal Traversal & Blast Radius** — walk backward from an incident to its
  root cause; walk forward across imports, dependencies, and test suites to
  see what an action could have affected.
- **Rogue-Agent Detection** — 17 host-observable attack-pattern detectors:
  prompt injection markers, credential access, sandbox escape trampolines,
  database destruction, persistence establishment, test-integrity rigging,
  PowerShell cradles, git-author spoofing, orphaned commits, DNS/ICMP tunnel
  signals, and more. Every finding carries a confidence level.
- **Incident-Derived Sabotage Detection** — six detector families built from
  documented real-world agent behavior (the OpenAI / Hugging Face agent
  incident and the monitoring literature): covert-channel structures
  (improvised message boards, chunked encoded transfers, encoded artifact
  names); tool-claim spoofing (agent-narrated results cross-validated against
  OS sensor ground truth — "tests passed" while the process crashed);
  post-exit persistence (cron, launch agents, and heartbeats that outlive the
  session, including the same artifact re-armed by a later session);
  cross-session credential loops (discovery → sharing → lateral reuse on
  token-identity fingerprints); refusal-then-act divergence (verbalized
  refusal followed by the refused action); and meta-detection staleness
  (detector silence is itself a signal). Incidents are hash-chained,
  confidence-labeled, and carry correlated evidence IDs.
- **Risk-Tiered Approval Gates** — pre-execution policy evaluation pauses or
  blocks destructive operations, out-of-scope writes, secret exposure, and
  unsanctioned network egress. Approvals are scoped (segment-exact paths,
  token-prefix commands), time-limited (server-capped at 24 h), anchored to
  the event chain, and revoked automatically on critical incidents.
- **Task Boundary Contracts** — structured contracts (`allowed_paths`,
  `prohibited_paths`, `allowed_tools`) checked continuously for scope drift,
  with segment-exact matching that cannot be bypassed by substring
  look-alikes (`src` never covers `/opt/darksrc/evil`).
- **Multi-Sensor Workspace Observers** — filesystem watching (via
  `watchfiles`), process-tree tracking with pid-reuse protection, Git state
  auditing (read-only), terminal command capture, network destination
  inspection, and — on Windows — a kernel-tier ETW process-audit observer.
- **Self-Improving Review Loop** — Planner → Worker → Reviewers → Synthesiser
  pipeline that runs real allowlisted verification commands (`pytest`, `ruff`,
  `mypy`) against the workspace and records every iteration as auditable
  evidence.
- **Replay Simulation** — branch-and-replay in isolated temporary worktrees;
  commands execute through a fail-closed isolation runner (container-based,
  refuses host fallback, reports `isolation_unavailable` rather than running
  anything unsandboxed), stdin detached, environment scrubbed,
  interactive/debug flags rejected. Live workspaces are never modified.
- **Honest Observability Gaps** — when something cannot be seen (kernel
  memory execution, unprivileged ETW, sealed-environment ambiguity),
  AgentTrace says so explicitly in reports instead of fabricating an
  explanation.
- **Zero Telemetry** — no external network calls, no analytics, no accounts.
  All data stays local, encrypted at rest.

## Requirements

| Component | Version |
|---|---|
| Python | 3.10 or newer |
| Operating System | Windows 10/11, Linux, macOS (see [Platform Support](#platform-support)) |
| Disk | ~100 MB for the package + ledger growth over time |
| Node.js + npm | Only if you want to run the web dashboard locally |

No database server, container runtime, or admin rights are required for core
operation.

## Installation

### 1. Clone and set up a virtual environment

```bash
git clone https://github.com/deepakchoudhary-dc/Agent-Trace.git
cd Agent-Trace

python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate
```

### 2. Install AgentTrace

```bash
pip install -e .
```

This installs the `agenttrace` CLI and all runtime dependencies
(pydantic, FastAPI, uvicorn, cryptography, psutil, and friends).

For development (tests, linting, type checking):

```bash
pip install -e ".[dev]"
```

### 3. Verify the installation

```bash
agenttrace --help          # CLI entry point works
pytest tests/ -q           # optional: full test suite (515+ tests)
```

### 4. (Optional) Set up the dashboard

The dashboard is a React + TypeScript single-page app served separately from
the API daemon:

```bash
cd dashboard
npm install
npm run dev                # dev server on http://localhost:5173
```

Production build:

```bash
npm run build              # outputs to dashboard/dist/
```

The dashboard talks to the daemon on `127.0.0.1:8765` using a local API token
(see [Security & Privacy Model](#security--privacy-model)).

## Quick Start

```bash
# Start the background daemon (local REST API on port 8765)
agenttrace daemon run

# Start auditing a workspace
agenttrace start --workspace /path/to/repo --task "Refactor authentication" --agent auto

# Check what's running
agenttrace status

# Verify the tamper-evidence chain for a session
agenttrace verify <session-id>

# Generate a forensic report
agenttrace report <session-id> --output report.json

# Stop sessions / the daemon when done
agenttrace stop
agenttrace daemon stop
```

On first start the daemon creates a data directory (default
`~/.agenttrace`, override with `AGENTTRACE_DATA_DIR`), generates an AES key
(DPAPI-protected on Windows) and a local API token, and restricts file
permissions on everything it stores.

## CLI Reference

| Command | Purpose |
|---|---|
| `agenttrace start` | Begin an audit session on a workspace |
| `agenttrace status` | List active sessions |
| `agenttrace stop` | Stop active session(s) |
| `agenttrace verify <sid>` | Recompute and verify the session's hash chain |
| `agenttrace incidents <sid>` | Show detected incidents for a session |
| `agenttrace report <sid>` | Export the forensic incident report |
| `agenttrace approve <finding-id>` | Record a scoped, expiring approval decision |
| `agenttrace gate` | Evaluate a proposed action against policy before running it |
| `agenttrace shield check` | Check a command through the policy gate |
| `agenttrace shield run` | Run a command under the policy gate (voluntary wrapper) |
| `agenttrace shield install` | Install optional PATH wrappers (consent-based) |
| `agenttrace daemon run` | Start the local API daemon |
| `agenttrace daemon stop` | Stop the daemon |
| `agenttrace daemon rotate-token` | Rotate the local API token |

Run `agenttrace <command> --help` for per-command options.

## Dashboard (Optional)

A local web UI for live sessions, timelines, diffs, causal graphs, findings,
approvals, forensic reports, and review-loop runs. See
[Installation step 4](#4-optional-set-up-the-dashboard). The dashboard is a
consumer of the same localhost-only, token-authenticated API — it grants no
additional authority.

## Architecture

```
src/agenttrace/
├── models/          # Pydantic data models (events, graph, session, task contract)
├── storage/         # SQLite ledger + encrypted content-addressed blob store
├── observers/       # Filesystem, process-tree, git, terminal, network, kernel (ETW)
├── graph/           # Context graph engine, baseline, causal, blast-radius, replay,
│                    #   incident-derived detectors (covert-channel, evidence-boundary,
│                    #   post-exit, credential-loop, hesitation, meta-detection)
├── security/        # Redaction, AES-256-GCM encryption, policy engine, approvals,
│                    #   permissions hardening, detectors (17 attack patterns
│                    #   + 6 incident-derived families)
├── adapters/        # Codex CLI, Claude Code, Copilot, universal, composite
├── review_loop/     # Planner/Worker/Reviewer/Synthesiser loop + verification runner
├── daemon.py        # Main async daemon: ingest pipeline, response ladder, flood guard
├── daemon_entry.py  # Supervised daemon process (watchdog, data-dir hardening)
├── cli.py           # Click + Rich CLI
└── api.py           # FastAPI localhost API (token-authenticated)

dashboard/           # React + TypeScript web UI (Vite, Zustand, vitest)
tests/               # pytest suite (515+ tests) + replayable eval corpus
.github/workflows/   # CI: ruff → mypy --strict (win+linux) → pytest → dashboard gates
```

**Ingest pipeline order** (per event): redact → detect (17 rule engines) →
policy evaluation → hash-chain append (encrypted) → graph projection. The
projection stage runs the incident-derivation engines (covert-channel,
evidence-boundary, post-exit, credential-loop, hesitation, meta-detection).
An anti-forensic flood guard and clock-anomaly detector watch the stream
itself.

## Security & Privacy Model

- **Local only.** The API binds to `127.0.0.1`. No component makes outbound
  connections. Zero telemetry by design.
- **Encryption at rest.** Event payloads, blobs, contract fields, approval
  scopes, and review payloads are AES-256-GCM encrypted. The master key is
  DPAPI-protected on Windows and permission-restricted (`0600`) on POSIX.
- **Tamper evidence.** Every event seals the previous event's hash plus a
  monotonically increasing sequence number; indexed columns carry a separate
  binding hash; reads fail closed on tampered rows. `agenttrace verify`
  proves it.
- **Redaction always on.** Secrets (API keys, tokens, passwords, connection
  strings, high-entropy credentials, hex secrets in URL params) are redacted
  at the write boundary — including binary blobs — *before* encryption.
  This is not configurable; there is no "turn off redaction" option.
- **Token-scoped API.** Every request except `/health` requires the local API
  token (`X-AgentTrace-Token`), compared in constant time, stored with
  restrictive ACLs, rotatable via `agenttrace daemon rotate-token`.
- **Data-dir hardening.** On startup the daemon restricts permissions on the
  data directory, keys, blobs, and top-level artifacts (POSIX `0700`/`0600`;
  Windows DACL limited to the current user + SYSTEM).
- **Supervised daemon.** The API server restarts on crash with exponential
  backoff and gives up loudly rather than dying silently.

### Honest threat boundary

AgentTrace observes and evidences agent behavior on your machine; it does not
claim kernel-grade enforcement:

- A process with your user account can read your files — including AgentTrace's
  own token and key files. Against same-account malware, local crypto cannot
  fully win; AgentTrace raises the bar (tamper evidence, scoped approvals,
  audit trails) rather than claiming impossibility.
- Windows Job Object containment exists but is currently observe-only unless
  processes were explicitly launched into it; heuristic "descendant"
  classification is never used as a kill criterion.
- Replay and review-loop verification are fail-closed: command execution
  requires the container-based isolation runner and never falls back to the
  host; without a container runtime, replayed verification reports
  `isolation_unavailable` instead of executing.

These limits are stated in reports as observability gaps rather than hidden.

## Platform Support

| Capability | Windows | Linux | macOS |
|---|---|---|---|
| Ledger, graph, policy, approvals, detectors | ✅ | ✅ | ✅ |
| Filesystem / process-tree / git / terminal observers | ✅ | ✅ | ✅ |
| Network destination inspection | ✅ | ✅ | ⚠️ best-effort |
| Key protection | DPAPI | `0600` keyfile | `0600` keyfile |
| Data-dir DACL hardening | icacls | chmod `0700`/`0600` | chmod `0700`/`0600` |
| Kernel-tier ETW process audit (4688/4689) | ✅ (admin for Security log) | ❌ | ❌ |
| Job Object containment primitives | ✅ (observe-only today) | ❌ (cgroup controller experimental) | ❌ |

CI runs the full suite on Ubuntu with strict type-checking for both Windows
and Linux platforms.

## Development & Testing

```bash
pip install -e ".[dev]"

ruff check src/ tests/                      # lint
mypy src/agenttrace --strict                # type check (Windows native)
mypy --platform linux src/agenttrace --strict
pytest tests/ -v                            # full suite

cd dashboard && npm run lint && npm run typecheck && npm run test && npm run build
```

Every change to this repo passes all of the above in CI before merge.

## Known Limitations

- Container isolation (replay, review-loop verification) requires a container
  runtime and the pinned image; without them execution fails closed rather
  than running on the host. Live-session containment is the remaining gap:
  Windows Job Object containment is observe-only unless processes were
  explicitly launched into it (daemon-owned sandbox lifecycle is not yet
  implemented).
- Kernel-tier observation is Windows-only today; Linux uses process polling
  (psutil) as the attribution source.
- The local API token is bearer authority: anything running as your user can
  use it. Approval decisions are bound to the ledger and scope-limited, but
  they are not cryptographic proof of human presence.
- Very large workspaces make first-session baseline generation slower
  (disk-bound hashing); standard ignore dirs (`.git`, `.venv`,
  `node_modules`, `__pycache__`) are pruned automatically.

## Community & feedback

AgentTrace improves from adversarial use. All channels are described in
[CONTRIBUTING.md](CONTRIBUTING.md):

- **Detector feedback** — false positives and false negatives are the most
  valuable input we get; there is a structured template for exactly this.
- **Bugs** — a structured report template; scrub every line before pasting.
- **Security vulnerabilities** — never in public issues; see
  [SECURITY.md](SECURITY.md) for private disclosure, scope, and safe harbor.
- **Questions** — GitHub Discussions for usage, reports, and configuration.

Every PR is reviewed against the project's honesty invariants (hash-chain
integrity, confidence labeling, no fabricated explanations, replay
isolation, local-only operation) — the PR template walks you through them.

## License

Released under the [MIT License](LICENSE).
