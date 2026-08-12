# AgentTrace — Local Causal Auditor for AI Coding Agents

AgentTrace is a local-first service that records, reconstructs, and explains how AI coding assistants behave across a developer’s workspace—including mixed use of Codex CLI, Claude Code, Copilot Chat, and local LLM tools.

## Core Features

- **Hash-Chained Event Ledger**: Immutable, append-only SQLite store with cryptographic SHA-256 tamper verification and AES-256-GCM encrypted payloads.
- **Context Graph Engine**: Temporal, evidence-backed directed graph connecting developer intent, repository snapshots, tool calls, process trees, file mutations, network destinations, and test results.
- **Causal Traversal & Blast Radius**: Backward graph traversal to root-cause incidents and forward blast-radius analysis across AST imports, dependencies, and test suites.
- **Risk-Tiered Approval Gates & Task Boundary**: Continuously checks scope drift against structured task contracts and pauses/blocks destructive operations or secret exposures.
- **Multi-Sensor Workspace Observers**: Rust-backed filesystem monitoring, process tree tracking, Git state auditing, terminal history capture, and network destination inspection.
- **Self-Improving Review Loop**: Built-in multi-agent review architecture (Planner, Worker, Reviewers, Synthesiser, Plan Reviewer) driving continuous code and policy improvement.
- **Replay Simulation**: Branch-and-replay in isolated temporary worktrees without ever modifying live workspace files.
- **Zero-Telemetry Local Privacy**: Zero external telemetry; automatic regex + Shannon entropy secret redaction.

## Installation & Setup

```bash
# Python 3.10+
pip install -e .
```

## CLI Usage

```bash
# Start an audit session on a workspace
agenttrace start --workspace /path/to/repo --task "Refactor authentication system" --agent auto

# Approve a policy-gated finding
agenttrace approve <finding-id> --scope "src/auth/*" --reason "Approved for refactor"

# Generate forensic incident report
agenttrace report <session-id> --output report.json

# Check active sessions
agenttrace status

# Stop active session(s)
agenttrace stop
```

## Architecture

```
src/agenttrace/
├── models/          # Pydantic data models (events, graph, session, task contract)
├── storage/         # SQLite ledger + encrypted content-addressed blob store
├── observers/       # Filesystem, process, git, terminal, network watchers
├── graph/           # Context graph engine, baseline, causal, blast-radius, replay
├── security/        # Redaction, AES-256-GCM encryption, policy engine, approvals
├── adapters/        # SDK + Codex CLI reference adapter + generic host observer
├── review_loop/     # Self-improving review loop implementation
├── daemon.py        # Main daemon process
├── cli.py           # Click & Rich CLI
└── api.py           # FastAPI local API
```

## Development & Testing

```bash
pytest tests/ -v
```
