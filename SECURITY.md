# Security Policy

AgentTrace is a **local-first security auditor for AI coding agents**. If you
find a vulnerability in it, we want to hear from you through a channel that
does not put other users at risk.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's **private vulnerability reporting** for this repository
(Security tab → "Report a vulnerability"), which notifies the maintainers
privately. If that is unavailable, open a public issue titled only
`security: request private contact channel` — with no technical detail — and
we will provide a private channel within 48 hours.

## What is in scope

- **The hash chain and ledger** (`src/agenttrace/storage/`): tampering with
  or forging events, reports, or approval records without detection.
- **Report authenticity** (`report_auth.py`): producing a signed report that
  does not correspond to real ledger history.
- **The execution broker** (`security/broker.py`): replaying or forging
  approval nonces, escaping path scoping.
- **Redaction and encryption** (`security/redaction.py`,
  `security/encryption.py`): secrets that survive redaction into storage,
  blobs, reports, or the dashboard.
- **The local API** (`api.py`): endpoints that let a local unprivileged
  process elevate, exfiltrate, or mutate session state.
- **Replay isolation** (`graph/replay.py`, `security/isolation.py`):
  simulations touching the live workspace or escaping containment.

## What is explicitly out of scope (known ceiling)

- **Same-user attacks.** AgentTrace runs as the user it audits. Malware in
  the same user session can read runtime tokens, encrypted blobs, and the
  ledger. Defense against same-user compromise is out of scope by design;
  see the "same-user trust boundary" entry in the project's architecture
  audit notes.
- **Host-level compromise.** A root/admin attacker can forge OS telemetry
  the sensors rely on. There is no out-of-band witness yet; this is a
  documented architectural limit, not a secret.
- **Model internals.** AgentTrace audits observable behavior (processes,
  files, network, git), not model reasoning. Sandbagging or concealed
  reasoning that leaves no OS-observable trace is undetectable by design.

Reporting in-scope findings in these ceiling areas that *break a specific
stated guarantee* (e.g., the hash chain, report signatures, redaction) is
welcome and in scope.

## Safe harbor

We will not pursue or support action against anyone who researches this
software in good faith, avoids privacy violations and service degradation,
and reports findings through the channels above.

## Response targets

- Acknowledgment: within 72 hours.
- Triage and severity assessment: within 7 days.
- Fix or documented mitigation for critical issues: within 30 days.

Coordinated disclosure is the default. Credit for reporters in the fix
release is given on request.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | yes       |
| < 0.2   | no        |
