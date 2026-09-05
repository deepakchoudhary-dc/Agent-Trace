# Contributing to AgentTrace

Thank you for helping build a trustworthy audit plane for AI agents. This
project has one non-negotiable principle: **honesty over capability**. A
feature that detects less but never lies beats a feature that detects more
and sometimes invents. Every contribution is reviewed against that standard.

## Ways to contribute

- **Use it and report back.** Real workloads are how detectors get calibrated.
  File [Detector feedback](.github/ISSUE_TEMPLATE/detector_feedback.yml) —
  false positives and false negatives are equally valuable.
- **Reproduce and verify.** Confirm bugs, test edge cases, review the docs
  against actual behavior.
- **Code.** Bug fixes, new detectors, sensor improvements — read the rest of
  this guide first.
- **Security research.** Found a way to break the hash chain, forge a report,
  or escape isolation? Do **not** open a public issue — see
  [SECURITY.md](SECURITY.md) for private disclosure and safe harbor.

## Getting set up

Requirements: **Python 3.10+** (3.11 recommended), git. Windows, Linux, and
macOS are all supported development platforms.

```bash
git clone https://github.com/deepakchoudhary-dc/Agent-Trace.git
cd Agent-Trace

python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

pip install -e '.[dev]'
```

Verify your setup matches CI before touching anything:

```bash
pytest tests/ -v
ruff check src/ tests/
mypy src/agenttrace --strict
```

The dashboard (optional) lives in `dashboard/`: Node 20, `npm ci`,
`npm run lint && npx tsc --noEmit && npm run test && npm run build`.

## The required reading

Three documents define the standards your PR will be reviewed against. They
are part of this repository's working set; ask in a discussion if a referenced
document is not public yet and a maintainer will paste the relevant rules.

1. **The spec** (`plan2.md` conventions section in the project wiki) — what
   the tool promises, the threat model, the honesty invariants.
2. **The review standard** (`review.md` conventions) — the anti-slop
   checklist reviewers actually apply.
3. **The mistake log** (`gotchas.md` conventions) — every bug class this
   codebase has hit before, so you don't hit it again.

> Maintainers keep the process documents in sync with the code. If a rule in
> a process doc contradicts what CI enforces, CI wins — then file an issue so
> the doc gets fixed.

## Ground rules

- **Python**: 3.10+ compatible. Type hints on every function signature;
  Pydantic models for all data structures. CI runs `mypy --strict` and it
  is a gate, not a suggestion.
- **Tests**: every behavior change ships with tests. Detector changes need
  tests for *both* the triggering and the benign case — a detector that
  cannot be proven quiet cannot be trusted loud.
- **Lint/format**: `ruff check src/ tests/` must pass with zero findings.
  Line length 100.
- **No `any`** in TypeScript; no `# type: ignore` in Python without a
  comment explaining the specific, verified reason.
- **No secrets, ever.** Nothing in code, tests, fixtures, or issue text.
  If a fixture needs a credential-shaped string, build one from characters
  — do not paste a real one even to "prove redaction works".
- **No network calls** in tests. The product is local-first; its tests are too.
- **Match existing style.** If the code around you does it one way, so do you.

## The honesty invariants (reviewers will check these first)

1. **Hash chain integrity** — every event's hash includes the previous
   event's hash. If your change touches serialization, prove old ledgers
   still verify.
2. **Confidence labeling** — direct observation is high confidence,
   correlation is medium, inference is low. Detectors never overclaim.
3. **No fabricated explanations** — if agent internals are not observable,
   the report shows the gap; it does not invent a story. Statistics about
   behavior, never assertions about motive.
4. **Replay isolation** — simulations never modify the live workspace.
5. **Local-only** — zero telemetry, zero network egress of user data. If
   your change adds any network surface, it will need an extremely good
   reason and an explicit maintainer discussion first.

## Pull request process

1. Fork, cut a branch from `main`, keep it focused. One PR, one concern.
2. Follow the commit convention CI and the maintainers use: `core:` for
   code, `docs:` for documentation, `test:` for tests-only.
3. Fill the PR template honestly — including the "what this does NOT do"
   section. Overselling is the fastest way to lose reviewer trust.
4. Ensure every CI gate is green locally before pushing.
5. A maintainer reviews; expect the review loop to iterate. Feedback is
   about the code, push back with evidence when you disagree.

## Reviewing contributions

Reviewers check spec compliance, correctness, anti-slop (no dead code, no
speculative abstractions, no copy-paste drift), and the honesty invariants
above. Detector PRs additionally need a documented false-positive analysis:
what benign workflow could trip this, and why the threshold holds.
