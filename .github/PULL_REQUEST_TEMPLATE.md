# Pull request

## What this PR does
<!-- One paragraph. If you cannot say it in one paragraph, split the PR. -->

## Why
<!-- Link the issue ("Fixes #123"). For detectors: which failure class, cite the incident or research. -->

## What this PR does NOT do
<!-- Honest scoping. Adjacent problems you noticed but did not touch. Reviewers read this first. -->

## How I verified it
- [ ] `pytest tests/ -v` — all green (list new test files)
- [ ] `ruff check src/ tests/` — zero findings
- [ ] `mypy src/agenttrace --strict` — clean
- [ ] Dashboard gates (`eslint`, `tsc`, `vitest`, `build`) if frontend touched
- [ ] No secrets, no network calls in tests, no files outside task scope

## Honesty invariants checklist
<!-- For changes touching events, storage, reports, replay, or detectors. N/A is fine — say so. -->
- [ ] Hash chain: serialization changes proven compatible with old ledgers
- [ ] Confidence labels: new findings use high (observed) / medium (correlated) / low (inferred) correctly
- [ ] No fabricated explanations: reports show gaps instead of inventing causes
- [ ] Replay isolation: nothing here lets a simulation touch the live workspace
- [ ] Local-only: no telemetry or user-data egress introduced

## Detector PRs only
- [ ] Triggering case AND benign case both tested
- [ ] False-positive analysis: which benign workflows could trip this, and why the threshold holds
