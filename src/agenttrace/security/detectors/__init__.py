"""Threat-detection rule engine — host-observable attack-pattern rules.

Detects attack patterns that are visible at the host/telemetry layer:
prompt-injection marker text in observed artifacts, config-file tampering,
credential reads, obfuscation tools, egress anomalies, git history rewriting,
path tricks, privilege changes, and sandbox-escape boundary routing.

Design boundaries (see plan.md §6 — do not overclaim):
- Detectors observe effects (commands, files, network, git, process) — never
  model intent or hidden chain-of-thought.
- Prompt-injection detection flags marker *text observed in artifacts*; it
  never asserts the model obeyed or was compromised.
- Each finding carries an evidence reference (the triggering event) and an
  explicit confidence label from :class:`agenttrace.models.events.ConfidenceLevel`.
"""

from agenttrace.security.detectors.base import DetectionContext, Detector, DetectorFinding
from agenttrace.security.detectors.engine import DetectionEngine
from agenttrace.security.detectors.rules import (
    DEFAULT_DETECTORS,
    ConfigTamperDetector,
    CredentialReadDetector,
    EgressAnomalyDetector,
    GitHistoryRewritingDetector,
    ObfuscationDetector,
    PathTrickDetector,
    PrivilegeChangeDetector,
    PromptInjectionDetector,
    SandboxEscapeDetector,
)

__all__ = [
    "DEFAULT_DETECTORS",
    "ConfigTamperDetector",
    "CredentialReadDetector",
    "DetectionContext",
    "DetectionEngine",
    "Detector",
    "DetectorFinding",
    "EgressAnomalyDetector",
    "GitHistoryRewritingDetector",
    "ObfuscationDetector",
    "PathTrickDetector",
    "PrivilegeChangeDetector",
    "PromptInjectionDetector",
    "SandboxEscapeDetector",
]
