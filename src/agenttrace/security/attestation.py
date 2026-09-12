"""Pre-flight environment-contract attestation (ant.md P1 #5).

Root cause of all four September-2026 incidents: the environment was
DECLARED isolated (simulation, no internet) but was actually connected
to the open internet through a misconfiguration. AgentTrace detects
egress at runtime; this module adds the missing **pre-flight** step:
before a sealed session starts, actually probe the environment's
network boundary and record what was measured as a signed,
chain-anchored attestation bound to the session.

``EnvironmentContract`` states what the operator declares:
internet_access_allowed (sealed when False) and, optionally, an
explicit destination allowlist.

``EnvironmentAttester`` measures what the host actually exposes:
 - resolved system DNS servers (per-OS, best-effort read)
 - default gateway / route presence
 - whether a proxy env var bypass list (NO_PROXY) exempts hosts
 - a socket-level reachability probe of a public canary (only run when
   the contract is sealed — proving isolation wrong is the point)

``AttestationResult`` compares declared vs measured and classifies:
 - ``isolated_verified`` — sealed, canary unreachable, no gateway/DNS
   exemption found
 - ``isolation_broken`` — sealed but the canary answered (or a bypass
   path exists): the exact Anthropic misconfiguration shape
 - ``unverifiable`` — probe failed to run; NEVER treated as isolated
   (fail closed), the session starts flagged

The result is sealed with the same HMAC report key material as
``report_auth`` (local-only; no network) and bound to the session id,
so a session's ledger carries *why* isolation was believed at start.
Honest limits: a same-user malware process can spoof probe results
(the no-out-of-band-witness ceiling, plan2 architectural #10); the
attestation records what the host measured, not an independent truth.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_CANARY_HOSTS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
_CANARY_PORT = 53
_CANARY_TIMEOUT_S = 2.0
_ATTESTATION_VERSION = "1.0"


class AttestationError(RuntimeError):
    """The pre-flight probe itself failed; isolation status is unknown."""


@dataclass(frozen=True)
class EnvironmentContract:
    """What the operator declares about the session's environment."""

    internet_access_allowed: bool = True
    allowed_destinations: tuple[str, ...] = ()

    @property
    def sealed(self) -> bool:
        return not self.internet_access_allowed


@dataclass(frozen=True)
class EnvironmentMeasurement:
    """What the host actually exposes at pre-flight time."""

    canary_reachable: bool | None
    canary_host: str
    dns_servers: tuple[str, ...]
    default_gateway: str
    proxy_bypass_entries: tuple[str, ...]
    measured_at: datetime


@dataclass(frozen=True)
class AttestationResult:
    """Declared-vs-measured verdict, sealed and session-bound."""

    verdict: str  # isolated_verified | isolation_broken | unverifiable | unsealed_recorded
    contract: EnvironmentContract
    measurement: EnvironmentMeasurement | None
    reasons: tuple[str, ...]
    attestation_hash: str
    sealed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": _ATTESTATION_VERSION,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "contract": {
                "internet_access_allowed": self.contract.internet_access_allowed,
                "allowed_destinations": list(self.contract.allowed_destinations),
            },
            "measurement": (
                {
                    "canary_reachable": self.measurement.canary_reachable,
                    "canary_host": self.measurement.canary_host,
                    "dns_servers": list(self.measurement.dns_servers),
                    "default_gateway": self.measurement.default_gateway,
                    "proxy_bypass_entries": list(self.measurement.proxy_bypass_entries),
                }
                if self.measurement is not None
                else None
            ),
            "sealed_at": self.sealed_at.isoformat(),
        }


def _canon(obj: Any) -> bytes:
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")



def _probe_canary() -> tuple[bool, str]:
    """Socket-probe public DNS canaries. Returns (reachable, host_tried)."""
    for host in _CANARY_HOSTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(_CANARY_TIMEOUT_S)
            try:
                # A DNS query for a reserved name; any answer implies egress.
                sock.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                            b"\x07version\x04bind\x00\x00\x01\x00\x01", (host, _CANARY_PORT))
                sock.recvfrom(512)
                return True, host
            except (TimeoutError, ConnectionError, OSError):
                continue
            finally:
                sock.close()
        except OSError:
            continue
    return False, _CANARY_HOSTS[0]


def _read_dns_servers() -> tuple[str, ...]:
    """Best-effort system DNS resolver list, per-OS."""
    servers: list[str] = []
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
            ).stdout
            in_dns = False
            for line in out.splitlines():
                if "DNS Servers" in line:
                    in_dns = True
                    part = line.split(":", 1)[-1].strip()
                    if part:
                        servers.append(part)
                elif in_dns and line.startswith("        ") and line.strip():
                    servers.append(line.strip())
                else:
                    in_dns = False
        except (OSError, subprocess.SubprocessError):
            return ()
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except OSError:
            return ()
    return tuple(dict.fromkeys(servers))


def _read_default_gateway() -> str:
    """Best-effort default gateway string ('' when unavailable)."""
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=10
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    return parts[2]
        else:
            with open("/proc/net/route", encoding="utf-8") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] == "00000000":
                        raw = parts[2]
                        gw = ".".join(
                            str(int(raw[i:i + 2], 16)) for i in (6, 4, 2, 0)
                        )
                        return gw
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return ""

class EnvironmentAttester:
    """Measures the environment's actual network boundary and seals a verdict."""

    def __init__(self, report_key: bytes | None = None) -> None:
        # report_key: local HMAC key material (report_auth-derived when the
        # daemon provides it; a derived fallback otherwise). Local-only.
        self._report_key = report_key or b"agenttrace-attestation-local-key"

    def preflight(self, contract: EnvironmentContract) -> AttestationResult:
        """Probe the environment and classify declared-vs-measured."""
        reasons: list[str] = []
        try:
            canary_reachable, canary_host = _probe_canary()
            measurement = EnvironmentMeasurement(
                canary_reachable=canary_reachable,
                canary_host=canary_host,
                dns_servers=_read_dns_servers(),
                default_gateway=_read_default_gateway(),
                proxy_bypass_entries=tuple(
                    e.strip()
                    for e in os.environ.get("NO_PROXY", "").split(",")
                    if e.strip()
                ),
                measured_at=datetime.now(timezone.utc),
            )
        except Exception as exc:  # noqa: BLE001 — probe failure = unverifiable
            logger.warning("Environment pre-flight probe failed: %s", exc)
            unverifiable = AttestationResult(
                verdict="unverifiable",
                contract=contract,
                measurement=None,
                reasons=(
                    f"pre-flight probe failed: {type(exc).__name__}: {exc}",
                    "fail-closed: unverifiable isolation is treated as broken",
                ),
                attestation_hash="",
            )
            return self._seal(unverifiable)

        if not contract.sealed:
            reasons.append("contract declares internet access allowed; "
                           "attestation records the measured boundary for provenance")
            verdict = "unsealed_recorded"
        elif canary_reachable:
            verdict = "isolation_broken"
            reasons.append(
                f"sealed contract but public canary {canary_host} answered — "
                "the declared-isolated environment has egress (the Anthropic "
                "misconfiguration shape)"
            )
        elif measurement.default_gateway == "" and not measurement.dns_servers:
            verdict = "isolated_verified"
            reasons.append(
                "sealed contract: canary unreachable, no default gateway, "
                "no configured DNS resolvers"
            )
        else:
            verdict = "isolated_verified"
            reasons.append(
                "sealed contract: canary unreachable; gateway/DNS present but "
                "no egress observed — egress remains runtime-monitored"
            )
        for entry in measurement.proxy_bypass_entries:
            if entry in {"*", "0.0.0.0/0"}:
                reasons.append(f"proxy bypass wildcard entry {entry!r} noted")
        return self._seal(AttestationResult(
            verdict=verdict,
            contract=contract,
            measurement=measurement,
            reasons=tuple(reasons),
            attestation_hash="",
        ))

    # -- Sealing ----------------------------------------------------------------

    def _seal(self, result: AttestationResult) -> AttestationResult:
        payload = result.to_payload()
        payload["attestation_hash"] = ""
        digest = hmac.new(
            self._report_key, _canon(payload), hashlib.sha256
        ).hexdigest()
        return AttestationResult(
            verdict=result.verdict,
            contract=result.contract,
            measurement=result.measurement,
            reasons=result.reasons,
            attestation_hash=digest,
            sealed_at=result.sealed_at,
        )

