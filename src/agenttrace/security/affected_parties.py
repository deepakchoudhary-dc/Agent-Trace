"""Affected-third-parties extraction (ant.md P2 #9).

Anthropic's incident report closes with "We have notified all affected
parties" — but no report section enumerates WHO those parties are. This
module produces that enumeration offline from the sealed ledger: the
external hosts and systems a session actually touched, each anchored to
the chain hashes of the events that observed the contact.

Extraction is deliberately conservative — the module states what it
saw, never what it inferred:

- **Authoritative plane:** ``NetworkEvent`` destination IPs are the
  kernel-observed record of real connections. These are always
  extracted (after excluding private/reserved ranges — a destination
  inside the observed machine or its LAN is not a third party).
- **Command plane:** URLs (``scheme://host[:port]/…``) and IP literals
  appearing in ``CommandEvent`` command lines are extracted as
  *claimed* contacts. Bare domain names in commands are NOT extracted:
  offline text cannot distinguish a hostname from a version string or
  a file name with a TLD-like suffix, and a false third party in a
  notification list is worse than a stated extraction limit.
- **Never fabricated:** an empty report means "no external contact was
  observed", not "no contact happened" — polling gaps and the
  single-host boundary apply (see ``extraction_limits``).

Every party carries the session ids that touched it and the event
hashes that evidence the contact, so the list is auditable back to the
ledger rather than a trust-me summary.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from agenttrace.models.events import CommandEvent, EventBase, NetworkEvent

if TYPE_CHECKING:
    from collections.abc import Mapping

# Maximum evidence refs retained per party: the full set lives in the
# ledger; the report keeps enough to anchor the finding without growing
# unbounded for beacon-style contacts.
_MAX_EVIDENCE_REFS_PER_PARTY = 12

_URL_RE = re.compile(r"https?://[^\s'\"<>|\\]+", re.IGNORECASE)
# Dotted-quad with optional :port. Matched only in command text; the
# hostname regex below is intentionally NOT applied to commands (see
# module docstring for why bare domains are not extracted).
_IPV4_PORT_RE = re.compile(
    r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?\b"
)
# netcat-style contact: the port is a following space-separated token
# (``nc <ip> <port>``), not a colon suffix.
_NC_PORT_RE = re.compile(
    r"\bnc(?:at)?\s+(?:-[^\s]+\s+)*"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<port>\d{1,5})\b",
    re.IGNORECASE,
)


def _is_third_party_ip(ip_text: str) -> bool:
    """True when the address is a plausible external third party.

    Private, loopback, link-local, reserved, multicast and unspecified
    ranges are excluded: those are the machine itself or its local
    network, and listing them as "affected parties" would be noise,
    not notification material.
    """
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


@dataclass
class AffectedParty:
    """One external host/system observed from inside the session."""

    kind: str  # "ip" | "hostname"
    identifier: str  # normalized address or URL authority
    port: int | None
    sessions: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "port": self.port,
            "sessions": list(self.sessions),
            "evidence_refs": list(self.evidence_refs),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class AffectedPartiesReport:
    """The session's external contacts, with the honest extraction scope."""

    session_ids: list[str]
    parties: list[AffectedParty]
    scope_note: str
    extraction_limits: list[str]

    def to_payload(self) -> dict[str, object]:
        return {
            "session_ids": list(self.session_ids),
            "party_count": len(self.parties),
            "parties": [p.to_payload() for p in self.parties],
            "scope_note": self.scope_note,
            "extraction_limits": list(self.extraction_limits),
        }


_EXTRACTION_LIMITS = (
    "network payload contents are not captured; parties are hosts, not data flows",
    "bare domain names in command text are not extracted (offline text cannot "
    "distinguish hostnames from version strings or file names) — URL-shaped and "
    "IP-shaped contacts and observed network connections only",
    "single-host visibility: contacts made by the same agent from another "
    "machine are invisible (documented architectural ceiling)",
    "an empty party list means 'none observed', never 'none happened'",
)


def extract_affected_parties(
    events_by_session: Mapping[Any, list[EventBase]],
) -> AffectedPartiesReport:
    """Enumerate external third parties contacted across the given sessions.

    Args:
        events_by_session: mapping of session id -> that session's
            events, in ledger order. Callers pass the sealed ledger's
            query output; this module never touches storage itself.
    """
    parties: dict[tuple[str, str], AffectedParty] = {}
    session_ids: list[str] = []

    for sid, events in events_by_session.items():
        sid_str = str(sid)
        session_ids.append(sid_str)
        for event in events:
            for kind, identifier, port in _candidates(event):
                key = (kind, identifier)
                party = parties.get(key)
                if party is None:
                    party = AffectedParty(
                        kind=kind, identifier=identifier, port=port
                    )
                    parties[key] = party
                if port is not None and party.port is None:
                    party.port = port
                if sid_str not in party.sessions:
                    party.sessions.append(sid_str)
                ref = str(event.event_hash or event.event_id)
                if (
                    ref not in party.evidence_refs
                    and len(party.evidence_refs) < _MAX_EVIDENCE_REFS_PER_PARTY
                ):
                    # One event may yield the same party through two shapes
                    # (an IP inside a URL matches both rules); the party
                    # carries the event once.
                    party.evidence_refs.append(ref)
                if not party.first_seen:
                    party.first_seen = event.timestamp.isoformat()
                party.last_seen = event.timestamp.isoformat()

    ordered = sorted(parties.values(), key=lambda p: (p.kind, p.identifier))
    return AffectedPartiesReport(
        session_ids=session_ids,
        parties=ordered,
        scope_note=(
            "External hosts/systems observed or claimed in command text by "
            "the listed session(s), derived offline from the sealed ledger. "
            "Every party is anchored to chain hashes of the events that "
            "observed the contact."
        ),
        extraction_limits=list(_EXTRACTION_LIMITS),
    )


def _candidates(event: EventBase) -> list[tuple[str, str, int | None]]:
    """Third-party candidates from one event: (kind, identifier, port)."""
    if isinstance(event, NetworkEvent) and event.destination_ip:
        if _is_third_party_ip(event.destination_ip):
            return [("ip", event.destination_ip, event.destination_port or None)]
        return []

    if isinstance(event, CommandEvent) and event.command:
        # (kind, identifier) -> [kind, identifier, port]; one command can
        # name the same party through several shapes (an IP inside a URL
        # also matches the bare-IP rule), and ports merge rather than
        # overwrite so the most specific value survives.
        found: dict[tuple[str, str], list[str | str | int | None]] = {}

        def _add(kind: str, ident: str, port: int | None) -> None:
            entry = found.setdefault((kind, ident), [kind, ident, None])
            if port is not None and entry[2] is None:
                entry[2] = port

        nc_ports: dict[str, int] = {}
        for match in _NC_PORT_RE.finditer(event.command):
            if _is_third_party_ip(match.group("ip")):
                nc_ports[match.group("ip")] = int(match.group("port"))

        for match in _URL_RE.finditer(event.command):
            try:
                parts = urlsplit(match.group(0))
            except ValueError:
                continue
            host = parts.hostname
            if not host:
                continue
            host = host.lower()
            if ":" in host:
                # urlsplit already separates brackets; a bare colon here
                # means the token was not a usable authority.
                continue
            if _looks_like_ip(host):
                if not _is_third_party_ip(host):
                    continue
                _add("ip", host, parts.port)
            else:
                # URL authority: scheme-qualified, so this is a claimed
                # contact with real structure behind it.
                _add("hostname", host, parts.port)
        for match in _IPV4_PORT_RE.finditer(event.command):
            ip = match.group("ip")
            if not _is_third_party_ip(ip):
                continue
            port_text = match.group("port")
            port = int(port_text) if port_text else nc_ports.get(ip)
            _add("ip", ip, port)
        return [
            (entry[0], entry[1], entry[2])  # type: ignore[misc]
            for entry in found.values()
        ]

    return []


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
