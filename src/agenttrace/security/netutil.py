"""Network address classification helpers.

Distinguishes *public* (real-world, internet-reachable) destinations from
private/loopback/link-local/reserved space. Used to elevate risk for actions
that touch real external systems — the failure mode of the case-study
incidents (Hugging Face production infra, the gym booking service).
"""

from __future__ import annotations

import ipaddress


def is_public_ip(ip: str | None) -> bool:
    """Return True if `ip` is a routable public IPv4/IPv6 address.

    Loopback, link-local, private (RFC 1918 / ULA), unspecified, multicast,
    and reserved ranges are treated as non-public. Unparseable values are
    treated as non-public (fail safe — do not escalate on garbage input).
    """
    if not ip:
        return False
    ip = ip.strip()
    if not ip:
        return False

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) resolves to the embedded address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return is_public_ip(str(addr.ipv4_mapped))
    return True
