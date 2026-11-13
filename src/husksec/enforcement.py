"""Cheap, structured scope filters over freeform shell.

The typed tools in ``tools.py`` are the *robust* scope path: a structured
``target`` argument, checked before anything runs. The generic ``run`` tool, by
contrast, takes arbitrary shell, which cannot be reliably scope-checked by
parsing. So here we do only what is SAFE to do by parsing: a **deny-first**
filter that refuses a command clearly referencing an explicitly out-of-scope
host. We never *approve* a freeform command on the strength of parsing -- only
refuse an obviously forbidden one. This mirrors husk's stance on its own
deny-list: a cheap first filter and a HITL trigger, not the real boundary (the
sandbox is).
"""
from __future__ import annotations

import re
import socket

from .scope import Scope, matches, normalize_target

# Token shapes we treat as possible network targets inside a shell command.
_URL_RE = re.compile(r"https?://[^\s'\"<>|]+", re.I)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _decode_ipv4(host: str) -> str | None:
    """If a host is an obfuscated IPv4 (integer like 2852039166, octal/hex dotted
    like 0251.0376..., or a shorthand like 127.1), return its canonical dotted
    form; else None. inet_aton is deliberately lenient here -- that is what lets
    the deny filter catch the alternate encodings that curl/libc would resolve to
    the same forbidden address."""
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except (OSError, UnicodeError, TypeError):
        return None


def extract_candidate_targets(command: str) -> list[str]:
    """Best-effort extraction of host-like tokens from a shell command. Used
    only for the deny-first filter below, so over-extraction is harmless. We also
    decode obfuscated IPv4 encodings so an out_of_scope IP cannot be dodged by
    writing it as an integer/octal/hex (a classic SSRF-to-metadata trick)."""
    raw: list[str] = []
    for rx in (_URL_RE, _IPV4_RE, _DOMAIN_RE):
        raw += rx.findall(command or "")
    seen: set[str] = set()
    out: list[str] = []

    def _add(h: str) -> None:
        if h and h not in seen:
            seen.add(h)
            out.append(h)

    for c in raw:
        h = normalize_target(c)
        _add(h)
        decoded = _decode_ipv4(h)
        if decoded and decoded != h:
            _add(decoded)
    return out


def out_of_scope_hit(scope: Scope, command: str):
    """Return (host, pattern) for the first command token matching an
    ``out_of_scope`` entry, else None. Only the exclusion list is consulted --
    we refuse the clearly-forbidden, we do not bless the rest."""
    for host in extract_candidate_targets(command):
        for pat in scope.out_of_scope:
            if matches(pat, host):
                return host, pat
    return None
