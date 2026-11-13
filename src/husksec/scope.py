"""Scope: the authorization boundary of the security layer.

Everything the agent may touch is declared, *by a human*, in a ``scope.yaml``
file. This module loads that file and answers exactly one question:

    "Is this target authorized?"

Nothing in the security layer acts on a target without a yes from here.

Two commitments, both chosen for safety over convenience:

1. **Fail-closed.** If the file is missing, malformed, unparseable, or not
   explicitly marked ``authorized: true``, the answer is *no* for every target.
   An allowlist that fails *open* (allowing when unsure) is worse than none, so
   every ambiguity resolves to deny. A parse error is never swallowed into an
   "empty = allow nothing but keep going" state silently -- it raises, and the
   caller must treat a raised :class:`ScopeError` as "deny everything".

2. **Deny overrides allow.** A target is authorized only if it matches
   ``in_scope`` *and* matches nothing in ``out_of_scope``. The exclusion list
   always wins -- the standard way to carve a forbidden host (a shared gateway,
   a production box, a CTF's own infrastructure) out of an otherwise in-scope
   range.

This gate is the *cheap, structured* first filter -- the direct analogue of
husk's generic host deny-list. It is a filter and a HITL trigger, **not** the
last line of defence: the real isolation boundary is still the sandbox (and,
for network egress, a scoped path on top of it). We also never resolve DNS: a
name is matched *as a name*, never silently turned into an address that an
attacker-controlled resolver could repoint. A CIDR pattern therefore only ever
matches a literal-IP target, and a hostname pattern only a hostname target.

Why a hand-written parser instead of PyYAML: a scope file is security config.
Parsing it with a large, surprising grammar is itself attack surface (YAML has
famous footguns -- type coercion, anchors, ``!!python`` tags). We accept a
tiny, explicit subset and *reject* everything else, so a typo can never quietly
widen the scope. Cost: no new dependency, and a grammar you can read in full.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(Exception):
    """A scope file could not be loaded or parsed.

    Callers MUST treat this as "deny every target", never as "empty scope, carry
    on". It exists so that an unreadable or malformed allowlist can never be
    mistaken for a permissive one.
    """


# --------------------------------------------------------------------------- #
# The restricted scope.yaml grammar.
#
#   engagement:   <scalar>          # free-text label for the engagement
#   authorized:   true|false        # explicit human go-ahead; default false
#   in_scope:                       # a list; targets allowed (if not excluded)
#     - <scalar>
#   out_of_scope:                   # a list; targets always denied
#     - <scalar>
#   notes:        <scalar>          # free text
#
# Scalars may be bare or quoted ("..." / '...'); an unquoted scalar may carry a
# trailing " # comment". Anything outside this grammar raises ScopeError.
# --------------------------------------------------------------------------- #

_SCALAR_KEYS = {"engagement", "authorized", "notes"}
_LIST_KEYS = {"in_scope", "out_of_scope"}
_KNOWN_KEYS = _SCALAR_KEYS | _LIST_KEYS

_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(.*)$")
_LIST_ITEM_RE = re.compile(r"^\s+-\s+(.*)$")


def _find_inline_comment(s: str) -> int:
    """Index of an inline ``#`` comment (one preceded by whitespace), or -1.

    We only treat ``#`` as a comment when a space/tab precedes it, so a ``#``
    inside a value (e.g. a URL fragment) is left intact."""
    for i, ch in enumerate(s):
        if ch == "#" and i > 0 and s[i - 1] in (" ", "\t"):
            return i
    return -1


def _parse_scalar(raw: str, lineno: int) -> str:
    s = raw.strip()
    if not s:
        return ""
    if s[0] in ("'", '"'):
        quote = s[0]
        end = s.find(quote, 1)
        if end == -1:
            raise ScopeError(f"line {lineno}: unterminated quote in {raw!r}")
        trailing = s[end + 1:].strip()
        if trailing and not trailing.startswith("#"):
            raise ScopeError(f"line {lineno}: unexpected text after quoted value: {trailing!r}")
        return s[1:end]
    cut = _find_inline_comment(s)
    if cut != -1:
        s = s[:cut].strip()
    return s


def _parse_scalar_key(key: str, value: str, lineno: int):
    s = _parse_scalar(value, lineno)
    if key == "authorized":
        low = s.strip().lower()
        if low in ("true", "yes"):
            return True
        if low in ("false", "no", ""):
            return False
        raise ScopeError(f"line {lineno}: 'authorized' must be true/false, got {s!r}")
    return s


def parse_scope_text(text: str) -> dict:
    """Parse the restricted scope grammar into a plain dict. Raises ScopeError
    on anything outside the grammar (fail-closed)."""
    data: dict = {}
    current_list_key: str | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if line[:1] in (" ", "\t"):  # indented -> must be a list item
            m = _LIST_ITEM_RE.match(line)
            if not m or current_list_key is None:
                raise ScopeError(f"line {lineno}: unexpected indented line {raw!r}")
            item = _parse_scalar(m.group(1), lineno)
            if item:
                data[current_list_key].append(item)
            continue

        m = _KEY_RE.match(line)  # top-level 'key: ...'
        if not m:
            raise ScopeError(f"line {lineno}: expected 'key: value' or '- item', got {raw!r}")
        key, rest = m.group(1), m.group(2)
        if key not in _KNOWN_KEYS:
            raise ScopeError(
                f"line {lineno}: unknown scope key {key!r}; allowed: {sorted(_KNOWN_KEYS)}"
            )
        if key in data:
            raise ScopeError(f"line {lineno}: duplicate key {key!r}")
        value = rest.strip()
        if key in _LIST_KEYS:
            if value and not value.startswith("#"):
                raise ScopeError(
                    f"line {lineno}: {key!r} is a list; put entries on indented '- ' lines, "
                    f"not inline ({value!r})"
                )
            data[key] = []
            current_list_key = key
        else:
            data[key] = _parse_scalar_key(key, value, lineno)
            current_list_key = None
    return data


# --------------------------------------------------------------------------- #
# Target normalization and matching.
# --------------------------------------------------------------------------- #

def normalize_target(target: str) -> str:
    """Reduce a target (URL, host:port, bare host or IP) to a bare lowercase
    host. Returns "" if no host can be extracted.

    Examples:
        https://TARGET.htb:8443/admin -> target.htb
        10.10.10.5:443                -> 10.10.10.5
        [::1]:8080                    -> ::1
        target.htb/login              -> target.htb
    """
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        t = urlsplit(t).hostname or ""
    else:
        t = t.split("/", 1)[0]                  # drop any path
        if t.startswith("["):                    # [ipv6]:port
            t = t[1:].split("]", 1)[0]
        elif t.count(":") == 1:                  # host:port (not bare IPv6)
            t = t.split(":", 1)[0]
    return t.strip().lower().rstrip(".")


def _as_network(pattern: str):
    """Return an ip_network for an IP/CIDR pattern, else None. A bare IP becomes
    its /32 (or /128) host network, so IP patterns match the exact address."""
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def matches(pattern: str, host: str, *, match_apex: bool = False) -> bool:
    """True if a normalized host matches a single scope pattern.

    Pattern forms: an IP (10.0.0.5), a CIDR (10.0.0.0/24), a wildcard subdomain
    (*.example.com), or an exact hostname. IP/CIDR patterns match only literal-IP
    hosts; hostname patterns match only hostname hosts -- we never resolve DNS to
    bridge the two.

    ``match_apex``: by convention ``*.example.com`` does NOT match the apex
    ``example.com``. For the EXCLUSION list that asymmetry is dangerous (an
    operator who walls off ``*.internal.corp`` would still expose
    ``internal.corp`` itself), so :meth:`Scope.check` passes match_apex=True when
    testing ``out_of_scope`` -- deny broadly, allow narrowly.
    """
    pat = (pattern or "").strip().lower().rstrip(".")
    if not pat:
        return False
    if "://" in pat:                              # a URL pattern -> match on its host
        pat = (urlsplit(pat).hostname or "").rstrip(".")
    if not pat or not host:
        return False
    net = _as_network(pat)
    if net is not None:
        ip = _as_ip(host)
        if ip is None:
            return False
        # An IPv4-mapped IPv6 address (::ffff:a.b.c.d) must be compared against
        # IPv4 networks as its embedded IPv4, or it would slip past IPv4 rules.
        if ip.version == 6 and getattr(ip, "ipv4_mapped", None) is not None and net.version == 4:
            ip = ip.ipv4_mapped
        if ip.version != net.version:
            return False
        return ip in net
    if pat.startswith("*."):
        suffix = pat[1:]                          # ".example.com"
        if host.endswith(suffix) and len(host) > len(suffix):
            return True
        return bool(match_apex and host == pat[2:])   # the zone apex, deny side only
    return host == pat


@dataclass
class Scope:
    """A loaded, queryable authorization scope.

    Build it with :meth:`load` (from a file) or :meth:`from_text`. Ask it
    :meth:`allows` / :meth:`check`. Everything is deny-by-default.
    """

    engagement: str = ""
    authorized: bool = False
    in_scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_text(cls, text: str) -> "Scope":
        d = parse_scope_text(text)
        return cls(
            engagement=d.get("engagement", ""),
            authorized=bool(d.get("authorized", False)),
            in_scope=list(d.get("in_scope", [])),
            out_of_scope=list(d.get("out_of_scope", [])),
            notes=d.get("notes", ""),
        )

    @classmethod
    def load(cls, path) -> "Scope":
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as e:
            raise ScopeError(f"cannot read scope file {path!r}: {e}") from e
        return cls.from_text(text)

    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, human-readable reason). The reason is meant to be
        fed back to the model as an observation when a call is refused."""
        if not self.authorized:
            return False, "scope is not marked 'authorized: true' (fail-closed: nothing is in scope)"
        host = normalize_target(target)
        if not host:
            return False, f"could not extract a host from target {target!r}"
        for pat in self.out_of_scope:
            if matches(pat, host, match_apex=True):
                return False, f"{host} matches out_of_scope entry {pat!r} (deny overrides allow)"
        for pat in self.in_scope:
            if matches(pat, host):
                return True, f"{host} is authorized (matches in_scope {pat!r})"
        return False, f"{host} is not in the declared scope"

    def allows(self, target: str) -> bool:
        return self.check(target)[0]
