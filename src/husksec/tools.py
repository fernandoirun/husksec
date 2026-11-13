"""Security tools as husk plugins.

Design (the hybrid model agreed for the layer):

* **Typed network tools** -- ``port_scan``, ``service_scan``, ``http_probe`` --
  take the target as a *structured argument*. The target's host is checked
  against the scope BEFORE the command is built or run, so authorization is
  robust and auditable (not a regex over freeform shell). Each is a thin
  wrapper over a standard utility (nmap, curl) executed inside husk's sandbox.
* **A guarded generic ``run``** -- keeps husk's bash-first flexibility for local
  work (writing exploits, parsing loot), with a deny-first scope filter and
  HITL on top. Network reached through ``run`` is a documented residual risk
  mitigated by the sandbox + audit log; prefer the typed tools for network.

The commands are *built* by pure functions (easy to test) and *run* separately.
Every tool is ``risky=True``: it always passes through husk's approval hook.
Recon utilities must exist in the sandbox image; if one is missing the tool
returns a clear observation instead of crashing (the loop corrects from text).
"""
from __future__ import annotations

import re
import shlex

from husk import Tool

from .enforcement import out_of_scope_hit
from .scope import Scope, normalize_target
from .util import truncate

# \Z (not $): $ also matches just before a trailing newline, which would let a
# newline be smuggled into the unquoted ports field of the nmap command.
_PORTS_RE = re.compile(r"[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*\Z")
_IP_RANGE_RE = re.compile(r"[0-9.]+-[0-9.]+\Z")


def single_host(target: str) -> str:
    """Return the one authorized host from a target, or raise ValueError if the
    target denotes MORE than one host (a CIDR, an nmap octet range, or a comma
    list). The per-host network tools must never expand a single-host
    authorization into a subnet/range scan -- so they build their command from
    THIS value, never from the raw argument.
    """
    raw = (target or "").strip()
    host = normalize_target(raw)
    if not host:
        raise ValueError(f"no host in target {target!r}")
    if "://" not in raw and "/" in raw:
        raise ValueError(f"target {target!r} looks like a CIDR; scan a single host (scope is per-host)")
    if "," in raw or _IP_RANGE_RE.match(host):
        raise ValueError(f"target {target!r} looks like a range/list; scan a single host (scope is per-host)")
    return host


# --- pure command builders ------------------------------------------------- #

def nmap_port_scan_cmd(host: str, ports: str = "1-1000") -> str:
    if not _PORTS_RE.match(ports or ""):
        raise ValueError(f"invalid port spec {ports!r} (use e.g. '22,80,443' or '1-1000')")
    # -Pn: skip host discovery; default TCP connect scan works unprivileged.
    return f"command -v nmap >/dev/null 2>&1 && nmap -Pn -T4 -p {ports} {shlex.quote(host)} || echo 'nmap not found in sandbox image'"


def nmap_service_scan_cmd(host: str, port: str) -> str:
    if not _PORTS_RE.match(str(port) or ""):
        raise ValueError(f"invalid port {port!r}")
    return f"command -v nmap >/dev/null 2>&1 && nmap -Pn -sV -p {shlex.quote(str(port))} {shlex.quote(host)} || echo 'nmap not found in sandbox image'"


def curl_probe_cmd(url: str) -> str:
    return f"command -v curl >/dev/null 2>&1 && curl -sS -i --max-time 20 {shlex.quote(url)} || echo 'curl not found in sandbox image'"


# --- scoped execution wrapper ---------------------------------------------- #

def _logger(logger):
    return logger or (lambda event, **kw: None)


def _scoped_net_tool(name, description, params, *, sandbox, scope, logger, build, target_of, timeout):
    log = _logger(logger)

    def fn(**kwargs) -> str:
        target = target_of(kwargs)
        allowed, reason = scope.check(target)
        log("scope_check", tool=name, target=target, allowed=allowed, reason=reason)
        if not allowed:
            return f"BLOCKED by scope: {reason}"
        try:
            cmd = build(**kwargs)
        except ValueError as e:
            return f"error: {e}"
        code, out = sandbox.exec(cmd, timeout=timeout)
        log("net_action", tool=name, target=target, command=cmd, exit_code=code)
        return f"$ {cmd}\nexit_code={code}\n{truncate(out)}"

    return Tool(name, description, params, fn, risky=True)


# --- the generic guarded run ----------------------------------------------- #

_RUN_PARAMS = {
    "type": "object",
    "properties": {
        "command": {"type": "string", "description": "Shell command to run inside the isolated sandbox."}
    },
    "required": ["command"],
}


def make_guarded_run_tool(sandbox, scope: Scope, logger=None, *, timeout: float = 60.0, max_output: int = 4000) -> Tool:
    log = _logger(logger)

    def run(command: str) -> str:
        hit = out_of_scope_hit(scope, command)
        if hit:
            host, pat = hit
            log("scope_block", tool="run", host=host, pattern=pat, command=command)
            return (
                f"BLOCKED by scope: command references {host!r}, which matches the "
                f"out_of_scope entry {pat!r}. Rewrite it to stay in scope."
            )
        code, out = sandbox.exec(command, timeout=timeout)
        log("run_action", tool="run", exit_code=code, command=command)
        return f"exit_code={code}\n{truncate(out, max_output)}"

    return Tool(
        "run",
        "Run a shell command inside the isolated sandbox (local work: write/parse files, "
        "run exploits, inspect loot). For network actions against a target, prefer the typed "
        "tools (port_scan, service_scan, http_probe) -- they enforce scope. Commands that "
        "reference an out-of-scope host are refused.",
        _RUN_PARAMS,
        run,
        risky=True,
    )


# --- the typed tool set ----------------------------------------------------- #

def build_security_tools(sandbox, scope: Scope, logger=None, *, timeout: float = 120.0) -> list:
    """The husksec tool set to hand to a husk ``Agent``: a guarded ``run`` plus
    scope-enforcing typed network tools."""
    port_scan = _scoped_net_tool(
        "port_scan",
        "Scan TCP ports on an authorized target with nmap. The target host is checked against "
        "the engagement scope before anything runs.",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host or IP to scan (must be in scope)."},
                "ports": {"type": "string", "description": "Port spec, e.g. '22,80,443' or '1-1000'. Default '1-1000'."},
            },
            "required": ["target"],
        },
        sandbox=sandbox, scope=scope, logger=logger,
        build=lambda target, ports="1-1000": nmap_port_scan_cmd(single_host(target), ports),
        target_of=lambda kw: kw.get("target", ""),
        timeout=timeout,
    )
    service_scan = _scoped_net_tool(
        "service_scan",
        "Identify the service/version on one port of an authorized target (nmap -sV). Scope-checked.",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host or IP (must be in scope)."},
                "port": {"type": "string", "description": "Single port, e.g. '443'."},
            },
            "required": ["target", "port"],
        },
        sandbox=sandbox, scope=scope, logger=logger,
        build=lambda target, port: nmap_service_scan_cmd(single_host(target), port),
        target_of=lambda kw: kw.get("target", ""),
        timeout=timeout,
    )
    http_probe = _scoped_net_tool(
        "http_probe",
        "Fetch an HTTP(S) URL's response headers and body (curl -i) from an authorized host. "
        "The URL's host is scope-checked.",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL. Its host must be in scope."},
            },
            "required": ["url"],
        },
        sandbox=sandbox, scope=scope, logger=logger,
        build=lambda url: curl_probe_cmd(url),
        target_of=lambda kw: kw.get("url", ""),
        timeout=timeout,
    )
    return [make_guarded_run_tool(sandbox, scope, logger), port_scan, service_scan, http_probe]


def build_findings_tools(store) -> list:
    """Tools that let the agent write to the structured findings memory. Not
    risky (recording notes changes nothing on a target). A hypothesis is only
    ever *confirmed* by ground truth (see verify.py), not by the model saying so
    -- so set_finding_status should be driven by a verifier, and the tool
    description says as much."""
    def record_hypothesis(hypothesis: str) -> str:
        return f"recorded {store.record(hypothesis)}"

    def add_evidence(id: str, evidence: str) -> str:
        try:
            store.add_evidence(id, evidence)
            return f"evidence added to {id}"
        except KeyError as e:
            return f"error: {e}"

    def set_finding_status(id: str, status: str, note: str = "") -> str:
        try:
            store.set_status(id, status, note)
            return f"{id} -> {status}"
        except (KeyError, ValueError) as e:
            return f"error: {e}"

    def list_findings(status: str = "") -> str:
        return store.summary() if not status else "\n".join(
            f.oneline() for f in store.list(status)
        ) or f"no findings with status {status!r}"

    return [
        Tool("record_hypothesis",
             "Record a new hypothesis to investigate. Returns its id (e.g. F001).",
             {"type": "object", "properties": {"hypothesis": {"type": "string"}}, "required": ["hypothesis"]},
             record_hypothesis),
        Tool("add_evidence",
             "Attach a piece of evidence (an observation, output, or note) to a finding by id.",
             {"type": "object", "properties": {"id": {"type": "string"}, "evidence": {"type": "string"}},
              "required": ["id", "evidence"]},
             add_evidence),
        Tool("set_finding_status",
             "Set a finding's status to pending|confirmed|refuted. Only mark 'confirmed' when a "
             "reproducible ground-truth check (flag/crash/patch) has passed.",
             {"type": "object", "properties": {
                 "id": {"type": "string"},
                 "status": {"type": "string", "enum": ["pending", "confirmed", "refuted"]},
                 "note": {"type": "string"}}, "required": ["id", "status"]},
             set_finding_status),
        Tool("list_findings",
             "List findings, optionally filtered by status.",
             {"type": "object", "properties": {"status": {"type": "string"}}},
             list_findings),
    ]


def scope_system_prompt(scope: Scope) -> str:
    """Text to append to the agent's system prompt so the model knows its rules
    of engagement -- in scope, and that network goes through the typed tools."""
    in_scope = ", ".join(scope.in_scope) or "(none)"
    return (
        "\n\nRULES OF ENGAGEMENT (hard constraints):\n"
        f"- Engagement: {scope.engagement or 'unnamed'}. Authorized: {scope.authorized}.\n"
        f"- In scope: {in_scope}.\n"
        "- You may act ONLY against in-scope targets. Out-of-scope actions are refused.\n"
        "- For any network action use the typed tools (port_scan, service_scan, http_probe); "
        "they enforce scope. Use run for local work only.\n"
        "- This is authorized security testing. Practice responsible disclosure."
    )
