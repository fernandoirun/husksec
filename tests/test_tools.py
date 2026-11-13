"""Tests for the security tools and the scope enforcement around them.

The key safety property: an out-of-scope action is refused WITHOUT touching the
sandbox. We prove that with a fake sandbox that records every exec call.
"""
from husksec.enforcement import extract_candidate_targets, out_of_scope_hit
from husksec.scope import Scope
from husksec.tools import (
    build_security_tools,
    curl_probe_cmd,
    make_guarded_run_tool,
    nmap_port_scan_cmd,
)

SCOPE = Scope.from_text(
    "authorized: true\n"
    "in_scope:\n  - 10.10.11.0/24\n  - target.htb\n"
    "out_of_scope:\n  - 10.10.11.1\n  - evil.example.com\n"
)


class FakeSandbox:
    shell_hint = "a POSIX shell"

    def __init__(self):
        self.calls = []

    def exec(self, command, timeout=60.0):
        self.calls.append(command)
        return 0, f"ran: {command}"


def _tool(tools, name):
    return next(t for t in tools if t.name == name)


# --- command builders ------------------------------------------------------ #

def test_port_scan_cmd_rejects_bad_ports():
    import pytest
    with pytest.raises(ValueError):
        nmap_port_scan_cmd("10.0.0.1", "1-1000; rm -rf /")


def test_curl_cmd_quotes_url():
    cmd = curl_probe_cmd("http://target.htb/a b")
    assert "curl" in cmd and "'http://target.htb/a b'" in cmd


# --- typed tools enforce scope BEFORE executing ---------------------------- #

def test_port_scan_in_scope_executes():
    sb = FakeSandbox()
    tools = build_security_tools(sb, SCOPE)
    out = _tool(tools, "port_scan")(target="10.10.11.50", ports="22,80")
    assert "ran: " in out and "nmap" in out
    assert len(sb.calls) == 1


def test_port_scan_out_of_scope_does_not_execute():
    sb = FakeSandbox()
    tools = build_security_tools(sb, SCOPE)
    out = _tool(tools, "port_scan")(target="10.10.11.1")        # excluded gateway
    assert out.startswith("BLOCKED by scope")
    assert sb.calls == []                                        # nothing ran


def test_http_probe_scopes_on_url_host():
    sb = FakeSandbox()
    tools = build_security_tools(sb, SCOPE)
    assert _tool(tools, "http_probe")(url="http://evil.example.com/x").startswith("BLOCKED")
    assert sb.calls == []
    ok = _tool(tools, "http_probe")(url="http://target.htb/login")
    assert "curl" in ok and len(sb.calls) == 1


def test_unauthorized_scope_blocks_everything():
    sb = FakeSandbox()
    s = Scope.from_text("authorized: false\nin_scope:\n  - 10.10.11.0/24\n")
    tools = build_security_tools(sb, s)
    assert _tool(tools, "port_scan")(target="10.10.11.50").startswith("BLOCKED")
    assert sb.calls == []


# --- guarded generic run --------------------------------------------------- #

def test_guarded_run_blocks_out_of_scope_token():
    sb = FakeSandbox()
    run = make_guarded_run_tool(sb, SCOPE)
    out = run(command="curl http://evil.example.com/")
    assert out.startswith("BLOCKED by scope")
    assert sb.calls == []


def test_guarded_run_allows_local_work():
    sb = FakeSandbox()
    run = make_guarded_run_tool(sb, SCOPE)
    out = run(command="echo hello > loot.txt && cat loot.txt")
    assert "exit_code=0" in out
    assert len(sb.calls) == 1


def test_run_tool_is_risky():
    sb = FakeSandbox()
    assert make_guarded_run_tool(sb, SCOPE).risky is True


# --- candidate extraction -------------------------------------------------- #

def test_extract_candidate_targets():
    got = extract_candidate_targets("nmap 10.0.0.5 && curl https://A.TARGET.htb/x")
    assert "10.0.0.5" in got
    assert "a.target.htb" in got


def test_out_of_scope_hit():
    assert out_of_scope_hit(SCOPE, "ping evil.example.com") is not None
    assert out_of_scope_hit(SCOPE, "ping target.htb") is None
