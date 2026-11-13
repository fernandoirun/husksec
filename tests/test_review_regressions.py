"""Regressions for bugs found by the adversarial code review. Each test pins a
concrete scenario the review reported, so the fix can never silently regress.
"""
import pytest

from husksec.bench.core import BenchmarkTask, RunOutput, run_task
from husksec.enforcement import out_of_scope_hit
from husksec.findings import FindingsStore
from husksec.scope import Scope
from husksec.tools import build_security_tools, nmap_port_scan_cmd
from husksec.verify import verify_crash


class _FakeSandbox:
    shell_hint = "a POSIX shell"

    def __init__(self):
        self.calls = []

    def exec(self, command, timeout=60.0):
        self.calls.append(command)
        return 0, f"ran: {command}"


def _tool(tools, name):
    return next(t for t in tools if t.name == name)


def _clock():
    t = [1000.0]
    def tick():
        t[0] += 1.0
        return t[0]
    return tick


# scope-bypass #5 (HIGH): a CIDR/range target must not expand a per-host
# authorization into a subnet scan, and the excluded host must never be reached.
def test_cidr_or_range_target_is_refused_and_not_executed():
    sb = _FakeSandbox()
    s = Scope.from_text("authorized: true\nin_scope:\n  - 10.10.11.0/24\nout_of_scope:\n  - 10.10.11.1\n")
    port_scan = _tool(build_security_tools(sb, s), "port_scan")
    for bad in ("10.10.11.4/31", "10.10.11.0/24", "10.10.11.1-50"):
        out = port_scan(target=bad)
        assert out.startswith("error") or out.startswith("BLOCKED"), (bad, out)
    assert sb.calls == []                                        # nothing ever ran


def test_single_host_scan_builds_from_the_authorized_host():
    sb = _FakeSandbox()
    s = Scope.from_text("authorized: true\nin_scope:\n  - 10.10.11.0/24\n")
    _tool(build_security_tools(sb, s), "port_scan")(target="10.10.11.5", ports="22")
    assert len(sb.calls) == 1 and "10.10.11.5" in sb.calls[0] and "/" not in sb.calls[0].split("nmap")[-1]


# injection #6 (LOW): trailing newline in ports must be rejected (\Z, not $).
def test_ports_trailing_newline_rejected():
    with pytest.raises(ValueError):
        nmap_port_scan_cmd("host.htb", "80\n")
    assert "nmap" in nmap_port_scan_cmd("host.htb", "1-1000")    # normal spec still fine


# scope-bypass #1 (HIGH): an out_of_scope wildcard must also deny the zone apex.
def test_out_of_scope_wildcard_denies_apex():
    s = Scope.from_text(
        "authorized: true\nin_scope:\n  - '*.example.com'\nout_of_scope:\n  - '*.internal.example.com'\n"
    )
    assert s.allows("api.example.com")
    assert not s.allows("internal.example.com")                 # the apex of the walled-off zone
    assert not s.allows("db.internal.example.com")


# scope-bypass #4 (LOW): IPv4-mapped IPv6 must not dodge an IPv4 exclusion.
def test_ipv4_mapped_ipv6_cannot_dodge_ipv4_exclusion():
    s = Scope.from_text("authorized: true\nin_scope:\n  - '::/0'\nout_of_scope:\n  - 169.254.169.254\n")
    assert not s.allows("http://[::ffff:169.254.169.254]/")


# scope-bypass #3 (MED): obfuscated IPv4 encodings must be caught by the deny filter.
def test_encoded_ip_caught_by_deny_filter():
    s = Scope.from_text("authorized: true\nin_scope:\n  - 10.0.0.0/8\nout_of_scope:\n  - 169.254.169.254\n")
    assert out_of_scope_hit(s, "curl http://2852039166/latest/meta-data/") is not None   # integer form
    assert out_of_scope_hit(s, "curl http://0251.0376.0251.0376/") is not None            # octal dotted form


# correctness (HIGH): JSONL replay must preserve the evidence appended on set_status.
def test_replay_preserves_status_note(tmp_path):
    p = tmp_path / "f.jsonl"
    s1 = FindingsStore(p, clock=_clock())
    fid = s1.record("heap overflow")
    s1.set_status(fid, "confirmed", note="ASan heap-buffer-overflow at parse()")
    live = list(s1.get(fid).evidence)
    s2 = FindingsStore(p)                                        # reload from disk
    assert s2.get(fid).evidence == live
    assert any("ASan" in e for e in s2.get(fid).evidence)


# correctness (MED): a SIGKILL (137) is a timeout/OOM, NOT a memory-safety crash.
def test_sigkill_is_not_a_crash():
    assert not verify_crash("", exit_code=137).verified
    assert verify_crash("", exit_code=139).verified             # SIGSEGV still a crash


# correctness (HIGH): a task with no ground-truth flag is unscoreable, never 'solved'.
def test_task_without_flag_is_unscoreable():
    t = BenchmarkTask(name="x", prompt="p")                     # no flag, no pattern
    r = run_task(t, lambda task: RunOutput(text="the answer is probably flag{guessed}"))
    assert r.solved is False
    assert "unscoreable" in r.detail
