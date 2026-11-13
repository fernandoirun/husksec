"""Tests for the findings store: state transitions and JSONL replay."""
import pytest

from husksec.findings import FindingsStore


def _clock():
    # deterministic monotonic-ish clock for tests
    t = [1000.0]
    def tick():
        t[0] += 1.0
        return t[0]
    return tick


def test_record_and_get():
    s = FindingsStore(clock=_clock())
    fid = s.record("SQLi in /login")
    f = s.get(fid)
    assert fid == "F001"
    assert f.status == "pending"
    assert f.hypothesis == "SQLi in /login"


def test_evidence_and_status_transition():
    s = FindingsStore(clock=_clock())
    fid = s.record("RCE via upload")
    s.add_evidence(fid, "uploaded shell.php, got 200")
    s.set_status(fid, "confirmed", note="reverse shell returned id=root")
    f = s.get(fid)
    assert f.status == "confirmed"
    assert any("shell.php" in e for e in f.evidence)
    assert any("root" in e for e in f.evidence)


def test_bad_status_rejected():
    s = FindingsStore(clock=_clock())
    fid = s.record("x")
    with pytest.raises(ValueError):
        s.set_status(fid, "probably", note="")


def test_missing_finding_raises():
    s = FindingsStore(clock=_clock())
    with pytest.raises(KeyError):
        s.add_evidence("F999", "nope")


def test_list_filter_and_summary():
    s = FindingsStore(clock=_clock())
    a = s.record("a")
    b = s.record("b")
    s.set_status(b, "refuted")
    assert [f.id for f in s.list("pending")] == [a]
    assert [f.id for f in s.list("refuted")] == [b]
    assert "pending=1" in s.summary() and "refuted=1" in s.summary()


def test_jsonl_replay_rebuilds_state(tmp_path):
    p = tmp_path / "findings.jsonl"
    s1 = FindingsStore(p, clock=_clock())
    fid = s1.record("heap overflow in parser")
    s1.add_evidence(fid, "crash: AddressSanitizer heap-buffer-overflow")
    s1.set_status(fid, "confirmed")
    s1.record("second hypothesis")

    # a fresh store over the same file must reconstruct everything
    s2 = FindingsStore(p)
    assert len(s2.list()) == 2
    f = s2.get(fid)
    assert f.status == "confirmed"
    assert any("AddressSanitizer" in e for e in f.evidence)
    # and the sequence continues, not restarts
    nxt = s2.record("third")
    assert nxt == "F003"
