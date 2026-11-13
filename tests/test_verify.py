"""Tests for ground-truth verifiers. These are the anti-hallucination anchor,
so their false-positive behaviour matters: a timeout is not a crash, and a patch
only 'closes' if the PoC actually fired before."""
from husksec.verify import verify_crash, verify_flag, verify_patch


def test_flag_exact():
    assert verify_flag("you win: HTB{abc_123}", flag="HTB{abc_123}")
    assert not verify_flag("nope", flag="HTB{abc_123}")


def test_flag_pattern_default():
    gt = verify_flag("output... flag{sql_injection_ftw} ...done")
    assert gt and "flag{sql_injection_ftw}" in gt.detail
    assert not verify_flag("no flag here")


def test_flag_custom_pattern():
    assert verify_flag("KEY=S3CR3T", pattern=r"KEY=\w+")


def test_crash_by_signature():
    assert verify_crash("==1234==ERROR: AddressSanitizer: heap-buffer-overflow")
    assert verify_crash("Program received signal SIGSEGV, Segmentation fault")
    assert not verify_crash("all tests passed")


def test_crash_by_exit_code():
    assert verify_crash("", exit_code=139).verified          # SIGSEGV
    assert verify_crash("", exit_code=134).verified          # SIGABRT


def test_timeout_is_not_a_crash():
    gt = verify_crash("[timeout after 60s]", exit_code=124)
    assert not gt.verified
    assert "timed out" in gt.detail


def test_patch_closes_only_when_poc_fired_before():
    before = verify_crash("", exit_code=139)                 # crashed unpatched
    after = verify_crash("ran cleanly, exit 0", exit_code=0)  # fine patched
    assert verify_patch(before, after).verified

    # if the PoC never reproduced, we prove nothing
    norepro = verify_crash("ran cleanly", exit_code=0)
    assert not verify_patch(norepro, norepro).verified

    # still crashing after patch => not closed
    assert not verify_patch(before, before).verified


def test_groundtruth_is_truthy():
    assert bool(verify_flag("flag{x}")) is True
    assert bool(verify_flag("")) is False
