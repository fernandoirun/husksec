"""Ground truth: the cheap, binary, reproducible checks that turn a hypothesis
into a confirmed finding.

In security (unlike open-ended science) the truth is usually binary and cheap:
did we get the flag? did the target crash? does the patch close the PoC? These
functions answer exactly those questions from observable output -- an exit code,
a sanitizer line, a flag string -- so a finding is confirmed by a *fact*, never
by the model's narration. This is the anti-hallucination anchor of the whole
autoresearch loop.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Default CTF flag shapes; override with your own pattern when you know it.
DEFAULT_FLAG_RE = re.compile(r"(?:flag|FLAG|HTB|CTF|pico(?:CTF)?)\{[^}]{1,200}\}")

# Substrings that indicate a crash / memory-safety violation in tool output.
_CRASH_SIGNS = (
    "segmentation fault", "segfault", "sigsegv", "sigabrt", "sigfpe",
    "addresssanitizer", "heap-buffer-overflow", "stack-buffer-overflow",
    "use-after-free", "double free", "core dumped", "stack smashing detected",
    "assertion failed", "assertion `", "panicked at", "runtime error:",
)
# Exit codes from `sh`: 128 + signal. These are genuine fault signals:
#   132 SIGILL, 133 SIGTRAP, 134 SIGABRT, 135 SIGBUS, 136 SIGFPE, 139 SIGSEGV.
# NOT included: 124 (husk/coreutils timeout) and 137 (128+9 SIGKILL) -- a process
# killed by SIGKILL is almost always a timeout (`timeout -s KILL`) or an OOM kill,
# i.e. "it hung", not "it crashed on a memory-safety bug". Counting 137 as a crash
# would manufacture false confirmed findings from hangs.
_CRASH_EXIT_CODES = {132, 133, 134, 135, 136, 139}


@dataclass
class GroundTruth:
    verified: bool
    kind: str          # "flag" | "crash" | "patch"
    detail: str

    def __bool__(self) -> bool:
        return self.verified


def verify_flag(output: str, flag: str | None = None, pattern: str | None = None) -> GroundTruth:
    """Confirmed iff the expected flag (exact) or a flag pattern is present."""
    text = output or ""
    if flag:
        ok = flag in text
        return GroundTruth(ok, "flag", f"exact flag {'found' if ok else 'not found'}")
    rx = re.compile(pattern) if pattern else DEFAULT_FLAG_RE
    m = rx.search(text)
    return GroundTruth(bool(m), "flag", f"matched {m.group(0)!r}" if m else "no flag pattern matched")


def verify_crash(output: str, exit_code: int | None = None) -> GroundTruth:
    """Confirmed iff the output or exit code shows a genuine crash. A timeout
    (124) is explicitly NOT a crash."""
    text = (output or "").lower()
    if exit_code == 124:
        return GroundTruth(False, "crash", "process timed out (not a crash)")
    if exit_code in _CRASH_EXIT_CODES:
        return GroundTruth(True, "crash", f"exit code {exit_code} (128 + signal {exit_code - 128})")
    for sign in _CRASH_SIGNS:
        if sign in text:
            return GroundTruth(True, "crash", f"crash signature: {sign!r}")
    return GroundTruth(False, "crash", "no crash signature or crashing exit code")


def verify_patch(before: GroundTruth, after: GroundTruth) -> GroundTruth:
    """A patch closes a vuln iff the PoC reproduced it BEFORE and no longer
    reproduces it AFTER. Both arguments are the ground truth of running the same
    PoC against the unpatched and patched target."""
    closes = bool(before) and not bool(after)
    if not before:
        return GroundTruth(False, "patch", "PoC did not reproduce on the unpatched target; nothing proven")
    detail = "patch closes the PoC (reproduced before, gone after)" if closes else "PoC still reproduces after patch"
    return GroundTruth(closes, "patch", detail)
