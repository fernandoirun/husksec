"""The 'lightweight layer' claim as a checked invariant.

The kernel's thesis is <800 SLOC. The security layer is allowed to be larger
(it is a whole domain capability: scope, tools, findings, benchmarks,
autoresearch) but must stay *small* and add NO runtime dependency beyond the
kernel itself. If a change blows either budget, this test fails. Same counting
rule as husk: non-blank, non-comment lines, docstrings included (we never
undercount to squeak under budget).
"""
from __future__ import annotations

import tomllib
from pathlib import Path

MAX_SLOC = 1400                      # the whole security layer
ALLOWED_DEPS = {"husk"}              # nothing beyond the kernel

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "husksec"


def _sloc(path: Path) -> int:
    return sum(
        1 for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def test_layer_under_sloc_budget():
    files = sorted(SRC.rglob("*.py"))
    assert files, f"no source found under {SRC}"
    per_file = {f.relative_to(ROOT).as_posix(): _sloc(f) for f in files}
    total = sum(per_file.values())
    report = "\n".join(f"  {n}: {c}" for n, c in sorted(per_file.items()))
    assert total <= MAX_SLOC, f"husksec SLOC {total} > {MAX_SLOC}\n{report}"


def test_no_dependency_beyond_the_kernel():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    names = {d.split(">")[0].split("=")[0].split("[")[0].strip() for d in deps}
    extra = names - ALLOWED_DEPS
    assert not extra, f"husksec must add no runtime dependency beyond husk; found extra: {extra}"
