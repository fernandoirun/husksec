"""CAIBench adapter.

CAIBench (arXiv 2510.24317, Alias Robotics) is a meta-benchmark for cybersecurity
AI agents. Same principle as the Cybench adapter: read challenge metadata into
husksec BenchmarkTasks and run in isolation; do not reimplement or vendor it.

Structure confirmed against the live source: CAIBench is NOT a standalone repo --
it lives inside github.com/aliasrobotics/cai (branch ``archive``) under
``src/cai/caibench/``. There is NO per-challenge ``challenge.json``: every CTF is
one entry in a single aggregated file, ``ctf-jsons/ctf_configs.jsonl`` -- which,
despite the ``.jsonl`` extension, is a JSON ARRAY (the repo's loader reads it with
``json.load``). Real per-entry keys include ``name`` (required), ``image`` (the
Docker image), ``description`` / ``instructions``, ``type``, ``techniques``,
``challenges`` and ``flag_commands``.

Honesty note on scoring: CAIBench does NOT carry a static ground-truth flag value
the way Cybench does. A challenge's flag is produced by running ``flag_commands``
inside its container (or read from a file there). So this adapter LOADS CAIBench
challenges -- you can run the agent on them -- but leaves ``flag=None``: without
resolving the flag in-container they are honestly UNSCOREABLE (``run_task`` says
so) rather than scored by the model's own say-so. In-container flag resolution is
the documented next step, not yet shipped.
"""
from __future__ import annotations

import json
from pathlib import Path

from .core import BenchmarkTask


def load(path, *, logger=None) -> tuple[list[BenchmarkTask], list[str]]:
    """Load CAIBench's aggregated config (``ctf_configs.jsonl``, a JSON array) into
    tasks. Returns (tasks, skipped); a malformed entry is listed, never dropped
    silently, so coverage is never overstated."""
    log = logger or (lambda event, **kw: None)
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):                       # tolerate a {"ctfs": [...]} wrapper
        data = data.get("ctfs") or data.get("tasks") or []
    tasks: list[BenchmarkTask] = []
    skipped: list[str] = []
    for i, d in enumerate(data):
        try:
            name = str(d["name"])
            prompt = d.get("description") or d.get("instructions")
            if not prompt:
                raise KeyError("description/instructions")
            tasks.append(BenchmarkTask(
                name=name,
                prompt=str(prompt),
                category=str(d.get("type", "") or ""),
                target=str(d.get("image", "") or d.get("container_name", "")),
                flag=None,          # CAIBench has no static ground truth -> unscoreable (see docstring)
            ))
        except (KeyError, TypeError) as e:
            label = d.get("name", "?") if isinstance(d, dict) else "?"
            skipped.append(f"entry {i} ({label}): {type(e).__name__}: {e}")
            log("task_skipped", index=i, error=str(e))
    log("discover", found=len(tasks), skipped=len(skipped))
    return tasks, skipped
