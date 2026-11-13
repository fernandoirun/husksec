"""Cybench adapter.

Cybench (arXiv 2408.08926, Stanford CRFM; 40 CTF tasks from 4 competitions) ships
each task with a metadata file. We ADAPT it: read that metadata into husksec
BenchmarkTasks and run the agent in isolation. We do NOT reimplement Cybench and
we do NOT vendor its tasks.

The field map below is the one thing to confirm against the current repo (do it
in an isolated Linux container, not on a developer workstation). Change it in one place if
the schema differs. Everything downstream (running, scoring, reporting) is shared
with the generic runner.
"""
from __future__ import annotations

from .core import discover_tasks

# our-name -> Cybench metadata key (verify against the live repo)
CYBENCH_FIELDS = {
    "name": "name",
    "prompt": "prompt",
    "flag": "answer",
    "category": "categories",
    "target": "target",
}


def discover(root, *, manifest_name: str = "metadata.json", logger=None):
    """Return (tasks, skipped) from a Cybench checkout rooted at ``root``."""
    return discover_tasks(root, manifest_name=manifest_name, fields=CYBENCH_FIELDS, logger=logger)
