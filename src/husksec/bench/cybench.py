"""Cybench adapter.

Cybench (arXiv 2408.08926, Stanford CRFM; 40 CTF tasks from 4 competitions) ships
each task with a metadata file. We ADAPT it: read that metadata into husksec
BenchmarkTasks and run the agent in isolation. We do NOT reimplement Cybench and
we do NOT vendor its tasks.

Structure confirmed against the live repo (github.com/andyzorigin/cybench, branch
``main``): each selected task keeps its metadata at
``<task_dir>/metadata/metadata.json`` -- the repo's own loader reads exactly that
path. The real top-level keys are ``categories`` (a LIST), ``easy_prompt`` /
``hard_prompt`` and ``subtasks``; there is NO flat ``name`` / ``prompt`` /
``answer`` / ``target``. Hence:
  - the task name is the task directory's basename (not a JSON key),
  - the prompt is ``easy_prompt`` (``hard_prompt`` is the no-hints variant),
  - the ground-truth flag is the LAST subtask's ``answer``: ``subtasks[-1]["answer"]``,
  - the network target, when present, is ``target_host``.
Everything downstream (running, scoring, reporting) is shared with the generic
runner. If the schema ever changes, ``_parse`` is the one place to edit.
"""
from __future__ import annotations

from pathlib import Path

from .core import BenchmarkTask, discover_tasks


def _parse(d: dict, path: Path) -> BenchmarkTask:
    """Build a task from one Cybench ``metadata.json``. Missing keys raise
    (KeyError / IndexError / TypeError) so the file is skipped, never guessed."""
    # path == <task>/metadata/metadata.json (or <task>/metadata.json if flattened)
    task_dir = path.parent.parent if path.parent.name == "metadata" else path.parent
    prompt = d.get("easy_prompt") or d["hard_prompt"]        # neither present -> KeyError -> skip
    categories = d.get("categories") or []
    flag = d["subtasks"][-1]["answer"]                       # no subtasks/answer -> skip
    return BenchmarkTask(
        name=task_dir.name,
        prompt=str(prompt),
        category=",".join(str(c) for c in categories),
        target=str(d.get("target_host", "")),
        flag=str(flag),
    )


def discover(root, *, manifest_name: str = "metadata.json", logger=None):
    """Return (tasks, skipped) from a Cybench checkout rooted at ``root``."""
    return discover_tasks(root, manifest_name=manifest_name, parse=_parse, logger=logger)
