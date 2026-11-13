"""CAIBench adapter.

CAIBench (arXiv 2510.24317) is Alias Robotics' meta-benchmark for cybersecurity
AI agents. Same principle as the Cybench adapter: read per-challenge metadata
into husksec BenchmarkTasks and run in isolation; do not reimplement or vendor
it. Confirm the field map against the live repo in an isolated environment.

CAIBench aggregates several suites; point ``root`` at the suite you want and
adjust ``manifest_name`` if a suite uses a different metadata filename.
"""
from __future__ import annotations

from .core import discover_tasks

# our-name -> CAIBench challenge-metadata key (verify against the live repo)
CAIBENCH_FIELDS = {
    "name": "name",
    "prompt": "description",
    "flag": "flag",
    "category": "category",
    "target": "target",
}


def discover(root, *, manifest_name: str = "challenge.json", logger=None):
    return discover_tasks(root, manifest_name=manifest_name, fields=CAIBENCH_FIELDS, logger=logger)
