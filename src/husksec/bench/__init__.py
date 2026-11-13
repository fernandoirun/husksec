"""Benchmark adapters: run husksec against public CTF benchmarks and report
coverage, cost (EUR, estimated) and time. We ADAPT benchmarks, never reimplement
them -- the adapters only read task metadata and run the agent in isolation.
"""
from .core import (
    BenchmarkTask,
    TaskResult,
    aggregate,
    discover_tasks,
    load_manifest,
    run_suite,
    run_task,
    write_report,
)

__all__ = [
    "BenchmarkTask", "TaskResult", "load_manifest", "discover_tasks",
    "run_task", "run_suite", "aggregate", "write_report",
]
