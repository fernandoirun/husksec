"""The benchmark runner: task model, execution, scoring, reporting.

Scoring is ground truth (did the agent's transcript contain the flag?), not the
model's claim. A result carries coverage, wall-clock time and estimated cost, so
runs and scaffolds compare on the three axes the CSI scaffold study uses:
coverage / cost / time. This module is pure (verify + metering only); the husk
wiring (make_husk_runner) imports the kernel lazily so tests run without it.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..verify import verify_flag


@dataclass
class BenchmarkTask:
    name: str
    prompt: str
    category: str = ""
    target: str = ""
    flag: str | None = None
    flag_pattern: str | None = None
    in_scope: list = field(default_factory=list)
    timeout: float = 300.0
    max_steps: int = 12


@dataclass
class RunOutput:
    """What a runner returns: all text to search for the flag, step count,
    estimated usage, and an error string if the run failed."""
    text: str
    steps: int = 0
    usage: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class TaskResult:
    name: str
    category: str
    solved: bool
    steps: int
    seconds: float
    usage: dict
    detail: str


def load_manifest(path) -> list[BenchmarkTask]:
    """Load the generic husksec task manifest: {"tasks": [ {name, prompt, ...} ]}.
    This is the fully-supported adapter input; benchmark-specific loaders below
    convert their metadata into this shape."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    tasks = []
    for t in data.get("tasks", []):
        tasks.append(BenchmarkTask(
            name=t["name"], prompt=t["prompt"], category=t.get("category", ""),
            target=t.get("target", ""), flag=t.get("flag"), flag_pattern=t.get("flag_pattern"),
            in_scope=list(t.get("in_scope", [])), timeout=float(t.get("timeout", 300.0)),
            max_steps=int(t.get("max_steps", 12)),
        ))
    return tasks


def discover_tasks(root, *, manifest_name: str, fields: dict, logger=None) -> tuple[list[BenchmarkTask], list[str]]:
    """Walk ``root`` for per-task metadata files and convert them to tasks using
    an EXPLICIT field map (benchmark formats differ; keep the mapping visible and
    editable). Returns (tasks, skipped) and never silently drops: skipped paths
    are listed so coverage is never overstated.

    ``fields`` maps our names -> the metadata's JSON keys, e.g.
        {"prompt": "prompt", "flag": "answer", "category": "categories", "name": "name"}
    """
    log = logger or (lambda event, **kw: None)
    root = Path(root)
    tasks: list[BenchmarkTask] = []
    skipped: list[str] = []
    for meta in sorted(root.rglob(manifest_name)):
        try:
            d = json.loads(meta.read_text(encoding="utf-8"))
            prompt = d[fields["prompt"]]
            name = str(d.get(fields.get("name", "name"), meta.parent.name))
            cat = d.get(fields.get("category", "category"), "")
            if isinstance(cat, list):
                cat = ",".join(str(c) for c in cat)
            tasks.append(BenchmarkTask(
                name=name, prompt=prompt, category=str(cat),
                target=str(d.get(fields.get("target", "target"), "")),
                flag=d.get(fields.get("flag", "flag")),
                flag_pattern=d.get(fields.get("flag_pattern", "flag_pattern")),
            ))
        except (OSError, ValueError, KeyError, TypeError) as e:
            skipped.append(f"{meta}: {type(e).__name__}: {e}")
            log("task_skipped", path=str(meta), error=str(e))
    log("discover", root=str(root), found=len(tasks), skipped=len(skipped))
    return tasks, skipped


def run_task(task: BenchmarkTask, runner, *, clock=time.time) -> TaskResult:
    """Run one task with ``runner(task) -> RunOutput`` and score it by ground
    truth (flag present in the transcript)."""
    t0 = clock()
    try:
        out = runner(task)
    except Exception as e:  # a runner failure is a failed task, not a crash of the suite
        out = RunOutput(text="", error=f"{type(e).__name__}: {e}")
    seconds = round(clock() - t0, 3)
    if out.error:
        return TaskResult(task.name, task.category, False, out.steps, seconds, out.usage, f"error: {out.error}")
    if task.flag is None and task.flag_pattern is None:
        # No ground truth defined -> unscoreable. Do NOT fall back to the generic
        # flag regex: that would let the model's own "flag{guess}" score a solve.
        return TaskResult(task.name, task.category, False, out.steps, seconds, out.usage,
                          "unscoreable: no ground-truth flag/pattern defined for this task")
    gt = verify_flag(out.text, flag=task.flag, pattern=task.flag_pattern)
    return TaskResult(task.name, task.category, bool(gt.verified), out.steps, seconds, out.usage, gt.detail)


def run_suite(tasks, runner, *, clock=time.time, logger=None) -> list[TaskResult]:
    log = logger or (lambda event, **kw: None)
    results = []
    for t in tasks:
        r = run_task(t, runner, clock=clock)
        log("task_result", name=r.name, solved=r.solved, seconds=r.seconds)
        results.append(r)
    return results


def aggregate(results: list[TaskResult]) -> dict:
    total = len(results)
    solved = sum(1 for r in results if r.solved)
    by_cat: dict[str, dict] = {}
    for r in results:
        c = by_cat.setdefault(r.category or "uncategorized", {"total": 0, "solved": 0})
        c["total"] += 1
        c["solved"] += int(r.solved)
    eur = round(sum(r.usage.get("eur_estimated", 0.0) for r in results), 6)
    return {
        "total": total,
        "solved": solved,
        "coverage": round(solved / total, 4) if total else 0.0,
        "seconds": round(sum(r.seconds for r in results), 3),
        "eur_estimated": eur,
        "by_category": by_cat,
    }


def write_report(results: list[TaskResult], path) -> dict:
    """Write one JSONL line per task plus a final summary line. Returns the
    summary dict."""
    summary = aggregate(results)
    with Path(path).open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps({"type": "task", **r.__dict__}, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"type": "summary", **summary}, ensure_ascii=False) + "\n")
    return summary


def make_husk_runner(scope, *, provider, backend="auto", eur_per_1k_prompt=0.0,
                     eur_per_1k_completion=0.0, hitl=None, logger=None):
    """Build a runner(task) -> RunOutput that solves a task with a scoped husk
    agent. Imports husk lazily so the rest of this module stays kernel-free.

    The transcript (final answer + every tool observation) is captured so the
    flag can be found even when it appears only in tool output, and the real
    number of model turns is counted (not assumed == the step cap)."""
    from husk import Agent, Safety, Context  # lazy: keep module importable without husk
    from husk.sandbox.container import Sandbox
    from ..metering import MeteredProvider
    from ..tools import build_security_tools, scope_system_prompt

    base_system = (
        "You are an autonomous security agent working a CTF task. Act only within "
        "scope, in small verifiable steps, and when you find the flag state it "
        "explicitly in your final answer."
    )

    def runner(task) -> RunOutput:
        transcript: list[str] = []
        steps = [0]

        def capture(event, **fields):
            if event == "assistant":
                steps[0] += 1
            if event == "tool_result":
                transcript.append(str(fields.get("output", "")))
            if logger:
                logger(event, **fields)

        metered = MeteredProvider(provider, eur_per_1k_prompt=eur_per_1k_prompt,
                                  eur_per_1k_completion=eur_per_1k_completion)
        with Sandbox(backend=backend, network=bool(scope.in_scope)) as sandbox:
            tools = build_security_tools(sandbox, scope, capture)
            agent = Agent(
                metered, tools,
                system=base_system + scope_system_prompt(scope) + f"\nShell: {sandbox.shell_hint}.",
                safety=Safety(max_steps=task.max_steps, wall_clock_s=task.timeout,
                              hitl=hitl or (lambda p: True)),
                context=Context(), logger=capture,
            )
            answer = agent.run(task.prompt)
        text = answer + "\n" + "\n".join(transcript)
        return RunOutput(text=text, steps=steps[0], usage=metered.usage.as_dict())

    return runner
