"""Tests for the benchmark runner and adapters, with a fake runner (no model,
no network). Proves scoring is by ground truth and coverage is never overstated.
"""
import json

from husksec.bench import aggregate, load_manifest, run_suite, run_task, write_report
from husksec.bench.core import BenchmarkTask, RunOutput
from husksec.bench import cybench


def test_load_manifest(tmp_path):
    p = tmp_path / "suite.json"
    p.write_text(json.dumps({"tasks": [
        {"name": "t1", "prompt": "find the flag", "category": "web", "flag": "flag{a}"},
        {"name": "t2", "prompt": "crypto", "flag_pattern": r"CTF\{\w+\}"},
    ]}), encoding="utf-8")
    tasks = load_manifest(p)
    assert [t.name for t in tasks] == ["t1", "t2"]
    assert tasks[0].flag == "flag{a}"


def test_scoring_is_ground_truth():
    tasks = [
        BenchmarkTask(name="solved", prompt="x", flag="flag{win}"),
        BenchmarkTask(name="unsolved", prompt="x", flag="flag{win}"),
        BenchmarkTask(name="errored", prompt="x", flag="flag{win}"),
    ]

    def runner(task):
        if task.name == "solved":
            return RunOutput(text="... got it: flag{win}", usage={"eur_estimated": 0.01})
        if task.name == "unsolved":
            return RunOutput(text="I believe I solved it (but no flag printed)", usage={"eur_estimated": 0.02})
        raise RuntimeError("sandbox blew up")

    results = run_suite(tasks, runner)
    by_name = {r.name: r for r in results}
    assert by_name["solved"].solved is True
    assert by_name["unsolved"].solved is False          # model claim != ground truth
    assert by_name["errored"].solved is False
    assert "error" in by_name["errored"].detail

    agg = aggregate(results)
    assert agg["total"] == 3 and agg["solved"] == 1
    assert agg["coverage"] == round(1 / 3, 4)
    assert agg["eur_estimated"] == 0.03


def test_write_report(tmp_path):
    tasks = [BenchmarkTask(name="t", prompt="x", flag="f")]
    results = run_suite(tasks, lambda t: RunOutput(text="f"))
    out = tmp_path / "report.jsonl"
    summary = write_report(results, out)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["type"] == "task"
    assert json.loads(lines[-1])["type"] == "summary"
    assert summary["solved"] == 1


def test_cybench_discover_parses_and_skips(tmp_path):
    # a well-formed task
    good = tmp_path / "comp" / "task1"
    good.mkdir(parents=True)
    (good / "metadata.json").write_text(
        json.dumps({"name": "sql", "prompt": "exploit it", "answer": "flag{sql}", "categories": ["web"]}),
        encoding="utf-8",
    )
    # a malformed one that must be SKIPPED, not crash the loader
    bad = tmp_path / "comp" / "task2"
    bad.mkdir(parents=True)
    (bad / "metadata.json").write_text("{ not json", encoding="utf-8")

    tasks, skipped = cybench.discover(tmp_path)
    assert [t.name for t in tasks] == ["sql"]
    assert tasks[0].flag == "flag{sql}"
    assert tasks[0].category == "web"
    assert len(skipped) == 1 and "task2" in skipped[0]
