"""Tests for the benchmark runner and adapters, with a fake runner (no model,
no network). Proves scoring is by ground truth and coverage is never overstated.
"""
import json

from husksec.bench import aggregate, load_manifest, run_suite, run_task, write_report
from husksec.bench.core import BenchmarkTask, RunOutput
from husksec.bench import caibench, cybench


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


def test_cybench_discover_parses_real_shape_and_skips(tmp_path):
    # Cybench's real layout: <task>/metadata/metadata.json, name from the task
    # dir, prompt in easy_prompt, flag in the LAST subtask's answer, target_host.
    good = tmp_path / "comp" / "noisier-crc" / "metadata"
    good.mkdir(parents=True)
    (good / "metadata.json").write_text(json.dumps({
        "categories": ["crypto"],
        "easy_prompt": "recover the key",
        "hard_prompt": "recover the key (no hints)",
        "target_host": "victim:9999",
        "subtasks": [
            {"question": "warm-up", "answer": "step1"},
            {"question": "the flag?", "answer": "SEKAI{win}"},
        ],
    }), encoding="utf-8")
    # a malformed one that must be SKIPPED, not crash the loader
    bad = tmp_path / "comp" / "task2" / "metadata"
    bad.mkdir(parents=True)
    (bad / "metadata.json").write_text("{ not json", encoding="utf-8")

    tasks, skipped = cybench.discover(tmp_path)
    assert [t.name for t in tasks] == ["noisier-crc"]     # from the dir, not a JSON key
    assert tasks[0].prompt == "recover the key"           # easy_prompt
    assert tasks[0].flag == "SEKAI{win}"                  # subtasks[-1]["answer"]
    assert tasks[0].category == "crypto"                  # categories list -> csv
    assert tasks[0].target == "victim:9999"               # target_host
    assert len(skipped) == 1 and "task2" in skipped[0]


def test_cybench_skips_task_without_subtask_answer(tmp_path):
    # no subtasks -> no ground truth -> skipped (never fabricate a flag)
    d = tmp_path / "comp" / "t" / "metadata"
    d.mkdir(parents=True)
    (d / "metadata.json").write_text(
        json.dumps({"easy_prompt": "x", "categories": ["pwn"]}), encoding="utf-8")
    tasks, skipped = cybench.discover(tmp_path)
    assert tasks == [] and len(skipped) == 1


def test_caibench_load_reads_aggregated_array_and_skips(tmp_path):
    # CAIBench is one aggregated JSON array (ctf_configs.jsonl), not per-challenge
    # files. No static flag -> flag is None (honestly unscoreable).
    cfg = tmp_path / "ctf_configs.jsonl"
    cfg.write_text(json.dumps([
        {"name": "picoctf_static_flag", "image": "img:1", "description": "pop the box",
         "type": "ctf", "flag_commands": {"get": "cat /flag"}},
        {"name": "broken"},                               # no description/instructions -> SKIP
    ]), encoding="utf-8")
    tasks, skipped = caibench.load(cfg)
    assert [t.name for t in tasks] == ["picoctf_static_flag"]
    assert tasks[0].prompt == "pop the box"
    assert tasks[0].target == "img:1"                     # the Docker image identifies the target
    assert tasks[0].category == "ctf"
    assert tasks[0].flag is None                          # no static ground truth in CAIBench
    assert len(skipped) == 1 and "broken" in skipped[0]


def test_caibench_tasks_are_unscoreable_until_flag_resolution():
    # A CAIBench task (flag=None) must not be scored by the model's say-so, even
    # if the transcript prints a flag-looking string.
    t = BenchmarkTask(name="x", prompt="p", flag=None)
    r = run_task(t, lambda task: RunOutput(text="I found flag{whatever}"))
    assert r.solved is False and "unscoreable" in r.detail
