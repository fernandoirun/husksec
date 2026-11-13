"""husksec command line: run a scoped agent, drive autoresearch, or run a bench.

Every subcommand loads a scope.yaml first and refuses to act outside it. The
audit trail is husk's JSONL (one event per line); add --log to send it to a file.

    husksec run "enumerate the box" --scope scope.yaml --approve
    husksec research "CVE-2024-XXXX: analyse variants" --scope scope.yaml
    husksec bench suite.json --report out.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import time


def _make_logger(path):
    stream = open(path, "a", encoding="utf-8") if path else sys.stderr

    def log(event, **fields):
        rec = {"ts": round(time.time(), 3), "event": event, **fields}
        stream.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        stream.flush()

    return log


def _interactive_hitl(prompt):
    sys.stderr.write(prompt + "  [y/N] ")
    sys.stderr.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")


def _load_scope(path):
    from .scope import Scope, ScopeError
    try:
        scope = Scope.load(path)
    except ScopeError as e:
        sys.stderr.write(f"husksec: refusing to run -- {e}\n")
        raise SystemExit(2)
    if not scope.authorized:
        sys.stderr.write("husksec: scope is not marked 'authorized: true'; nothing is in scope.\n")
    return scope


def _resolve_backend(args):
    """Fail closed on missing isolation. By default we require Docker; running
    without a sandbox is an explicit, loud opt-in via --no-docker, not a silent
    fallback. This keeps the 'commands run in the sandbox' promise true for the
    default path."""
    if args.no_docker:
        sys.stderr.write("husksec: --no-docker set; running WITHOUT sandbox isolation (host). Authorized targets only.\n")
        return "local"
    from husk.sandbox.container import has_docker
    if has_docker():
        return "docker"
    sys.stderr.write(
        "husksec: refusing to run -- Docker is not available, so there is no sandbox isolation.\n"
        "         Install/start Docker, or pass --no-docker to run unsandboxed on the host at your own risk.\n"
    )
    raise SystemExit(3)


SYSTEM = (
    "You are a careful autonomous security agent. Accomplish the task by calling tools to act, "
    "observing results, and iterating in small verifiable steps. Record hypotheses and evidence "
    "as you go, and mark a finding confirmed only when a reproducible check proves it. Stop and "
    "summarise when done."
)


def _cmd_run(args):
    from husk import Agent, Context, Safety
    from husk.providers.openai_compat import OpenAICompatProvider
    from husk.sandbox.container import Sandbox
    from .findings import FindingsStore
    from .tools import build_findings_tools, build_security_tools, scope_system_prompt

    log = _make_logger(args.log)
    scope = _load_scope(args.scope)
    provider = OpenAICompatProvider(model=args.model)
    backend = _resolve_backend(args)
    safety = Safety(max_steps=args.max_steps, wall_clock_s=args.timeout,
                    hitl=_interactive_hitl if args.approve else (lambda p: True))
    try:
        with Sandbox(backend=backend, network=bool(scope.in_scope)) as sandbox:
            store = FindingsStore(args.findings or None)
            tools = build_security_tools(sandbox, scope, log) + build_findings_tools(store)
            system = SYSTEM + scope_system_prompt(scope) + f"\nShell: {sandbox.shell_hint}."
            agent = Agent(provider, tools, system=system, safety=safety, context=Context(), logger=log)
            answer = agent.run(args.task)
    finally:
        provider.close()
    print(answer)
    print("\n--- findings ---\n" + store.summary())
    return 0


def _cmd_research(args):
    from husk.providers.openai_compat import OpenAICompatProvider
    from .findings import FindingsStore
    from .research import autoresearch, make_ground_truth_verifier, make_husk_experiment, make_llm_hypothesizer

    log = _make_logger(args.log)
    scope = _load_scope(args.scope)
    provider = OpenAICompatProvider(model=args.model)
    backend = _resolve_backend(args)
    hitl = _interactive_hitl if args.approve else None
    try:
        store = FindingsStore(args.findings or None)
        result = autoresearch(
            args.seed, store=store,
            hypothesizer=make_llm_hypothesizer(provider, args.max_hypotheses),
            experiment=make_husk_experiment(provider, scope, backend=backend,
                                            max_steps=args.max_steps, timeout=args.timeout,
                                            hitl=hitl, logger=log),
            verify=make_ground_truth_verifier(flag=args.flag, pattern=args.flag_pattern),
            max_hypotheses=args.max_hypotheses, logger=log,
        )
    finally:
        provider.close()
    print("\n--- findings ---\n" + store.summary())
    print("\nconfirmed:", result["confirmed"])
    return 0


def _cmd_bench(args):
    from husk.providers.openai_compat import OpenAICompatProvider
    from .bench.core import load_manifest, make_husk_runner, run_suite, write_report
    from .scope import Scope

    log = _make_logger(args.log)
    provider = OpenAICompatProvider(model=args.model)
    backend = _resolve_backend(args)
    hitl = _interactive_hitl if args.approve else None
    tasks = load_manifest(args.manifest)

    def runner(task):
        scope = Scope(engagement=task.name, authorized=True,
                      in_scope=list(task.in_scope) or ([task.target] if task.target else []))
        return make_husk_runner(scope, provider=provider, backend=backend,
                                eur_per_1k_prompt=args.eur_in, eur_per_1k_completion=args.eur_out,
                                hitl=hitl, logger=log)(task)

    try:
        results = run_suite(tasks, runner, logger=log)
        summary = write_report(results, args.report)
    finally:
        provider.close()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(prog="husksec", description="Scope-enforced security agent on husk.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--scope", default="scope.yaml", help="scope.yaml path (authorization boundary)")
        p.add_argument("--model", default=None, help="override HUSK_MODEL")
        p.add_argument("--log", default=None, help="JSONL audit log file (default: stderr)")
        p.add_argument("--findings", default=None, help="append-only findings JSONL file")
        p.add_argument("--max-steps", type=int, default=12)
        p.add_argument("--timeout", type=float, default=300.0)
        p.add_argument("--no-docker", action="store_true", help="force local (unsandboxed) backend")

    pr = sub.add_parser("run", help="run a scoped agent on one task")
    pr.add_argument("task")
    pr.add_argument("--approve", action="store_true", help="HITL: confirm risky actions")
    common(pr)
    pr.set_defaults(func=_cmd_run)

    pre = sub.add_parser("research", help="autoresearch: hypothesis -> experiment -> verification")
    pre.add_argument("seed")
    pre.add_argument("--max-hypotheses", type=int, default=5)
    pre.add_argument("--flag", default=None, help="exact flag to confirm against")
    pre.add_argument("--flag-pattern", default=None, help="regex flag pattern")
    pre.add_argument("--approve", action="store_true", help="HITL: confirm risky actions")
    common(pre)
    pre.set_defaults(func=_cmd_research)

    pb = sub.add_parser("bench", help="run a task manifest and report coverage/cost/time")
    pb.add_argument("manifest")
    pb.add_argument("--report", default="bench_report.jsonl")
    pb.add_argument("--eur-in", type=float, default=0.0, help="EUR per 1k prompt tokens (for cost estimate)")
    pb.add_argument("--eur-out", type=float, default=0.0, help="EUR per 1k completion tokens")
    pb.add_argument("--approve", action="store_true", help="HITL: confirm risky actions")
    common(pb)
    pb.set_defaults(func=_cmd_bench)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
