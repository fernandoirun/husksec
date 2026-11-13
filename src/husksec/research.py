"""Autoresearch: the hypothesis -> experiment -> verification loop.

This is the "artificial security researcher" built ON TOP of the kernel. It does
not reinvent the agent loop; it orchestrates it:

    seed -> generate hypotheses -> for each: run an experiment (a husk agent in
    the sandbox) -> verify with GROUND TRUTH (flag? crash? patch closes it?) ->
    record the outcome in the findings memory.

The one rule that gives this project its spine: **a hypothesis is only ever
confirmed by a reproducible ground-truth check, never by the model's narration.**
A refuted hypothesis is a result too -- it is recorded, not hidden.

The three stages are plain callables so they are trivially testable with mocks
(no model, no network). husk-backed defaults are provided by the make_* helpers,
which import the kernel lazily.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .verify import GroundTruth, verify_crash, verify_flag


@dataclass
class Experiment:
    """The observable outcome of testing one hypothesis."""
    text: str
    exit_code: int | None = None


def autoresearch(seed: str, *, store, hypothesizer, experiment, verify, max_hypotheses: int = 5, logger=None) -> dict:
    """Run the loop. ``hypothesizer(seed, summary) -> list[str]``,
    ``experiment(hypothesis) -> Experiment``, ``verify(hypothesis, Experiment)
    -> GroundTruth``. Returns confirmed finding ids and the findings summary."""
    log = logger or (lambda event, **kw: None)
    hypotheses = list(hypothesizer(seed, store.summary()))[:max_hypotheses]
    log("hypotheses", seed=seed, count=len(hypotheses))
    confirmed: list[str] = []
    for h in hypotheses:
        fid = store.record(h)
        exp = experiment(h)
        store.add_evidence(fid, f"experiment output (first 500): {exp.text[:500]}")
        gt = verify(h, exp)
        status = "confirmed" if gt.verified else "refuted"
        store.set_status(fid, status, note=f"[{gt.kind}] {gt.detail}")
        log("hypothesis_result", id=fid, verified=bool(gt.verified), kind=gt.kind, detail=gt.detail)
        if gt.verified:
            confirmed.append(fid)
    return {"confirmed": confirmed, "summary": store.summary()}


# --- ground-truth verifier ------------------------------------------------- #

def make_ground_truth_verifier(flag: str | None = None, pattern: str | None = None):
    """Verify a hypothesis by flag OR crash evidence in the experiment output.
    This is the anti-hallucination anchor."""
    def verify(hypothesis: str, exp: Experiment) -> GroundTruth:
        gt_flag = verify_flag(exp.text, flag=flag, pattern=pattern)
        if gt_flag.verified:
            return gt_flag
        gt_crash = verify_crash(exp.text, exp.exit_code)
        if gt_crash.verified:
            return gt_crash
        return GroundTruth(False, "flag", f"unverified ({gt_flag.detail}; {gt_crash.detail})")
    return verify


# --- husk-backed defaults (lazy import) ------------------------------------ #

def make_llm_hypothesizer(provider, n: int = 5):
    """Ask the model for up to ``n`` concrete, testable hypotheses given the seed
    and the findings so far. Returns a list of strings."""
    def hypothesizer(seed: str, summary: str) -> list[str]:
        prompt = (
            "You are a security researcher doing variant analysis. Given the seed and the "
            "findings so far, list up to "
            f"{n} CONCRETE, TESTABLE hypotheses (each a single line, no numbering) about a "
            "specific vulnerability or behaviour that could be checked with a flag or a crash. "
            f"\n\nSEED:\n{seed}\n\nFINDINGS SO FAR:\n{summary}"
        )
        msg = provider.chat([{"role": "user", "content": prompt}], tools=[])
        text = msg.get("content") or ""
        out = []
        for line in text.splitlines():
            s = line.strip().lstrip("-*0123456789. )").strip()
            if s:
                out.append(s)
        return out[:n]
    return hypothesizer


def make_husk_experiment(provider, scope, *, backend="auto", network=None, max_steps=8, timeout=180.0, hitl=None, logger=None):
    """Return experiment(hypothesis) -> Experiment that tests a hypothesis with a
    scoped husk agent in the sandbox, capturing the full transcript so ground
    truth can be read from what actually happened."""
    from husk import Agent, Context, Safety
    from husk.sandbox.container import Sandbox
    from .tools import build_security_tools, scope_system_prompt

    use_net = bool(scope.in_scope) if network is None else network

    def experiment(hypothesis: str) -> Experiment:
        transcript: list[str] = []

        def capture(event, **fields):
            if event == "tool_result":
                transcript.append(str(fields.get("output", "")))
            if logger:
                logger(event, **fields)

        system = (
            "You are testing ONE hypothesis against an authorized target. Design and run the "
            "smallest experiment that would produce a flag or a crash if the hypothesis holds. "
            "Report exactly what you observed." + scope_system_prompt(scope)
        )
        with Sandbox(backend=backend, network=use_net) as sandbox:
            tools = build_security_tools(sandbox, scope, capture)
            agent = Agent(provider, tools, system=system,
                          safety=Safety(max_steps=max_steps, wall_clock_s=timeout,
                                        hitl=hitl or (lambda p: True)),
                          context=Context(), logger=capture)
            answer = agent.run(f"Hypothesis to test: {hypothesis}")
        return Experiment(text=answer + "\n" + "\n".join(transcript))

    return experiment
