"""Offline, reproducible autoresearch demo -- no API key, no network, no Docker.

A scripted (mock) model drives one hypothesis -> experiment -> verification cycle
end to end. The experiment runs a real command in husk's sandbox (local fallback
here); the flag appears in the actual output, and the ground-truth verifier is
what flips the finding to 'confirmed'. The model never gets to *claim* success.

Run:  python examples/autoresearch_demo.py
"""
import json

from husksec.findings import FindingsStore
from husksec.research import autoresearch, make_ground_truth_verifier, make_husk_experiment
from husksec.scope import Scope

FLAG = "flag{autoresearch_demo_works}"


class MockProvider:
    """One experiment: run a command that elicits the flag, then summarise."""

    context_window = 128000

    def __init__(self):
        # python is portable across cmd.exe, sh and the container.
        cmd = f"python -c \"print('the service responded: {FLAG}')\""
        self._steps = iter([
            {"role": "assistant", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "run", "arguments": json.dumps({"command": cmd})}}]},
        ])

    def chat(self, messages, tools=None):
        step = next(self._steps, None)
        if step is not None:
            return step
        last = next((m["content"] for m in reversed(messages) if m.get("role") == "tool"), "")
        return {"role": "assistant", "content": f"Experiment observation:\n{last}"}


def log(event, **fields):
    extra = " ".join(f"{k}={v}" for k, v in fields.items() if k != "output")
    print(f"[{event}] {extra}")


def main():
    scope = Scope.from_text(
        "engagement: offline-demo\nauthorized: true\nin_scope:\n  - 127.0.0.1\n"
    )
    store = FindingsStore()
    experiment = make_husk_experiment(
        MockProvider(), scope, backend="local", network=False, max_steps=4, logger=log
    )
    result = autoresearch(
        seed="A local service is suspected to leak a flag when probed.",
        store=store,
        hypothesizer=lambda seed, summary: ["Probing the service prints a flag"],
        experiment=experiment,
        verify=make_ground_truth_verifier(),   # default: any flag{...}/HTB{...}/...
        logger=log,
    )

    print("\n=== FINDINGS ===")
    print(store.summary())
    print("\nconfirmed:", result["confirmed"])
    assert result["confirmed"], "demo should confirm exactly one finding via ground truth"
    print("\nOK: one hypothesis confirmed by a reproduced flag, not by the model's claim.")


if __name__ == "__main__":
    main()
