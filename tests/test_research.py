"""Tests for the autoresearch loop with injected (mock) stages -- no model, no
network. The property under test: only ground-truth-verified hypotheses become
'confirmed'; everything else is recorded as 'refuted'."""
from husksec.findings import FindingsStore
from husksec.research import Experiment, autoresearch, make_ground_truth_verifier


def _clock():
    t = [0.0]
    def tick():
        t[0] += 1.0
        return t[0]
    return tick


def test_only_verified_hypotheses_are_confirmed():
    store = FindingsStore(clock=_clock())

    def hypothesizer(seed, summary):
        return [
            "The /login endpoint leaks a flag",      # will 'produce' a flag
            "The parser crashes on long input",      # will 'crash'
            "The admin panel is unauthenticated",    # unverified
        ]

    def experiment(h):
        if "flag" in h:
            return Experiment(text="response body: flag{sqli_login}")
        if "crash" in h:
            return Experiment(text="==123==ERROR: AddressSanitizer: heap-buffer-overflow", exit_code=139)
        return Experiment(text="HTTP 200 OK, looks interesting but no proof")

    result = autoresearch(
        "seed: a web app + a parser", store=store,
        hypothesizer=hypothesizer, experiment=experiment,
        verify=make_ground_truth_verifier(),
    )

    assert len(result["confirmed"]) == 2                      # flag + crash
    statuses = {f.hypothesis: f.status for f in store.list()}
    assert statuses["The /login endpoint leaks a flag"] == "confirmed"
    assert statuses["The parser crashes on long input"] == "confirmed"
    assert statuses["The admin panel is unauthenticated"] == "refuted"


def test_max_hypotheses_caps_work():
    store = FindingsStore(clock=_clock())
    calls = []

    def experiment(h):
        calls.append(h)
        return Experiment(text="nothing")

    autoresearch(
        "seed", store=store,
        hypothesizer=lambda s, summ: [f"h{i}" for i in range(10)],
        experiment=experiment, verify=make_ground_truth_verifier(),
        max_hypotheses=3,
    )
    assert len(calls) == 3                                     # capped, not all 10


def test_refuted_is_still_recorded():
    store = FindingsStore(clock=_clock())
    autoresearch(
        "seed", store=store,
        hypothesizer=lambda s, summ: ["unprovable claim"],
        experiment=lambda h: Experiment(text="no flag, no crash"),
        verify=make_ground_truth_verifier(),
    )
    assert len(store.list("refuted")) == 1                     # negative results are results


def test_verifier_prefers_flag_then_crash():
    v = make_ground_truth_verifier(flag="flag{known}")
    assert v("h", Experiment(text="... flag{known} ...")).kind == "flag"
    assert v("h", Experiment(text="Segmentation fault", exit_code=139)).kind == "crash"
    assert not v("h", Experiment(text="nothing here")).verified
