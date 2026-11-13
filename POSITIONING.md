# Positioning: CSI::nano

> A scope-enforced cybersecurity agent whose kernel fits in **<800 SLOC with one
> runtime dependency**, plus a ~1.2k-SLOC security layer that adds **zero**
> further dependencies, built to be measured on public CTF benchmarks by
> **efficiency** (coverage per line of code, coverage per euro) rather than size.

This project **confirms**, rather than contradicts, the direction of current
cybersecurity-AI research. Two findings from that literature frame it.

## 1. No single scaffold is best — so the cheapest useful node has a place

A 2026 study comparing agent harnesses on a fixed model concludes that
*"no single scaffold is the best harness"* (Towards Cybersecurity
SuperIntelligence, arXiv:2605.28334). On 33 Cybench challenges with the model
held fixed it reports, verbatim figures from the paper:

| Configuration | Cybench solved |
|---|---|
| Best individual scaffold | 15 / 33 (45.5%) |
| Union of four scaffolds | 17 / 33 (51.5%) |
| Blackboard (parallel agents, shared substrate) | 19 / 33 (57.6%) |

The blackboard's 19/33 is a **27% relative gain** over the strongest single
scaffold. The lesson: heterogeneity wins, and an ensemble benefits from adding
*different, cheap* members. **CSI::nano aims to be exactly that**: the smallest,
cheapest heterogeneous node that can plug into such an ensemble and contribute
coverage for a fraction of the cost and size — not a frontal competitor to any
single large harness.

> Note: Cybench itself defines **40** tasks across 4 CTF competitions (Cybench,
> arXiv:2408.08926, Stanford CRFM, ICLR 2025). The **33** above is the evaluation
> subset used by the scaffold study, not Cybench's full size.

## 2. Architecture↔model coupling is a real lever

A meta-benchmark for cybersecurity agents reports that *"proper matches improve
up to 2.6x variance in Attack and Defense CTFs"* (CAIBench, arXiv:2510.24317) —
i.e. matching the **framework scaffolding to the chosen model** moves results
substantially. This is about *coupling*, scoped to Attack & Defense CTFs; it is
**not** a claim that architecture beats the model in general. A small scaffold
that is well-matched to a given model is therefore a legitimate efficiency lever,
not a gimmick.

## 3. Efficiency, stated honestly

What we can state as hard, self-measured facts:

| | husk + husksec | A large open harness (CAI) |
|---|---|---|
| Runtime dependencies | **1** (httpx) | **27** (declared in its `pyproject.toml`) |
| Kernel SLOC | **≈600** (CI-enforced <800) | — |
| Security layer SLOC | **≈1,200** (CI-enforced) | — |

The 27-dependency figure for CAI is confirmed from its public `pyproject.toml`.
Line-count comparisons to CAI are **deliberately not asserted here**: no official
SLOC figure is published, and any number must be measured with `cloc`/`scc` in an
isolated environment before it is quoted. CAI is best described as *built on /
derived from* `openai-agents-python` (it vendors MIT-licensed components of it),
not as a straight fork.

Minimalist precedent that makes "small but effective" credible: mini-swe-agent's
agent class is ~100 lines and reports **>74% on SWE-bench Verified**;
hackingBuddyGPT (TU Wien) ships Linux privilege-escalation in tens of lines.

## 4. Honesty of capability

Autonomy is reported on the L0–L5 scale from the CAI Fluency framework
(arXiv:2508.13588), which distinguishes *automation* from *autonomy*. On that
scale, large frameworks like CAI *target* **Level 4** ("semi-autonomous"), and
LLM-assisted tools like PentestGPT sit at **Level 2**. CSI::nano claims **L3–L4
honestly and never L5** ("fully autonomous"): a human can interrupt (Ctrl+C) at
any time and can require per-action approval with `--approve`, and no finding is
reported as real without a reproducible ground-truth check.

## Primary sources

- Scaffold comparison / blackboard: arXiv:2605.28334
- Cybersecurity-agent meta-benchmark (the 2.6× coupling result): arXiv:2510.24317
- Autonomy L0–L5 taxonomy: arXiv:2508.13588 (traces to arXiv:2506.23592)
- Cybench (40 tasks): arXiv:2408.08926
- CAI framework: arXiv:2504.06017 and its public repository

All figures above were checked against these primary sources; where a figure
could not be confirmed from a primary source (e.g. CAI's total line count), it is
omitted rather than guessed.
