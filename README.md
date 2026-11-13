# husksec · CSI::nano

**A tiny, scope-enforced cybersecurity layer on top of the [husk](../husk) agent kernel.**

`husksec` adds security capability to `husk` *as plugins* — without changing a
line of the kernel. The kernel stays frozen and minimal (≈600 SLOC, one runtime
dependency); the layer rides on top and adds **zero** further runtime
dependencies, in ~1.2k SLOC. The thesis is **efficiency**, measured on public
CTF benchmarks: coverage per line of code and per euro, not raw size.

```
kernel: husk ≈600 SLOC · layer: husksec ≈1.2k SLOC · extra runtime deps: 0
```

## What it is

- **Scope enforcement** — `scope.yaml` declares the only targets any action may
  touch. Fail-closed, deny-overrides-allow.
- **Security tools** — thin wrappers over standard utilities (nmap, curl) that
  run inside the kernel's sandbox, with the target checked against scope before
  anything runs; plus a guarded generic shell for local work.
- **Findings memory** — an append-only JSONL log of hypotheses, evidence and
  status (`pending` / `confirmed` / `refuted`), replayable.
- **Benchmark adapters** — load tasks from public CTF benchmarks and run the agent
  in isolation, reporting coverage, cost (estimated €) and time. **Cybench** maps
  cleanly: its metadata carries a static ground-truth flag, scored from the
  transcript. **CAIBench** is *loaded* but honestly **unscoreable** by our method
  until in-container flag resolution lands (its flags come from commands in the
  container, not a static field). We *adapt*, never reimplement.
- **Autoresearch** — a hypothesis → experiment → verification loop where a
  finding is confirmed only by reproducible **ground truth** (a flag, a crash, a
  patch that closes the PoC), never by the model's say-so.

## Ethics & Safety

This is offensive tooling. It is built for **authorized** security testing and
for confirming, not overstating, what small agents can do. Use it only where you
have the right to, and disclose responsibly.

**Legitimate use only.** Run it exclusively against:
- public CTFs and practice ranges (HackTheBox, lab VMs),
- systems you own, or
- a target covered by a written, in-scope engagement.

**Controls that make that enforceable, not aspirational:**

1. **Scope is the authorization boundary.** It is **fail-closed**: a missing,
   malformed, or un-`authorized` scope denies *everything*, and the exclusion
   list always wins over the allow list. The enforcement is layered, and the
   two layers give different guarantees — state them honestly:
   - **Typed network tools** (`port_scan`, `service_scan`, `http_probe`) check
     the target's host against `in_scope`/`out_of_scope` *before* building or
     running a command, and build the command from the single authorized host.
     This is the robust path: use it for anything that touches a target.
   - **The generic `run` shell** is *deny-first only*: it refuses commands that
     reference an explicitly `out_of_scope` host, but it does **not** require a
     host to be in `in_scope` (it is meant for local work — writing/parsing
     files, running exploits). Prefer the typed tools for network actions.
2. **The sandbox is the isolation boundary.** The CLI **requires Docker by
   default and refuses to run without sandbox isolation**; passing `--no-docker`
   is an explicit opt-in to run unsandboxed on the host (husk prints a loud
   warning in that mode). Scope checks are a cheap filter on top of the sandbox,
   not a substitute for it (same honesty as the kernel's own deny-list).
3. **Human-in-the-loop.** `--approve` (on `run`, `research` and `bench`) routes
   risky actions through husk's approval hook; without it, runs proceed
   unattended under the step and wall-clock caps. Ctrl+C always interrupts.
4. **Everything is audited.** One JSONL event per model turn, tool call, scope
   decision and result — greppable, diffable, replayable.

**Honest limits (by design, documented so they are not surprises):**
- Scope is enforced at **host granularity**, not URL path. DNS is never resolved
  inside the authorization check, so an IP pattern matches only IP targets and a
  hostname pattern only hostname targets. **Consequence:** if you want to exclude
  a host, list it in *both* forms you expect the agent to use (its IP *and* its
  name) — excluding only one form does not block the other.
- For a freeform shell command, scope can only *refuse the obviously
  out-of-scope*; it cannot bless arbitrary shell. Prefer the typed tools for
  network actions. A hardened egress path (a scope-enforcing proxy in front of
  the sandbox network) is the documented next step, not yet shipped.
- Benchmark cost is an **estimate** (tokens approximated from message size); good
  for comparing runs, not a billing oracle.
- **CAIBench scoring is not shipped.** Its challenges carry no static flag (the
  flag is produced inside the container), so the adapter loads them but marks them
  **unscoreable** rather than guess. Cybench, which ships a static ground-truth
  flag, is fully scoreable. In-container flag resolution for CAIBench is the next step.
- Capability is **L3–L4** (semi-automated to high-automation), never L5. Nothing
  here is "fully autonomous".

## Quickstart

```bash
pip install -e ../husk        # the kernel
pip install -e ".[dev]"       # this layer
pytest -q                     # the pure modules test with no kernel or network

cp examples/scope.example.yaml scope.yaml   # then edit to YOUR authorized targets

export HUSK_BASE_URL=... HUSK_API_KEY=... HUSK_MODEL=...   # any OpenAI-compatible endpoint

husksec run "enumerate services on the box and report" --scope scope.yaml --approve
husksec research "analyse variants of CVE-XXXX in this service" --scope scope.yaml
husksec bench suite.json --report out.jsonl
```

See it work with **no key, no network, no Docker**:

```bash
python examples/autoresearch_demo.py
```

## Positioning

See [POSITIONING.md](POSITIONING.md) for how CSI::nano relates to larger harnesses,
with figures checked against primary sources.

## License

MIT.
