"""Structured findings memory: hypothesis / evidence / status.

A finding is a claim the agent is investigating, its supporting evidence, and a
status that is only ever ``pending``, ``confirmed`` or ``refuted``. The store is
an **append-only JSONL log of events** (record / evidence / status), exactly like
husk's audit trail: every mutation is one line, so the full history is greppable,
diffable and replayable, and the current state is rebuilt by replaying the log.

This is the bridge to autoresearch: a hypothesis is only ever marked
``confirmed`` by a reproducible ground-truth check (see verify.py), never by the
model's say-so.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

STATUSES = ("pending", "confirmed", "refuted")


@dataclass
class Finding:
    id: str
    hypothesis: str
    status: str = "pending"
    evidence: list = field(default_factory=list)
    created: float = 0.0
    updated: float = 0.0

    def oneline(self) -> str:
        mark = {"pending": "?", "confirmed": "+", "refuted": "-"}.get(self.status, "?")
        return f"[{mark}] {self.id} ({self.status}, {len(self.evidence)} evidence): {self.hypothesis}"


class FindingsStore:
    """In-memory current state backed by an optional append-only JSONL file."""

    def __init__(self, path=None, *, clock=time.time):
        self.path = Path(path) if path else None
        self._clock = clock
        self._by_id: dict[str, Finding] = {}
        self._seq = 0
        if self.path and self.path.exists():
            self._replay()

    # -- persistence -------------------------------------------------------
    def _emit(self, event: dict) -> None:
        if not self.path:
            return
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    def _replay(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            op = ev.get("op")
            if op == "record":
                f = Finding(
                    id=ev["id"], hypothesis=ev["hypothesis"], status=ev.get("status", "pending"),
                    evidence=list(ev.get("evidence", [])), created=ev.get("ts", 0.0), updated=ev.get("ts", 0.0),
                )
                self._by_id[f.id] = f
            elif op == "evidence" and ev["id"] in self._by_id:
                self._by_id[ev["id"]].evidence.append(ev["text"])
                self._by_id[ev["id"]].updated = ev.get("ts", 0.0)
            elif op == "status" and ev["id"] in self._by_id:
                self._by_id[ev["id"]].status = ev["status"]
                self._by_id[ev["id"]].updated = ev.get("ts", 0.0)
                # Mirror the live mutation: set_status appends the note to
                # evidence, so replay must too or reloaded state diverges.
                if ev.get("note"):
                    self._by_id[ev["id"]].evidence.append(f"[status -> {ev['status']}] {ev['note']}")
            n = _seq_of(ev.get("id", ""))
            if n > self._seq:
                self._seq = n

    # -- mutations ---------------------------------------------------------
    def record(self, hypothesis: str) -> str:
        self._seq += 1
        fid = f"F{self._seq:03d}"
        now = self._clock()
        self._by_id[fid] = Finding(id=fid, hypothesis=hypothesis, created=now, updated=now)
        self._emit({"ts": now, "op": "record", "id": fid, "hypothesis": hypothesis, "status": "pending"})
        return fid

    def add_evidence(self, fid: str, text: str) -> None:
        self._require(fid)
        now = self._clock()
        self._by_id[fid].evidence.append(text)
        self._by_id[fid].updated = now
        self._emit({"ts": now, "op": "evidence", "id": fid, "text": text})

    def set_status(self, fid: str, status: str, note: str = "") -> None:
        self._require(fid)
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, got {status!r}")
        now = self._clock()
        self._by_id[fid].status = status
        self._by_id[fid].updated = now
        if note:
            self._by_id[fid].evidence.append(f"[status -> {status}] {note}")
        self._emit({"ts": now, "op": "status", "id": fid, "status": status, "note": note})

    # -- queries -----------------------------------------------------------
    def get(self, fid: str) -> Finding:
        self._require(fid)
        return self._by_id[fid]

    def list(self, status: str | None = None) -> list[Finding]:
        items = sorted(self._by_id.values(), key=lambda f: f.id)
        return [f for f in items if status is None or f.status == status]

    def summary(self) -> str:
        if not self._by_id:
            return "no findings recorded"
        counts = {s: 0 for s in STATUSES}
        for f in self._by_id.values():
            counts[f.status] = counts.get(f.status, 0) + 1
        head = ", ".join(f"{k}={v}" for k, v in counts.items())
        body = "\n".join(f.oneline() for f in self.list())
        return f"{head}\n{body}"

    def as_dicts(self) -> list[dict]:
        return [asdict(f) for f in self.list()]

    def _require(self, fid: str) -> None:
        if fid not in self._by_id:
            raise KeyError(f"no such finding {fid!r}")


def _seq_of(fid: str) -> int:
    if fid.startswith("F") and fid[1:].isdigit():
        return int(fid[1:])
    return 0
