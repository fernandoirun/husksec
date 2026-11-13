"""Token and cost metering, by wrapping any husk-style provider.

husk's provider returns only the assistant message -- it drops the API usage
block to stay tiny. For the efficiency axis (coverage per euro) we need a cost
figure, so husksec wraps the provider and ESTIMATES tokens from the messages it
sends and receives (~4 chars/token, the same heuristic husk uses to decide when
to compact). Costs are therefore clearly-labelled *estimates* -- good enough to
compare runs and scaffolds, not a billing oracle. Zero new dependency, core
untouched. Swap in real usage numbers here later if a provider exposes them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass


def estimate_tokens_text(text) -> int:
    return len(str(text)) // 4 if text else 0


def estimate_message_tokens(messages: list, tools: list | None = None) -> int:
    chars = 0
    for m in messages:
        content = m.get("content")
        if content:
            chars += len(str(content))
        for call in m.get("tool_calls") or []:
            fn = call.get("function") or {}
            chars += len(str(fn.get("name") or "")) + len(str(fn.get("arguments") or ""))
    if tools:
        chars += len(json.dumps(tools, default=str))
    return chars // 4


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    eur: float = 0.0

    def as_dict(self) -> dict:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
            "calls": self.calls,
            "eur_estimated": round(self.eur, 6),
        }


class MeteredProvider:
    """Wraps a provider exposing ``chat(messages, tools)`` and ``context_window``,
    accumulating estimated token usage and euro cost. Drop-in for husk's Agent."""

    def __init__(self, inner, *, eur_per_1k_prompt: float = 0.0, eur_per_1k_completion: float = 0.0):
        self.inner = inner
        self.eur_per_1k_prompt = eur_per_1k_prompt
        self.eur_per_1k_completion = eur_per_1k_completion
        self.usage = Usage()

    @property
    def context_window(self) -> int:
        return getattr(self.inner, "context_window", 128000)

    def chat(self, messages: list, tools: list | None = None) -> dict:
        self.usage.prompt_tokens += estimate_message_tokens(messages, tools)
        msg = self.inner.chat(messages, tools=tools)
        self.usage.completion_tokens += estimate_message_tokens([msg])
        self.usage.calls += 1
        self.usage.eur = (
            self.usage.prompt_tokens / 1000 * self.eur_per_1k_prompt
            + self.usage.completion_tokens / 1000 * self.eur_per_1k_completion
        )
        return msg

    def close(self) -> None:
        close = getattr(self.inner, "close", None)
        if callable(close):
            close()
