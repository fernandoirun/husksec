"""Tiny shared helpers. Kept dependency-free on purpose."""
from __future__ import annotations


def truncate(text: str, max_chars: int = 4000) -> str:
    """Clip noisy tool output so one command cannot blow the context window.
    Keeps the head and the tail, which is where signal usually lives."""
    text = text or ""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    dropped = len(text) - max_chars
    return f"{text[:half]}\n...[{dropped} chars truncated]...\n{text[-half:]}"
