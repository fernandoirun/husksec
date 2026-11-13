"""Tests for the metering provider wrapper."""
from husksec.metering import MeteredProvider, estimate_message_tokens


class FakeInner:
    context_window = 64000

    def __init__(self):
        self.closed = False

    def chat(self, messages, tools=None):
        return {"role": "assistant", "content": "a short reply"}

    def close(self):
        self.closed = True


def test_accumulates_usage_and_cost():
    m = MeteredProvider(FakeInner(), eur_per_1k_prompt=1.0, eur_per_1k_completion=2.0)
    m.chat([{"role": "user", "content": "x" * 400}], tools=None)   # ~100 prompt tokens
    m.chat([{"role": "user", "content": "y" * 800}])               # ~200 more prompt tokens
    u = m.usage.as_dict()
    assert u["calls"] == 2
    assert u["prompt_tokens"] >= 300
    assert u["completion_tokens"] > 0
    assert u["eur_estimated"] > 0
    # cost is prompt/1k*1 + completion/1k*2
    expected = u["prompt_tokens"] / 1000 * 1.0 + u["completion_tokens"] / 1000 * 2.0
    assert abs(u["eur_estimated"] - round(expected, 6)) < 1e-6


def test_context_window_passthrough_and_close():
    inner = FakeInner()
    m = MeteredProvider(inner)
    assert m.context_window == 64000
    m.close()
    assert inner.closed is True


def test_estimate_counts_tool_calls():
    msgs = [{"role": "assistant", "content": None,
             "tool_calls": [{"function": {"name": "run", "arguments": '{"command":"ls -la /"}'}}]}]
    assert estimate_message_tokens(msgs) > 0
