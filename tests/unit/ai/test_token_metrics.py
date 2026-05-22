import pytest
from prometheus_client import REGISTRY

from app.infrastructure.ai import models as model_constants
from app.infrastructure.ai.token_metrics import (
    claude_cost_usd_total,
    claude_requests_total,
    claude_tokens_total,
    record_request_outcome,
    record_token_usage,
)


def _cost(model: str) -> float:
    return REGISTRY.get_sample_value(
        "claude_cost_usd_total", {"model": model}
    ) or 0.0


def _tokens(model: str, type_: str) -> float:
    return REGISTRY.get_sample_value(
        "claude_tokens_total", {"model": model, "type": type_}
    ) or 0.0


def _requests(model: str, outcome: str) -> float:
    return REGISTRY.get_sample_value(
        "claude_requests_total", {"model": model, "outcome": outcome}
    ) or 0.0


class TestRecordTokenUsage:
    def test_unknown_model_is_silent_noop(self):
        before = _cost("unknown-model")
        record_token_usage(
            model="unknown-model",
            input_tokens=1000,
            cache_read_tokens=0,
            cache_write_tokens=0,
            output_tokens=500,
        )
        assert _cost("unknown-model") == before

    def test_fresh_input_pricing_for_reasoning(self):
        model = model_constants.REASONING
        before = _cost(model)
        # 1M fresh input @ $3.0 + 500k output @ $15.0 = $3.0 + $7.5 = $10.50
        record_token_usage(
            model=model,
            input_tokens=1_000_000,
            cache_read_tokens=0,
            cache_write_tokens=0,
            output_tokens=500_000,
        )
        delta = _cost(model) - before
        assert delta == pytest.approx(10.50, rel=1e-3)

    def test_cache_read_pricing_for_reasoning(self):
        model = model_constants.REASONING
        before = _cost(model)
        # input_tokens=1M includes 800k cache_read.
        # fresh = 200k → $0.60; cache_read 800k @ $0.30 → $0.24
        # output 0 → $0. Total: $0.84
        record_token_usage(
            model=model,
            input_tokens=1_000_000,
            cache_read_tokens=800_000,
            cache_write_tokens=0,
            output_tokens=0,
        )
        delta = _cost(model) - before
        assert delta == pytest.approx(0.84, rel=1e-3)

    def test_cache_write_pricing_higher_than_input(self):
        model = model_constants.REASONING
        before = _cost(model)
        # 1M cache_write @ $3.75 (mais caro que input fresh)
        record_token_usage(
            model=model,
            input_tokens=1_000_000,
            cache_read_tokens=0,
            cache_write_tokens=1_000_000,
            output_tokens=0,
        )
        delta = _cost(model) - before
        assert delta == pytest.approx(3.75, rel=1e-3)

    def test_haiku_is_cheaper_than_sonnet(self):
        reasoning = model_constants.REASONING
        formatting = model_constants.FORMATTING
        before_r = _cost(reasoning)
        before_f = _cost(formatting)

        record_token_usage(
            model=reasoning,
            input_tokens=1_000_000,
            cache_read_tokens=0,
            cache_write_tokens=0,
            output_tokens=0,
        )
        record_token_usage(
            model=formatting,
            input_tokens=1_000_000,
            cache_read_tokens=0,
            cache_write_tokens=0,
            output_tokens=0,
        )
        r_cost = _cost(reasoning) - before_r
        f_cost = _cost(formatting) - before_f
        assert r_cost > f_cost
        assert r_cost == pytest.approx(3.0, rel=1e-3)
        assert f_cost == pytest.approx(1.0, rel=1e-3)

    def test_tokens_recorded_in_buckets(self):
        model = model_constants.REASONING
        b_input = _tokens(model, "input")
        b_cache_read = _tokens(model, "cache_read")
        b_cache_write = _tokens(model, "cache_write")
        b_output = _tokens(model, "output")

        record_token_usage(
            model=model,
            input_tokens=1500,
            cache_read_tokens=300,
            cache_write_tokens=200,
            output_tokens=100,
        )
        assert _tokens(model, "input") - b_input == 1000  # fresh = 1500-300-200
        assert _tokens(model, "cache_read") - b_cache_read == 300
        assert _tokens(model, "cache_write") - b_cache_write == 200
        assert _tokens(model, "output") - b_output == 100

    def test_negative_fresh_clamped_to_zero(self):
        """Se a API reportar cache_read > input_tokens (pode acontecer
        em algumas circunstâncias), fresh deve ser 0, não negativo."""
        model = model_constants.REASONING
        b = _tokens(model, "input")
        record_token_usage(
            model=model,
            input_tokens=100,
            cache_read_tokens=300,  # maior que input
            cache_write_tokens=0,
            output_tokens=0,
        )
        assert _tokens(model, "input") == b  # no incremento (max(.., 0))


class TestRequestOutcome:
    def test_increments_for_each_outcome(self):
        model = model_constants.REASONING
        before_success = _requests(model, "success")
        before_error = _requests(model, "error")

        record_request_outcome(model, "success")
        record_request_outcome(model, "success")
        record_request_outcome(model, "error")

        assert _requests(model, "success") - before_success == 2
        assert _requests(model, "error") - before_error == 1
