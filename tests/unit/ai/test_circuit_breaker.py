import time

import pytest

from app.infrastructure.ai.circuit_breaker import CircuitBreaker, CircuitState


class TestInitialState:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state is CircuitState.CLOSED
        assert cb.is_open() is False
        assert cb.failures == 0


class TestFailureProgression:
    def test_does_not_open_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_seconds=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.state is CircuitState.CLOSED
        assert cb.failures == 2

    def test_opens_at_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_seconds=60)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.state is CircuitState.OPEN
        assert cb.is_open() is True

    def test_custom_threshold(self):
        cb = CircuitBreaker(failure_threshold=5, recovery_seconds=60)
        for _ in range(4):
            cb.record_failure()
        assert cb.state is CircuitState.CLOSED
        cb.record_failure()
        assert cb.state is CircuitState.OPEN


class TestRecovery:
    def test_record_success_resets_state(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_seconds=60)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.failures == 0
        assert cb.state is CircuitState.CLOSED

    def test_half_open_after_recovery_window(self, monkeypatch):
        cb = CircuitBreaker(failure_threshold=2, recovery_seconds=10)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open() is True

        # Avança o relógio monotônico além da janela
        original_monotonic = time.monotonic
        offset = [0.0]

        def fake_monotonic():
            return original_monotonic() + offset[0]

        offset[0] = 11.0
        monkeypatch.setattr(time, "monotonic", fake_monotonic)
        # is_open() deve transitar para HALF_OPEN e retornar False
        assert cb.is_open() is False
        assert cb.state is CircuitState.HALF_OPEN

    def test_success_after_half_open_returns_to_closed(self, monkeypatch):
        cb = CircuitBreaker(failure_threshold=2, recovery_seconds=10)
        cb.record_failure()
        cb.record_failure()

        offset = [11.0]
        original_monotonic = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + offset[0])
        cb.is_open()  # transiciona para HALF_OPEN
        cb.record_success()
        assert cb.state is CircuitState.CLOSED


class TestDefaults:
    def test_default_thresholds(self):
        cb = CircuitBreaker()
        assert cb.failure_threshold == 3
        assert cb.recovery_seconds == 300
