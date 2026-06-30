"""Circuit breaker para chamadas à Claude API.

Após ``failure_threshold`` falhas consecutivas, abre por
``recovery_seconds`` segundos. Durante o período aberto, todas as
chamadas falham imediatamente sem tentar a API — o pipeline continua
em modo degradado (findings brutos sem narrativa Claude).

O singleton ``DEFAULT_BREAKER`` é compartilhado pelo processo worker,
garantindo que múltiplas threads/instâncias de ``ClaudeClient`` somem
suas falhas — não que cada uma conte 3 falhas separadamente.
"""
from __future__ import annotations

import time
from enum import Enum


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_seconds: int = 300,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._failures = 0
        self._state = CircuitState.CLOSED
        self._opened_at = 0.0

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failures(self) -> int:
        return self._failures

    def is_open(self) -> bool:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._opened_at > self.recovery_seconds:
                self._state = CircuitState.HALF_OPEN
                return False
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._state = CircuitState.OPEN
            self._opened_at = time.monotonic()


# Singleton de processo. Importadores devem fazer
# ``from app.infrastructure.ai.circuit_breaker import DEFAULT_BREAKER``
# para compartilhar estado entre todas as instâncias de ClaudeClient.
DEFAULT_BREAKER = CircuitBreaker()
