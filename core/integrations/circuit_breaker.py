"""
Circuit Breaker Implementation for External Integrations (SIEM, Jira, ServiceNow, Webhooks).

States:
- CLOSED: Requests pass through normally. Success resets failure counter.
- OPEN: Requests fail fast without attempting network calls.
- HALF_OPEN: Probe request allowed after cooldown. If successful, transitions to CLOSED; otherwise back to OPEN.

SEC-007 (Sprint 1): All mutable state accesses are protected by a threading.Lock so that
concurrent callers from a multi-threaded Celery worker cannot corrupt the state machine.
"""
import time
import threading
import logging
from typing import Callable, Any, Optional

logger = logging.getLogger("sentinelwp.integrations.circuit_breaker")


class CircuitBreakerOpenException(Exception):
    """Raised when request is rejected because circuit is OPEN."""
    pass


class CircuitBreaker:
    """
    State machine: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.
    Thread-safe (SEC-007) and process-local.
    """
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_success_threshold: int = 2
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_success_threshold = half_open_success_threshold

        self._lock = threading.Lock()
        self.state = self.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_state_change = time.time()
        self.last_failure_time = 0.0

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Executes func protected by the circuit breaker."""
        with self._lock:
            now = time.time()

            # Check if OPEN state has expired -> transition to HALF_OPEN
            if self.state == self.OPEN:
                if now - self.last_failure_time >= self.recovery_timeout:
                    logger.info(f"CircuitBreaker [{self.name}]: recovery timeout elapsed, entering HALF_OPEN")
                    self.state = self.HALF_OPEN
                    self.success_count = 0
                    self.last_state_change = now
                else:
                    raise CircuitBreakerOpenException(
                        f"CircuitBreaker [{self.name}] is OPEN. Fast failing request without network call."
                    )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except CircuitBreakerOpenException:
            raise
        except Exception as exc:
            self._on_failure(exc)
            raise

    def _on_success(self):
        with self._lock:
            if self.state == self.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.half_open_success_threshold:
                    logger.info(f"CircuitBreaker [{self.name}]: probe succeeded, transitioning to CLOSED")
                    self.state = self.CLOSED
                    self.failure_count = 0
                    self.success_count = 0
                    self.last_state_change = time.time()
            elif self.state == self.CLOSED:
                self.failure_count = 0

    def _on_failure(self, exc: Exception):
        with self._lock:
            now = time.time()
            self.last_failure_time = now
            self.failure_count += 1
            logger.warning(
                f"CircuitBreaker [{self.name}]: failure recorded ({self.failure_count}/{self.failure_threshold}): {exc}"
            )

            if self.state in (self.CLOSED, self.HALF_OPEN) and self.failure_count >= self.failure_threshold:
                logger.error(f"CircuitBreaker [{self.name}]: failure threshold reached, entering OPEN state")
                self.state = self.OPEN
                self.last_state_change = now


# Shared registry of circuit breakers
_BREAKERS: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, failure_threshold: int = 5, recovery_timeout: float = 30.0) -> CircuitBreaker:
    if name not in _BREAKERS:
        _BREAKERS[name] = CircuitBreaker(name, failure_threshold=failure_threshold, recovery_timeout=recovery_timeout)
    return _BREAKERS[name]
