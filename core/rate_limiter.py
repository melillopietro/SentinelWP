"""
Enterprise Sliding-Window Rate Limiter for SentinelWP.
Supports Redis-backed distributed rate limiting with configurable failure policy.
Protects login endpoints, scanning triggers, and REST API tokens across clustered nodes.

Failure Modes (RATE_LIMIT_FAIL_MODE):
  - "closed" (default in production): Redis failure → deny all requests (fail-closed).
  - "open": Redis failure → allow all requests (fail-open, for dev/staging only).
  - "fallback": Redis failure → use in-memory sliding window (development default).
"""
import os
import time
import logging
from collections import defaultdict
from typing import Any, Dict, List, Tuple, Optional

logger = logging.getLogger("sentinelwp.rate_limiter")

# Failure mode configuration
_ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
RATE_LIMIT_FAIL_MODE = os.getenv(
    "RATE_LIMIT_FAIL_MODE",
    "closed" if _ENVIRONMENT in ("production", "prod") else "fallback"
).lower()


class DistributedRateLimiter:
    """
    Sliding-window log rate limiter with Redis backend and configurable failure policy.

    Production default: fail-closed (deny on Redis failure).
    Development default: fallback to in-memory sliding window.
    """

    def __init__(self, redis_url: Optional[str] = None, redis_client: Any = None,
                 fail_mode: Optional[str] = None):
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self.redis_client = None
        self.fail_mode = (fail_mode or RATE_LIMIT_FAIL_MODE).lower()

        if redis_client is not None:
            # Explicit False means "no Redis, use in-memory" (for tests)
            if redis_client is not False:
                self.redis_client = redis_client
        else:
            target_redis = redis_url or os.getenv("REDIS_URL")
            if target_redis and not os.getenv("TESTING"):
                try:
                    import redis
                    self.redis_client = redis.Redis.from_url(target_redis, socket_timeout=2)
                    self.redis_client.ping()
                    logger.info("DistributedRateLimiter initialized with Redis backend.")
                except Exception as e:
                    logger.warning(f"Redis unavailable for DistributedRateLimiter: {e}")
                    if self.fail_mode == "closed":
                        logger.error("RATE_LIMIT_FAIL_MODE=closed: Redis required but unavailable. "
                                     "All rate-limited requests will be DENIED.")
                    elif self.fail_mode == "fallback":
                        logger.warning("RATE_LIMIT_FAIL_MODE=fallback: Using in-memory sliding window.")
                    self.redis_client = None

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Check if request for key is allowed under rate limits.
        Returns (is_allowed: bool, retry_after: int)
        """
        now = time.time()
        cutoff = now - window_seconds

        # Redis sliding-window implementation
        if self.redis_client:
            try:
                pipe = self.redis_client.pipeline()
                r_key = f"rl:{key}"
                # Remove timestamps older than cutoff
                pipe.zremrangebyscore(r_key, 0, cutoff)
                # Count remaining requests in current window
                pipe.zcard(r_key)
                # Get oldest entry for retry-after calculation
                pipe.zrange(r_key, 0, 0, withscores=True)
                results = pipe.execute()

                current_count = results[1]
                oldest_entries = results[2]

                if current_count < max_requests:
                    pipe = self.redis_client.pipeline()
                    pipe.zadd(r_key, {str(now): now})
                    pipe.expire(r_key, window_seconds + 5)
                    pipe.execute()
                    return True, 0

                # Rate limit exceeded
                if oldest_entries:
                    oldest_ts = float(oldest_entries[0][1])
                    retry_after = max(1, int(oldest_ts + window_seconds - now) + 1)
                else:
                    retry_after = window_seconds
                return False, retry_after

            except Exception as e:
                # Redis operation failed — apply failure policy
                if self.fail_mode == "closed":
                    logger.error(f"Redis rate limiting error (fail-closed): {e}")
                    return False, 60  # Deny with 60s retry-after
                elif self.fail_mode == "open":
                    logger.warning(f"Redis rate limiting error (fail-open): {e}")
                    return True, 0  # Allow through
                else:
                    logger.warning(f"Redis rate limiting error (fallback to in-memory): {e}")
                    # Fall through to in-memory below

        elif self.fail_mode == "closed" and not os.getenv("TESTING"):
            # No Redis client and fail-closed → deny
            return False, 60

        # In-memory sliding-window fallback
        timestamps = [t for t in self._requests[key] if t > cutoff]
        self._requests[key] = timestamps

        if len(timestamps) < max_requests:
            timestamps.append(now)
            return True, 0

        oldest = timestamps[0]
        retry_after = int(oldest + window_seconds - now) + 1
        return False, max(1, retry_after)

    def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Convenience method returning True if request allowed, False otherwise."""
        allowed, _ = self.is_allowed(key, max_requests, window_seconds)
        return allowed

    def reset(self):
        """Clears in-memory rate limiting entries and flushes test keys if in test mode."""
        self._requests.clear()
        if self.redis_client and os.getenv("TESTING"):
            try:
                for k in self.redis_client.scan_iter("rl:*"):
                    self.redis_client.delete(k)
            except Exception:
                pass


# Alias for backward compatibility
RateLimiter = DistributedRateLimiter

# Global rate limiter instance
rate_limiter = DistributedRateLimiter()
