"""
In-memory Rate Limiter Middleware for SentinelWP.
Implements sliding-window request throttling per IP address.
"""
import time
from collections import defaultdict
from typing import Dict, List, Tuple


class RateLimiter:
    def __init__(self):
        # Maps key -> list of timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Check if request for key is allowed under rate limits.
        Returns (is_allowed: bool, retry_after: int)
        """
        now = time.time()
        cutoff = now - window_seconds
        
        # Clean expired timestamps
        timestamps = [t for t in self._requests[key] if t > cutoff]
        self._requests[key] = timestamps

        if len(timestamps) < max_requests:
            timestamps.append(now)
            return True, 0

        # Calculate seconds until the oldest request in window expires
        oldest = timestamps[0]
        retry_after = int(oldest + window_seconds - now) + 1
        return False, max(1, retry_after)


# Global rate limiter instance
rate_limiter = RateLimiter()
