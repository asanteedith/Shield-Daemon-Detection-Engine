import math
import time
from collections import deque
from datetime import datetime


class BaselineTracker:
    """
    Tracks rolling baseline of traffic.
    - Maintains a 30-minute window of per-second request counts
    - Recalculates mean and stddev every 60 seconds
    - Maintains per-hour slots for better accuracy
    - Uses floor values to prevent division by zero
    """

    def __init__(self, config: dict):
        # Rolling window size in seconds (30 minutes)
        self.window_size = config.get('baseline_window', 1800)
        # How often to recalculate baseline in seconds
        self.recalc_interval = config.get('baseline_interval', 60)
        # Minimum requests before baseline is valid
        self.min_requests = config.get('baseline_min_requests', 10)
        # Floor values to prevent division by zero
        self.floor_mean = config.get('baseline_floor_mean', 1.0)
        self.floor_std = config.get('baseline_floor_std', 0.5)

        # Deque stores (timestamp, count) tuples for last 30 minutes
        self.global_counts = deque()
        # Per-hour slots - key is hour string like "2026-05-11T10"
        self.hourly_slots = {}

        # Current baseline values
        self.effective_mean = self.floor_mean
        self.effective_std = self.floor_std

        # Per-second counter
        self.current_second = int(time.time())
        self.current_count = 0

        # Last recalculation time
        self.last_recalc = time.time()

        # Error rate tracking
        self.error_counts = deque()
        self.error_mean = 0.0
        self.error_std = 0.0

    def record_request(self, timestamp: float, is_error: bool = False):
        """Record a single request."""
        second = int(timestamp)

        # If we moved to a new second flush current count
        if second != self.current_second:
            self._flush_second()
            self.current_second = second
            self.current_count = 0

        self.current_count += 1

        if is_error:
            self.error_counts.append((timestamp, 1))

        # Recalculate baseline every 60 seconds
        if time.time() - self.last_recalc >= self.recalc_interval:
            self._recalculate()
            self.last_recalc = time.time()

    def _flush_second(self):
        """Save current second count to the rolling window."""
        now = time.time()
        cutoff = now - self.window_size

        # Add current second to window
        self.global_counts.append((self.current_second, self.current_count))

        # Get current hour slot
        hour_key = datetime.utcnow().strftime('%Y-%m-%dT%H')
        if hour_key not in self.hourly_slots:
            self.hourly_slots[hour_key] = deque()
        self.hourly_slots[hour_key].append(
            (self.current_second, self.current_count)
        )

        # Evict old entries outside the window
        while self.global_counts and self.global_counts[0][0] < cutoff:
            self.global_counts.popleft()

        # Evict old error counts
        while self.error_counts and self.error_counts[0][0] < cutoff:
            self.error_counts.popleft()

    def _recalculate(self):
        """
        Recalculate mean and stddev from rolling window.
        Prefer current hour's data if it has enough samples.
        """
        # Try current hour first
        hour_key = datetime.utcnow().strftime('%Y-%m-%dT%H')
        hour_data = self.hourly_slots.get(hour_key, deque())

        if len(hour_data) >= self.min_requests:
            counts = [c for _, c in hour_data]
        elif len(self.global_counts) >= self.min_requests:
            counts = [c for _, c in self.global_counts]
        else:
            # Not enough data yet — keep floor values
            return

        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std = math.sqrt(variance)

        # Apply floor values
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_std = max(std, self.floor_std)

        print(
            f"[BASELINE] Recalculated — "
            f"mean={self.effective_mean:.2f} "
            f"std={self.effective_std:.2f} "
            f"samples={len(counts)}"
        )

    def get_baseline(self) -> tuple:
        """Return current effective mean and stddev."""
        return self.effective_mean, self.effective_std

    def get_z_score(self, rate: float) -> float:
        """Calculate z-score for a given rate."""
        if self.effective_std == 0:
            return 0.0
        return (rate - self.effective_mean) / self.effective_std
