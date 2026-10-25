from collections import deque
from datetime import datetime, timezone
from typing import Any, Mapping

from app.services.detection_engine import (
    DetectionAlert,
    DetectionConfig,
    DetectionEngine,
)


class RollingWindowDetector:
    """Detect patterns from deltas of cumulative traffic counters."""

    def __init__(
        self,
        config: DetectionConfig | None = None,
        window_seconds: float = 10.0,
        minimum_interval: float = 1.0,
    ):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if minimum_interval <= 0:
            raise ValueError("minimum_interval must be positive")
        if minimum_interval > window_seconds:
            raise ValueError("minimum_interval cannot exceed window_seconds")

        self.window_seconds = window_seconds
        self.minimum_interval = minimum_interval
        self.engine = DetectionEngine(config)
        self.samples = deque()

    @staticmethod
    def _counter(value: Any) -> float:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, float(value))
        return 0.0

    def _normalize(self, snapshot: Mapping[str, Any]) -> dict:
        raw_protocols = snapshot.get("protocols", {})
        protocols = {}

        if isinstance(raw_protocols, Mapping):
            protocols = {
                str(name): self._counter(count)
                for name, count in raw_protocols.items()
            }

        return {
            "packets_total": self._counter(snapshot.get("packets_total")),
            "bytes_total": self._counter(snapshot.get("bytes_total")),
            "protocols": protocols,
        }

    @staticmethod
    def _has_counter_reset(previous: dict, current: dict) -> bool:
        for key in ("packets_total", "bytes_total"):
            if current[key] < previous[key]:
                return True

        names = set(previous["protocols"]) | set(current["protocols"])
        for name in names:
            if current["protocols"].get(name, 0.0) < (
                previous["protocols"].get(name, 0.0)
            ):
                return True

        return False

    def observe(
        self,
        snapshot: Mapping[str, Any],
        now_monotonic: float | None = None,
        now: datetime | None = None,
    ) -> list[DetectionAlert]:
        """Record a snapshot and evaluate rates across the recent window."""
        import time

        moment = time.monotonic() if now_monotonic is None else float(now_monotonic)
        wall_time = now or datetime.now(timezone.utc)
        current = self._normalize(snapshot)

        if self.samples and moment <= self.samples[-1][0]:
            # Ignore duplicate or out-of-order sample timestamps.
            return []

        if self.samples and self._has_counter_reset(
            self.samples[-1][1], current
        ):
            # Establish a fresh baseline rather than treating reset counters
            # as a sudden traffic spike.
            self.samples.clear()
            self.samples.append((moment, current))
            return []

        self.samples.append((moment, current))

        # Keep one sample just before the window boundary when available.
        while (
            len(self.samples) > 2
            and self.samples[1][0] < moment - self.window_seconds
        ):
            self.samples.popleft()

        if len(self.samples) < 2:
            return []

        start_time, start = self.samples[0]
        elapsed = moment - start_time
        if elapsed < self.minimum_interval:
            return []

        packet_delta = max(0.0, current["packets_total"] - start["packets_total"])
        byte_delta = max(0.0, current["bytes_total"] - start["bytes_total"])

        protocol_names = set(start["protocols"]) | set(current["protocols"])
        protocol_delta = {
            name: max(
                0.0,
                current["protocols"].get(name, 0.0)
                - start["protocols"].get(name, 0.0),
            )
            for name in protocol_names
        }

        window_snapshot = {
            "packets_per_second": packet_delta / elapsed,
            "bytes_per_second": byte_delta / elapsed,
            "protocols": protocol_delta,
        }

        return self.engine.evaluate(window_snapshot, now=wall_time)
