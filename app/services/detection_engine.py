from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


@dataclass(frozen=True)
class DetectionConfig:
    warning_pps: float = 500.0
    critical_pps: float = 1500.0
    warning_bytes_per_second: float = 2_000_000.0
    critical_bytes_per_second: float = 8_000_000.0
    high_udp_share: float = 0.80
    minimum_packets_for_protocol_alert: float = 100.0


@dataclass(frozen=True)
class DetectionAlert:
    rule_id: str
    severity: str
    title: str
    reason: str
    observed_value: float
    threshold: float
    timestamp: str


def _number(data: Mapping[str, Any], *keys: str) -> float:
    """Read a numeric metric while safely handling missing or invalid values."""
    for key in keys:
        value = data.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, float(value))
    return 0.0


class DetectionEngine:
    """Evaluate observed traffic metadata; this class does not block traffic."""

    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()

    def evaluate(
        self,
        snapshot: Mapping[str, Any],
        now: datetime | None = None,
    ) -> list[DetectionAlert]:
        timestamp = (now or datetime.now(timezone.utc)).isoformat()
        alerts: list[DetectionAlert] = []

        pps = _number(
            snapshot, "packets_per_second", "pps", "packet_rate"
        )
        bps = _number(
            snapshot, "bytes_per_second", "bytes_per_sec", "byte_rate"
        )

        def add(
            rule_id: str,
            severity: str,
            title: str,
            reason: str,
            observed: float,
            threshold: float,
        ) -> None:
            alerts.append(
                DetectionAlert(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    reason=reason,
                    observed_value=round(observed, 2),
                    threshold=threshold,
                    timestamp=timestamp,
                )
            )

        if pps >= self.config.critical_pps:
            add(
                "TRAFFIC_PPS_CRITICAL",
                "CRITICAL",
                "Very high packet rate",
                "Observed packet rate reached the critical configured threshold.",
                pps,
                self.config.critical_pps,
            )
        elif pps >= self.config.warning_pps:
            add(
                "TRAFFIC_PPS_HIGH",
                "WARNING",
                "Elevated packet rate",
                "Observed packet rate exceeded the warning configured threshold.",
                pps,
                self.config.warning_pps,
            )

        if bps >= self.config.critical_bytes_per_second:
            add(
                "TRAFFIC_BANDWIDTH_CRITICAL",
                "CRITICAL",
                "Very high bandwidth rate",
                "Observed byte rate reached the critical configured threshold.",
                bps,
                self.config.critical_bytes_per_second,
            )
        elif bps >= self.config.warning_bytes_per_second:
            add(
                "TRAFFIC_BANDWIDTH_HIGH",
                "WARNING",
                "Elevated bandwidth rate",
                "Observed byte rate exceeded the warning configured threshold.",
                bps,
                self.config.warning_bytes_per_second,
            )

        protocols = snapshot.get("protocols", {})
        if isinstance(protocols, Mapping) and pps >= (
            self.config.minimum_packets_for_protocol_alert
        ):
            tcp = _number(protocols, "TCP")
            udp = _number(protocols, "UDP")
            total = sum(
                _number(protocols, key)
                for key in ("TCP", "UDP", "ICMP", "ARP", "IPv6", "IPv4", "Other")
            )

            if total > 0:
                udp_share = udp / total
                if udp_share >= self.config.high_udp_share:
                    add(
                        "PROTOCOL_UDP_SHARE_HIGH",
                        "WARNING",
                        "Unusually high UDP share",
                        "UDP accounts for a high share of the protocol counts. "
                        "This is a signal to investigate, not proof of an attack.",
                        udp_share * 100,
                        self.config.high_udp_share * 100,
                    )

        return alerts
