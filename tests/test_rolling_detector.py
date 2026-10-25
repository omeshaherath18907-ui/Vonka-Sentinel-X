from datetime import datetime, timezone

from app.services.detection_engine import DetectionConfig
from app.services.rolling_detector import RollingWindowDetector


def snapshot(packets, bytes_count, tcp=0, udp=0):
    return {
        "packets_total": packets,
        "bytes_total": bytes_count,
        "protocols": {"TCP": tcp, "UDP": udp},
    }


def test_waits_for_enough_samples():
    detector = RollingWindowDetector()
    alerts = detector.observe(snapshot(100, 1000, tcp=100), now_monotonic=1)
    assert alerts == []


def test_critical_rate_is_detected_from_counter_deltas():
    detector = RollingWindowDetector()
    detector.observe(snapshot(100, 1000, tcp=100), now_monotonic=1)

    alerts = detector.observe(
        snapshot(2100, 2000, tcp=2100),
        now_monotonic=2,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert any(a.rule_id == "TRAFFIC_PPS_CRITICAL" for a in alerts)


def test_normal_recent_rate_does_not_alert():
    detector = RollingWindowDetector()
    detector.observe(snapshot(100, 1000, tcp=100), now_monotonic=1)

    alerts = detector.observe(
        snapshot(120, 2000, tcp=120),
        now_monotonic=2,
    )

    assert alerts == []


def test_udp_share_uses_recent_protocol_deltas():
    detector = RollingWindowDetector()
    detector.observe(snapshot(100, 1000, tcp=100), now_monotonic=1)

    alerts = detector.observe(
        snapshot(300, 2000, tcp=120, udp=180),
        now_monotonic=2,
    )

    assert any(a.rule_id == "PROTOCOL_UDP_SHARE_HIGH" for a in alerts)


def test_counter_reset_reestablishes_baseline():
    detector = RollingWindowDetector()
    detector.observe(snapshot(1000, 5000, tcp=1000), now_monotonic=1)

    alerts = detector.observe(
        snapshot(10, 100, tcp=10),
        now_monotonic=2,
    )

    assert alerts == []
    assert len(detector.samples) == 1


def test_thresholds_are_configurable():
    config = DetectionConfig(warning_pps=10, critical_pps=20)
    detector = RollingWindowDetector(config=config)
    detector.observe(snapshot(0, 0), now_monotonic=1)

    alerts = detector.observe(
        snapshot(15, 1000, tcp=15),
        now_monotonic=2,
    )

    assert any(a.rule_id == "TRAFFIC_PPS_HIGH" for a in alerts)
