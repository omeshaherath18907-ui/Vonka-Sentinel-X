from datetime import datetime, timezone

from app.services.detection_engine import (
    DetectionConfig,
    DetectionEngine,
)


def test_normal_traffic_produces_no_alerts():
    engine = DetectionEngine()
    alerts = engine.evaluate({
        "packets_per_second": 25,
        "bytes_per_second": 12000,
        "protocols": {"TCP": 20, "UDP": 5},
    })
    assert alerts == []


def test_high_packet_rate_produces_warning():
    engine = DetectionEngine()
    alerts = engine.evaluate({
        "packets_per_second": 700,
        "bytes_per_second": 1000,
        "protocols": {"TCP": 700},
    })
    assert any(a.rule_id == "TRAFFIC_PPS_HIGH" for a in alerts)
    assert any(a.severity == "WARNING" for a in alerts)


def test_critical_packet_rate_produces_critical_alert():
    engine = DetectionEngine()
    alerts = engine.evaluate({
        "packets_per_second": 2000,
        "bytes_per_second": 1000,
        "protocols": {"TCP": 2000},
    })
    assert any(
        a.rule_id == "TRAFFIC_PPS_CRITICAL"
        and a.severity == "CRITICAL"
        for a in alerts
    )


def test_alert_timestamp_can_be_fixed_for_testing():
    engine = DetectionEngine()
    fixed_time = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = engine.evaluate(
        {"packets_per_second": 600},
        now=fixed_time,
    )

    assert alerts[0].timestamp == fixed_time.isoformat()


def test_thresholds_are_configurable():
    engine = DetectionEngine(
        DetectionConfig(warning_pps=50, critical_pps=100)
    )
    alerts = engine.evaluate({"packets_per_second": 60})
    assert any(a.rule_id == "TRAFFIC_PPS_HIGH" for a in alerts)


def test_high_udp_share_is_reported_as_investigation_signal():
    engine = DetectionEngine()
    alerts = engine.evaluate({
        "packets_per_second": 200,
        "protocols": {"UDP": 180, "TCP": 20},
    })
    assert any(a.rule_id == "PROTOCOL_UDP_SHARE_HIGH" for a in alerts)
