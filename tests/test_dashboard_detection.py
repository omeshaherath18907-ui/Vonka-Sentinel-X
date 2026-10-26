import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from app.ui.main_window import MainWindow
from app.services.rolling_detector import RollingWindowDetector
from types import SimpleNamespace


class FakeCollector:
    def snapshot(self):
        return {
            "packets_total": 10000,
            "bytes_total": 1000000,
            "packets_per_second": 2000,
            "bytes_per_second": 1000,
            "protocols": {"TCP": 2000, "UDP": 0},
            "last_packet_at": "2026-10-25T12:00:00",
            "last_error": None,
            "capture_running": True,
        }


class FakeDetector:
    def __init__(self):
        self.alert = SimpleNamespace(
            rule_id="TRAFFIC_PPS_CRITICAL",
            severity="CRITICAL",
            title="Very high packet rate",
            reason="Synthetic integration-test alert.",
            timestamp="2026-01-01T00:00:00+00:00",
        )

    def observe(self, snapshot):
        return [self.alert]


def test_dashboard_displays_and_deduplicates_detection_alerts(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)

    monkeypatch.setenv("VONKA_SENTINEL_DB", str(tmp_path / "dashboard-test.db"))
    window = MainWindow()
    try:
        assert isinstance(window.detector, RollingWindowDetector)
        window.collector = FakeCollector()
        window.detector = FakeDetector()

        window.refresh_dashboard()

        assert window.alert_table.rowCount() == 1
        assert window.alert_table.item(0, 0).text() == "CRITICAL"
        assert window.alert_table.item(0, 2).text() == "Very high packet rate"
        assert window.alert_table.columnCount() == 5
        assert window.alert_table.item(0, 3).text() == "Synthetic integration-test alert."
        assert window.alert_table.item(0, 4).text() == "New"

        # Another refresh with the same active condition must not duplicate it.
        window.refresh_dashboard()
        assert window.alert_table.rowCount() == 1

        # Clearing the visible history should remove the displayed alert.
        window.clear_alert_history()
        assert window.alert_table.rowCount() == 0
    finally:
        window.close()

def test_dashboard_filters_and_analytics_are_independent(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    monkeypatch.setenv("VONKA_SENTINEL_DB", str(tmp_path / "filter-test.db"))
    window = MainWindow()
    try:
        alerts = [
            SimpleNamespace(
                rule_id="RULE_INFO", severity="INFO",
                title="Informational event", reason="Synthetic info event",
                timestamp="2026-01-01T00:00:01+00:00",
                observed_value="10", threshold="100",
            ),
            SimpleNamespace(
                rule_id="RULE_WARNING", severity="WARNING",
                title="Warning traffic rise", reason="Synthetic warning event",
                timestamp="2026-01-01T00:00:02+00:00",
                observed_value="600", threshold="500",
            ),
            SimpleNamespace(
                rule_id="RULE_CRITICAL", severity="CRITICAL",
                title="Critical traffic spike", reason="Synthetic critical event",
                timestamp="2026-01-01T00:00:03+00:00",
                observed_value="2000", threshold="1500",
            ),
        ]
        for alert in alerts:
            window.incident_store.save_alert(alert, window.incident_key(alert))

        resolved_key = window.incident_key(alerts[0])
        window.incident_store.update_metadata(resolved_key, "Resolved", "test")
        window.incident_status[resolved_key] = "Resolved"
        window.alert_history = alerts

        window.refresh_alert_table()
        window.refresh_analytics()
        assert window.total_incidents_metric.text() == "3"
        assert window.critical_incidents_metric.text() == "1"
        assert window.unresolved_incidents_metric.text() == "2"
        assert window.resolved_incidents_metric.text() == "1"
        assert window.alert_table.rowCount() == 3

        window.severity_filter.setCurrentText("CRITICAL")
        assert window.alert_table.rowCount() == 1
        assert window.filtered_alerts[0].title == "Critical traffic spike"
        assert window.alert_table.item(0, 0).background().color().isValid()
        assert window.total_incidents_metric.text() == "3"

        window.severity_filter.setCurrentText("All severities")
        window.status_filter.setCurrentText("Resolved")
        assert window.alert_table.rowCount() == 1
        assert window.filtered_alerts[0].title == "Informational event"

        window.clear_incident_filters()
        assert window.alert_table.rowCount() == 3
        window.incident_search.setText("warning")
        assert window.alert_table.rowCount() == 1
        assert window.filtered_alerts[0].title == "Warning traffic rise"
    finally:
        window.close()
