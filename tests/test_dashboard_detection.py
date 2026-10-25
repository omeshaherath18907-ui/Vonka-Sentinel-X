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

        # Another refresh with the same active condition must not duplicate it.
        window.refresh_dashboard()
        assert window.alert_table.rowCount() == 1

        # Clearing the visible history should remove the displayed alert.
        window.clear_alert_history()
        assert window.alert_table.rowCount() == 0
    finally:
        window.close()
