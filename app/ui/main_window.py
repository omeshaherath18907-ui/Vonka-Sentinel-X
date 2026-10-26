import os
import csv
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

from PySide6.QtCore import QTimer, Qt, QPointF, QRectF
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QAbstractItemView,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QScrollArea,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.traffic_collector import TrafficCollector
from app.services.rolling_detector import RollingWindowDetector
from app.services.incident_store import IncidentStore
from types import SimpleNamespace


class TrafficChart(QWidget):
    """Lightweight rolling traffic chart painted with Qt."""

    def __init__(self, title, unit, parent=None):
        super().__init__(parent)
        self.title = title
        self.unit = unit
        self.values = []
        self.setMinimumHeight(180)
        self.setMinimumWidth(260)

    def set_data(self, values):
        self.values = [
            max(0.0, float(value))
            for value in values
        ]
        self.update()

    def _format_axis(self, value):
        if self.unit == "B/s":
            if value >= 1024 * 1024:
                return f"{value / (1024 * 1024):.1f} MB/s"
            if value >= 1024:
                return f"{value / 1024:.1f} KB/s"
            return f"{value:.0f} B/s"
        return f"{value:.0f} pps"

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#141d2b"))

        painter.setPen(QPen(QColor("#2d3b50"), 1))
        painter.drawRoundedRect(
            self.rect().adjusted(1, 1, -2, -2), 8, 8
        )

        painter.setPen(QColor("#e6edf7"))
        painter.drawText(14, 22, self.title)

        left, top, right, bottom = 76, 36, 14, 30
        plot_width = self.width() - left - right
        plot_height = self.height() - top - bottom

        if plot_width <= 10 or plot_height <= 10:
            painter.end()
            return

        highest = max(self.values, default=0.0)
        scale = max(highest * 1.15, 1.0)

        for index in range(5):
            y = top + index * plot_height / 4
            value = scale * (4 - index) / 4

            painter.setPen(QPen(QColor("#2d3b50"), 1))
            painter.drawLine(
                int(left), int(y),
                int(left + plot_width), int(y)
            )

            painter.setPen(QColor("#9aabc2"))
            painter.drawText(
                5, int(y + 4), self._format_axis(value)
            )

        if self.values:
            points = []
            denominator = max(len(self.values) - 1, 1)

            for index, value in enumerate(self.values):
                x = left + index * plot_width / denominator
                y = top + plot_height - (value / scale) * plot_height
                points.append(QPointF(x, y))

            painter.setPen(QPen(QColor("#64d8ff"), 2))

            for first, second in zip(points, points[1:]):
                painter.drawLine(first, second)

            painter.setBrush(QColor("#64d8ff"))
            if len(points) == 1:
                painter.drawEllipse(points[0], 3, 3)
            else:
                painter.drawEllipse(points[-1], 3, 3)

        painter.setPen(QColor("#9aabc2"))
        painter.drawText(int(left), self.height() - 8, "60s ago")
        painter.drawText(
            self.width() - 38, self.height() - 8, "now"
        )
        painter.end()



class DonutChart(QWidget):
    """Compact donut chart rendered using QPainter."""

    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.title = title
        self.entries = []
        self.setMinimumSize(245, 220)

    def set_data(self, entries):
        self.entries = [
            (str(label), max(0, int(value)), QColor(color))
            for label, value, color in entries
        ]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#141d2b"))
        painter.setPen(QPen(QColor("#2d3b50"), 1))
        painter.setBrush(QColor("#141d2b"))
        painter.drawRoundedRect(
            self.rect().adjusted(1, 1, -2, -2), 9, 9
        )
        painter.setPen(QColor("#e6edf7"))
        painter.drawText(12, 23, self.title)

        total = sum(value for _, value, _ in self.entries)
        side = min(105, max(70, self.height() - 95))
        rect = QRectF(14, 40, side, side)

        if total:
            start = 90 * 16
            for _, value, color in self.entries:
                if value <= 0:
                    continue
                span = round(value / total * 360 * 16)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(color)
                painter.drawPie(rect, start, -span)
                start -= span

            hole = rect.adjusted(
                side * 0.29, side * 0.29,
                -side * 0.29, -side * 0.29
            )
            painter.setBrush(QColor("#141d2b"))
            painter.drawEllipse(hole)
            painter.setPen(QColor("#e6edf7"))
            painter.drawText(
                hole, Qt.AlignmentFlag.AlignCenter, str(total)
            )
        else:
            painter.setPen(QPen(QColor("#40516a"), 7))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(rect.adjusted(7, 7, -7, -7))
            painter.setPen(QColor("#9aabc2"))
            painter.drawText(
                rect, Qt.AlignmentFlag.AlignCenter, "0"
            )

        lx = int(rect.right() + 12)
        ly = 53
        for label, value, color in self.entries:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(
                QRectF(lx, ly - 8, 8, 8), 2, 2
            )
            painter.setPen(QColor("#d7e1ef"))
            painter.drawText(lx + 12, ly, f"{label}: {value}")
            ly += 24

        painter.end()


class IncidentTrendChart(QWidget):
    """Seven-day incident trend chart rendered using QPainter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.labels = []
        self.values = []
        self.setMinimumHeight(220)
        self.setMinimumWidth(300)

    def set_data(self, labels, values):
        self.labels = list(labels)
        self.values = [max(0, int(v)) for v in values]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#141d2b"))
        painter.setPen(QPen(QColor("#2d3b50"), 1))
        painter.drawRoundedRect(
            self.rect().adjusted(1, 1, -2, -2), 9, 9
        )
        painter.setPen(QColor("#e6edf7"))
        painter.drawText(14, 23, "INCIDENT TREND - LAST 7 DAYS")

        left, right, top, bottom = 38, 16, 42, 36
        width = self.width() - left - right
        height = self.height() - top - bottom
        if width <= 10 or height <= 10:
            painter.end()
            return

        highest = max(self.values, default=0)
        scale = max(1, highest)
        for i in range(4):
            y = top + height * i / 3
            painter.setPen(QPen(QColor("#2d3b50"), 1))
            painter.drawLine(
                int(left), int(y), int(left + width), int(y)
            )
            painter.setPen(QColor("#9aabc2"))
            painter.drawText(
                7, int(y + 4), str(round(scale * (3 - i) / 3))
            )

        count = max(1, len(self.values))
        slot = width / count
        bar_width = min(28, slot * 0.58)

        for i, value in enumerate(self.values):
            bar_height = value / scale * height
            x = left + i * slot + (slot - bar_width) / 2
            y = top + height - bar_height
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#64d8ff"))
            painter.drawRoundedRect(
                QRectF(x, y, bar_width, max(2, bar_height)), 3, 3
            )
            painter.setPen(QColor("#d7e1ef"))
            painter.drawText(
                QRectF(x - 5, max(top, y - 18), bar_width + 10, 16),
                Qt.AlignmentFlag.AlignCenter, str(value)
            )
            label = self.labels[i] if i < len(self.labels) else ""
            painter.setPen(QColor("#9aabc2"))
            painter.drawText(
                QRectF(left + i * slot, top + height + 5, slot, 22),
                Qt.AlignmentFlag.AlignCenter, label
            )

        painter.end()



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("VONKA SENTINEL-X | Network Monitor")
        self.resize(1180, 950)
        self.collector = None
        self.detector = RollingWindowDetector(window_seconds=10.0, minimum_interval=1.0)
        self.alert_history = []
        self.filtered_alerts = []
        self.active_alert_keys = set()
        self.max_alert_history = 100
        self.incident_status = {}
        self.incident_notes = {}
        self.incident_file = Path("data/incidents.json")
        self.incident_file.parent.mkdir(parents=True, exist_ok=True)
        database_path = os.environ.get("VONKA_SENTINEL_DB", "data/sentinel.db")
        self.incident_store = IncidentStore(database_path)
        self.load_incidents()
        self.load_persisted_alerts()
        self.pps_history = deque(maxlen=60)
        self.bps_history = deque(maxlen=60)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #10151f;
                color: #e6edf7;
                font-family: Segoe UI;
                font-size: 13px;
            }
            QLabel#heading {
                font-size: 25px;
                font-weight: bold;
                color: #64d8ff;
            }
            QLabel#metric {
                font-size: 25px;
                font-weight: bold;
                color: #64d8ff;
            }
            QLabel#card {
                background-color: #1a2332;
                border: 1px solid #2d3b50;
                border-radius: 10px;
                padding: 15px;
            }
            QPushButton {
                background-color: #176b87;
                border: none;
                border-radius: 6px;
                padding: 10px 18px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #2185a5; }
            QPushButton:disabled { background-color: #303b4b; color: #8d9aab; }
            QComboBox, QTableWidget {
                background-color: #1a2332;
                border: 1px solid #34445b;
                padding: 6px;
                gridline-color: #34445b;
            }
            QHeaderView::section {
                background-color: #263449;
                padding: 7px;
                border: none;
            }
        """)

        # Scrollable dashboard: keeps lower analytics and incident controls accessible.
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        root = QWidget()
        scroll_area.setWidget(root)
        self.setCentralWidget(scroll_area)

        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("VONKA SENTINEL-X")
        title.setObjectName("heading")
        header.addWidget(title)
        header.addStretch()

        self.api_status = QLabel("Local API: checking...")
        header.addWidget(self.api_status)
        layout.addLayout(header)

        subtitle = QLabel(
            "DEFENSIVE NETWORK MONITOR  |  Passive metadata collection"
        )
        subtitle.setStyleSheet("color: #9aabc2;")
        layout.addWidget(subtitle)

        selection = QHBoxLayout()
        selection.addWidget(QLabel("Capture interface:"))

        self.interface_combo = QComboBox()
        self.interface_combo.addItem(
            "Wi-Fi â€” Intel(R) Wi-Fi 6E AX211 160MHz",
            "Intel(R) Wi-Fi 6E AX211 160MHz",
        )
        selection.addWidget(self.interface_combo, 1)

        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        selection.addWidget(self.start_button)
        selection.addWidget(self.stop_button)
        layout.addLayout(selection)

        self.capture_status = QLabel("Capture status: STOPPED")
        self.capture_status.setStyleSheet("color: #ffcc66; font-weight: bold;")
        layout.addWidget(self.capture_status)

        self.traffic_health_label = QLabel("Traffic health: WAITING FOR DATA")
        self.traffic_health_label.setStyleSheet(
            "font-size: 15px; font-weight: bold; color: #9aabc2;"
        )
        layout.addWidget(self.traffic_health_label)

        self.capture_summary_label = QLabel(
            "Capture summary: waiting for monitoring data"
        )
        self.capture_summary_label.setWordWrap(True)
        self.capture_summary_label.setStyleSheet("color: #9aabc2;")
        layout.addWidget(self.capture_summary_label)

        cards = QGridLayout()
        cards.setSpacing(12)
        self.packet_metric = self.make_metric_card(
            cards, 0, "Packets captured", "0"
        )
        self.byte_metric = self.make_metric_card(
            cards, 1, "Bytes captured", "0 B"
        )
        self.pps_metric = self.make_metric_card(
            cards, 2, "Packets per second", "0"
        )
        self.bps_metric = self.make_metric_card(
            cards, 3, "Bytes per second", "0 B/s"
        )
        layout.addLayout(cards)

        layout.addWidget(QLabel("Live traffic analytics â€” last 60 seconds"))
        chart_row = QHBoxLayout()
        self.pps_chart = TrafficChart("Packet rate", "pps")
        self.bandwidth_chart = TrafficChart("Bandwidth", "B/s")
        chart_row.addWidget(self.pps_chart, 1)
        chart_row.addWidget(self.bandwidth_chart, 1)
        layout.addLayout(chart_row)

        layout.addWidget(QLabel("Protocol distribution"))
        self.protocol_table = QTableWidget(0, 2)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Packets"])
        self.protocol_table.horizontalHeader().setStretchLastSection(True)
        self.protocol_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.protocol_table.setMaximumHeight(220)
        layout.addWidget(self.protocol_table)

        self.protocol_chart = DonutChart("LIVE PROTOCOL DISTRIBUTION")
        self.protocol_chart.setMinimumHeight(220)
        layout.addWidget(self.protocol_chart)

        analytics_title = QLabel("INCIDENT ANALYTICS")
        analytics_title.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #64d8ff;"
        )
        layout.addWidget(analytics_title)

        analytics_grid = QGridLayout()
        analytics_grid.setSpacing(10)
        self.total_incidents_metric = self.make_metric_card(
            analytics_grid, 0, "Total incidents", "0"
        )
        self.critical_incidents_metric = self.make_metric_card(
            analytics_grid, 1, "Critical incidents", "0"
        )
        self.unresolved_incidents_metric = self.make_metric_card(
            analytics_grid, 2, "Unresolved incidents", "0"
        )
        self.resolved_incidents_metric = self.make_metric_card(
            analytics_grid, 3, "Resolved incidents", "0"
        )
        layout.addLayout(analytics_grid)

        time_grid = QGridLayout()
        time_grid.setSpacing(10)
        self.last_24h_metric = self.make_metric_card(
            time_grid, 0, "Incidents - last 24 hours", "0"
        )
        self.last_7d_metric = self.make_metric_card(
            time_grid, 1, "Incidents - last 7 days", "0"
        )
        self.daily_average_metric = self.make_metric_card(
            time_grid, 2, "7-day daily average", "0"
        )
        layout.addLayout(time_grid)

        charts_row = QHBoxLayout()
        self.severity_chart = DonutChart("SEVERITY DISTRIBUTION")
        self.status_chart = DonutChart("INVESTIGATION STATUS")
        charts_row.addWidget(self.severity_chart, 1)
        charts_row.addWidget(self.status_chart, 1)
        layout.addLayout(charts_row)

        self.trend_chart = IncidentTrendChart()
        layout.addWidget(self.trend_chart)

        self.severity_summary_label = QLabel("Severity distribution")
        self.severity_summary_label.setWordWrap(True)
        self.severity_summary_label.setStyleSheet("color: #9aabc2;")
        layout.addWidget(self.severity_summary_label)

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Severity"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(
            ["All severities", "CRITICAL", "WARNING", "INFO", "OTHER"]
        )
        filters.addWidget(self.severity_filter)

        filters.addWidget(QLabel("Status"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(
            ["All statuses", "New", "Investigating", "Resolved"]
        )
        filters.addWidget(self.status_filter)

        self.incident_search = QLineEdit()
        self.incident_search.setPlaceholderText(
            "Search detection, rule ID, or reason..."
        )
        filters.addWidget(self.incident_search, 1)

        self.clear_filters_button = QPushButton("Clear filters")
        self.clear_filters_button.clicked.connect(self.clear_incident_filters)
        filters.addWidget(self.clear_filters_button)

        self.severity_filter.currentTextChanged.connect(
            lambda _value: self.refresh_alert_table()
        )
        self.status_filter.currentTextChanged.connect(
            lambda _value: self.refresh_alert_table()
        )
        self.incident_search.textChanged.connect(
            lambda _value: self.refresh_alert_table()
        )
        layout.addLayout(filters)

        alerts_header = QHBoxLayout()
        alerts_header.addWidget(QLabel("Detection alerts"))
        alerts_header.addStretch()

        self.clear_alerts_button = QPushButton("Clear alert history")
        self.clear_alerts_button.clicked.connect(self.clear_alert_history)
        alerts_header.addWidget(self.clear_alerts_button)
        layout.addLayout(alerts_header)

        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(
            ["Severity", "Time (UTC)", "Detection", "Reason", "Status"]
        )
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        self.alert_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.alert_table.setWordWrap(True)
        self.alert_table.setMaximumHeight(210)
        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alert_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.alert_table.itemSelectionChanged.connect(self.load_selected_incident)
        layout.addWidget(self.alert_table)

        incident_title = QLabel("Incident investigation")
        incident_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #64d8ff;")
        layout.addWidget(incident_title)
        incident_form = QFormLayout()
        self.incident_selected_label = QLabel("Select an alert above")
        incident_form.addRow("Selected alert:", self.incident_selected_label)
        self.incident_status_combo = QComboBox()
        self.incident_status_combo.addItems(["New", "Investigating", "Resolved"])
        incident_form.addRow("Status:", self.incident_status_combo)
        self.incident_notes_edit = QLineEdit()
        self.incident_notes_edit.setPlaceholderText("Investigation notes (avoid sensitive payloads)")
        incident_form.addRow("Notes:", self.incident_notes_edit)
        layout.addLayout(incident_form)
        incident_buttons = QHBoxLayout()
        self.save_incident_button = QPushButton("Save investigation")
        self.save_incident_button.clicked.connect(self.save_selected_incident)
        self.export_incidents_button = QPushButton("Export incidents to CSV")
        self.export_incidents_button.clicked.connect(self.export_incidents_csv)
        self.export_pdf_button = QPushButton("Export PDF Report")
        self.export_pdf_button.clicked.connect(self.export_incidents_pdf)
        incident_buttons.addWidget(self.save_incident_button)
        self.view_audit_button = QPushButton("View Audit History")
        self.view_audit_button.clicked.connect(self.view_selected_audit_history)
        incident_buttons.addWidget(self.view_audit_button)
        self.view_audit_button = QPushButton("View Audit History")
        self.view_audit_button.clicked.connect(self.view_selected_audit_history)
        incident_buttons.addWidget(self.view_audit_button)
        incident_buttons.addWidget(self.export_incidents_button)
        layout.addLayout(incident_buttons)

        self.last_packet_label = QLabel("Last packet: none")
        self.last_packet_label.setStyleSheet("color: #9aabc2;")
        layout.addWidget(self.last_packet_label)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #ff8c8c;")
        layout.addWidget(self.error_label)

        footer = QLabel(
            "Local monitoring only. Packet payloads are not retained by "
            "this collector. Capture only networks you are authorized to monitor."
        )
        footer.setWordWrap(True)
        footer.setStyleSheet("color: #9aabc2;")
        layout.addWidget(footer)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_dashboard)
        self.refresh_timer.start(1000)

        self.api_timer = QTimer(self)
        self.api_timer.timeout.connect(self.check_api)
        self.api_timer.start(5000)

        self.check_api()
        self.refresh_alert_table()
        self.refresh_analytics()

    def make_metric_card(self, grid, column, heading, value):
        card = QWidget()
        card.setObjectName("card")
        box = QVBoxLayout(card)

        name = QLabel(heading)
        name.setStyleSheet("color: #9aabc2;")

        metric = QLabel(value)
        metric.setObjectName("metric")

        box.addWidget(name)
        box.addWidget(metric)
        grid.addWidget(card, 0, column)
        return metric

    def check_api(self):
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8765/health", timeout=1.5
            ) as response:
                if response.status == 200:
                    self.api_status.setText("Local API: ONLINE")
                    self.api_status.setStyleSheet("color: #70e1a1;")
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

        self.api_status.setText("Local API: OFFLINE")
        self.api_status.setStyleSheet("color: #ff8c8c;")

    def start_monitoring(self):
        if self.collector is not None:
            if self.collector.snapshot()["capture_running"]:
                return

        interface = self.interface_combo.currentData()
        collector = TrafficCollector(interface=interface)

        self.error_label.setText("")
        self.capture_status.setText("Capture status: STARTING...")

        try:
            collector.start()
        except Exception as exc:
            self.capture_status.setText("Capture status: STOPPED")
            self.error_label.setText(
                f"Could not start capture: {exc}\n"
                "Check Npcap, interface selection, and Windows permissions. "
                "If needed, close the app and retry with approved elevated "
                "permissions; do not disable security protections."
            )
            QMessageBox.warning(
                self,
                "Capture could not start",
                "Live capture failed. See the dashboard for the error details.",
            )
            return

        self.collector = collector
        self.detector = RollingWindowDetector(window_seconds=10.0, minimum_interval=1.0)
        self.active_alert_keys.clear()
        self.pps_history.clear()
        self.bps_history.clear()
        self.pps_chart.set_data([])
        self.bandwidth_chart.set_data([])
        self.interface_combo.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.capture_status.setText("Capture status: RUNNING")

    def stop_monitoring(self):
        if self.collector is not None:
            try:
                self.collector.stop()
            except Exception as exc:
                self.error_label.setText(f"Capture stop error: {exc}")

        self.interface_combo.setEnabled(True)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.capture_status.setText("Capture status: STOPPED")
        self.refresh_dashboard()

    @staticmethod
    def format_bytes(value):
        value = float(value)
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024 or unit == "GB":
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} GB"

    def refresh_dashboard(self):
        if self.collector is None:
            return

        result = self.collector.snapshot()

        if result['capture_running']:
            self.pps_history.append(
                max(0.0, float(result['packets_per_second']))
            )
            self.bps_history.append(
                max(0.0, float(result['bytes_per_second']))
            )
            self.pps_chart.set_data(list(self.pps_history))
            self.bandwidth_chart.set_data(list(self.bps_history))

        # Keep one alert entry while each detection condition remains active.
        current_alert_keys = set()
        for alert in self.detector.observe(result):
            key = (alert.rule_id, alert.severity)
            current_alert_keys.add(key)

            if key not in self.active_alert_keys:
                self.alert_history.append(alert)
                try:
                    self.incident_store.save_alert(alert, self.incident_key(alert))
                except Exception as exc:
                    print(f"Could not persist alert: {exc}")
                if len(self.alert_history) > self.max_alert_history:
                    self.alert_history.pop(0)

        self.active_alert_keys = current_alert_keys
        self.refresh_alert_table()

        self.packet_metric.setText(
            f"{result['packets_total']:,}"
        )
        self.byte_metric.setText(
            self.format_bytes(result["bytes_total"])
        )
        self.pps_metric.setText(
            f"{result['packets_per_second']:,.2f}"
        )
        self.bps_metric.setText(
            self.format_bytes(result["bytes_per_second"]) + "/s"
        )

        protocols = result["protocols"]
        self.protocol_table.setRowCount(len(protocols))

        for row, (protocol, count) in enumerate(
            sorted(protocols.items(), key=lambda item: item[1], reverse=True)
        ):
            self.protocol_table.setItem(
                row, 0, QTableWidgetItem(protocol)
            )
            self.protocol_table.setItem(
                row, 1, QTableWidgetItem(f"{count:,}")
            )

        # Live protocol distribution, using the existing donut chart.
        palette = [
            "#64d8ff", "#a78bfa", "#34d399", "#fbbf24",
            "#fb7185", "#60a5fa", "#94a3b8",
        ]
        protocol_entries = [
            (protocol, count, palette[index % len(palette)])
            for index, (protocol, count) in enumerate(
                sorted(protocols.items(), key=lambda item: item[1], reverse=True)
            )
        ]
        self.protocol_chart.set_data(protocol_entries)

        # Health reflects configured default thresholds, not attack certainty.
        pps = max(0.0, float(result["packets_per_second"]))
        bps = max(0.0, float(result["bytes_per_second"]))
        protocol_total = sum(max(0, int(count)) for count in protocols.values())
        udp_count = max(0, int(protocols.get("UDP", 0)))
        udp_share = udp_count / protocol_total if protocol_total else 0.0

        if pps >= 1500 or bps >= 8_000_000:
            health, health_color = "HIGH", "#fb7185"
        elif (
            pps >= 500
            or bps >= 2_000_000
            or (pps >= 100 and udp_share >= 0.80)
        ):
            health, health_color = "ELEVATED", "#fbbf24"
        elif result["capture_running"]:
            health, health_color = "NORMAL", "#34d399"
        else:
            health, health_color = "WAITING / STOPPED", "#9aabc2"

        self.traffic_health_label.setText(
            f"Traffic health: {health}  |  Based on observed traffic rates"
        )
        self.traffic_health_label.setStyleSheet(
            f"font-size: 15px; font-weight: bold; color: {health_color};"
        )

        self.capture_summary_label.setText(
            f"Capture summary: {result['packets_total']:,} packets | "
            f"{self.format_bytes(result['bytes_total'])} total | "
            f"{protocol_total:,} protocol-classified packets in counters | "
            f"{len(protocols)} protocol types | "
            f"UDP share {udp_share:.1%}"
        )

        self.last_packet_label.setText(
            f"Last packet: {result['last_packet_at'] or 'none'}"
        )

        if result["last_error"]:
            self.error_label.setText(result["last_error"])

        if result["capture_running"]:
            self.capture_status.setText("Capture status: RUNNING")

    def refresh_alert_table(self):
        alerts = list(reversed(self.alert_history))
        severity_filter = self.severity_filter.currentText()
        status_filter = self.status_filter.currentText()
        search = self.incident_search.text().strip().casefold()
        visible = []

        for alert in alerts:
            key = self.incident_key(alert)
            severity = str(alert.severity).upper()
            status = self.incident_status.get(key, "New")

            if severity_filter == "OTHER":
                if severity in {"CRITICAL", "WARNING", "INFO"}:
                    continue
            elif severity_filter != "All severities" and severity != severity_filter:
                continue

            if status_filter != "All statuses" and status != status_filter:
                continue

            searchable = " ".join((
                str(getattr(alert, "rule_id", "")),
                str(alert.title),
                str(alert.reason),
            )).casefold()
            if search and search not in searchable:
                continue
            visible.append(alert)

        self.filtered_alerts = visible
        self.alert_table.setRowCount(len(visible))

        severity_colors = {
            "CRITICAL": ("#5b2028", "#ffb4bd"),
            "WARNING": ("#59431b", "#ffe0a0"),
            "INFO": ("#183b50", "#a8e4ff"),
        }
        status_colors = {
            "New": ("#303b4b", "#e6edf7"),
            "Investigating": ("#59431b", "#ffe0a0"),
            "Resolved": ("#174b37", "#a8f0c6"),
        }

        for row, alert in enumerate(visible):
            key = self.incident_key(alert)
            status = self.incident_status.get(key, "New")
            values = (
                alert.severity,
                alert.timestamp.replace("T", " ")[:19],
                alert.title,
                alert.reason,
                status,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    bg, fg = severity_colors.get(
                        str(alert.severity).upper(),
                        ("#303b4b", "#e6edf7"),
                    )
                    item.setBackground(QColor(bg))
                    item.setForeground(QColor(fg))
                elif column == 4:
                    bg, fg = status_colors.get(
                        status, ("#303b4b", "#e6edf7")
                    )
                    item.setBackground(QColor(bg))
                    item.setForeground(QColor(fg))
                self.alert_table.setItem(row, column, item)

    def clear_incident_filters(self):
        self.severity_filter.setCurrentIndex(0)
        self.status_filter.setCurrentIndex(0)
        self.incident_search.clear()
        self.refresh_alert_table()

    def refresh_analytics(self):
        from datetime import timedelta

        try:
            total = self.incident_store.count()
            records = self.incident_store.get_recent(total) if total else []
        except Exception as exc:
            self.error_label.setText(f"Analytics unavailable: {exc}")
            return

        now = datetime.now(timezone.utc)
        parsed = []

        for record in records:
            stamp = None
            try:
                stamp = datetime.fromisoformat(
                    str(record.get("timestamp", "")).replace("Z", "+00:00")
                )
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                stamp = stamp.astimezone(timezone.utc)
            except (ValueError, TypeError):
                pass
            parsed.append((record, stamp))

        critical = sum(
            str(r["severity"]).upper() == "CRITICAL" for r in records
        )
        resolved = sum(r["status"] == "Resolved" for r in records)

        self.total_incidents_metric.setText(f"{total:,}")
        self.critical_incidents_metric.setText(f"{critical:,}")
        self.unresolved_incidents_metric.setText(f"{total - resolved:,}")
        self.resolved_incidents_metric.setText(f"{resolved:,}")

        last_24h = sum(
            stamp is not None and now - timedelta(hours=24) <= stamp <= now
            for _, stamp in parsed
        )
        last_7d = sum(
            stamp is not None and now - timedelta(days=7) <= stamp <= now
            for _, stamp in parsed
        )
        self.last_24h_metric.setText(f"{last_24h:,}")
        self.last_7d_metric.setText(f"{last_7d:,}")
        self.daily_average_metric.setText(f"{last_7d / 7:.1f}")

        severity_counts = {}
        for record in records:
            sev = str(record["severity"]).upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        colors = {
            "CRITICAL": "#ff5c70",
            "WARNING": "#ffbd4a",
            "INFO": "#64d8ff",
        }
        entries = [
            (sev, severity_counts.get(sev, 0), color)
            for sev, color in colors.items()
        ]
        other = sum(
            n for sev, n in severity_counts.items() if sev not in colors
        )
        entries.append(("Other", other, "#b49bff"))
        self.severity_chart.set_data(entries)

        statuses = ("New", "Investigating", "Resolved")
        status_colors = {
            "New": "#64d8ff",
            "Investigating": "#ffbd4a",
            "Resolved": "#55d6a7",
        }
        self.status_chart.set_data([
            (
                status,
                sum(r["status"] == status for r in records),
                status_colors[status],
            )
            for status in statuses
        ])

        today = now.date()
        days = [
            today - timedelta(days=i) for i in range(6, -1, -1)
        ]
        daily = {day: 0 for day in days}
        for _, stamp in parsed:
            if stamp is not None and stamp.date() in daily:
                daily[stamp.date()] += 1

        self.trend_chart.set_data(
            [day.strftime("%d %b") for day in days],
            [daily[day] for day in days],
        )

        summary = [
            f"{sev}: {severity_counts.get(sev, 0)}"
            for sev in ("CRITICAL", "WARNING", "INFO")
        ]
        summary.extend(
            f"{sev}: {n}"
            for sev, n in sorted(severity_counts.items())
            if sev not in ("CRITICAL", "WARNING", "INFO")
        )
        self.severity_summary_label.setText(
            "Severity distribution | " + "  |  ".join(summary)
        )

    @staticmethod
    def incident_key(alert):
        return "|".join((alert.timestamp, alert.rule_id, alert.severity, alert.title))

    def load_incidents(self):
        try:
            data = json.loads(self.incident_file.read_text(encoding="utf-8"))
            self.incident_status = data.get("status", {})
            self.incident_notes = data.get("notes", {})
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError, AttributeError):
            self.incident_status = {}
            self.incident_notes = {}

    def load_persisted_alerts(self):
        """Restore recent alerts and investigation metadata from SQLite."""
        try:
            records = self.incident_store.get_recent(self.max_alert_history)
            self.alert_history = [
                SimpleNamespace(
                    timestamp=record["timestamp"],
                    rule_id=record["rule_id"],
                    severity=record["severity"],
                    title=record["title"],
                    reason=record["reason"],
                    observed_value=record["observed_value"],
                    threshold=record["threshold"],
                )
                for record in reversed(records)
            ]
            for record in records:
                key = record["incident_key"]
                self.incident_status[key] = record["status"]
                self.incident_notes[key] = record["notes"]
        except Exception as exc:
            print(f"Could not restore SQLite incident history: {exc}")

    def persist_incidents(self):
        for key in set(self.incident_status) | set(self.incident_notes):
            self.incident_store.update_metadata(
                key, self.incident_status.get(key, "New"),
                self.incident_notes.get(key, "")
            )
        payload = {"status": self.incident_status, "notes": self.incident_notes}
        temp_path = self.incident_file.with_suffix(".tmp")
        temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temp_path.replace(self.incident_file)

    def load_selected_incident(self):
        row = self.alert_table.currentRow()
        alerts = self.filtered_alerts
        if row < 0 or row >= len(alerts):
            self.incident_selected_label.setText("Select an alert above")
            self.incident_notes_edit.clear()
            return
        alert = alerts[row]
        key = self.incident_key(alert)
        self.incident_selected_label.setText(f"{alert.severity} â€” {alert.title}")
        self.incident_status_combo.setCurrentText(self.incident_status.get(key, "New"))
        self.incident_notes_edit.setText(self.incident_notes.get(key, ""))

    def view_selected_audit_history(self):
        from PySide6.QtWidgets import QDialog, QPlainTextEdit, QVBoxLayout

        row = self.alert_table.currentRow()
        alerts = self.filtered_alerts

        if row < 0 or row >= len(alerts):
            QMessageBox.information(
                self,
                "No incident selected",
                "Select an alert row first to view its audit history."
            )
            return

        alert = alerts[row]
        key = self.incident_key(alert)

        try:
            records = self.incident_store.get_audit_history(key, limit=200)
        except Exception as exc:
            QMessageBox.warning(
                self, "Audit history error",
                f"Could not load audit history: {exc}"
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("VONKA SENTINEL-X â€” Incident Audit History")
        dialog.resize(720, 420)

        dialog_layout = QVBoxLayout(dialog)
        history_view = QPlainTextEdit()
        history_view.setReadOnly(True)

        if not records:
            history_view.setPlainText("No audit events recorded for this incident.")
        else:
            lines = []
            for record in records:
                lines.append(
                    f"Time: {record['created_at']}\n"
                    f"Action: {record['action']}\n"
                    f"Status: {record['old_status'] or '-'}"
                    f" -> {record['new_status'] or '-'}\n"
                    f"Details: {record['details']}\n"
                    f"{'-' * 60}"
                )
            history_view.setPlainText("\n".join(lines))

        dialog_layout.addWidget(history_view)
        dialog.exec()
    def view_selected_audit_history(self):
        from PySide6.QtWidgets import QDialog, QPlainTextEdit, QVBoxLayout

        row = self.alert_table.currentRow()
        alerts = self.filtered_alerts

        if row < 0 or row >= len(alerts):
            QMessageBox.information(
                self,
                "No incident selected",
                "Select an alert row first to view its audit history."
            )
            return

        alert = alerts[row]
        key = self.incident_key(alert)

        try:
            records = self.incident_store.get_audit_history(key, limit=200)
        except Exception as exc:
            QMessageBox.warning(
                self, "Audit history error",
                f"Could not load audit history: {exc}"
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("VONKA SENTINEL-X â€” Incident Audit History")
        dialog.resize(720, 420)

        dialog_layout = QVBoxLayout(dialog)
        history_view = QPlainTextEdit()
        history_view.setReadOnly(True)

        if not records:
            history_view.setPlainText("No audit events recorded for this incident.")
        else:
            lines = []
            for record in records:
                lines.append(
                    f"Time: {record['created_at']}\n"
                    f"Action: {record['action']}\n"
                    f"Status: {record['old_status'] or '-'}"
                    f" -> {record['new_status'] or '-'}\n"
                    f"Details: {record['details']}\n"
                    f"{'-' * 60}"
                )
            history_view.setPlainText("\n".join(lines))

        dialog_layout.addWidget(history_view)
        dialog.exec()
    def save_selected_incident(self):
        row = self.alert_table.currentRow()
        alerts = self.filtered_alerts
        if row < 0 or row >= len(alerts):
            QMessageBox.information(self, "No incident selected", "Select an alert row first.")
            return
        alert = alerts[row]
        key = self.incident_key(alert)
        self.incident_status[key] = self.incident_status_combo.currentText()
        self.incident_notes[key] = self.incident_notes_edit.text().strip()
        try:
            self.persist_incidents()
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", f"Could not save incident: {exc}")
            return
        self.refresh_alert_table()
        self.refresh_analytics()
        QMessageBox.information(self, "Incident saved", "Investigation status and notes saved locally.")

    def export_incidents_csv(self):
        from PySide6.QtWidgets import QFileDialog

        default_name = f"vonka_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export incident report", default_name, "CSV files (*.csv)"
        )
        if not filename:
            return

        try:
            total = self.incident_store.count()
            records = self.incident_store.get_recent(total) if total else []
            with open(filename, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow([
                    "Timestamp (UTC)", "Rule ID", "Severity", "Detection",
                    "Reason", "Observed value", "Threshold", "Status",
                    "Investigation notes"
                ])
                for record in records:
                    writer.writerow([
                        record["timestamp"], record["rule_id"],
                        record["severity"], record["title"], record["reason"],
                        record["observed_value"], record["threshold"],
                        record["status"], record["notes"]
                    ])
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", f"Could not export CSV: {exc}")
            return

        QMessageBox.information(
            self, "Export complete", f"Incident report saved to:\\n{filename}"
        )

    def export_incidents_pdf(self):
        from html import escape
        from datetime import datetime
        from PySide6.QtWidgets import QFileDialog
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )

        default_name = (
            f"vonka_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export PDF incident report",
            default_name,
            "PDF files (*.pdf)"
        )
        if not filename:
            return
        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"

        try:
            total = self.incident_store.count()
            records = self.incident_store.get_recent(total) if total else []

            critical = sum(
                1 for record in records
                if str(record.get("severity", "")).upper() == "CRITICAL"
            )
            warnings = sum(
                1 for record in records
                if str(record.get("severity", "")).upper() == "WARNING"
            )
            unresolved = sum(
                1 for record in records
                if str(record.get("status", "New")).lower() != "resolved"
            )
            resolved = sum(
                1 for record in records
                if str(record.get("status", "New")).lower() == "resolved"
            )

            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(
                name="VonkaTitle",
                parent=styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=20,
                leading=24,
                textColor=colors.HexColor("#163A70"),
                alignment=TA_CENTER,
                spaceAfter=5 * mm,
            ))
            styles.add(ParagraphStyle(
                name="SmallCell",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=7,
                leading=9,
                wordWrap="CJK",
            ))
            styles.add(ParagraphStyle(
                name="SectionHeading",
                parent=styles["Heading2"],
                textColor=colors.HexColor("#163A70"),
                spaceBefore=4 * mm,
                spaceAfter=2 * mm,
            ))

            page_size = landscape(A4)
            doc = SimpleDocTemplate(
                filename,
                pagesize=page_size,
                rightMargin=12 * mm,
                leftMargin=12 * mm,
                topMargin=17 * mm,
                bottomMargin=15 * mm,
                title="VONKA SENTINEL-X Incident Report",
                author="VONKA SENTINEL-X",
            )

            story = [
                Paragraph("VONKA SENTINEL-X", styles["VonkaTitle"]),
                Paragraph(
                    "DEFENSIVE NETWORK MONITOR ? INCIDENT REPORT",
                    styles["Heading2"],
                ),
                Paragraph(
                    "Generated: " + escape(datetime.now().astimezone().isoformat(
                        timespec="seconds"
                    )),
                    styles["Normal"],
                ),
                Spacer(1, 4 * mm),
                Paragraph("Incident Summary", styles["SectionHeading"]),
            ]

            summary_data = [
                ["Total incidents", "Critical", "Warnings", "Unresolved", "Resolved"],
                [str(total), str(critical), str(warnings),
                 str(unresolved), str(resolved)],
            ]
            summary_table = Table(
                summary_data,
                colWidths=[doc.width / 5] * 5,
            )
            summary_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163A70")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCD5E0")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]))
            story.extend([summary_table, Spacer(1, 5 * mm)])
            story.append(Paragraph("Incident Details", styles["SectionHeading"]))

            headers = [
                "Timestamp (UTC)", "Severity", "Rule ID", "Detection",
                "Reason", "Observed", "Threshold", "Status", "Investigation Notes"
            ]
            table_data = [[
                Paragraph(f"<b>{escape(header)}</b>", styles["SmallCell"])
                for header in headers
            ]]

            def cell(value):
                if value is None or str(value) == "":
                    value = "?"
                return Paragraph(escape(str(value)), styles["SmallCell"])

            for record in records:
                table_data.append([
                    cell(record.get("timestamp")),
                    cell(record.get("severity")),
                    cell(record.get("rule_id")),
                    cell(record.get("title")),
                    cell(record.get("reason")),
                    cell(record.get("observed_value")),
                    cell(record.get("threshold")),
                    cell(record.get("status", "New")),
                    cell(record.get("notes")),
                ])

            if not records:
                story.append(Paragraph(
                    "No incidents have been recorded yet.",
                    styles["Normal"]
                ))
            else:
                widths = [
                    27 * mm, 15 * mm, 27 * mm, 28 * mm, 43 * mm,
                    18 * mm, 18 * mm, 20 * mm, 35 * mm
                ]
                incident_table = Table(
                    table_data,
                    colWidths=widths,
                    repeatRows=1,
                    hAlign="LEFT",
                )
                incident_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163A70")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CCD5E0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white, colors.HexColor("#F1F5FA")
                    ]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(incident_table)

            def draw_page(canvas, document):
                canvas.saveState()
                canvas.setFont("Helvetica", 8)
                canvas.setFillColor(colors.HexColor("#667085"))
                canvas.drawString(
                    12 * mm, 8 * mm,
                    "VONKA SENTINEL-X | Confidential local incident report"
                )
                canvas.drawRightString(
                    page_size[0] - 12 * mm, 8 * mm,
                    f"Page {document.page}"
                )
                canvas.restoreState()

            doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)

        except Exception as exc:
            QMessageBox.warning(
                self, "PDF export failed",
                f"Could not create the PDF report:\n{exc}"
            )
            return

        QMessageBox.information(
            self, "PDF export complete",
            f"Incident report saved to:\n{filename}"
        )

    def clear_alert_history(self):
        self.alert_history.clear()
        self.refresh_alert_table()

    def closeEvent(self, event):
        self.refresh_timer.stop()
        self.api_timer.stop()

        if self.collector is not None:
            try:
                self.collector.stop()
            except Exception:
                pass

        event.accept()
