import os
import csv
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

from PySide6.QtCore import QTimer, Qt, QPointF
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



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("VONKA SENTINEL-X | Network Monitor")
        self.resize(1180, 950)
        self.collector = None
        self.detector = RollingWindowDetector(window_seconds=10.0, minimum_interval=1.0)
        self.alert_history = []
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

        root = QWidget()
        self.setCentralWidget(root)
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
            "Wi-Fi — Intel(R) Wi-Fi 6E AX211 160MHz",
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

        layout.addWidget(QLabel("Live traffic analytics — last 60 seconds"))
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

        alerts_header = QHBoxLayout()
        alerts_header.addWidget(QLabel("Detection alerts"))
        alerts_header.addStretch()

        self.clear_alerts_button = QPushButton("Clear alert history")
        self.clear_alerts_button.clicked.connect(self.clear_alert_history)
        alerts_header.addWidget(self.clear_alerts_button)
        layout.addLayout(alerts_header)

        self.alert_table = QTableWidget(0, 4)
        self.alert_table.setHorizontalHeaderLabels(
            ["Severity", "Time (UTC)", "Detection", "Reason"]
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
        incident_buttons.addWidget(self.save_incident_button)
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

        self.last_packet_label.setText(
            f"Last packet: {result['last_packet_at'] or 'none'}"
        )

        if result["last_error"]:
            self.error_label.setText(result["last_error"])

        if result["capture_running"]:
            self.capture_status.setText("Capture status: RUNNING")

    def refresh_alert_table(self):
        alerts = list(reversed(self.alert_history))
        self.alert_table.setRowCount(len(alerts))

        for row, alert in enumerate(alerts):
            values = (
                alert.severity,
                alert.timestamp.replace("T", " ")[:19],
                alert.title,
                alert.reason,
            )
            for column, value in enumerate(values):
                self.alert_table.setItem(
                    row, column, QTableWidgetItem(str(value))
                )
            key = self.incident_key(alert)
            status_item = QTableWidgetItem(self.incident_status.get(key, "New"))
            self.alert_table.setItem(row, 0, status_item)
            self.alert_table.setItem(row, 0, QTableWidgetItem(alert.severity))
            self.alert_table.setItem(row, 3, QTableWidgetItem(f"{alert.reason} | Status: {self.incident_status.get(key, 'New')}"))

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
        alerts = list(reversed(self.alert_history))
        if row < 0 or row >= len(alerts):
            self.incident_selected_label.setText("Select an alert above")
            self.incident_notes_edit.clear()
            return
        alert = alerts[row]
        key = self.incident_key(alert)
        self.incident_selected_label.setText(f"{alert.severity} — {alert.title}")
        self.incident_status_combo.setCurrentText(self.incident_status.get(key, "New"))
        self.incident_notes_edit.setText(self.incident_notes.get(key, ""))

    def save_selected_incident(self):
        row = self.alert_table.currentRow()
        alerts = list(reversed(self.alert_history))
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
