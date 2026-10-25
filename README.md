# VONKA SENTINEL-X

**A defensive network traffic monitoring and DDoS detection research platform.**

VONKA SENTINEL-X is a Windows desktop cybersecurity project designed to monitor network traffic, identify potentially suspicious traffic patterns, and support incident investigation through a graphical dashboard.

## Features

- **Live traffic monitoring:** Capture packet metadata and display traffic statistics through Scapy.
- **Traffic analytics:** Monitor packet rates, bandwidth, and protocol distributions.
- **Rule-based detection:** Evaluate configurable thresholds for packet rates, bandwidth, and UDP traffic share.
- **Rolling-window analysis:** Analyze changes in cumulative traffic counters over time.
- **Desktop dashboard:** View live metrics, charts, and detection alerts.
- **Incident investigation:** Review alerts and record investigation status and notes.
- **SQLite persistence:** Store incident records locally across application restarts.
- **CSV reporting:** Export stored incidents for further analysis.
- **Automated tests:** Test API functionality, traffic collection, detection rules, rolling analysis, and incident storage.

## Technology stack

- Python 3.11+
- PySide6
- Scapy
- FastAPI and Uvicorn
- SQLite
- pytest

## Requirements

- Windows 11
- Python 3.11 or newer
- Git (optional, for source control)
- Npcap installed and configured for packet capture on Windows
- Appropriate permissions to capture traffic on the selected interface

## Installation

Open PowerShell in the project directory.

Create a virtual environment:

```powershell
py -3.11 -m venv .venv
```

Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the application

```powershell
.\.venv\Scripts\python.exe -m app.main
```

The local API health endpoint is available at:

`http://127.0.0.1:8765/health`

The API is intended for local use. Do not expose it to an untrusted network without appropriate security controls.

## Run tests

Run the full test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest .\tests -q
```

The project has previously passed 24 automated tests. Run the command above to verify the current checkout.

## Detection approach

The detection engine evaluates traffic statistics against configured rules, including packet-rate thresholds, bandwidth thresholds, and a high UDP traffic share.

These rules identify potentially suspicious patterns. They do not independently establish that an event is a confirmed DDoS attack. Legitimate traffic spikes can trigger alerts, and attacks may evade fixed thresholds.

Detection thresholds should be evaluated against representative baseline traffic and documented test scenarios.

## Data and privacy

- Packet collection is intended for authorized monitoring.
- The incident database is stored locally at `data/sentinel.db` by default.
- Incident history and investigation notes may contain sensitive operational information.
- Local databases, logs, environment files, and private keys should not be committed to a public repository.
- The database location can be overridden using the `VONKA_SENTINEL_DB` environment variable.

## Safety and responsible use

Use VONKA SENTINEL-X only on networks and devices you own or are explicitly authorized to monitor.

This project is a research and defensive monitoring tool, not a production-grade DDoS mitigation service. Automated firewall changes, attack generation, and production mitigation should not be assumed to be implemented.

Any future load-testing feature should use explicitly authorized targets, bounded traffic levels, duration limits, and clear stop controls.

## Current limitations

- Rule-based detection may produce false positives and false negatives.
- Results depend on the selected network interface, packet visibility, permissions, and system configuration.
- A single local capture point cannot observe all traffic across an entire network.
- The current test suite does not by itself establish real-world DDoS detection accuracy.
- Production deployment requires additional security, reliability, and performance evaluation.

## Roadmap

- Improve detection evaluation using documented, controlled test scenarios.
- Measure false-positive rates, detection latency, and resource usage.
- Improve dashboard usability and incident reporting.
- Add reproducible evaluation reports and sample datasets.
- Investigate safe, explicitly authorized lab testing.

## Project purpose

VONKA SENTINEL-X is developed as a cybersecurity learning and portfolio project focused on defensive network monitoring, traffic analysis, detection engineering, and incident investigation.

## License

No license has been selected yet. Unless a license is added, reuse and redistribution are not automatically granted.
