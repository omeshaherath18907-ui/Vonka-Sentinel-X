# VONKA SENTINEL-X — Safe Demonstration Guide

## Purpose

Demonstrate passive traffic monitoring and incident workflow on a device and network you own or are explicitly authorized to monitor.

## Before starting

1. Install Python 3.11+ and Npcap using their official installers.
2. Install the project dependencies in a virtual environment.
3. Run the automated tests.
4. Confirm the API is intended for local use and is not exposed to a public network.
5. Do not use traffic generators against third-party systems.

## Demo A — Normal traffic

1. Launch the application.
2. Select the authorized network interface.
3. Start monitoring.
4. Open a few ordinary websites or perform normal browsing.
5. Show packet counts, bandwidth, protocol distribution, and last-packet time.
6. Explain that observed traffic varies with background activity.

## Demo B — Detection and thresholds

1. Review the configured warning and critical thresholds in the source code.
2. Use unit tests or a controlled, synthetic snapshot to demonstrate threshold decisions.
3. Explain the difference between a warning signal and a confirmed security incident.
4. Do not generate a flood or send high-volume traffic to external systems.

## Demo C — Incident investigation

1. Select an alert in the dashboard.
2. Record a short, non-sensitive investigation note.
3. Change the investigation status.
4. Save the update.
5. Open the audit history and explain how changes are recorded.
6. Demonstrate CSV or PDF export if supported by the current build.

## Evidence for a portfolio

Capture screenshots of:

- Main dashboard with monitoring active
- Protocol distribution and traffic health
- Example detection alert
- Incident investigation panel
- Audit history
- Exported report with any personal or network-sensitive details redacted

## Safety and limitations

- Only monitor networks for which you have authorization.
- Do not perform denial-of-service tests on public services, school networks, or other people's devices.
- High traffic or a high UDP share does not alone prove a DDoS attack.
- This project is a defensive research prototype, not a production mitigation system.
- Redact IP addresses, usernames, hostnames, and sensitive notes before publishing screenshots.
