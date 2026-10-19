ThreatLens – Security Information and Event Management System

A Python-based Security Information and Event Management (SIEM) application that monitors security events, detects brute-force login attempts, generates security alerts, and provides an interactive security operations dashboard.

📌 Project Overview

ThreatLens is a lightweight security monitoring application designed to demonstrate the core functionality of a Security Information and Event Management system.

It records login activities, monitors failed authentication attempts, identifies potential brute-force attacks, generates security alerts, and allows administrators to manage detected incidents.

The application uses SQLite for storing security events and alerts, Streamlit for the dashboard, and Docker for containerized deployment.

🎯 Objectives

Centralize security event logging and monitoring.

Detect repeated failed login attempts from suspicious IP addresses.

Generate automated security alerts.

Provide a dashboard for monitoring security activities.

Maintain and manage security incidents.

Demonstrate containerized deployment using Docker.

✨ Features

1. Security Dashboard

Total security events.

Failed login statistics.

Total security alerts.

Open incident count.

Unique IP address tracking.

Login activity and event timeline analytics.

2. Log Monitoring

View recorded security events.

Monitor successful and failed login attempts.

Inspect usernames, IP addresses, timestamps, and event details.

Filter and export security logs.

3. Brute-Force Attack Detection

Simulate repeated failed login attempts.

Detect five or more failed attempts within a configurable time window.

Generate HIGH-severity security alerts.

Avoid duplicate alerts for the same IP within the detection window.

4. Incident Management

View detected security incidents.

Track incident severity and descriptions.

Update incident status:

Open

Investigating

Resolved

5. Docker Deployment

Build a Docker image.

Run the application inside a container.

Access the application through a browser.

Persist SQLite database files using a mounted host directory.

🛠️ Technologies Used

Technology

Purpose

Python

Application development

Streamlit

Interactive web dashboard

SQLite

Security event and alert storage

Pandas

Data processing

Plotly

Security analytics and charts

Docker

Containerization

Git & GitHub

Version control
🔍 Demonstration

The project supports controlled security event simulation.

Example: Brute-Force Attack Simulation

Open the Attack Simulator module.

Enter a username and an IP address.

Generate five failed login attempts.

The detection engine checks the failed login count.

A HIGH-severity alert is generated when the configured threshold is reached.

Open Incident Management to review and update the incident status.

All simulated events are generated locally. The simulator does not attack real accounts or external systems.

🔐 Security Scope

ThreatLens is an educational prototype intended for controlled security monitoring demonstrations.

Its current detection capability focuses on repeated failed login attempts and rule-based brute-force detection. It is not a production SIEM replacement and does not currently provide comprehensive network traffic monitoring or detection of every attack category.

🚀 Future Enhancements

Machine-learning-based anomaly detection.

Additional detection rules for suspicious authentication patterns.

Email notifications for critical alerts.

User authentication and role-based access control.

Integration with real system log sources.

Cloud-based deployment.

Advanced incident investigation and reporting.

👨‍💻 Project Information

Project: ThreatLens – Security Information and Event Management System

Category: Cybersecurity / Security Monitoring

Development: Python and Docker

Purpose: Academic project and practical demonstration of security event monitoring and threat detection.

📄 License

No open-source license has been assigned to this repository yet.