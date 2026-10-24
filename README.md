# ThreatLens: ML-Based Predictive Resource Management for Cloud Security Event Monitoring

A Python-based Cloud Security Information and Event Management (SIEM) application combining threat monitoring, brute-force attack detection, and **Machine Learning-driven Predictive Auto-Scaling** to dynamically provision cloud container resources 5 minutes ahead of security event surges.

---

## 📌 Project Overview

**ThreatLens** bridges the gap between **Cybersecurity Event Monitoring (SIEM)** and **Cloud Resource Management (CRM)**.

Cybersecurity events (such as brute-force authentication storms and credential stuffing attacks) generate sudden, severe bursts in log ingestion rates. Traditional **reactive cloud auto-scaling** only reacts after CPU usage crosses high thresholds, resulting in a 1–3 minute container spin-up lag during which log processing queues back up and latency spikes.

ThreatLens integrates a **Scikit-learn Random Forest Regressor** that forecasts security-event arrival rates **5 minutes ahead**, allowing cloud worker instances to be spun up proactively before the surge arrives.

---

## 🎯 Core Objectives

1. **Centralize SIEM Security Operations:** Monitor security events, failed authentication attempts, and automated high-severity alerts.
2. **Predict Cloud Workload 5 Minutes Ahead:** Use historical time-series features (failed logins, CPU%, lag indicators) without data leakage to forecast event volume.
3. **Proactive Cloud Auto-Scaling:** Auto-scale cloud container worker instances preemptively to absorb attack waves without latency spikes.
4. **Comparative Evaluation:** Evaluate predictive scaling against reactive scaling on identical workloads using real metrics (MAE, RMSE, $R^2$, latency, cost, and energy).
5. **Prediction Error Safeguards:** Implement a +10% safety margin buffer and reactive fallback mechanisms against under-prediction.

---

## ✨ Features

### 1. Predictive Resource Management & ML (New)
- **Workload Predictor:** 5-minute-ahead forecasting using Random Forest Regressor ($R^2 \approx 0.658$, $\text{MAE} = 33.2$ events/min).
- **Auto-Scaling Engine:** Proactive vs Reactive cluster scaling simulation.
- **Latency & Queue Modeling:** Demonstrates a **57.4% reduction in peak latency** during cyberattack surges.
- **Cost & Energy Optimization:** 6.0% cloud cost savings with carbon-aware energy tracking.
- **Interactive Surge Simulator:** Test instant 500% attack bursts in real time.

### 2. Security Dashboard

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