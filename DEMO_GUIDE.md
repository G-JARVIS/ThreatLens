# ThreatLens — Demonstration & Video Screencast Guide

**Project:** ThreatLens: ML-Based Predictive Resource Management for Cloud Security Event Monitoring  
**Target Submission:** College Continuous Assessment (CA)

---

## 1. Quick Start Commands

### For Windows PowerShell
Open Windows PowerShell inside the project directory:

```powershell
# 1. Navigate to project root
cd C:\Path\To\ThreatLens

# 2. Create Python virtual environment (if not already created)
python -m venv .venv

# 3. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the automated test suite
python test_ml_workload.py

# 6. Launch the ThreatLens Streamlit Application
streamlit run app.py
```
> The dashboard will open automatically in your browser at `http://localhost:8501`.

---

### For macOS / Linux (Terminal)

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Run automated test suite
python test_ml_workload.py

# 3. Launch application
streamlit run app.py
```

---

## 2. 3-Minute Video Screencast Script (Presentation Flow)

Use this step-by-step walkthrough for recording your screencast or demonstrating to the faculty.

---

### Minute 0:00 – 0:45 | Introduction & Problem Statement
* **Screen Display:** Open `http://localhost:8501` on the **Dashboard** page.
* **Script / What to Say:**
  > "Good day, professors. Today I am presenting **ThreatLens: ML-Based Predictive Resource Management for Cloud Security Event Monitoring**."
  > "In cloud-hosted SIEM environments, security events like brute-force login attacks create sudden, intense workload surges. Traditional **reactive auto-scaling** only responds *after* CPU usage crosses 80%. But because cloud containers require 1 to 3 minutes to spin up, reactive systems suffer from severe queue delays and high latency, giving attackers time to operate undetected."
  > "To solve this, we implemented a Machine Learning-based Predictive Resource Manager that forecasts security event workloads **5 minutes ahead**, proactively spinning up cloud instances before the attack wave hits."

---

### Minute 0:45 – 1:30 | Core SIEM Demonstration
* **Screen Display:** Click on **Attack Simulator** in the sidebar.
* **Script / What to Say:**
  > "ThreatLens is built on top of a functional SIEM foundation. In the Attack Simulator, I enter an IP address `203.0.113.50` and target username `admin`, then generate 5 failed login attempts."
  > "The rule-based detection engine immediately flags a **HIGH-severity Brute-Force Alert**. In **Incident Management**, security analysts can track and resolve this incident. All of these authentication events flow into our cloud workload ingestion pipeline."

---

### Minute 1:30 – 2:30 | ML Prediction & Auto-Scaling Comparison
* **Screen Display:** Click on **Resource Management** in the sidebar.
* **Script / What to Say:**
  > "Now, navigating to our **Resource Management** page:"
  > "1. Under the **Workload Prediction** tab, our Scikit-Learn **Random Forest Regressor** predicts event demand 5 minutes into the future ($t+5$). Notice our feature importances: `failed_logins` is the number-one leading indicator (over 36% importance), proving how cybersecurity signals directly inform cloud resource allocation."
  > "2. Under the **Predictive vs Reactive Auto-Scaling** tab, we compare both strategies on the identical 573-minute workload stream. Look at the latency graph: reactive scaling experiences massive latency spikes up to **166.8 ms** because instances arrive late. In contrast, ThreatLens predictive scaling proactively provisions containers, capping peak latency at **71.0 ms** — a **57.4% reduction in peak latency**."
  > "3. We also achieve an overall **6.0% cloud cost reduction** and lower energy consumption because the model scales down promptly once an attack subsides."

---

### Minute 2:30 – 3:00 | Prediction Error Safeguards & Conclusion
* **Screen Display:** Click on **Prediction Errors & Safeguards** tab and click **"Inject Sudden Attack Surge Now"**.
* **Script / What to Say:**
  > "Finally, we addressed what happens when predictions are incorrect. If the model under-predicts an attack wave, our system employs two layers of defense:"
  > "First, a **+10% safety margin buffer**."
  > "Second, an automatic **reactive fallback trigger** that immediately spins up emergency instances if cluster CPU exceeds 90%."
  > "When I click 'Inject Sudden Attack Surge Now', you can see the simulated difference in real time: reactive scaling is overwhelmed and suffers queue backlog, while predictive scaling absorbs the wave seamlessly with zero latency spike."
  > "Thank you, that concludes our demonstration."

---

## 3. Faculty Viva Questions & Answers (FAQ)

### Q1: Why did you choose Random Forest instead of deep learning (e.g., LSTM)?
**Answer:** Random Forest Regressor provides high interpretability, excels with tabular time-series features (lags, rolling stats), and trains in seconds without requiring GPU infrastructure. Its feature importance output confirmed that `failed_logins` is the primary leading feature for security event surges.

### Q2: Why is the prediction horizon exactly 5 minutes?
**Answer:** Cloud container provisioning (e.g., AWS ECS/Fargate task startup, Docker container spin-up, and ALB health check registration) typically takes between 45 and 90 seconds. A 5-minute horizon gives ample lead time (3+ minutes of buffer) for instances to be warm and ready before the peak traffic arrives.

### Q3: How did you avoid future-data leakage in your dataset?
**Answer:** We used a strictly **time-ordered sequential train/test split** (first 80% train, last 20% test) with no shuffling. All features are strictly backward-looking historical lags ($t-1, t-2, t-5$) and rolling averages. Only the target variable is shifted to represent $t+5$.

### Q4: What happens if the ML model completely under-predicts?
**Answer:** ThreatLens includes a dual safeguard:
1. **Safety Margin:** Predictions are automatically scaled by +10% to provide an operational head-room buffer.
2. **Reactive Fallback:** If live cluster utilization breaches 90%, the system overrides the ML prediction and triggers an immediate reactive emergency scale-out.
