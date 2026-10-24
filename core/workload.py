"""
ThreatLens - Cloud Security Workload Generator
Generates realistic, timestamped security event traffic for SIEM monitoring
and ML-based predictive resource autoscaling.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DATASET_PATH = DATA_DIR / "workload_dataset.csv"


def generate_workload_dataset(
    n_points=2880,  # 2 days of minute-by-minute data (48 hours = 2880 mins)
    start_time=None,
    random_seed=42,
    save_path=DEFAULT_DATASET_PATH
):
    """
    Generate realistic SIEM security-event workload time-series data with:
    - Baseline diurnal business cycle (higher in day, lower at night)
    - Random failed login noise
    - Injected brute-force attack storms and sudden surges
    - System metrics (CPU%, Memory%)
    - Time-series lag features (no data leakage)
    - 5-minute-ahead prediction target (target_workload_5m)
    """
    np.random.seed(random_seed)

    if start_time is None:
        start_time = datetime.now() - timedelta(minutes=n_points)

    timestamps = [start_time + timedelta(minutes=i) for i in range(n_points)]

    # 1. Base Diurnal Cycle (events/minute: 100 baseline up to 450 during peak hours)
    minute_of_day = np.array([ts.hour * 60 + ts.minute for ts in timestamps])
    # Peak at 14:00 (minute 840)
    diurnal = 180 + 120 * np.sin(2 * np.pi * (minute_of_day - 360) / 1440)
    noise = np.random.normal(0, 15, n_points)
    base_events = np.maximum(50, diurnal + noise)

    # 2. Injected Attack Surges (Brute-Force Bursts, DDoS Log Floods)
    attack_events = np.zeros(n_points)
    failed_logins = np.zeros(n_points)
    brute_force_alerts = np.zeros(n_points)

    # Base failure rate is ~5-8% under normal conditions
    failed_logins = np.random.binomial(base_events.astype(int), 0.06).astype(float)

    # Inject discrete attack incidents (every 60-180 minutes)
    attack_indices = [
        120, 280, 490, 720, 950, 1140, 1400, 1680, 1920, 2200, 2450, 2700
    ]

    for idx in attack_indices:
        if idx < n_points - 30:
            duration = np.random.randint(12, 35)  # Attack lasts 12-35 minutes
            surge_intensity = np.random.randint(300, 850)  # Extra 300-850 events/min
            
            # Attack profile: rapid ramp up, sustained peak, decay
            profile = np.concatenate([
                np.linspace(50, surge_intensity, 4),
                np.full(max(1, duration - 8), surge_intensity),
                np.linspace(surge_intensity, 30, 4)
            ])
            actual_len = min(len(profile), n_points - idx)
            attack_events[idx:idx + actual_len] += profile[:actual_len]
            
            # During attacks, failed login ratio surges to 65-90%
            failed_surge = (profile[:actual_len] * np.random.uniform(0.70, 0.90)).astype(int)
            failed_logins[idx:idx + actual_len] += failed_surge
            
            # High severity alerts generated
            brute_force_alerts[idx:idx + actual_len] = (failed_surge > 40).astype(int) * np.random.randint(1, 4, actual_len)

    total_events = np.round(base_events + attack_events).astype(int)
    failed_logins = np.minimum(failed_logins, total_events).astype(int)

    # Unique IPs tracking
    unique_ips = np.round(np.maximum(5, (total_events * 0.18) + np.random.normal(0, 4, n_points))).astype(int)

    # 3. Server Resource Utilization Simulation (Per standard container instance capacity)
    # Modeling baseline resource usage + CPU load proportional to event ingestion rate
    # Single container baseline threshold: 250 events/min = ~70% CPU
    base_cpu = 15.0  # Idle OS overhead
    dynamic_cpu = (total_events / 350.0) * 65.0
    cpu_noise = np.random.normal(0, 2.5, n_points)
    cpu_util = np.clip(base_cpu + dynamic_cpu + cpu_noise, 8.0, 99.5)

    # Memory utilization: base + heap retention with slow leak and garbage collection
    mem_util = np.zeros(n_points)
    current_mem = 30.0
    for i in range(n_points):
        # Memory rises with load, clears when low
        target_mem = 25.0 + (total_events[i] / 400.0) * 45.0
        current_mem = current_mem * 0.92 + target_mem * 0.08 + np.random.normal(0, 0.5)
        mem_util[i] = np.clip(current_mem, 20.0, 94.0)

    # Construct DataFrame
    df = pd.DataFrame({
        "timestamp": timestamps,
        "events_per_minute": total_events,
        "failed_logins": failed_logins,
        "unique_ips": unique_ips,
        "brute_force_alerts": brute_force_alerts.astype(int),
        "cpu_utilization": np.round(cpu_util, 2),
        "memory_utilization": np.round(mem_util, 2)
    })

    # Temporal Calendar Features
    df["hour_of_day"] = df["timestamp"].dt.hour
    df["minute_of_hour"] = df["timestamp"].dt.minute
    df["day_of_week"] = df["timestamp"].dt.day_of_week

    # 4. Feature Engineering (Strictly Historical Lags - No Future Data Leakage)
    df["workload_lag_1"] = df["events_per_minute"].shift(1)
    df["workload_lag_2"] = df["events_per_minute"].shift(2)
    df["workload_lag_3"] = df["events_per_minute"].shift(3)
    df["workload_lag_5"] = df["events_per_minute"].shift(5)
    df["workload_lag_10"] = df["events_per_minute"].shift(10)
    df["workload_rolling_mean_5"] = df["events_per_minute"].shift(1).rolling(5).mean()
    df["workload_rolling_max_5"] = df["events_per_minute"].shift(1).rolling(5).max()
    df["workload_rolling_std_5"] = df["events_per_minute"].shift(1).rolling(5).std()

    df["failed_logins_lag_1"] = df["failed_logins"].shift(1)
    df["failed_logins_rolling_5"] = df["failed_logins"].shift(1).rolling(5).mean()
    df["cpu_lag_1"] = df["cpu_utilization"].shift(1)
    df["memory_lag_1"] = df["memory_utilization"].shift(1)

    # 5. Prediction Target: EXACTLY 5 MINUTES AHEAD (target_workload_5m)
    # Target value at row t is the events_per_minute at row t + 5
    df["target_workload_5m"] = df["events_per_minute"].shift(-5)

    # Drop NaNs created by lagging (first 10 rows) and future shift (last 5 rows)
    clean_df = df.dropna().reset_index(drop=True)

    if save_path:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        clean_df.to_csv(save_path, index=False)

    return clean_df


def load_or_generate_workload(force_regenerate=False, n_points=2880):
    """Load workload dataset from disk if exists, otherwise generate a new one."""
    if not force_regenerate and DEFAULT_DATASET_PATH.exists():
        try:
            df = pd.read_csv(DEFAULT_DATASET_PATH)
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            return df
        except Exception:
            pass
    return generate_workload_dataset(n_points=n_points)


if __name__ == "__main__":
    data = generate_workload_dataset()
    print(f"Generated {len(data)} workload records.")
    print("Columns:", list(data.columns))
    print(data[["timestamp", "events_per_minute", "failed_logins", "cpu_utilization", "target_workload_5m"]].head())
