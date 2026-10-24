"""
ThreatLens - Cloud Resource Auto-Scaler Simulation
Compares Predictive Auto-Scaling (ML 5-min ahead) against Reactive Auto-Scaling
for Cloud Security Event Monitoring workloads.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd


class ScalingSimulator:
    """
    Simulates Cloud Container Cluster (e.g. AWS ECS/EKS worker cluster)
    handling SIEM log ingestion and analysis.
    """

    def __init__(
        self,
        instance_capacity=220,      # Events/min handled by 1 container instance at ~75% target CPU
        min_instances=2,           # Minimum baseline high-availability instances
        max_instances=10,          # Maximum cluster scaling ceiling
        provisioning_delay_mins=1, # Warmup / spinup delay for a new container instance
        scale_in_cooldown=3,       # Minutes to wait before terminating an instance (anti-flapping)
        safety_margin=0.10,        # 10% predictive safety buffer for ML uncertainty
        reactive_high_thresh=0.80, # Reactive scale out when CPU > 80%
        reactive_low_thresh=0.35,  # Reactive scale in when CPU < 35%
        cost_per_hour_instance=0.0464, # AWS t3.medium / standard 2vCPU SIEM container instance ($/hr)
        p_idle_watts=15.0,         # Idle server power draw per instance (Watts)
        p_max_watts=55.0           # Peak load power draw per instance (Watts)
    ):
        self.instance_capacity = instance_capacity
        self.min_instances = min_instances
        self.max_instances = max_instances
        self.provisioning_delay_mins = provisioning_delay_mins
        self.scale_in_cooldown = scale_in_cooldown
        self.safety_margin = safety_margin
        self.reactive_high_thresh = reactive_high_thresh
        self.reactive_low_thresh = reactive_low_thresh
        self.cost_per_minute = cost_per_hour_instance / 60.0
        self.p_idle_watts = p_idle_watts
        self.p_max_watts = p_max_watts

    def run_simulation(self, test_df: pd.DataFrame):
        """
        Runs both Predictive and Reactive scaling across the sequential workload stream.
        test_df must contain:
          - 'events_per_minute' (actual current demand)
          - 'target_workload_5m' (actual future demand 5m ahead)
          - 'predicted_workload_5m' (ML predicted demand 5m ahead)
        """
        df = test_df.copy().reset_index(drop=True)
        n = len(df)

        # -------------------------------------------------------------
        # 1. REACTIVE SCALING SIMULATION
        # -------------------------------------------------------------
        # Reactive scaling only observes CURRENT workload at time t.
        # If load exceeds high threshold, requests +1 or +2 instances.
        # Due to 1-minute container startup delay, new instances arrive at t+1.
        
        reactive_instances = np.zeros(n, dtype=int)
        reactive_actions = 0
        reactive_scale_in_cooldown_counter = 0

        # Start at min_instances
        curr_instances = self.min_instances
        pending_instance_delta = 0

        for t in range(n):
            # Apply any instances that finished spinning up from t-1
            curr_instances = int(np.clip(curr_instances + pending_instance_delta, self.min_instances, self.max_instances))
            pending_instance_delta = 0
            reactive_instances[t] = curr_instances

            current_workload = df.loc[t, "events_per_minute"]
            cluster_capacity = curr_instances * self.instance_capacity
            current_util = current_workload / max(1.0, cluster_capacity)

            # Decision for next minute
            if current_util > self.reactive_high_thresh:
                # Urgent scale out needed
                needed_inst = int(np.ceil(current_workload / (self.instance_capacity * 0.70)))
                delta = needed_inst - curr_instances
                if delta > 0 and curr_instances < self.max_instances:
                    pending_instance_delta = min(delta, self.max_instances - curr_instances)
                    reactive_actions += 1
                reactive_scale_in_cooldown_counter = self.scale_in_cooldown
            elif current_util < self.reactive_low_thresh:
                if reactive_scale_in_cooldown_counter <= 0:
                    if curr_instances > self.min_instances:
                        pending_instance_delta = -1
                        reactive_actions += 1
                        reactive_scale_in_cooldown_counter = self.scale_in_cooldown
                else:
                    reactive_scale_in_cooldown_counter -= 1
            else:
                if reactive_scale_in_cooldown_counter > 0:
                    reactive_scale_in_cooldown_counter -= 1

        # -------------------------------------------------------------
        # 2. PREDICTIVE SCALING SIMULATION
        # -------------------------------------------------------------
        # Predictive scaling uses predicted_workload_5m to schedule scaling
        # well in advance of the provisioning delay.
        # Includes a safety margin (e.g. +10%) and a reactive fallback safeguard.

        predictive_instances = np.zeros(n, dtype=int)
        predictive_actions = 0
        pred_scale_in_cooldown_counter = 0

        curr_pred_instances = self.min_instances

        for t in range(n):
            current_workload = df.loc[t, "events_per_minute"]
            pred_future_workload = df.loc[t, "predicted_workload_5m"]

            # Calculate desired capacity based on predicted 5m future load + safety margin
            target_workload = pred_future_workload * (1.0 + self.safety_margin)
            desired_instances = int(np.ceil(target_workload / (self.instance_capacity * 0.75)))
            desired_instances = int(np.clip(desired_instances, self.min_instances, self.max_instances))

            # SAFEGUARD / REACTIVE FALLBACK:
            # If current load suddenly exceeds current capacity (e.g. unpredictable instant surge),
            # immediately trigger reactive fallback scaling!
            curr_cluster_cap = curr_pred_instances * self.instance_capacity
            if (current_workload / max(1.0, curr_cluster_cap)) > 0.90:
                fallback_instances = int(np.ceil(current_workload / (self.instance_capacity * 0.75)))
                desired_instances = max(desired_instances, fallback_instances)
                desired_instances = min(desired_instances, self.max_instances)

            # Apply scale-in cooldown to prevent premature scale-down
            if desired_instances > curr_pred_instances:
                # Scale out proactively (predictive model gives plenty of lead time for warmup)
                curr_pred_instances = desired_instances
                predictive_actions += 1
                pred_scale_in_cooldown_counter = self.scale_in_cooldown
            elif desired_instances < curr_pred_instances:
                if pred_scale_in_cooldown_counter <= 0:
                    curr_pred_instances = max(self.min_instances, curr_pred_instances - 1)
                    predictive_actions += 1
                    pred_scale_in_cooldown_counter = self.scale_in_cooldown
                else:
                    pred_scale_in_cooldown_counter -= 1
            else:
                if pred_scale_in_cooldown_counter > 0:
                    pred_scale_in_cooldown_counter -= 1

            predictive_instances[t] = curr_pred_instances

        # -------------------------------------------------------------
        # 3. PERFORMANCE & EVALUATION METRIC COMPUTATION
        # -------------------------------------------------------------
        # Assign series to dataframe
        df["reactive_instances"] = reactive_instances
        df["predictive_instances"] = predictive_instances

        df["reactive_capacity"] = df["reactive_instances"] * self.instance_capacity
        df["predictive_capacity"] = df["predictive_instances"] * self.instance_capacity

        df["reactive_utilization"] = np.round(
            (df["events_per_minute"] / df["reactive_capacity"]) * 100.0, 1
        )
        df["predictive_utilization"] = np.round(
            (df["events_per_minute"] / df["predictive_capacity"]) * 100.0, 1
        )

        # Overload conditions (when actual incoming events exceed total cluster capacity)
        df["reactive_overload"] = df["events_per_minute"] > df["reactive_capacity"]
        df["predictive_overload"] = df["events_per_minute"] > df["predictive_capacity"]

        # Latency Simulation Model:
        # Base ingestion latency is 14ms when cluster load is healthy (<80%).
        # When cluster is overloaded (>100%), processing queue backs up exponentially:
        # latency = base + queue_factor * (events - capacity)^1.3
        def compute_latency(events, capacity):
            util = events / capacity
            base_latency = 14.0 + np.maximum(0, util - 0.5) * 8.0
            overload = np.maximum(0.0, events - capacity)
            queue_delay = (overload ** 1.35) * 0.45
            return np.round(base_latency + queue_delay, 1)

        df["reactive_latency_ms"] = [
            compute_latency(e, c) for e, c in zip(df["events_per_minute"], df["reactive_capacity"])
        ]
        df["predictive_latency_ms"] = [
            compute_latency(e, c) for e, c in zip(df["events_per_minute"], df["predictive_capacity"])
        ]

        # Power & Energy Model: P(u) = P_idle + (P_max - P_idle) * (u/100) per instance
        def compute_energy_kwh(instances, util_pct):
            u_clamped = np.clip(util_pct / 100.0, 0.0, 1.0)
            instance_watts = self.p_idle_watts + (self.p_max_watts - self.p_idle_watts) * u_clamped
            total_watts = instances * instance_watts
            # 1 minute duration in kWh: watts * (1/60 hours) / 1000
            return total_watts * (1.0 / 60.0) / 1000.0

        df["reactive_energy_kwh"] = [
            compute_energy_kwh(i, u) for i, u in zip(df["reactive_instances"], df["reactive_utilization"])
        ]
        df["predictive_energy_kwh"] = [
            compute_energy_kwh(i, u) for i, u in zip(df["predictive_instances"], df["predictive_utilization"])
        ]

        # Cost: $/minute per active instance
        df["reactive_cost_usd"] = df["reactive_instances"] * self.cost_per_minute
        df["predictive_cost_usd"] = df["predictive_instances"] * self.cost_per_minute

        # Aggregate Summary Metrics
        summary = {
            "Reactive": {
                "Avg Instances": round(float(df["reactive_instances"].mean()), 2),
                "Avg Utilization (%)": round(float(df["reactive_utilization"].mean()), 1),
                "Max Latency (ms)": round(float(df["reactive_latency_ms"].max()), 1),
                "Avg Latency (ms)": round(float(df["reactive_latency_ms"].mean()), 1),
                "Overload Minutes": int(df["reactive_overload"].sum()),
                "Overload Rate (%)": round(float((df["reactive_overload"].sum() / n) * 100.0), 2),
                "Total Scaling Actions": reactive_actions,
                "Total Cost ($)": round(float(df["reactive_cost_usd"].sum()), 4),
                "Total Energy (kWh)": round(float(df["reactive_energy_kwh"].sum()), 4)
            },
            "Predictive": {
                "Avg Instances": round(float(df["predictive_instances"].mean()), 2),
                "Avg Utilization (%)": round(float(df["predictive_utilization"].mean()), 1),
                "Max Latency (ms)": round(float(df["predictive_latency_ms"].max()), 1),
                "Avg Latency (ms)": round(float(df["predictive_latency_ms"].mean()), 1),
                "Overload Minutes": int(df["predictive_overload"].sum()),
                "Overload Rate (%)": round(float((df["predictive_overload"].sum() / n) * 100.0), 2),
                "Total Scaling Actions": predictive_actions,
                "Total Cost ($)": round(float(df["predictive_cost_usd"].sum()), 4),
                "Total Energy (kWh)": round(float(df["predictive_energy_kwh"].sum()), 4)
            }
        }

        # Calculate deltas & improvements
        react = summary["Reactive"]
        pred = summary["Predictive"]
        latency_reduction_pct = round(
            ((react["Avg Latency (ms)"] - pred["Avg Latency (ms)"]) / react["Avg Latency (ms)"]) * 100.0, 1
        ) if react["Avg Latency (ms)"] > 0 else 0.0

        overload_reduction_pct = round(
            ((react["Overload Minutes"] - pred["Overload Minutes"]) / max(1, react["Overload Minutes"])) * 100.0, 1
        )

        cost_delta_pct = round(
            ((pred["Total Cost ($)"] - react["Total Cost ($)"]) / react["Total Cost ($)"]) * 100.0, 1
        )

        summary["Comparison"] = {
            "Latency Reduction (%)": latency_reduction_pct,
            "Overload Reduction (%)": overload_reduction_pct,
            "Cost Difference (%)": cost_delta_pct,
            "Duration (Minutes)": n
        }

        return summary, df


if __name__ == "__main__":
    from core.workload import load_or_generate_workload
    from core.predictor import WorkloadPredictor

    data = load_or_generate_workload()
    predictor = WorkloadPredictor()
    metrics, eval_test = predictor.train_and_evaluate(data)

    sim = ScalingSimulator()
    summary, sim_df = sim.run_simulation(eval_test)

    print("\n===== SCALING STRATEGY COMPARISON =====")
    print(pd.DataFrame(summary).to_string())
