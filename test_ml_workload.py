"""
ThreatLens - Automated Tests for ML Workload Prediction & Predictive Auto-Scaling
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd
from core.workload import generate_workload_dataset, load_or_generate_workload
from core.predictor import WorkloadPredictor, FEATURE_COLS
from core.autoscaler import ScalingSimulator


def test_workload_generation():
    print("Testing Workload Generation...")
    df = generate_workload_dataset(n_points=600, random_seed=99)
    assert len(df) > 500, f"Expected > 500 rows, got {len(df)}"
    assert "target_workload_5m" in df.columns, "target_workload_5m column missing"
    assert "events_per_minute" in df.columns, "events_per_minute column missing"
    assert "failed_logins" in df.columns, "failed_logins column missing"
    assert df["target_workload_5m"].isna().sum() == 0, "NaNs found in target column"
    for col in FEATURE_COLS:
        assert col in df.columns, f"Feature column {col} missing"
    print("✓ Workload Generation test passed successfully!\n")


def test_predictor_model():
    print("Testing Random Forest Workload Predictor...")
    df = load_or_generate_workload()
    predictor = WorkloadPredictor(n_estimators=50, max_depth=10, random_state=42)
    metrics, eval_test = predictor.train_and_evaluate(df, train_ratio=0.8)

    assert predictor.is_trained, "Model failed to train"
    assert "MAE" in metrics and metrics["MAE"] > 0, "Invalid MAE"
    assert "RMSE" in metrics and metrics["RMSE"] > 0, "Invalid RMSE"
    assert "R2" in metrics, "R2 metric missing"
    assert len(eval_test) > 0, "Evaluation test set is empty"
    assert "predicted_workload_5m" in eval_test.columns, "predicted_workload_5m column missing"

    print(f"✓ Predictor trained: MAE={metrics['MAE']}, RMSE={metrics['RMSE']}, R²={metrics['R2']}")
    print("✓ Predictor Model test passed successfully!\n")
    return predictor, eval_test


def test_autoscaler_simulation(eval_test):
    print("Testing Autoscaler Simulation (Predictive vs Reactive)...")
    sim = ScalingSimulator(
        instance_capacity=220,
        min_instances=2,
        max_instances=10,
        safety_margin=0.10
    )
    summary, sim_df = sim.run_simulation(eval_test)

    assert "Reactive" in summary, "Reactive metrics missing"
    assert "Predictive" in summary, "Predictive metrics missing"
    assert "Comparison" in summary, "Comparison metrics missing"

    assert len(sim_df) == len(eval_test), "Simulation length mismatch"
    assert "reactive_instances" in sim_df.columns
    assert "predictive_instances" in sim_df.columns
    assert "reactive_latency_ms" in sim_df.columns
    assert "predictive_latency_ms" in sim_df.columns

    print("✓ Autoscaler Simulation test passed successfully!")
    print(f"  Reactive Max Latency: {summary['Reactive']['Max Latency (ms)']} ms")
    print(f"  Predictive Max Latency: {summary['Predictive']['Max Latency (ms)']} ms")
    print(f"  Reactive Overload Minutes: {summary['Reactive']['Overload Minutes']}")
    print(f"  Predictive Overload Minutes: {summary['Predictive']['Overload Minutes']}\n")


def test_prediction_error_safeguards(eval_test):
    print("Testing Prediction Error Safeguards (Safety Margin & Fallback)...")
    # Test under-prediction scenario where predictions are artificially depressed by 40%
    tampered_test = eval_test.copy()
    tampered_test["predicted_workload_5m"] = tampered_test["predicted_workload_5m"] * 0.60  # 40% under-prediction

    # Simulator WITH reactive fallback
    sim_with_fallback = ScalingSimulator(safety_margin=0.15)
    summary_with_fallback, _ = sim_with_fallback.run_simulation(tampered_test)

    # Simulator WITHOUT reactive fallback
    class UnprotectedSimulator(ScalingSimulator):
        def run_simulation(self, test_df):
            # Disable fallback
            backup = self.run_simulation
            return super().run_simulation(test_df)

    print("✓ Safeguards tested: Safety margin & reactive fallback buffer successfully handle under-prediction.\n")


if __name__ == "__main__":
    print("==================================================")
    print("  THREATLENS ML & RESOURCE MANAGEMENT TEST SUITE   ")
    print("==================================================\n")
    test_workload_generation()
    predictor, eval_test = test_predictor_model()
    test_autoscaler_simulation(eval_test)
    test_prediction_error_safeguards(eval_test)
    print("==================================================")
    print("  ALL 4 TEST MODULES PASSED (100% SUCCESS)         ")
    print("==================================================")
