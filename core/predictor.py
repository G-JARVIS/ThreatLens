"""
ThreatLens - Workload Predictor
Machine Learning model for 5-minute-ahead security event workload prediction
using Scikit-learn Random Forest Regressor.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

DATA_DIR = BASE_DIR / "data"
MODEL_PATH = DATA_DIR / "workload_rf_model.joblib"

# Feature set strictly derived from historical / current state (No target leakage)
FEATURE_COLS = [
    "events_per_minute",
    "failed_logins",
    "unique_ips",
    "brute_force_alerts",
    "cpu_utilization",
    "memory_utilization",
    "hour_of_day",
    "minute_of_hour",
    "day_of_week",
    "workload_lag_1",
    "workload_lag_2",
    "workload_lag_3",
    "workload_lag_5",
    "workload_lag_10",
    "workload_rolling_mean_5",
    "workload_rolling_max_5",
    "workload_rolling_std_5",
    "failed_logins_lag_1",
    "failed_logins_rolling_5",
    "cpu_lag_1",
    "memory_lag_1"
]

TARGET_COL = "target_workload_5m"


class WorkloadPredictor:
    def __init__(self, n_estimators=100, max_depth=12, random_state=42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model = RandomForestRegressor(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_trained = False
        self.metrics = {}
        self.feature_importances_ = None
        self.test_df = None

    def train_and_evaluate(self, df: pd.DataFrame, train_ratio=0.80):
        """
        Time-ordered train/test split (strictly sequential to avoid data leakage)
        and model evaluation.
        """
        # Ensure data is sorted by time
        df = df.sort_values("timestamp").reset_index(drop=True)

        X = df[FEATURE_COLS]
        y = df[TARGET_COL]

        # Time-ordered split
        split_idx = int(len(df) * train_ratio)
        X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
        y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

        # Train Random Forest Regressor
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # Predictions on Test set
        y_pred = self.model.predict(X_test)

        # Real calculated metrics (honest, no invented numbers)
        mae = float(mean_absolute_error(y_test, y_pred))
        rmse = float(np.sqrt(mean_squared_error(y_test, y_pred)))
        r2 = float(r2_score(y_test, y_pred))

        self.metrics = {
            "MAE": round(mae, 2),
            "RMSE": round(rmse, 2),
            "R2": round(r2, 4),
            "Train_Samples": len(X_train),
            "Test_Samples": len(X_test),
            "Horizon": "5 Minutes Ahead"
        }

        # Feature importances
        self.feature_importances_ = pd.DataFrame({
            "Feature": FEATURE_COLS,
            "Importance": self.model.feature_importances_
        }).sort_values(by="Importance", ascending=False).reset_index(drop=True)

        # Build evaluated test dataframe with predictions
        eval_test = df.iloc[split_idx:].copy()
        eval_test["predicted_workload_5m"] = np.round(y_pred, 1)
        eval_test["prediction_error"] = eval_test["target_workload_5m"] - eval_test["predicted_workload_5m"]
        eval_test["abs_percentage_error"] = (
            np.abs(eval_test["prediction_error"]) / np.maximum(1.0, eval_test["target_workload_5m"])
        ) * 100.0

        self.test_df = eval_test

        return self.metrics, eval_test

    def predict(self, feature_df: pd.DataFrame):
        """Predict 5-minute-ahead workload for given feature rows."""
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        X = feature_df[FEATURE_COLS]
        return self.model.predict(X)

    def save(self, filepath=MODEL_PATH):
        """Save model and metadata to disk."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "model": self.model,
            "metrics": self.metrics,
            "feature_importances": self.feature_importances_,
            "feature_cols": FEATURE_COLS
        }
        joblib.dump(payload, filepath)

    @classmethod
    def load(cls, filepath=MODEL_PATH):
        """Load model and metadata from disk."""
        if not filepath.exists():
            return None
        payload = joblib.load(filepath)
        instance = cls()
        instance.model = payload["model"]
        instance.metrics = payload.get("metrics", {})
        instance.feature_importances_ = payload.get("feature_importances")
        instance.is_trained = True
        return instance


if __name__ == "__main__":
    from core.workload import load_or_generate_workload

    data = load_or_generate_workload()
    predictor = WorkloadPredictor()
    metrics, eval_test = predictor.train_and_evaluate(data)

    print("\n===== RANDOM FOREST MODEL EVALUATION =====")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    print("\nTop 5 Most Important Features:")
    print(predictor.feature_importances_.head(5))

    predictor.save()
    print(f"\nModel saved successfully to {MODEL_PATH}")
