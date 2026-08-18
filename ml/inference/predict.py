from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# PATHS
# ============================================================

MODEL_DIR = Path("models")

RF_MODEL_PATH = MODEL_DIR / "random_forest_final.joblib"
IF_MODEL_PATH = MODEL_DIR / "isolation_forest_final.joblib"
CONFIG_PATH = MODEL_DIR / "ids_config.joblib"


# ============================================================
# LOAD MODELS
# ============================================================

print("Loading IDS models...")

rf_model = joblib.load(RF_MODEL_PATH)
if_model = joblib.load(IF_MODEL_PATH)
config = joblib.load(CONFIG_PATH)

RF_THRESHOLD = config["rf_threshold"]
IF_THRESHOLD = config["if_threshold"]
FEATURE_COLUMNS = config["feature_columns"]

print("Models loaded successfully.")

print(f"RF threshold: {RF_THRESHOLD:.2f}")
print(f"IF threshold: {IF_THRESHOLD:.2f}")


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def predict_traffic(record):
    """
    Predict the security status of one network traffic record.

    Returns:
        dict containing:
            decision
            rf_probability
            if_score
            rf_prediction
            if_anomaly
    """

    # --------------------------------------------------------
    # Convert input to DataFrame
    # --------------------------------------------------------

    if isinstance(record, dict):
        df = pd.DataFrame([record])

    elif isinstance(record, pd.DataFrame):
        df = record.copy()

    else:
        raise TypeError(
            "record must be a dictionary or pandas DataFrame"
        )

    # --------------------------------------------------------
    # Validate features
    # --------------------------------------------------------

    missing_features = [
        column
        for column in FEATURE_COLUMNS
        if column not in df.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing required features: "
            + ", ".join(missing_features)
        )

    df = df[FEATURE_COLUMNS]

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    rf_probability = rf_model.predict_proba(df)[:, 1]

    rf_attack = (
        rf_probability >= RF_THRESHOLD
    )

    # --------------------------------------------------------
    # Isolation Forest
    # --------------------------------------------------------

    # Isolation Forest:
    #
    # higher decision_function = more normal
    # lower decision_function  = more anomalous
    #
    # Therefore we use the raw decision score here.

    if_score = if_model.decision_function(df)

    if_anomaly = (
        if_score <= IF_THRESHOLD
    )

    # --------------------------------------------------------
    # Hybrid decision
    # --------------------------------------------------------

    decisions = []

    for rf_attack_flag, if_anomaly_flag in zip(
        rf_attack,
        if_anomaly,
    ):

        if rf_attack_flag:
            decision = "ATTACK"

        elif if_anomaly_flag:
            decision = "SUSPICIOUS"

        else:
            decision = "NORMAL"

        decisions.append(decision)

    # --------------------------------------------------------
    # Return results
    # --------------------------------------------------------

    if len(df) == 1:

        return {
            "decision": decisions[0],
            "rf_probability": float(rf_probability[0]),
            "if_score": float(if_score[0]),
            "rf_prediction": bool(rf_attack[0]),
            "if_anomaly": bool(if_anomaly[0]),
        }

    return pd.DataFrame(
        {
            "decision": decisions,
            "rf_probability": rf_probability,
            "if_score": if_score,
            "rf_prediction": rf_attack,
            "if_anomaly": if_anomaly,
        }
    )


# ============================================================
# TEST WITH TEST DATA
# ============================================================

if __name__ == "__main__":

    TEST_PATH = Path(
        "data/processed/nsl-kdd/test.csv"
    )

    print("\nLoading test data...")

    test_df = pd.read_csv(TEST_PATH)

    print(
        f"Test samples: {len(test_df)}"
    )

    print("\nRunning IDS inference...")

    results = predict_traffic(
        test_df
    )

    print("\n" + "=" * 80)
    print("IDS INFERENCE RESULTS")
    print("=" * 80)

    print(
        results["decision"].value_counts()
    )

    print("\nSample predictions:")
    print(
        results.head(10).to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # Save predictions
    # --------------------------------------------------------

    output_path = Path(
        "data/analysis/final_ids_predictions.csv"
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        output_path,
        index=False,
    )

    print(
        f"\nResults saved:"
        f"\n  {output_path}"
    )

    print("\nStep 5B complete.")
