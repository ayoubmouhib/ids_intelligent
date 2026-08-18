from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# MODEL PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

RF_MODEL_PATH = PROJECT_ROOT / "models" / "random_forest_final.joblib"
IF_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest_final.joblib"
CONFIG_PATH = PROJECT_ROOT / "models" / "ids_config.joblib"


# ============================================================
# LOAD MODELS
# ============================================================

print("Loading IDS models...")

random_forest = joblib.load(RF_MODEL_PATH)
isolation_forest = joblib.load(IF_MODEL_PATH)
config = joblib.load(CONFIG_PATH)

print("IDS models loaded successfully.")


# ============================================================
# LOAD CONFIGURATION
# ============================================================

RF_THRESHOLD = config["rf_threshold"]
IF_THRESHOLD = config["if_threshold"]


print(f"RF threshold: {RF_THRESHOLD}")
print(f"IF threshold: {IF_THRESHOLD}")


# ============================================================
# NSL-KDD FEATURES
# ============================================================

FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def predict_traffic(features: dict) -> dict:

    # Convert request dictionary to DataFrame
    df = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS,
    )

    # --------------------------------------------------------
    # RANDOM FOREST
    # --------------------------------------------------------

    rf_probability = float(
        random_forest.predict_proba(df)[0][1]
    )

    rf_prediction = rf_probability >= RF_THRESHOLD

    # --------------------------------------------------------
    # ISOLATION FOREST
    # --------------------------------------------------------

    if_score = float(
        isolation_forest.decision_function(df)[0]
    )

    if_anomaly = if_score <= IF_THRESHOLD

    # --------------------------------------------------------
    # HYBRID DECISION
    # --------------------------------------------------------

    if rf_prediction:

        decision = "ATTACK"

    elif if_anomaly:

        decision = "SUSPICIOUS"

    else:

        decision = "NORMAL"

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {
        "decision": decision,
        "rf_probability": rf_probability,
        "rf_prediction": bool(rf_prediction),
        "if_score": if_score,
        "if_anomaly": bool(if_anomaly),
    }

def predict_traffic_batch(samples: list[dict]) -> list[dict]:

    df = pd.DataFrame(
        samples,
        columns=FEATURE_COLUMNS,
    )

    # ========================================================
    # RANDOM FOREST
    # ========================================================

    rf_probabilities = random_forest.predict_proba(df)[:, 1]

    rf_predictions = rf_probabilities >= RF_THRESHOLD

    # ========================================================
    # ISOLATION FOREST
    # ========================================================

    if_scores = isolation_forest.decision_function(df)

    if_anomalies = if_scores <= IF_THRESHOLD

    # ========================================================
    # HYBRID DECISION
    # ========================================================

    results = []

    for rf_probability, rf_prediction, if_score, if_anomaly in zip(
        rf_probabilities,
        rf_predictions,
        if_scores,
        if_anomalies,
    ):

        if rf_prediction:
            decision = "ATTACK"

        elif if_anomaly:
            decision = "SUSPICIOUS"

        else:
            decision = "NORMAL"

        results.append(
            {
                "decision": decision,
                "rf_probability": float(rf_probability),
                "rf_prediction": bool(rf_prediction),
                "if_score": float(if_score),
                "if_anomaly": bool(if_anomaly),
            }
        )

    return results