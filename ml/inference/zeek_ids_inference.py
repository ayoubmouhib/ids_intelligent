import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd

# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "models"

RF_MODEL_PATH = MODEL_DIR / "random_forest_final.joblib"
IF_MODEL_PATH = MODEL_DIR / "isolation_forest_final.joblib"
CONFIG_PATH = MODEL_DIR / "ids_config.joblib"

DEFAULT_INPUT = (
    PROJECT_ROOT
    / "capture"
    / "zeek"
    / "pcaps"
    / "test-output"
    / "conn.log"
)

DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "analysis"
    / "zeek_ids_predictions.jsonl"
)


# ============================================================
# IMPORT EXISTING ZEEK PIPELINE
# ============================================================

from zeek_conn_parser import parse_zeek_conn_log
from zeek_feature_extractor import (
    extract_features,
    FEATURE_COLUMNS,
)


# ============================================================
# MODEL LOADING
# ============================================================

def load_models():
    """
    Load the trained Random Forest, Isolation Forest,
    and IDS configuration.
    """

    print("Loading IDS models...")

    if not RF_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Random Forest model not found:\n{RF_MODEL_PATH}"
        )

    if not IF_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Isolation Forest model not found:\n{IF_MODEL_PATH}"
        )

    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"IDS configuration not found:\n{CONFIG_PATH}"
        )

    rf_model = joblib.load(RF_MODEL_PATH)
    if_model = joblib.load(IF_MODEL_PATH)
    config = joblib.load(CONFIG_PATH)

    print("Models loaded successfully.")

    return rf_model, if_model, config


# ============================================================
# MODEL VALIDATION
# ============================================================

def validate_models(rf_model, if_model, config):
    """
    Validate that the trained models expect exactly the
    feature representation produced by the Zeek extractor.
    """

    expected_features = config.get(
        "feature_columns"
    )

    if expected_features is None:
        raise ValueError(
            "ids_config.joblib does not contain "
            "'feature_columns'."
        )

    # --------------------------------------------------------
    # Validate config feature count
    # --------------------------------------------------------

    if len(expected_features) != 41:

        raise ValueError(
            "Unexpected feature count in configuration: "
            f"{len(expected_features)}. Expected 41."
        )

    # --------------------------------------------------------
    # Validate extractor feature order
    # --------------------------------------------------------

    if list(expected_features) != list(FEATURE_COLUMNS):

        raise ValueError(
            "Feature mismatch between ids_config.joblib "
            "and zeek_feature_extractor.py."
        )

    # --------------------------------------------------------
    # Validate Random Forest
    # --------------------------------------------------------

    rf_feature_count = getattr(
        rf_model,
        "n_features_in_",
        None,
    )

    if rf_feature_count != len(expected_features):

        raise ValueError(
            "Random Forest feature count mismatch: "
            f"model={rf_feature_count}, "
            f"expected={len(expected_features)}"
        )

    # --------------------------------------------------------
    # Validate Isolation Forest
    # --------------------------------------------------------

    if_feature_count = getattr(
        if_model,
        "n_features_in_",
        None,
    )

    if if_feature_count != len(expected_features):

        raise ValueError(
            "Isolation Forest feature count mismatch: "
            f"model={if_feature_count}, "
            f"expected={len(expected_features)}"
        )

    print()
    print("Model validation:")
    print("  RF features : OK (41)")
    print("  IF features : OK (41)")
    print("  Feature order: OK")

    print(
        f"  RF threshold: "
        f"{config['rf_threshold']:.2f}"
    )

    print(
        f"  IF threshold: "
        f"{config['if_threshold']:.2f}"
    )


# ============================================================
# IDS PREDICTION
# ============================================================

def predict_features(
    features: pd.DataFrame,
    rf_model,
    if_model,
    config,
):
    """
    Run hybrid IDS inference on extracted Zeek features.

    Decision logic:

        RF attack       -> ATTACK
        RF normal +
        IF anomaly      -> SUSPICIOUS
        otherwise       -> NORMAL
    """

    feature_columns = config["feature_columns"]

    # --------------------------------------------------------
    # Validate columns
    # --------------------------------------------------------

    missing_columns = [
        column
        for column in feature_columns
        if column not in features.columns
    ]

    if missing_columns:

        raise ValueError(
            "Missing required features: "
            + ", ".join(missing_columns)
        )

    # Always enforce the exact training order.
    X = features[
        feature_columns
    ].copy()

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    rf_probability = (
        rf_model.predict_proba(X)[:, 1]
    )

    rf_threshold = config[
        "rf_threshold"
    ]

    rf_attack = (
        rf_probability >= rf_threshold
    )

    # --------------------------------------------------------
    # Isolation Forest
    # --------------------------------------------------------

    if_score = (
        if_model.decision_function(X)
    )

    if_threshold = config[
        "if_threshold"
    ]

    if_anomaly = (
        if_score <= if_threshold
    )

    # --------------------------------------------------------
    # Hybrid decision
    # --------------------------------------------------------

    decisions = []

    for rf_flag, if_flag in zip(
        rf_attack,
        if_anomaly,
    ):

        if rf_flag:
            decision = "ATTACK"

        elif if_flag:
            decision = "SUSPICIOUS"

        else:
            decision = "NORMAL"

        decisions.append(decision)

    # --------------------------------------------------------
    # Build result DataFrame
    # --------------------------------------------------------

    results = pd.DataFrame(
        {
            "decision": decisions,

            "rf_probability": [
                float(value)
                for value in rf_probability
            ],

            "if_score": [
                float(value)
                for value in if_score
            ],

            "rf_prediction": [
                bool(value)
                for value in rf_attack
            ],

            "if_anomaly": [
                bool(value)
                for value in if_anomaly
            ],
        }
    )

    return results


# ============================================================
# BUILD JSONL OUTPUT
# ============================================================

def build_output_records(
    connections,
    features,
    predictions,
):
    """
    Combine the original Zeek connection information,
    extracted features, and IDS predictions into one
    JSON-serializable record per connection.
    """

    records = []

    for index in range(
        len(predictions)
    ):

        connection = (
            connections[index]
            if index < len(connections)
            else {}
        )

        feature_record = (
            features.iloc[index]
            .to_dict()
        )

        prediction = (
            predictions.iloc[index]
            .to_dict()
        )

        # ----------------------------------------------------
        # Convert numpy/pandas values into normal Python types
        # ----------------------------------------------------

        clean_features = {}

        for key, value in feature_record.items():

            if pd.isna(value):
                clean_features[key] = None

            elif hasattr(value, "item"):
                clean_features[key] = value.item()

            else:
                clean_features[key] = value

        clean_prediction = {}

        for key, value in prediction.items():

            if pd.isna(value):
                clean_prediction[key] = None

            elif hasattr(value, "item"):
                clean_prediction[key] = value.item()

            else:
                clean_prediction[key] = value

        record = {
            "connection": connection,
            "features": clean_features,
            "prediction": clean_prediction,
        }

        records.append(record)

    return records


def save_jsonl(
    records,
    output_path,
):
    """
    Save inference results as JSONL.
    """

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        for record in records:

            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )


# ============================================================
# TERMINAL SUMMARY
# ============================================================

def print_summary(
    connections,
    features,
    predictions,
):
    """
    Print a readable summary of IDS inference.
    """

    print()
    print("=" * 80)
    print("ZEEK IDS INFERENCE RESULTS")
    print("=" * 80)

    print()
    print(
        f"Connections : {len(connections)}"
    )

    print(
        f"Features    : {len(features.columns)}"
    )

    print()
    print("Decision counts:")
    print(
        predictions[
            "decision"
        ].value_counts()
        .to_string()
    )

    print()
    print("Prediction details:")

    display_columns = [
        "decision",
        "rf_probability",
        "if_score",
        "rf_prediction",
        "if_anomaly",
    ]

    display = predictions[
        display_columns
    ].copy()

    display["rf_probability"] = (
        display["rf_probability"]
        .round(4)
    )

    display["if_score"] = (
        display["if_score"]
        .round(4)
    )

    print(
        display.to_string(
            index=True
        )
    )

    print()
    print("=" * 80)


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run end-to-end IDS inference on "
            "Zeek conn.log data."
        )
    )

    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT,
        help=(
            "Path to Zeek conn.log "
            "(default: capture/zeek/pcaps/"
            "test-output/conn.log)"
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=(
            "Output JSONL file"
        ),
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Resolve relative paths from project root
    # --------------------------------------------------------

    input_path = args.input

    if not input_path.is_absolute():
        input_path = (
            PROJECT_ROOT
            / input_path
        )

    output_path = args.output

    if not output_path.is_absolute():
        output_path = (
            PROJECT_ROOT
            / output_path
        )

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("ZEEK → IDS INFERENCE PIPELINE")
    print("=" * 80)

    print()
    print(f"Project root : {PROJECT_ROOT}")
    print(f"Input        : {input_path}")
    print(f"Output       : {output_path}")

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    if not input_path.exists():

        print()
        print(
            "ERROR: Zeek conn.log does not exist:"
        )

        print(
            f"  {input_path}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Load models
    # --------------------------------------------------------

    try:

        rf_model, if_model, config = (
            load_models()
        )

        validate_models(
            rf_model,
            if_model,
            config,
        )

    except Exception as error:

        print()
        print(
            "ERROR while loading/validating models:"
        )

        print(
            f"  {error}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Parse Zeek
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("STEP 1 — ZEEK CONNECTION PARSING")
    print("-" * 80)

    connections = (
        parse_zeek_conn_log(
            input_path
        )
    )

    print(
        f"Parsed connections: "
        f"{len(connections)}"
    )

    if not connections:

        print()
        print(
            "ERROR: No valid Zeek connections found."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("STEP 2 — FEATURE EXTRACTION")
    print("-" * 80)

    features = extract_features(
        connections
    )

    print(
        f"Feature records: "
        f"{len(features)}"
    )

    print(
        f"Feature count: "
        f"{len(features.columns)}"
    )

    if len(features) != len(connections):

        print()
        print(
            "ERROR: Number of feature records "
            "does not match number of connections."
        )

        sys.exit(1)

    if len(features.columns) != 41:

        print()
        print(
            "ERROR: Expected 41 features, "
            f"got {len(features.columns)}."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # IDS inference
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("STEP 3 — IDS MODEL INFERENCE")
    print("-" * 80)

    predictions = predict_features(
        features,
        rf_model,
        if_model,
        config,
    )

    print(
        f"Predictions generated: "
        f"{len(predictions)}"
    )

    # --------------------------------------------------------
    # Build output
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("STEP 4 — SAVE RESULTS")
    print("-" * 80)

    output_records = build_output_records(
        connections,
        features,
        predictions,
    )

    save_jsonl(
        output_records,
        output_path,
    )

    print(
        f"Saved predictions: "
        f"{output_path}"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_summary(
        connections,
        features,
        predictions,
    )

    print()
    print("End-to-end Zeek IDS inference complete.")
    print()


if __name__ == "__main__":
    main()
