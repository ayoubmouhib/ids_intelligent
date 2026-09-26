import json
from collections import Counter
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PREDICTION_PATH = (
    PROJECT_ROOT
    / "data"
    / "analysis"
    / "zeek_ids_predictions.jsonl"
)


# ============================================================
# VALIDATION
# ============================================================

def load_predictions(path: Path):

    records = []

    with path.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError as error:

                raise ValueError(
                    f"Invalid JSON at line "
                    f"{line_number}: {error}"
                )

    return records


def validate_record(record, index):

    required_sections = [
        "connection",
        "features",
        "prediction",
    ]

    for section in required_sections:

        if section not in record:

            raise ValueError(
                f"Record {index}: missing "
                f"'{section}' section"
            )


def main():

    print("=" * 80)
    print("STEP 5D - ZEEK IDS PIPELINE VALIDATION")
    print("=" * 80)

    # --------------------------------------------------------
    # FILE
    # --------------------------------------------------------

    print("\nPrediction file:")

    print(
        f"  {PREDICTION_PATH}"
    )

    if not PREDICTION_PATH.exists():

        print(
            "\nERROR: Prediction file does not exist."
        )

        print(
            "\nRun first:"
        )

        print(
            "  python ml/inference/zeek_ids_inference.py"
        )

        return 1

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    records = load_predictions(
        PREDICTION_PATH
    )

    print(
        f"\nRecords loaded: {len(records)}"
    )

    if not records:

        print(
            "\nERROR: No prediction records."
        )

        return 1

    # --------------------------------------------------------
    # REQUIRED SECTIONS
    # --------------------------------------------------------

    print("\nChecking record structure...")

    for index, record in enumerate(records):

        validate_record(
            record,
            index,
        )

    print(
        "  [OK] All records contain "
        "connection/features/prediction"
    )

    # --------------------------------------------------------
    # FEATURES
    # --------------------------------------------------------

    expected_feature_count = 41

    print("\nChecking feature count...")

    for index, record in enumerate(records):

        features = record["features"]

        if len(features) != expected_feature_count:

            print(
                f"  [FAIL] Record {index}: "
                f"{len(features)} features"
            )

            return 1

    print(
        f"  [OK] All records contain "
        f"{expected_feature_count} features"
    )

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    print("\nChecking predictions...")

    valid_decisions = {
        "NORMAL",
        "SUSPICIOUS",
        "ATTACK",
    }

    for index, record in enumerate(records):

        prediction = record["prediction"]

        decision = prediction.get(
            "decision"
        )

        if decision not in valid_decisions:

            print(
                f"  [FAIL] Record {index}: "
                f"invalid decision '{decision}'"
            )

            return 1

        rf_probability = prediction.get(
            "rf_probability"
        )

        if not (
            0.0
            <= rf_probability
            <= 1.0
        ):

            print(
                f"  [FAIL] Record {index}: "
                f"invalid RF probability "
                f"{rf_probability}"
            )

            return 1

    print(
        "  [OK] Prediction values valid"
    )

    # --------------------------------------------------------
    # THRESHOLD LOGIC
    # --------------------------------------------------------

    print("\nChecking hybrid decision logic...")

    rf_threshold = 0.40
    if_threshold = -0.10

    for index, record in enumerate(records):

        prediction = record["prediction"]

        rf_probability = prediction[
            "rf_probability"
        ]

        if_score = prediction[
            "if_score"
        ]

        expected_rf_attack = (
            rf_probability
            >= rf_threshold
        )

        expected_if_anomaly = (
            if_score
            <= if_threshold
        )

        expected_decision = (
            "ATTACK"
            if expected_rf_attack
            else (
                "SUSPICIOUS"
                if expected_if_anomaly
                else "NORMAL"
            )
        )

        actual_decision = prediction[
            "decision"
        ]

        if expected_decision != actual_decision:

            print(
                f"  [FAIL] Record {index}: "
                f"expected {expected_decision}, "
                f"got {actual_decision}"
            )

            return 1

    print(
        "  [OK] Hybrid decision logic valid"
    )

    # --------------------------------------------------------
    # SERVICE VALIDATION
    # --------------------------------------------------------

    print("\nChecking service normalization...")

    services = Counter(
        record["features"].get("service")
        for record in records
    )

    print(
        "  Services:"
    )

    for service, count in services.items():

        print(
            f"    {service}: {count}"
        )

    if any(
        service in {None, "nan", "NaN"}
        for service in services
    ):

        print(
            "\n  [FAIL] Missing services remain"
        )

        return 1

    print(
        "  [OK] No unresolved service values"
    )

    # --------------------------------------------------------
    # DECISION DISTRIBUTION
    # --------------------------------------------------------

    decisions = Counter(
        record["prediction"]["decision"]
        for record in records
    )

    print("\nDecision distribution:")

    for decision in [
        "NORMAL",
        "SUSPICIOUS",
        "ATTACK",
    ]:

        print(
            f"  {decision:10s}: "
            f"{decisions.get(decision, 0)}"
        )

    # --------------------------------------------------------
    # CONNECTION STATISTICS
    # --------------------------------------------------------

    protocols = Counter(
        record["connection"].get(
            "protocol"
        )
        for record in records
    )

    states = Counter(
        record["connection"].get(
            "connection_state"
        )
        for record in records
    )

    print("\nProtocols:")

    for protocol, count in protocols.items():

        print(
            f"  {protocol}: {count}"
        )

    print("\nConnection states:")

    for state, count in states.items():

        print(
            f"  {state}: {count}"
        )

    # --------------------------------------------------------
    # ATTACK DETAILS
    # --------------------------------------------------------

    attacks = [
        record
        for record in records
        if record["prediction"]["decision"]
        == "ATTACK"
    ]

    print("\nDetected attacks:")

    if not attacks:

        print("  None")

    else:

        for index, record in enumerate(
            attacks,
            start=1,
        ):

            connection = record[
                "connection"
            ]

            prediction = record[
                "prediction"
            ]

            print(
                f"  [{index}] "
                f"{connection.get('source_ip')}:"
                f"{connection.get('source_port')}"
                f" -> "
                f"{connection.get('destination_ip')}:"
                f"{connection.get('destination_port')}"
            )

            print(
                f"      RF="
                f"{prediction['rf_probability']:.4f} "
                f"IF="
                f"{prediction['if_score']:.4f}"
            )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    print("\n" + "=" * 80)
    print("STEP 5D VALIDATION PASSED")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
