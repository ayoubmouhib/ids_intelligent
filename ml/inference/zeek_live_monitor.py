import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

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
    / "zeek_live_predictions.jsonl"
)


# ============================================================
# IMPORT EXISTING IDS COMPONENTS
# ============================================================

INFERENCE_DIR = Path(__file__).resolve().parent

sys.path.insert(
    0,
    str(INFERENCE_DIR),
)

from zeek_feature_extractor import extract_features
from predict import predict_traffic


# ============================================================
# CONFIGURATION
# ============================================================

POLL_INTERVAL = 1.0


# ============================================================
# ZEEK RECORD NORMALIZATION
# ============================================================

def normalize_zeek_record(data):
    """
    Convert one raw Zeek JSON record into the normalized
    connection structure used by the IDS pipeline.
    """

    return {
        "timestamp": data.get("ts"),
        "uid": data.get("uid"),

        "source_ip": data.get("id.orig_h"),
        "source_port": data.get("id.orig_p"),

        "destination_ip": data.get("id.resp_h"),
        "destination_port": data.get("id.resp_p"),

        "protocol": data.get("proto"),
        "service": data.get("service"),

        "duration": data.get("duration"),

        "source_bytes": data.get("orig_bytes"),
        "destination_bytes": data.get("resp_bytes"),

        "connection_state": data.get("conn_state"),

        "source_packets": data.get("orig_pkts"),
        "destination_packets": data.get("resp_pkts"),

        "source_ip_bytes": data.get("orig_ip_bytes"),
        "destination_ip_bytes": data.get("resp_ip_bytes"),

        "missed_bytes": data.get("missed_bytes"),

        "history": data.get("history"),

        "local_source": data.get("local_orig"),
        "local_destination": data.get("local_resp"),

        "ip_protocol": data.get("ip_proto"),
    }


# ============================================================
# LOAD EXISTING ZEEK LOG
# ============================================================

def load_existing_records(input_file):
    """
    Load all existing valid Zeek records.

    Returns:
        records
        total number of physical lines in the file
    """

    records = []

    with input_file.open(
        "r",
        encoding="utf-8",
    ) as file:

        lines = file.readlines()

    for line_number, line in enumerate(
        lines,
        start=1,
    ):

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        try:

            data = json.loads(line)

        except json.JSONDecodeError as error:

            print(
                f"WARNING: Invalid JSON at line "
                f"{line_number}: {error}"
            )

            continue

        records.append(
            normalize_zeek_record(data)
        )

    return records, len(lines)


# ============================================================
# READ NEW LINES
# ============================================================

def read_new_records(
    input_file,
    processed_lines,
):
    """
    Read only lines appended since processed_lines.

    Returns:
        new_records
        updated line position
    """

    new_records = []

    with input_file.open(
        "r",
        encoding="utf-8",
    ) as file:

        lines = file.readlines()

    current_line_count = len(lines)

    if current_line_count <= processed_lines:

        return (
            new_records,
            current_line_count,
        )

    new_lines = lines[
        processed_lines:
    ]

    for line_number, line in enumerate(
        new_lines,
        start=processed_lines + 1,
    ):

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        try:

            data = json.loads(line)

        except json.JSONDecodeError as error:

            print(
                f"WARNING: Invalid JSON at line "
                f"{line_number}: {error}"
            )

            continue

        new_records.append(
            normalize_zeek_record(data)
        )

    return (
        new_records,
        current_line_count,
    )


# ============================================================
# PREDICTION
# ============================================================

def predict_new_record(
    historical_records,
    new_record,
):
    """
    Extract features using the complete connection history,
    then predict only the newly appended connection.

    This preserves the same contextual feature extraction
    strategy used by the offline Zeek IDS pipeline.
    """

    all_records = (
        historical_records
        + [new_record]
    )

    features = extract_features(
        all_records
    )

    # The last feature row corresponds to the new connection.
    new_features = features.iloc[
        [-1]
    ].copy()

    # predict_traffic() returns a dictionary when
    # exactly one record is provided.
    prediction = predict_traffic(
        new_features
    )

    feature_dict = {
        key: (
            None
            if pd.isna(value)
            else value
        )
        for key, value
        in new_features.iloc[0].to_dict().items()
    }

    return (
        feature_dict,
        prediction,
    )


# ============================================================
# PRINT PREDICTION
# ============================================================

def print_prediction(
    index,
    connection,
    prediction,
):
    """
    Print one IDS prediction.
    """

    print(
        f"{index:04d} | "
        f"{prediction['decision']:10s} | "
        f"RF={prediction['rf_probability']:.4f} | "
        f"IF={prediction['if_score']:.4f} | "
        f"{connection.get('source_ip')}:"
        f"{connection.get('source_port')} -> "
        f"{connection.get('destination_ip')}:"
        f"{connection.get('destination_port')} | "
        f"{connection.get('protocol')} | "
        f"{connection.get('service')} | "
        f"{connection.get('connection_state')}"
    )


# ============================================================
# SAVE RESULT
# ============================================================

def save_prediction(
    connection,
    features,
    prediction,
    output_file,
):
    """
    Append one prediction to JSONL.
    """

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    result = {
        "connection": connection,
        "features": features,
        "prediction": prediction,
    }

    with output_file.open(
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(
                result,
                default=str,
            )
            + "\n"
        )


# ============================================================
# ALERT
# ============================================================

def print_alert(
    connection,
    prediction,
):
    """
    Print an alert for ATTACK or SUSPICIOUS traffic.
    """

    decision = prediction["decision"]

    if decision == "ATTACK":

        print()
        print("!" * 90)
        print("🚨 IDS ATTACK ALERT")
        print("!" * 90)

    elif decision == "SUSPICIOUS":

        print()
        print("-" * 90)
        print("⚠️ IDS SUSPICIOUS TRAFFIC")
        print("-" * 90)

    else:

        return

    print(
        f"Source      : "
        f"{connection.get('source_ip')}:"
        f"{connection.get('source_port')}"
    )

    print(
        f"Destination : "
        f"{connection.get('destination_ip')}:"
        f"{connection.get('destination_port')}"
    )

    print(
        f"Protocol    : "
        f"{connection.get('protocol')}"
    )

    print(
        f"Service     : "
        f"{connection.get('service')}"
    )

    print(
        f"State       : "
        f"{connection.get('connection_state')}"
    )

    print(
        f"RF probability : "
        f"{prediction['rf_probability']:.4f}"
    )

    print(
        f"IF score       : "
        f"{prediction['if_score']:.4f}"
    )

    print("!" * 90)


# ============================================================
# ARGUMENTS
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "Real-time Zeek IDS monitor"
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Zeek JSON log file",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="JSONL prediction output",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=POLL_INTERVAL,
        help="Polling interval in seconds",
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_args()

    input_file = args.input
    output_file = args.output

    print(
        "Loading IDS models..."
    )

    print(
        "Models loaded successfully."
    )

    print(
        "=========================================================================================="
    )

    print(
        "ZEEK → REAL-TIME IDS MONITOR"
    )

    print(
        "=========================================================================================="
    )

    print(
        f"\nZeek log : {input_file}"
    )

    print(
        f"Output   : {output_file}"
    )

    print(
        f"Interval : {args.interval}s"
    )

    # --------------------------------------------------------
    # VALIDATE INPUT
    # --------------------------------------------------------

    if not input_file.exists():

        print(
            f"\nERROR: Zeek log does not exist:"
            f"\n{input_file}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # LOAD HISTORICAL CONTEXT
    # --------------------------------------------------------

    print(
        "\nLoading existing Zeek connections..."
    )

    historical_records, processed_lines = (
        load_existing_records(
            input_file
        )
    )

    print(
        f"Historical connections: "
        f"{len(historical_records)}"
    )

    print(
        f"Processed file lines   : "
        f"{processed_lines}"
    )

    # --------------------------------------------------------
    # TRACK UIDS
    # --------------------------------------------------------

    processed_uids = {
        record.get("uid")
        for record in historical_records
        if record.get("uid") is not None
    }

    print(
        f"Historical UIDs        : "
        f"{len(processed_uids)}"
    )

    # --------------------------------------------------------
    # MONITOR
    # --------------------------------------------------------

    print(
        "\nMonitoring for NEW connections..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print(
        "\n" + "-" * 90
    )

    prediction_index = 0

    try:

        while True:

            new_records, processed_lines = (
                read_new_records(
                    input_file,
                    processed_lines,
                )
            )

            if new_records:

                for new_record in new_records:

                    uid = new_record.get(
                        "uid"
                    )

                    # ------------------------------------------------
                    # DUPLICATE PROTECTION
                    # ------------------------------------------------

                    if (
                        uid is not None
                        and uid in processed_uids
                    ):

                        continue

                    # ------------------------------------------------
                    # PREDICT
                    # ------------------------------------------------

                    features, prediction = (
                        predict_new_record(
                            historical_records,
                            new_record,
                        )
                    )

                    print_prediction(
                        prediction_index,
                        new_record,
                        prediction,
                    )

                    save_prediction(
                        new_record,
                        features,
                        prediction,
                        output_file,
                    )

                    print_alert(
                        new_record,
                        prediction,
                    )

                    # ------------------------------------------------
                    # UPDATE CONTEXT
                    # ------------------------------------------------

                    historical_records.append(
                        new_record
                    )

                    if uid is not None:

                        processed_uids.add(
                            uid
                        )

                    prediction_index += 1

            time.sleep(
                args.interval
            )

    except KeyboardInterrupt:

        print(
            "\n\n"
            + "=" * 90
        )

        print(
            "ZEEK LIVE IDS MONITOR STOPPED"
        )

        print(
            "=" * 90
        )

        print(
            f"Predictions generated: "
            f"{prediction_index}"
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
PYcat > ml/inference/zeek_live_monitor.py <<'PY'
import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

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
    / "zeek_live_predictions.jsonl"
)


# ============================================================
# IMPORT EXISTING IDS COMPONENTS
# ============================================================

INFERENCE_DIR = Path(__file__).resolve().parent

sys.path.insert(
    0,
    str(INFERENCE_DIR),
)

from zeek_feature_extractor import extract_features
from predict import predict_traffic


# ============================================================
# CONFIGURATION
# ============================================================

POLL_INTERVAL = 1.0


# ============================================================
# ZEEK RECORD NORMALIZATION
# ============================================================

def normalize_zeek_record(data):
    """
    Convert one raw Zeek JSON record into the normalized
    connection structure used by the IDS pipeline.
    """

    return {
        "timestamp": data.get("ts"),
        "uid": data.get("uid"),

        "source_ip": data.get("id.orig_h"),
        "source_port": data.get("id.orig_p"),

        "destination_ip": data.get("id.resp_h"),
        "destination_port": data.get("id.resp_p"),

        "protocol": data.get("proto"),
        "service": data.get("service"),

        "duration": data.get("duration"),

        "source_bytes": data.get("orig_bytes"),
        "destination_bytes": data.get("resp_bytes"),

        "connection_state": data.get("conn_state"),

        "source_packets": data.get("orig_pkts"),
        "destination_packets": data.get("resp_pkts"),

        "source_ip_bytes": data.get("orig_ip_bytes"),
        "destination_ip_bytes": data.get("resp_ip_bytes"),

        "missed_bytes": data.get("missed_bytes"),

        "history": data.get("history"),

        "local_source": data.get("local_orig"),
        "local_destination": data.get("local_resp"),

        "ip_protocol": data.get("ip_proto"),
    }


# ============================================================
# LOAD EXISTING ZEEK LOG
# ============================================================

def load_existing_records(input_file):
    """
    Load all existing valid Zeek records.

    Returns:
        records
        total number of physical lines in the file
    """

    records = []

    with input_file.open(
        "r",
        encoding="utf-8",
    ) as file:

        lines = file.readlines()

    for line_number, line in enumerate(
        lines,
        start=1,
    ):

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        try:

            data = json.loads(line)

        except json.JSONDecodeError as error:

            print(
                f"WARNING: Invalid JSON at line "
                f"{line_number}: {error}"
            )

            continue

        records.append(
            normalize_zeek_record(data)
        )

    return records, len(lines)


# ============================================================
# READ NEW LINES
# ============================================================

def read_new_records(
    input_file,
    processed_lines,
):
    """
    Read only lines appended since processed_lines.

    Returns:
        new_records
        updated line position
    """

    new_records = []

    with input_file.open(
        "r",
        encoding="utf-8",
    ) as file:

        lines = file.readlines()

    current_line_count = len(lines)

    if current_line_count <= processed_lines:

        return (
            new_records,
            current_line_count,
        )

    new_lines = lines[
        processed_lines:
    ]

    for line_number, line in enumerate(
        new_lines,
        start=processed_lines + 1,
    ):

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        try:

            data = json.loads(line)

        except json.JSONDecodeError as error:

            print(
                f"WARNING: Invalid JSON at line "
                f"{line_number}: {error}"
            )

            continue

        new_records.append(
            normalize_zeek_record(data)
        )

    return (
        new_records,
        current_line_count,
    )


# ============================================================
# PREDICTION
# ============================================================

def predict_new_record(
    historical_records,
    new_record,
):
    """
    Extract features using the complete connection history,
    then predict only the newly appended connection.

    This preserves the same contextual feature extraction
    strategy used by the offline Zeek IDS pipeline.
    """

    all_records = (
        historical_records
        + [new_record]
    )

    features = extract_features(
        all_records
    )

    # The last feature row corresponds to the new connection.
    new_features = features.iloc[
        [-1]
    ].copy()

    prediction = predict_traffic(
        new_features
    )

    feature_dict = {
        key: (
            None
            if pd.isna(value)
            else value
        )
        for key, value
        in new_features.iloc[0].to_dict().items()
    }

    return (
        feature_dict,
        prediction,
    )


# ============================================================
# PRINT PREDICTION
# ============================================================

def print_prediction(
    index,
    connection,
    prediction,
):
    """
    Print one IDS prediction.
    """

    print(
        f"{index:04d} | "
        f"{prediction['decision']:10s} | "
        f"RF={prediction['rf_probability']:.4f} | "
        f"IF={prediction['if_score']:.4f} | "
        f"{connection.get('source_ip')}:"
        f"{connection.get('source_port')} -> "
        f"{connection.get('destination_ip')}:"
        f"{connection.get('destination_port')} | "
        f"{connection.get('protocol')} | "
        f"{connection.get('service')} | "
        f"{connection.get('connection_state')}"
    )


# ============================================================
# SAVE RESULT
# ============================================================

def save_prediction(
    connection,
    features,
    prediction,
    output_file,
):
    """
    Append one prediction to JSONL.
    """

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    result = {
        "connection": connection,
        "features": features,
        "prediction": prediction,
    }

    with output_file.open(
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(
                result,
                default=str,
            )
            + "\n"
        )


# ============================================================
# ALERT
# ============================================================

def print_alert(
    connection,
    prediction,
):
    """
    Print an alert for ATTACK or SUSPICIOUS traffic.
    """

    decision = prediction["decision"]

    if decision == "ATTACK":

        print()
        print("!" * 90)
        print("🚨 IDS ATTACK ALERT")
        print("!" * 90)

    elif decision == "SUSPICIOUS":

        print()
        print("-" * 90)
        print("⚠️ IDS SUSPICIOUS TRAFFIC")
        print("-" * 90)

    else:

        return

    print(
        f"Source      : "
        f"{connection.get('source_ip')}:"
        f"{connection.get('source_port')}"
    )

    print(
        f"Destination : "
        f"{connection.get('destination_ip')}:"
        f"{connection.get('destination_port')}"
    )

    print(
        f"Protocol    : "
        f"{connection.get('protocol')}"
    )

    print(
        f"Service     : "
        f"{connection.get('service')}"
    )

    print(
        f"State       : "
        f"{connection.get('connection_state')}"
    )

    print(
        f"RF probability : "
        f"{prediction['rf_probability']:.4f}"
    )

    print(
        f"IF score       : "
        f"{prediction['if_score']:.4f}"
    )

    print("!" * 90)


# ============================================================
# ARGUMENTS
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "Real-time Zeek IDS monitor"
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Zeek JSON log file",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="JSONL prediction output",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=POLL_INTERVAL,
        help="Polling interval in seconds",
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_args()

    input_file = args.input
    output_file = args.output

    print(
        "Loading IDS models..."
    )

    print(
        "Models loaded successfully."
    )

    print(
        "=========================================================================================="
    )

    print(
        "ZEEK → REAL-TIME IDS MONITOR"
    )

    print(
        "=========================================================================================="
    )

    print(
        f"\nZeek log : {input_file}"
    )

    print(
        f"Output   : {output_file}"
    )

    print(
        f"Interval : {args.interval}s"
    )

    # --------------------------------------------------------
    # VALIDATE INPUT
    # --------------------------------------------------------

    if not input_file.exists():

        print(
            f"\nERROR: Zeek log does not exist:"
            f"\n{input_file}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # LOAD HISTORICAL CONTEXT
    # --------------------------------------------------------

    print(
        "\nLoading existing Zeek connections..."
    )

    historical_records, processed_lines = (
        load_existing_records(
            input_file
        )
    )

    print(
        f"Historical connections: "
        f"{len(historical_records)}"
    )

    print(
        f"Processed file lines   : "
        f"{processed_lines}"
    )

    # --------------------------------------------------------
    # TRACK UIDS
    # --------------------------------------------------------

    processed_uids = {
        record.get("uid")
        for record in historical_records
        if record.get("uid") is not None
    }

    print(
        f"Historical UIDs        : "
        f"{len(processed_uids)}"
    )

    # --------------------------------------------------------
    # MONITOR
    # --------------------------------------------------------

    print(
        "\nMonitoring for NEW connections..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print(
        "\n" + "-" * 90
    )

    prediction_index = 0

    try:

        while True:

            new_records, processed_lines = (
                read_new_records(
                    input_file,
                    processed_lines,
                )
            )

            if new_records:

                for new_record in new_records:

                    uid = new_record.get(
                        "uid"
                    )

                    # ------------------------------------------------
                    # DUPLICATE PROTECTION
                    # ------------------------------------------------

                    if (
                        uid is not None
                        and uid in processed_uids
                    ):

                        continue

                    # ------------------------------------------------
                    # PREDICT
                    # ------------------------------------------------

                    features, prediction = (
                        predict_new_record(
                            historical_records,
                            new_record,
                        )
                    )

                    display_connection = new_record.copy()
                    display_connection["service"] = features.get(
                        "service",
                        new_record.get("service"),
                        )

                    print_prediction(
                        prediction_index,
                        display_connection,
                        prediction,
                        )

                    save_prediction(
                        new_record,
                        features,
                        prediction,
                        output_file,
                    )

                    print_alert(
                        new_record,
                        prediction,
                    )

                    # ------------------------------------------------
                    # UPDATE CONTEXT
                    # ------------------------------------------------

                    historical_records.append(
                        new_record
                    )

                    if uid is not None:

                        processed_uids.add(
                            uid
                        )

                    prediction_index += 1

            time.sleep(
                args.interval
            )

    except KeyboardInterrupt:

        print(
            "\n\n"
            + "=" * 90
        )

        print(
            "ZEEK LIVE IDS MONITOR STOPPED"
        )

        print(
            "=" * 90
        )

        print(
            f"Predictions generated: "
            f"{prediction_index}"
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
