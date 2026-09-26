import json
import sys
from pathlib import Path

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_INPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "zeek_connections.jsonl"
)


# ============================================================
# NSL-KDD FEATURE ORDER
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
# ZEEK → NSL-KDD MAPPINGS
# ============================================================

PROTOCOL_MAP = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}


SERVICE_DEFAULT = "other"

PORT_SERVICE_MAP = {
    20: "ftp",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop_3",
    143: "imap4",
    443: "https",
    587: "smtp",
    993: "imap4",
    995: "pop_3",
}

# Zeek connection states are not identical to NSL-KDD flags.
#
# We therefore use a conservative mapping for the common states.
ZEEK_STATE_TO_FLAG = {
    "SF": "SF",
    "S1": "S1",
    "S2": "S2",
    "S3": "S3",
    "REJ": "REJ",
    "RSTO": "RSTO",
    "RSTR": "RSTR",
    "RSTOS0": "RSTOS0",
    "OTH": "OTH",
    "SH": "SH",
    "SHR": "SHR",
}


# ============================================================
# HELPERS
# ============================================================

def safe_number(value, default=0):
    """
    Convert a value to float safely.
    """
    if value is None:
        return default

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_protocol(protocol):
    """
    Normalize Zeek protocol names.
    """
    protocol = str(protocol).lower()

    return PROTOCOL_MAP.get(
        protocol,
        protocol,
    )


def normalize_service(service, destination_port=None):
    """
    Normalize Zeek service names.

    If Zeek did not identify the application service,
    use the destination port as a conservative fallback.
    """

    if service is not None:

        try:
            if not pd.isna(service):

                service = str(service).strip()

                if service:
                    return service

        except (TypeError, ValueError):
            pass

    # --------------------------------------------------------
    # Port-based fallback
    # --------------------------------------------------------

    try:
        port = int(destination_port)
    except (TypeError, ValueError):
        port = None

    if port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[port]

    return SERVICE_DEFAULT

def normalize_flag(connection_state):
    """
    Convert Zeek connection state into an IDS flag.
    """
    if connection_state is None:
        return "OTH"

    return ZEEK_STATE_TO_FLAG.get(
        connection_state,
        "OTH",
    )


# ============================================================
# LOAD ZEEK CONNECTIONS
# ============================================================

def load_connections(input_path):
    """
    Load Zeek JSONL connection records.
    """

    records = []

    with open(input_path, "r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
                records.append(record)

            except json.JSONDecodeError as exc:

                print(
                    f"Warning: invalid JSON on line "
                    f"{line_number}: {exc}"
                )

    return records


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(records):
    """
    Convert normalized Zeek connections into
    NSL-KDD-compatible feature records.
    """

    if not records:
        return pd.DataFrame(
            columns=FEATURE_COLUMNS
        )

    dataframe = pd.DataFrame(records)

    # --------------------------------------------------------
    # GLOBAL COUNTS
    # --------------------------------------------------------

    total_connections = len(dataframe)

    # --------------------------------------------------------
    # SOURCE / DESTINATION GROUPS
    # --------------------------------------------------------

    source_counts = (
        dataframe
        .groupby("source_ip")
        .size()
        .to_dict()
    )

    destination_counts = (
        dataframe
        .groupby("destination_ip")
        .size()
        .to_dict()
    )

    # --------------------------------------------------------
    # SERVICE COUNTS
    # --------------------------------------------------------

    service_counts = (
        dataframe
        .fillna({"service": SERVICE_DEFAULT})
        .groupby("service")
        .size()
        .to_dict()
    )

    # --------------------------------------------------------
    # BUILD FEATURES
    # --------------------------------------------------------

    feature_records = []

    for _, row in dataframe.iterrows():

        source_ip = row.get("source_ip")
        destination_ip = row.get("destination_ip")

        service = normalize_service(
            row.get("service"),
            row.get("destination_port"),
        )

        protocol = normalize_protocol(
            row.get("protocol")
        )

        connection_state = row.get(
            "connection_state"
        )

        flag = normalize_flag(
            connection_state
        )

        # ----------------------------------------------------
        # BASIC CONNECTION FEATURES
        # ----------------------------------------------------

        duration = safe_number(
            row.get("duration")
        )

        src_bytes = safe_number(
            row.get("source_bytes")
        )

        dst_bytes = safe_number(
            row.get("destination_bytes")
        )

        # ----------------------------------------------------
        # CONNECTION COUNTS
        # ----------------------------------------------------

        count = source_counts.get(
            source_ip,
            1,
        )

        dst_host_count = destination_counts.get(
            destination_ip,
            1,
        )

        srv_count = service_counts.get(
            service,
            1,
        )

        dst_host_srv_count = (
            sum(
                1
                for record in records
                if record.get("destination_ip")
                == destination_ip
                and normalize_service(
                    record.get("service"),
                    record.get("destination_port"),
                )
                == service
            )
        )

        # ----------------------------------------------------
        # SERVICE RATIOS
        # ----------------------------------------------------

        same_srv_rate = (
            srv_count / count
            if count > 0
            else 0.0
        )

        diff_srv_rate = (
            1.0 - same_srv_rate
        )

        # ----------------------------------------------------
        # HOST RATIOS
        # ----------------------------------------------------

        dst_host_same_srv_rate = (
            dst_host_srv_count / dst_host_count
            if dst_host_count > 0
            else 0.0
        )

        dst_host_diff_srv_rate = (
            1.0 - dst_host_same_srv_rate
        )

        # ----------------------------------------------------
        # ERROR FEATURES
        # ----------------------------------------------------

        is_error_state = connection_state in {
            "REJ",
            "S1",
            "S2",
            "S3",
            "RSTO",
            "RSTR",
            "RSTOS0",
        }

        error_rate = (
            1.0 if is_error_state else 0.0
        )

        # ----------------------------------------------------
        # BUILD NSL-KDD RECORD
        # ----------------------------------------------------

        features = {

            # Basic
            "duration": duration,
            "protocol_type": protocol,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,

            # Connection flags
            "land": int(
                source_ip == destination_ip
            ),

            "wrong_fragment": 0,
            "urgent": 0,

            # Host / login information
            #
            # Not available from conn.log.
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,

            # Traffic statistics
            "count": int(count),
            "srv_count": int(srv_count),

            "serror_rate": error_rate,
            "srv_serror_rate": error_rate,
            "rerror_rate": error_rate,
            "srv_rerror_rate": error_rate,

            "same_srv_rate": min(
                max(same_srv_rate, 0.0),
                1.0,
            ),

            "diff_srv_rate": min(
                max(diff_srv_rate, 0.0),
                1.0,
            ),

            "srv_diff_host_rate": 0.0,

            # Destination host statistics
            "dst_host_count": int(
                dst_host_count
            ),

            "dst_host_srv_count": int(
                dst_host_srv_count
            ),

            "dst_host_same_srv_rate": min(
                max(
                    dst_host_same_srv_rate,
                    0.0,
                ),
                1.0,
            ),

            "dst_host_diff_srv_rate": min(
                max(
                    dst_host_diff_srv_rate,
                    0.0,
                ),
                1.0,
            ),

            "dst_host_same_src_port_rate": 0.0,

            "dst_host_srv_diff_host_rate": 0.0,

            "dst_host_serror_rate": error_rate,

            "dst_host_srv_serror_rate": error_rate,

            "dst_host_rerror_rate": error_rate,

            "dst_host_srv_rerror_rate": error_rate,
        }

        feature_records.append(features)

    result = pd.DataFrame(
        feature_records,
        columns=FEATURE_COLUMNS,
    )

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    input_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_INPUT
    )

    print("=" * 70)
    print("ZEEK → NSL-KDD FEATURE EXTRACTOR")
    print("=" * 70)

    print(f"\nInput: {input_path}")

    if not input_path.exists():

        print(
            f"\nERROR: Input file does not exist:\n"
            f"{input_path}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    records = load_connections(
        input_path
    )

    print(
        f"Connections loaded: {len(records)}"
    )

    # --------------------------------------------------------
    # EXTRACT
    # --------------------------------------------------------

    features = extract_features(
        records
    )

    print(
        f"Feature records: {len(features)}"
    )

    print(
        f"Feature count: {len(features.columns)}"
    )

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    missing_columns = [
        column
        for column in FEATURE_COLUMNS
        if column not in features.columns
    ]

    if missing_columns:

        print(
            "\nERROR: Missing features:"
        )

        for column in missing_columns:
            print(f"  - {column}")

        sys.exit(1)

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    output_path = (
        PROJECT_ROOT
        / "data"
        / "processed"
        / "zeek_features.csv"
    )

    features.to_csv(
        output_path,
        index=False,
    )

    print(
        f"\nSaved: {output_path}"
    )

    # --------------------------------------------------------
    # DISPLAY SAMPLE
    # --------------------------------------------------------

    print("\nFirst feature record:")

    print(
        features.iloc[0].to_dict()
    )

    print("\n" + "=" * 70)
    print("FEATURE EXTRACTION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
